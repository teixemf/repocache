"""Read-only access to system state and NGINX JSON logs.

The CLI never invents metrics; missing data is reported as unavailable.
"""
from __future__ import annotations

import glob
import json
import queue
import threading
import os
import re
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class Settings:
    cache_dir: Path = Path(os.getenv("REPOCACHE_CACHE_DIR", "/var/cache/nginx/repos"))
    metrics_log: Path = Path(os.getenv("REPOCACHE_METRICS_LOG", "/var/log/nginx/repocache-metrics.log"))
    nginx_bin: str = os.getenv("REPOCACHE_NGINX_BIN", "nginx")
    nginx_dump_file: str = os.getenv("REPOCACHE_NGINX_DUMP_FILE", "")
    nginx_conf: Path = Path(os.getenv("REPOCACHE_NGINX_CONF", "/etc/nginx/nginx.conf"))


def command(argv: List[str], timeout: int = 10) -> Dict[str, Any]:
    """Run commands without a shell; return structured errors and enforce a timeout."""
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return {"ok": result.returncode == 0, "code": result.returncode,
                "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"ok": False, "code": None, "stdout": "", "stderr": str(error)}


def permission_blocked(message: str) -> bool:
    """A permission error does not mean NGINX configuration syntax is invalid."""
    return bool(re.search(r"permission denied|operation not permitted|access denied", message, re.I))


def _read_nginx_includes(entry: Path) -> Dict[str, Any]:
    """Read nginx.conf include trees without invoking nginx -T.

    Discovery only (not syntax validation); limit depth and size to avoid
    cycles and unbounded reads of externally controlled files.
    """
    warnings: List[str] = []
    files: List[str] = []
    count = [0]
    prefix = entry.parent
    include_re = re.compile(r"(?m)^[ \t]*include[ \t]+([^;]+)[ \t]*;")

    def expand(file: Path, ancestry: frozenset, depth: int) -> str:
        resolved = file.resolve()
        if depth > 12 or resolved in ancestry or count[0] >= 150:
            warnings.append(f"Include depth limit or cycle: {file}")
            return ""
        try:
            if file.stat().st_size > 2_000_000:
                warnings.append(f"Include too large: {file}")
                return ""
            content = file.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            warnings.append(f"Could not read {file}: {error}")
            return ""
        count[0] += 1
        files.append(str(file))

        def replace(match: re.Match) -> str:
            raw = match.group(1).strip().strip('"\'')
            if '$' in raw:  # nginx cannot resolve includes containing shell variables
                warnings.append(f"Dynamic include not expanded: {raw}")
                return ""
            pattern = raw if os.path.isabs(raw) else str(prefix / raw)
            matches = sorted(glob.glob(pattern))[:150]
            return "\n".join(expand(Path(name), ancestry | {resolved}, depth + 1)
                             for name in matches if Path(name).is_file())

        return include_re.sub(replace, content)

    expanded = expand(entry, frozenset(), 0)
    return {"text": expanded, "files": files, "warnings": warnings}


def nginx_config(settings: Settings) -> Dict[str, Any]:
    """Discover routes even when nginx -T cannot access TLS keys.

    'ok' means configuration was available for discovery;
    'validated' is True only if nginx -T completed successfully.
    """
    if settings.nginx_dump_file:
        try:
            return {"ok": True, "validated": False, "partial": False,
                    "source": settings.nginx_dump_file, "files": [settings.nginx_dump_file],
                    "warnings": [],
                    "stdout": Path(settings.nginx_dump_file).read_text(encoding="utf-8"),
                    "stderr": "", "code": 0}
        except OSError as error:
            return {"ok": False, "validated": False, "partial": True, "source": "dump",
                    "files": [], "warnings": [str(error)], "stdout": "", "stderr": str(error), "code": None}
    attempted = command([settings.nginx_bin, "-T"], timeout=12)
    if attempted["ok"]:
        return {**attempted, "validated": True, "partial": False, "source": "nginx -T",
                "files": [], "warnings": []}
    fallback = _read_nginx_includes(settings.nginx_conf)
    if fallback["files"]:
        return {"ok": True, "validated": False,
                "partial": bool(fallback["warnings"]), "source": "NGINX files (direct read)",
                "files": fallback["files"], "warnings": fallback["warnings"],
                "stdout": fallback["text"], "stderr": attempted["stderr"], "code": attempted["code"]}
    # An interrupted nginx -T may have emitted partial configuration.
    partial_stdout = attempted["stdout"]
    return {"ok": bool(partial_stdout), "validated": False, "partial": True,
            "source": "nginx -T (partial)" if partial_stdout else "unavailable",
            "files": [], "warnings": fallback["warnings"],
            "stdout": partial_stdout, "stderr": attempted["stderr"], "code": attempted["code"]}


def _location_blocks(config: str) -> List[Tuple[str, str]]:
    """Extract location blocks by brace depth (NGINX subset).

    This does not evaluate NGINX expressions; used for display only.
    """
    pattern = re.compile(r"(?m)^\s*location\s+(?:\^~\s+|=\s+)?(/[^\s{]*)\s*\{")
    results: List[Tuple[str, str]] = []
    for found in pattern.finditer(config):
        depth, start, end = 1, found.end(), found.end()
        while end < len(config) and depth:
            if config[end] == "{":
                depth += 1
            elif config[end] == "}":
                depth -= 1
            end += 1
        if depth == 0:
            results.append((found.group(1), config[start:end-1]))
    return results


def discover_repos(config: str) -> List[Dict[str, str]]:
    repos: Dict[str, Dict[str, str]] = {}
    for path, body in _location_blocks(config):
        found = re.search(r"(?m)^\s*proxy_pass\s+([^;\s]+)\s*;", body)
        if found:
            name = path.strip("/").replace("/", ":") or "root"
            repos[path] = {"name": name, "path": path, "upstream": found.group(1)}
    return sorted(repos.values(), key=lambda x: x["path"])




def probe_upstream(repo: Dict[str, str], timeout: float = 4.0) -> Dict[str, str]:
    """Bounded, non-mutating DNS/TCP/TLS probe of a selected upstream.

    This never tests via the local cache. DNS is resolved in a daemon thread to
    bound UI waiting even on platforms with blocking getaddrinfo implementations.
    The shared deadline also bounds TCP connection and TLS negotiation.
    """
    url = repo.get("upstream", "")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        parsed, port = None, None
    base = {"dns": "not checked", "connectivity": "not checked",
            "tls": "not checked", "result": "WARN"}
    if (parsed is None or "$" in url or parsed.scheme not in ("https", "http") or not parsed.hostname
            or parsed.username or parsed.password or port is None):
        return {**base, "detail": "Dynamic or unsafe upstream: direct probing unavailable"}
    host = parsed.hostname
    timeout = max(0.5, min(float(timeout), 8.0))
    deadline = time.monotonic() + timeout
    answers: "queue.Queue[Any]" = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            value = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except (OSError, ValueError) as error:
            value = error
        answers.put(value)

    threading.Thread(target=resolve, daemon=True).start()
    try:
        result = answers.get(timeout=timeout)
    except queue.Empty:
        return {**base, "dns": "timeout", "result": "FAIL",
                "detail": "DNS resolution timed out"}
    if isinstance(result, Exception) or not result:
        return {**base, "dns": "failed", "result": "FAIL",
                "detail": "DNS resolution failed"}
    for family, socktype, protocol, _, address in result[:3]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            with socket.socket(family, socktype, protocol) as connection:
                connection.settimeout(remaining)
                connection.connect(address)
                if parsed.scheme == "https":
                    context = ssl.create_default_context()
                    connection.settimeout(max(0.01, deadline - time.monotonic()))
                    with context.wrap_socket(connection, server_hostname=host):
                        pass
                    return {"dns": "resolved", "connectivity": "reachable",
                            "tls": "verified", "result": "OK",
                            "detail": "DNS, TCP and TLS certificate checks succeeded"}
                return {"dns": "resolved", "connectivity": "reachable",
                        "tls": "not applicable (HTTP)", "result": "OK",
                        "detail": "DNS and TCP checks succeeded (HTTP, no TLS)"}
        except ssl.SSLError:
            return {"dns": "resolved", "connectivity": "reachable",
                    "tls": "failed", "result": "FAIL",
                    "detail": "TLS handshake or certificate validation failed"}
        except (OSError, ValueError):
            continue
    return {"dns": "resolved", "connectivity": "unreachable",
            "tls": "not checked", "result": "FAIL",
            "detail": "TCP connection failed or exceeded the deadline"}

def service_status() -> str:
    result = command(["systemctl", "is-active", "nginx"], timeout=4)
    if result["ok"] and result["stdout"] == "active":
        return "active"
    if result["stdout"] in {"inactive", "failed", "activating", "deactivating"}:
        return result["stdout"]
    return "unknown"


def disk_status(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"ok": False, "path": str(path), "reason": "directory does not exist",
                "total": None, "used": None, "free": None, "percent": None}
    try:
        usage = shutil.disk_usage(path)
        return {"ok": True, "path": str(path), "total": usage.total,
                "used": usage.used, "free": usage.free,
                "percent": round(100 * usage.used / usage.total, 1) if usage.total else None,
                "note": "filesystem usage (not just cache files)"}
    except OSError as error:
        return {"ok": False, "path": str(path), "reason": str(error),
                "total": None, "used": None, "free": None, "percent": None}


def timestamp(raw: Any) -> Optional[datetime]:
    if raw is None or raw == "":
        return None
    if isinstance(raw, (int, float)):
        try:
            return datetime.fromtimestamp(float(raw), tz=timezone.utc)
        except (OverflowError, ValueError, OSError):
            return None
    value = str(raw).strip()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return (parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except ValueError:
        pass
    try:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except ValueError:
        return None


def _first(record: Dict[str, Any], *names: str) -> Any:
    for name in names:
        if record.get(name) not in (None, ""):
            return record[name]
    return None


def _number(raw: Any) -> Optional[float]:
    try:
        x = float(raw)
        return x if 0 <= x < 1e18 else None
    except (TypeError, ValueError, OverflowError):
        return None


def _tail_bytes(path: Path, max_bytes: int = 8_000_000) -> Tuple[List[str], bool]:
    """Read at most max_bytes, discarding an initial incomplete line."""
    with path.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        offset = max(0, size - max_bytes)
        stream.seek(offset)
        payload = stream.read()
    if offset:
        newline = payload.find(b"\n")
        payload = payload[newline + 1:] if newline >= 0 else b""
    return payload.decode("utf-8", errors="replace").splitlines(), offset > 0


def _metrics_repo_prefix(value: str) -> Optional[str]:
    """Canonicalize a read-only repository filter to an exact route prefix."""
    if not isinstance(value, str) or len(value) > 256:
        return None
    parts = value.strip("/").split("/")
    if any(not part or part in (".", "..") or
           not re.fullmatch(r"[A-Za-z0-9._~+-]+", part) for part in parts):
        return None
    return "/" + "/".join(parts) + "/"


def _metrics_request_path(record: Dict[str, Any]) -> Optional[str]:
    """Use only an absolute URI path, never a query string, to match a route."""
    raw = _first(record, "uri", "request_uri", "path")
    if not isinstance(raw, str) or len(raw) > 8192 or not raw.startswith("/"):
        return None
    path = raw.split("?", 1)[0]
    if (not path or "\\" in path or "#" in path or "//" in path
            or any(part in (".", "..") for part in path.split("/"))
            or re.search(r"%(?:2f|5c|2e)", path, flags=re.I)):
        return None
    return path


def metrics(settings: Settings, hours: int = 24, repo: Optional[str] = None,
            now: Optional[datetime] = None) -> Dict[str, Any]:
    """Aggregate NDJSON without assuming that a sampled window covers all history."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    cutoff = now - timedelta(hours=hours)
    base = {"hours": hours, "repo": repo, "source": str(settings.metrics_log),
            "available": False, "requests": 0, "hit": 0, "miss": 0, "bypass": 0,
            "cache_observed": 0, "hit_rate": None, "errors_5xx": 0,
            "bytes_sent": None, "bytes_observed": 0, "statuses_observed": 0,
            "avg_request_ms": None, "series": [], "series_unit": "day" if hours > 24 else "hour",
            "first_seen": None, "last_seen": None, "truncated": False,
            "ignored_records": 0, "coverage": "unavailable", "detail": ""}
    prefix = _metrics_repo_prefix(repo) if repo is not None else None
    if repo is not None and prefix is None:
        base["detail"] = "Invalid repository route filter"
        return base
    if settings.metrics_log.is_symlink() or not settings.metrics_log.is_file():
        base["detail"] = "Metrics log is missing, symlinked or inaccessible"
        return base
    try:
        lines, truncated = _tail_bytes(settings.metrics_log)
    except OSError as error:
        base["detail"] = "Cannot read log: " + str(error)
        return base
    base["truncated"] = truncated
    times: List[datetime] = []
    statuses: Counter = Counter()
    hourly: Counter = Counter()
    daily: Counter = Counter()
    durations: List[float] = []
    bytes_total = 0
    for line in lines:
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("JSON is not an object")
        except (ValueError, TypeError):
            base["ignored_records"] += 1
            continue
        stamp = timestamp(_first(record, "time_iso8601", "timestamp", "@timestamp", "time", "ts", "date"))
        if stamp is None:
            base["ignored_records"] += 1
            continue
        if stamp < cutoff or stamp > now:
            continue
        if prefix is not None:
            # A deployment-generated route label avoids retaining request paths.
            # Legacy logs can use strict path-prefix matching as a fallback.
            label = record.get("repocache_repository")
            if label is not None:
                if label != prefix:
                    continue
            else:
                path = _metrics_request_path(record)
                if path is None or not path.startswith(prefix):
                    continue
        times.append(stamp)
        base["requests"] += 1
        hour = stamp.replace(minute=0, second=0, microsecond=0).isoformat()
        hourly[hour] += 1
        day = stamp.replace(hour=0, minute=0, second=0, microsecond=0).date().isoformat()
        daily[day] += 1
        code = _first(record, "status", "http_status", "response_status", "status_code")
        try:
            parsed_code = int(code)
            if 100 <= parsed_code <= 599:
                base["statuses_observed"] += 1
            if 500 <= parsed_code <= 599:
                base["errors_5xx"] += 1
        except (ValueError, TypeError):
            pass
        cache = str(_first(record, "upstream_cache_status", "cache_status", "cache") or "").upper()
        if cache in {"HIT", "MISS", "BYPASS", "EXPIRED", "STALE", "UPDATING", "REVALIDATED"}:
            base["cache_observed"] += 1
            statuses[cache] += 1
        size = _number(_first(record, "body_bytes_sent", "bytes_sent", "response_bytes"))
        if size is not None:
            bytes_total += int(size)
            base["bytes_observed"] += 1
        duration = _number(_first(record, "request_time", "duration"))
        if duration is not None:
            durations.append(duration)
    if times:
        base["available"] = True
        base["first_seen"] = min(times).isoformat()
        base["last_seen"] = max(times).isoformat()
        base["bytes_sent"] = bytes_total if base["bytes_observed"] else None
        base["errors_5xx"] = base["errors_5xx"] if base["statuses_observed"] else None
        base["hit"] = statuses["HIT"]
        base["miss"] = statuses["MISS"]
        base["bypass"] = statuses["BYPASS"]
        if base["cache_observed"]:
            base["hit_rate"] = round(100 * base["hit"] / base["cache_observed"], 1)
        if durations:
            base["avg_request_ms"] = round(1000 * sum(durations) / len(durations), 1)
        if hours > 24 and hours % 24 == 0:
            start_day = cutoff.date()
            days = (now.date() - start_day).days + 1
            # UTC boundaries: first and last calendar days may contain partial hours.
            base["series"] = [{"hour": (start_day + timedelta(days=i)).isoformat(),
                               "requests": daily[(start_day + timedelta(days=i)).isoformat()]}
                              for i in range(min(days, 366))]
            base["series_unit"] = "day"
        else:
            start_hour = cutoff.replace(minute=0, second=0, microsecond=0)
            count = min(169, hours + 1)
            base["series"] = [{"hour": (start_hour + timedelta(hours=i)).isoformat(),
                               "requests": hourly[(start_hour + timedelta(hours=i)).isoformat()]}
                              for i in range(count)]
            base["series_unit"] = "hour"
        base["coverage"] = ("truncated" if truncated else
                            "partial" if base["ignored_records"] else "sampled")
        base["detail"] = ("Sampled current log up to 8 MB; rotation and earlier "
                          "history may be missing")
        if base["ignored_records"]:
            base["detail"] += "; malformed records were ignored"
    else:
        base["coverage"] = ("truncated" if truncated else
                            "invalid" if base["ignored_records"] else "no_observations")
        base["detail"] = "No valid timestamped requests in the selected time range"
        if truncated:
            base["detail"] += "; the log sample was truncated"
        elif base["ignored_records"]:
            base["detail"] += "; malformed records were ignored"
    return base


def snapshot(settings: Settings, hours: int = 24) -> Dict[str, Any]:
    dump = nginx_config(settings)
    return {"service": service_status(), "disk": disk_status(settings.cache_dir),
            "repos": discover_repos(dump["stdout"]),
            "nginx_config_readable": dump["ok"],
            "nginx_config_validated": dump["validated"],
            "nginx_config_source": dump["source"],
            "nginx_config_partial": dump["partial"],
            "nginx_config_warnings": dump["warnings"],
            "nginx_config_error": dump["stderr"] if not dump["validated"] else "",
            "metrics": metrics(settings, hours=hours),
            "collected_at": datetime.now(timezone.utc).isoformat()}


def health(settings: Settings, deep: bool = False) -> Dict[str, Any]:
    checks: List[Dict[str, str]] = []
    state = service_status()
    checks.append({"name": "NGINX service", "result": "OK" if state == "active" else "WARN",
                   "detail": state})
    config = command([settings.nginx_bin, "-t"], timeout=12)
    config_detail = (config["stderr"] or config["stdout"])[-320:]
    denied = not config["ok"] and permission_blocked(config_detail)
    checks.append({"name": "NGINX syntax",
                   "result": "WARN" if denied else ("OK" if config["ok"] else "FAIL"),
                   "detail": ("Not verified: insufficient permissions. Run sudo repocache config check"
                              if denied else config_detail)})
    disk = disk_status(settings.cache_dir)
    checks.append({"name": "Filesystem cache", "result": "OK" if disk["ok"] else "FAIL",
                   "detail": disk.get("reason", disk.get("note", ""))})
    if disk["ok"] and disk["percent"] is not None and disk["percent"] >= 90:
        checks.append({"name": "Disk usage", "result": "WARN",
                       "detail": f"{disk['percent']}% used"})
    log_ok = settings.metrics_log.is_file() and os.access(settings.metrics_log, os.R_OK)
    checks.append({"name": "Metrics log", "result": "OK" if log_ok else "WARN",
                   "detail": str(settings.metrics_log)})
    dump = nginx_config(settings)
    repos = discover_repos(dump["stdout"])
    if dump["ok"]:
        note = f"{len(repos)} proxy_pass routes · source: {dump['source']}"
        if not dump["validated"]:
            note += " · NGINX validation pending"
        if dump["partial"]:
            note += " · partial read"
        if not repos:
            note += " · no routes detected (check configuration and syntax)"
    else:
        note = "Cannot access configuration: " + (dump["stderr"] or "; ".join(dump["warnings"]))[-220:]
    checks.append({"name": "Repository discovery",
                   "result": ("WARN" if not dump["ok"] or dump["partial"] or not repos else "OK"),
                   "detail": note})
    if deep:
        for repo in repos:
            result = check_upstream(repo)
            checks.append({"name": "Upstream " + repo["name"],
                           "result": result["result"], "detail": result["detail"]})
    return {"checks": checks, "ok": not any(c["result"] == "FAIL" for c in checks)}


def check_upstream(repo: Dict[str, str], timeout: int = 5) -> Dict[str, str]:
    """Check DNS and HTTP/TLS for proxy_pass upstreams, not the local proxy."""
    url = repo["upstream"]
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {"result": "WARN", "detail": "dynamic NGINX upstream; automatic probing unavailable"}
    try:
        socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
                           type=socket.SOCK_STREAM)
    except (OSError, ValueError) as error:
        return {"result": "FAIL", "detail": "DNS: " + str(error)}
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "REPOCACHE-CLI/0.1"})
    try:
        # Bypass environment proxies to test the configured proxy_pass origin.
        with urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPSHandler(context=ssl.create_default_context())).open(
                                            request, timeout=timeout) as response:
            code = response.status
    except urllib.error.HTTPError as error:
        code = error.code
    except (OSError, urllib.error.URLError, ValueError) as error:
        return {"result": "FAIL", "detail": "HTTP/TLS: " + str(error)}
    status = "OK" if 200 <= code < 400 else ("WARN" if 400 <= code < 500 else "FAIL")
    return {"result": status, "detail": f"DNS OK; HTTPS/HTTP HEAD {code} (direct upstream, not local proxy)"}
