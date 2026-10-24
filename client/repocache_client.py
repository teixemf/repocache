#!/usr/bin/env python3
"""Read-only REPOCACHE client for inventory, diagnostics and safe exports.

The client never modifies APT/DNF sources and never enables server-side
submissions implicitly. Only explicit local JSON exports are supported here.
"""
from __future__ import annotations

import argparse
import configparser
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler, HTTPSHandler, ProxyHandler

DEFAULT_SERVER = "https://cache.example.org"
CONFIG_FILE = Path("/etc/repocache-client/config.json")
MAX_CATALOG_BYTES = 512_000


class ClientError(ValueError):
    """Invalid client inputs or an unavailable untrusted upstream."""


def _server(value: str) -> str:
    try:
        p = urlsplit(value)
        port = p.port
    except ValueError as exc:
        raise ClientError("Invalid server address") from exc
    if (p.scheme != "https" or not p.hostname or p.username is not None
            or p.password is not None or p.path not in ("", "/")
            or p.query or p.fragment or (port is not None and port < 1)):
        raise ClientError("Server must be a HTTPS origin without credentials or paths")
    return value.rstrip("/")


def _safe_url(value: str) -> str:
    try:
        p = urlsplit(value.strip())
        if p.scheme not in ("http", "https") or not p.hostname:
            return "[non-HTTP upstream]"
        host = p.hostname
        if ":" in host:
            host = "[" + host + "]"
        if p.port:
            host += ":" + str(p.port)
        return urlunsplit((p.scheme, host, p.path, "", ""))
    except ValueError:
        return "[invalid upstream]"


def _url_host(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def _distro(root: Path) -> dict[str, str]:
    try:
        lines = (root / "etc/os-release").read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    output = {}
    for line in lines:
        if "=" in line and not line.startswith("#"):
            name, value = line.split("=", 1)
            if name in {"ID", "VERSION_ID", "PRETTY_NAME"}:
                output[name] = value.strip().strip('"').strip("'")
    return output


def _repo(name: str, kind: str, urls: list[str], path: Path,
          server: str, enabled: bool = True) -> dict:
    safe = list(dict.fromkeys(_safe_url(item) for item in urls if item.strip()))
    via = [_url_host(url) == _url_host(server) for url in safe]
    route = "mixed" if any(via) and not all(via) else (
        "repocache" if via and all(via) else "direct"
    )
    return {"name": name, "type": kind, "urls": safe,
            "source": str(path), "enabled": enabled, "route": route}


def _expand_mirror(uri: str, root: Path) -> list[str]:
    if not uri.startswith("mirror+file:"):
        return [uri]
    p = urlsplit(uri)
    if p.query or p.fragment or not p.path.startswith("/etc/apt/mirrors/"):
        return [uri]
    parent = root / "etc/apt/mirrors"
    path = root / p.path.lstrip("/")
    if (path.is_symlink() or not path.is_file() or
            path.resolve().parent != parent.resolve()):
        return [uri]
    try:
        if path.stat().st_size > 65536:
            return [uri]
        urls = [ln.split()[0] for ln in path.read_text().splitlines()
                if ln.strip() and not ln.lstrip().startswith("#")]
        return urls[:30] or [uri]
    except OSError:
        return [uri]


def _apt_sources(root: Path, server: str) -> list[dict]:
    candidates = [root / "etc/apt/sources.list"]
    directory = root / "etc/apt/sources.list.d"
    if directory.is_dir():
        candidates.extend(sorted(directory.glob("*.list")))
        candidates.extend(sorted(directory.glob("*.sources")))
    repos = []
    for path in candidates:
        if path.is_symlink() or not path.is_file():
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if path.suffix == ".sources":
            for number, stanza in enumerate(re.split(r"\n\s*\n", source), 1):
                props: dict[str, str] = {}
                previous = ""
                for line in stanza.splitlines():
                    if line.startswith((" ", "\t")) and previous:
                        props[previous] += " " + line.strip()
                    elif ":" in line and not line.lstrip().startswith("#"):
                        key, val = line.split(":", 1)
                        previous = key.lower().strip()
                        props[previous] = val.strip()
                if props.get("types") and props.get("uris"):
                    urls = [u for uri in props["uris"].split()
                            for u in _expand_mirror(uri, root)]
                    repos.append(_repo(f"{path.name}:{number}", "apt-deb822",
                                       urls, path, server,
                                       props.get("enabled", "yes").lower() != "no"))
            continue
        for number, line in enumerate(source.splitlines(), 1):
            match = re.match(r"^\s*(?:deb|deb-src)\s+(?:\[[^\]]+\]\s+)?(\S+)\s+", line)
            if match:
                repos.append(_repo(f"{path.name}:{number}", "apt-list",
                                   _expand_mirror(match.group(1), root), path, server))
    return repos


def _dnf_sources(root: Path, server: str) -> list[dict]:
    directory = root / "etc/yum.repos.d"
    if not directory.is_dir():
        return []
    repos = []
    for path in sorted(directory.glob("*.repo")):
        if path.is_symlink() or not path.is_file():
            continue
        parser = configparser.RawConfigParser(interpolation=None, strict=False)
        try:
            parser.read(path, encoding="utf-8")
        except (OSError, configparser.Error):
            continue
        for section in parser.sections():
            val = parser[section]
            urls = [item for key in ("baseurl", "mirrorlist", "metalink")
                    for item in val.get(key, "").split()]
            repos.append(_repo(section, "dnf", urls, path, server,
                               val.get("enabled", "1").lower() not in ("0", "no", "false")))
    return repos


def discover(root: Path, server: str) -> list[dict]:
    return _apt_sources(root, server) + _dnf_sources(root, server)


def _fetch_json(url: str, *, max_bytes: int):
    req = Request(url, headers={"Accept": "application/json",
                                "User-Agent": "repocache-client/0.4"})
    with urlopen(req, timeout=5) as response:
        if response.url != url:
            raise ClientError("Catalog redirects are not permitted")
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ClientError("Catalog too large")
    return json.loads(data.decode("utf-8"))


def _catalog(server: str) -> dict:
    try:
        doc = _fetch_json(server + "/.well-known/repocache/catalog.json",
                          max_bytes=MAX_CATALOG_BYTES)
    except (OSError, ValueError) as exc:
        raise ClientError("Catalog unavailable or invalid") from exc
    if not isinstance(doc, dict) or doc.get("schema") != 1:
        raise ClientError("Unsupported catalog schema")
    items = doc.get("repositories")
    if not isinstance(items, list) or len(items) > 500:
        raise ClientError("Invalid catalog entries")
    verified = []
    for mapping in items:
        if not isinstance(mapping, dict):
            raise ClientError("Invalid catalog entry")
        source = mapping.get("upstream")
        cache = mapping.get("cache")
        if not isinstance(source, str) or not isinstance(cache, str):
            raise ClientError("Missing catalog URLs")
        if (not source.startswith("https://") or not cache.startswith("https://")
                or _safe_url(source) != source or _safe_url(cache) != cache
                or not source.endswith("/") or not cache.endswith("/")
                or _url_host(cache) != _url_host(server)):
            raise ClientError("Invalid catalog URL")
        verified.append({"upstream": source, "cache": cache})
    return {"schema": 1, "repositories": verified}


def _mapped(repo: dict, catalog: dict) -> bool:
    return any(url == item["upstream"].rstrip("/") or url.startswith(item["upstream"])
               for url in repo.get("urls", []) for item in catalog["repositories"])


def _classify_repository(repo: dict, catalog: dict | None) -> str:
    urls = repo.get("urls", [])
    if not urls or any(not isinstance(url, str)
                       or not url.startswith(("http://", "https://"))
                       or not _url_host(url) for url in urls):
        return "invalid"
    if catalog is None:
        return "unavailable"
    prefixes = [u for item in catalog["repositories"]
                for u in (item["upstream"], item["cache"])]
    return ("supported" if all(any(url == pre.rstrip("/") or url.startswith(pre)
                                   for pre in prefixes) for url in urls)
            else "unknown")


def _compatibility_summary(repos: list[dict]) -> dict[str, int]:
    return {status: sum(r.get("compatibility") == status for r in repos)
            for status in ("supported", "unknown", "unavailable", "invalid")}


def _connectivity(server: str) -> list[dict]:
    p = urlsplit(server)
    host, port = p.hostname or "", p.port or 443
    try:
        socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return [{"name": "dns", "ok": False, "detail": "DNS resolution failed"}]
    checks = [{"name": "dns", "ok": True, "detail": "Resolved"}]
    try:
        with socket.create_connection((host, port), timeout=4) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host):
                pass
        checks.append({"name": "https", "ok": True, "detail": "TLS and certificate valid"})
    except OSError:
        checks.append({"name": "https", "ok": False, "detail": "TLS connection failed"})
    return checks


def _payload(distro: dict, repos: list[dict], server: str) -> dict:
    seen = set()
    out = []
    for repo in repos:
        if not repo["enabled"] or repo["route"] == "repocache":
            continue
        for url in repo["urls"]:
            pair = (repo["type"], url)
            if (url.startswith(("http://", "https://"))
                    and _url_host(url) != _url_host(server) and pair not in seen):
                seen.add(pair)
                out.append({"type": repo["type"], "url": url})
    return {"schema": 1, "os": {"id": distro.get("ID", ""),
                                "version": distro.get("VERSION_ID", "")},
            "repositories": out}


class RemoteSubmissionError(ClientError):
    def __init__(self, message: str, code: int):
        super().__init__(message)
        self.exit_code = code


def _submission_credential(path: Path) -> tuple[str, bytes]:
    """Read a local, non-symlinked 0600 file without exposing its contents."""
    try:
        st = path.lstat()
        parent = path.parent.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077
                or st.st_uid not in {0, os.geteuid()} or st.st_size > 4096
                or not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o022):
            raise ClientError("Credential file ownership or permissions are unsafe")
        # Validate the inode actually opened, not only a pre-open lstat:
        # an attacker might replace the file between those operations.
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            actual = os.fstat(stream.fileno())
            if (not stat.S_ISREG(actual.st_mode) or actual.st_mode & 0o077
                    or actual.st_uid not in {0, os.geteuid()}
                    or actual.st_size > 4096
                    or (actual.st_dev, actual.st_ino) != (st.st_dev, st.st_ino)):
                raise ClientError("Credential file changed or is unsafe")
            raw = stream.read(4097)
        cfg = json.loads(raw.decode("utf-8"))
        if not isinstance(cfg, dict) or set(cfg) != {"key_id", "secret"}:
            raise ClientError("Invalid submission credential format")
        key_id, encoded = cfg["key_id"], cfg["secret"]
        if (not isinstance(key_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key_id)
                or not isinstance(encoded, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded)):
            raise ClientError("Invalid submission credential format")
        secret = base64.urlsafe_b64decode(encoded + "=")
        if (len(secret) != 32 or base64.urlsafe_b64encode(secret).decode().rstrip("=")
                != encoded):
            raise ClientError("Invalid submission credential format")
        return key_id, secret
    except (OSError, ValueError, UnicodeError) as exc:
        if isinstance(exc, ClientError):
            raise
        raise ClientError("Cannot read a valid protected submission credential") from None


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        # Never replay credentials, request bodies or signatures to any URL.
        return None


def _send_submission(server: str, payload: dict, credential: Path) -> dict:
    """Explicit HTTPS-only one-shot submission; never follow redirects."""
    key_id, secret = _submission_credential(credential)
    if not payload["repositories"]:
        raise ClientError("No eligible repositories to submit")
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode("ascii")
    if not 0 < len(raw) <= 65536:
        raise ClientError("Submission exceeds the maximum size")
    timestamp = str(int(time.time()))
    nonce = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")
    target = server + "/v1/repository-submissions"
    canonical = (f"repocache-v1\nPOST\n/v1/repository-submissions\n{timestamp}\n{nonce}\n"
                 f"{hashlib.sha256(raw).hexdigest()}").encode("ascii")
    signature = hmac.new(secret, canonical, hashlib.sha256).hexdigest()
    request = Request(target, data=raw, method="POST", headers={
        "Content-Type": "application/json",
        "X-Repocache-Key-Id": key_id,
        "X-Repocache-Timestamp": timestamp,
        "X-Repocache-Nonce": nonce,
        "X-Repocache-Signature": signature,
    })
    # No ambient proxy, no redirected Authorization/HMAC headers, standard TLS
    # validation and hostname checking from the OS trust store.
    opener = build_opener(ProxyHandler({}), _RejectRedirects(),
                          HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(request, timeout=8) as response:
            if response.status != 202:
                raise RemoteSubmissionError("Submission not accepted", 6)
            answer = response.read(2049)
            if len(answer) > 2048:
                raise RemoteSubmissionError("Oversized submission response", 6)
            doc = json.loads(answer.decode("utf-8"))
            ident = doc.get("proposal_id") if isinstance(doc, dict) else None
            if (not isinstance(ident, str) or
                    not re.fullmatch(r"[a-f0-9]{32}", ident)):
                raise RemoteSubmissionError("Invalid submission response", 6)
            return {"ok": True, "status": "pending", "proposal_id": ident}
    except HTTPError as exc:
        # Ignore untrusted response text and headers; 3xx cannot be followed.
        if exc.code in (401, 403):
            raise RemoteSubmissionError("Submission authentication failed", 4) from None
        if exc.code == 429:
            raise RemoteSubmissionError("Submission rate limit exceeded", 5) from None
        raise RemoteSubmissionError("Submission endpoint rejected request", 6) from None
    except (URLError, TimeoutError, OSError):
        raise RemoteSubmissionError("Submission endpoint unavailable or TLS failed", 6) from None
    except (UnicodeError, ValueError, TypeError):
        raise RemoteSubmissionError("Invalid submission response", 6) from None


def _output(data: dict, json_mode: bool) -> None:
    if json_mode:
        print(json.dumps(data, indent=2))
        return
    for item in data.get("checks", []):
        print(("OK" if item["ok"] else "WARN") + " " + item["name"] + ": " + item["detail"])
    for repo in data.get("repositories", []):
        print(repo["name"] + " " + repo.get("support", repo["route"]) +
              " " + ", ".join(repo.get("urls", [])))
    if "note" in data:
        print(data["note"])


def _common_options(parser: argparse.ArgumentParser, *, nested: bool = False) -> None:
    """Allow globals at every command depth without erasing parent values."""
    defaults = {"default": argparse.SUPPRESS} if nested else {}
    parser.add_argument("--server", **defaults)
    parser.add_argument("--json", action="store_true", **defaults)


def build_parser() -> argparse.ArgumentParser:
    """Register the approved client command grammar in one auditable place."""
    parser = argparse.ArgumentParser(prog="repocache-client")
    _common_options(parser)
    cmds = parser.add_subparsers(dest="command", required=True)
    check = cmds.add_parser("check")
    _common_options(check, nested=True)
    repos_cmd = cmds.add_parser("repos", aliases=["repo"])
    _common_options(repos_cmd, nested=True)
    actions = repos_cmd.add_subparsers(dest="action")
    listing = actions.add_parser("list", aliases=["ls"])
    _common_options(listing, nested=True)
    submit = actions.add_parser("submit")
    _common_options(submit, nested=True)
    submit.add_argument("--output", type=Path)
    submit.add_argument("--token-file", type=Path)
    submit.add_argument("--send", action="store_true", help="Explicit authenticated pending-only HTTPS submission")
    sync = actions.add_parser("sync")
    _common_options(sync, nested=True)
    sync.add_argument("--apply", action="store_true")
    return parser


def run(argv: list[str] | None = None, root: Path = Path("/")) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in {"repos", "repo"} and args.action is None:
        # Do not consult the network or local package manager for object help.
        repos_action = next(action for action in parser._actions
                            if isinstance(action, argparse._SubParsersAction))
        repos_action.choices["repos"].print_help()
        return 0
    try:
        cfg = root / CONFIG_FILE.relative_to("/")
        configured = ""
        if cfg.is_file() and not cfg.is_symlink():
            item = json.loads(cfg.read_text())
            if isinstance(item, dict):
                configured = str(item.get("server") or "")
        server = _server(args.server or configured or DEFAULT_SERVER)
        repos = discover(root, server)
        distro = _distro(root)
        if args.command == "check":
            checks = _connectivity(server)
            catalog = None
            if checks and all(c["ok"] for c in checks):
                try:
                    catalog = _catalog(server)
                    checks.append({"name": "catalog", "ok": True, "detail": "Available"})
                except ClientError:
                    checks.append({"name": "catalog", "ok": False, "required": False,
                                   "detail": "Catalog unavailable"})
            else:
                checks.append({"name": "catalog", "ok": False, "required": False,
                               "detail": "Skipped"})
            for repo in repos:
                repo["compatibility"] = _classify_repository(repo, catalog)
                repo["support"] = ("via REPOCACHE" if repo["route"] == "repocache"
                                   else "supported (not synced)" if catalog and _mapped(repo, catalog)
                                   else "unconfirmed (catalog unavailable)" if catalog is None
                                   else "not supported by catalog")
                if repo["compatibility"] == "invalid":
                    repo["support"] = "invalid repository URL"
            cached = [r for r in repos if r["enabled"] and r["route"] != "direct"]
            ok_fallback = sum(r["route"] == "mixed" for r in cached)
            checks.append({"name": "fallback", "ok": bool(cached) and ok_fallback == len(cached),
                           "required": False, "detail": "Configured fallback check"})
            bad = any(r["enabled"] and r["compatibility"] == "invalid" for r in repos)
            code = 1 if not all(c["ok"] for c in checks if c.get("required", True)) else 3 if bad else 0
            _output({"ok": code == 0, "os": distro, "server": server, "checks": checks,
                     "repositories": repos, "compatibility_summary": _compatibility_summary(repos),
                     "exit_code": code}, args.json)
            return code
        if args.action in {"list", "ls"}:
            _output({"os": distro, "server": server, "repositories": repos}, args.json)
            return 0
        if args.action == "submit":
            payload = _payload(distro, repos, server)
            if args.send:
                if args.output or not args.token_file:
                    raise ClientError("Explicit --send requires --token-file and forbids --output")
                result = _send_submission(server, payload, args.token_file)
                if args.json:
                    print(json.dumps(result))
                else:
                    print("Submission accepted as pending: " + result["proposal_id"])
                return 0
            if args.output and not args.token_file:
                fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2)
                    handle.write("\n")
                _output({"note": "Request exported", "count": len(payload["repositories"])}, args.json)
                return 0
            raise ClientError("Remote submission is not enabled; use --output FILE")
        if args.action == "sync":
            if args.apply:
                raise ClientError("Applying changes is disabled until reviewed")
            catalog = _catalog(server)
            _output({"server": server,
                     "repositories": [dict(r, supported=_mapped(r, catalog)) for r in repos],
                     "note": "DRY RUN: no APT/DNF configuration was changed."}, args.json)
            return 0
        raise ClientError("Unknown command")
    except RemoteSubmissionError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc), "exit_code": exc.exit_code}))
        else:
            print("ERROR: " + str(exc), file=sys.stderr)
        return exc.exit_code
    except (OSError, ValueError, ClientError) as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}))
        else:
            print("ERROR: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(run())
