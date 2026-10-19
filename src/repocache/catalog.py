"""Explicitly approved, read-only repository catalog publishing.

Discovery does not grant approval. This module never changes NGINX.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any

from repocache.core import _location_blocks, discover_repos


class CatalogError(ValueError):
    """A catalog cannot be safely generated or published."""


_ROUTE = re.compile(r"^/(?:[A-Za-z0-9._~+-]+/)+$")
_HOST = re.compile(r"^[A-Za-z0-9.-]+$")


def _https_url(value: Any, *, origin: bool = False) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise CatalogError("A HTTPS URL is required")
    try:
        url = urllib.parse.urlsplit(value)
        port = url.port
        host = url.hostname
    except ValueError as exc:
        raise CatalogError("Malformed HTTPS URL") from exc
    if (url.scheme != "https" or not host or not _HOST.fullmatch(host)
            or url.username or url.password or url.query or url.fragment
            or "\\" in value or any(ch.isspace() for ch in value)
            or (port is not None and not 1 <= port <= 65535)):
        raise CatalogError("Unsafe HTTPS URL")
    if origin:
        if url.path not in ("", "/"):
            raise CatalogError("Server URL must be an HTTPS origin")
        return value.rstrip("/")
    if not url.path.endswith("/") or "//" in url.path or "%" in url.path:
        raise CatalogError("Upstream URL must have an unambiguous trailing slash")
    if any(part in (".", "..") for part in url.path.split("/")):
        raise CatalogError("Upstream URL contains unsafe segments")
    return value


def _route(value: Any) -> str:
    if (not isinstance(value, str) or value == "/"
            or not _ROUTE.fullmatch(value)
            or any(x in (".", "..") for x in value.split("/"))):
        raise CatalogError("Approved path must be a safe NGINX prefix ending in /")
    return value


def load_approvals(path: Path) -> list[dict[str, str]]:
    """Read a small explicit allowlist, not untrusted client submissions."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise CatalogError("Approval file is missing, a symlink, or too large")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, ValueError, OSError) as exc:
        raise CatalogError("Approval file is not valid UTF-8 JSON") from exc
    if not isinstance(data, dict) or data.get("schema") != 1:
        raise CatalogError("Unsupported approvals schema")
    entries = data.get("approved_routes")
    if not isinstance(entries, list) or len(entries) > 500:
        raise CatalogError("Invalid approvals list")
    checked = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "upstream"}:
            raise CatalogError("Each approval must contain only path and upstream")
        path_value = _route(entry["path"])
        upstream = _https_url(entry["upstream"])
        if path_value in seen:
            raise CatalogError("Duplicate approved route")
        seen.add(path_value)
        checked.append({"path": path_value, "upstream": upstream})
    return checked


def build_catalog(nginx: dict[str, Any], approvals: list[dict[str, str]],
                  server: str) -> dict[str, Any]:
    """Require validated NGINX discovery and an exact per-route approval."""
    origin = _https_url(server, origin=True)
    if not nginx.get("ok") or not nginx.get("validated") or nginx.get("partial"):
        raise CatalogError("NGINX configuration must pass nginx -T before catalog export")
    # The generic UI discovery coalesces identical paths across virtual hosts.
    # A public catalog cannot resolve that ambiguity safely.
    paths = [path for path, _ in _location_blocks(nginx.get("stdout", ""))]
    if len(paths) != len(set(paths)):
        raise CatalogError("Ambiguous NGINX location path across server blocks")
    configured: dict[str, str] = {}
    for repo in discover_repos(nginx.get("stdout", "")):
        path = repo["path"]
        if path in configured:
            raise CatalogError("Ambiguous NGINX route")
        configured[path] = repo["upstream"]
    result = []
    used = set()
    for item in approvals:
        path = _route(item["path"])
        upstream = _https_url(item["upstream"])
        if path in used:
            raise CatalogError("Duplicate approval")
        used.add(path)
        if configured.get(path) != upstream:
            raise CatalogError("An approved route does not exactly match validated NGINX")
        result.append({"upstream": upstream, "cache": origin + path})
    result.sort(key=lambda item: (item["upstream"], item["cache"]))
    if len({x["cache"] for x in result}) != len(result):
        raise CatalogError("Duplicate cache destinations")
    return {"schema": 1, "repositories": result}


def publish_catalog(data: dict[str, Any], output: Path) -> None:
    """Atomically replace only the requested static JSON file (no NGINX edits)."""
    if output.is_symlink() or not output.parent.is_dir():
        raise CatalogError("Unsafe output file or missing parent directory")
    if not isinstance(data, dict) or data.get("schema") != 1:
        raise CatalogError("Invalid catalog")
    payload = (json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True)
               + "\n").encode("utf-8")
    if len(payload) > 512000:
        raise CatalogError("Catalog exceeds the client size limit")
    fd, name = tempfile.mkstemp(prefix=".repocache-catalog-", dir=output.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o644)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if output.is_symlink():
            raise CatalogError("Refusing to replace a symlink")
        os.replace(name, output)
    finally:
        if os.path.exists(name):
            os.unlink(name)
