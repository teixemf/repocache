"""Read-only discovery of stable GitHub Releases, public or private.

Anonymous HTTPS is always attempted first. Optional credentials come from a
protected file and are only used after an authentication-relevant response.
No Git/SSH, shell commands, writes, or implicit mirrors are involved.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPOSITORY = "teixemf/repocache"
API_ORIGIN = "https://api.github.com"
TOKEN_FILE = Path("/etc/repocache/github-token")
MAX_RESPONSE = 2_000_000
VERSION = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class DiscoveryError(RuntimeError):
    """A sanitized discovery failure carrying a stable status."""

    def __init__(self, status: str, message: str):
        self.status = status
        super().__init__(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects, especially when Authorization is present."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


def credential_path() -> Path:
    """Prefer a protected per-user credential for non-root read-only checks."""
    explicit = os.environ.get("REPOCACHE_GITHUB_TOKEN_FILE")
    if explicit:
        return Path(explicit)
    user_file = Path.home() / ".config/repocache/github-token"
    return user_file if user_file.exists() or user_file.is_symlink() else TOKEN_FILE


def _token(path: Path = TOKEN_FILE) -> Optional[str]:
    """Return an optional read-only token without exposing it to the CLI."""
    if not path.is_absolute():
        raise DiscoveryError("authentication-required", "Token-file path must be absolute")
    if not path.exists() and not path.is_symlink():
        return None
    try:
        stat = path.lstat()
        if (path.is_symlink() or not path.is_file() or stat.st_mode & 0o077
                or stat.st_uid not in (0, os.geteuid())):
            raise DiscoveryError("authentication-required",
                                 "Token file must be a regular file with mode 0600")
        if stat.st_size > 4096:
            raise DiscoveryError("authentication-required", "Token file is too large")
        token = path.read_text(encoding="ascii").strip()
    except DiscoveryError:
        raise
    except (OSError, UnicodeError):
        raise DiscoveryError("authentication-required", "Could not read protected token file")
    if not token or not re.fullmatch(r"[A-Za-z0-9_-]+", token):
        raise DiscoveryError("authentication-required", "Protected token file is invalid")
    return token


def _request(url: str, token: Optional[str] = None) -> Any:
    """Only contact the fixed official GitHub Releases API."""
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.netloc != "api.github.com" or
            parsed.username or parsed.password or parsed.fragment or
            not parsed.path.startswith("/repos/" + REPOSITORY + "/releases")):
        raise DiscoveryError("error", "Unexpected release API endpoint")
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "repocache-release-discovery/1",
               "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(
        NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(req, timeout=8) as response:
            data = response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 404):
            raise DiscoveryError("authentication-required",
                                 "Release repository not found or authentication is required")
        if exc.code == 403:
            raise DiscoveryError("error", "GitHub API access denied or rate limited")
        if exc.code in (301, 302, 303, 307, 308):
            raise DiscoveryError("error", "Untrusted GitHub API redirect rejected")
        raise DiscoveryError("error", "GitHub API returned HTTP " + str(exc.code))
    except (OSError, urllib.error.URLError, TimeoutError):
        raise DiscoveryError("offline", "GitHub Releases could not be reached")
    if len(data) > MAX_RESPONSE:
        raise DiscoveryError("invalid-release", "Release metadata exceeds size limit")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise DiscoveryError("invalid-release", "Invalid GitHub Release JSON")


def _request_public_first(url: str, token_file: Path = TOKEN_FILE) -> Any:
    try:
        return _request(url)
    except DiscoveryError as error:
        if error.status != "authentication-required":
            raise
        token = _token(token_file)
        if not token:
            raise
        return _request(url, token=token)


def _version(tag: Any) -> Optional[Tuple[int, int, int]]:
    match = VERSION.fullmatch(tag) if isinstance(tag, str) else None
    return tuple(int(p) for p in match.groups()) if match else None


def _asset(asset: Any, expected: str) -> Optional[Dict[str, Any]]:
    if not isinstance(asset, dict) or asset.get("name") != expected:
        return None
    value = asset.get("id")
    size = asset.get("size")
    if (type(value) is not int or value <= 0 or
            type(size) is not int or size <= 0):
        return None
    return {"name": expected, "id": value, "size": size}


def _release(record: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(record, dict) or record.get("draft") is not False or record.get("prerelease") is not False:
        return None
    tag = record.get("tag_name")
    version = _version(tag)
    if version is None:
        return None
    url = record.get("html_url")
    expected_url = "https://github.com/" + REPOSITORY + "/releases/tag/" + tag
    if url != expected_url:
        return None
    assets = record.get("assets")
    if not isinstance(assets, list) or len(assets) > 100:
        return None
    archive_name = "repocache-" + tag + ".tar.gz"
    checksum_name = archive_name + ".sha256"
    archives = [a for a in assets if isinstance(a, dict) and a.get("name") == archive_name]
    checksums = [a for a in assets if isinstance(a, dict) and a.get("name") == checksum_name]
    manifest_name = archive_name + ".manifest.json"
    signature_name = manifest_name + ".sig"
    wheelhouse_name = archive_name + ".wheelhouse.tar.gz"
    wheelhouses = [a for a in assets if isinstance(a, dict) and a.get("name") == wheelhouse_name]
    manifests = [a for a in assets if isinstance(a, dict) and a.get("name") == manifest_name]
    signatures = [a for a in assets if isinstance(a, dict) and a.get("name") == signature_name]
    if any(len(entries) != 1 for entries in (archives, checksums, manifests, signatures, wheelhouses)):
        return None
    archive = _asset(archives[0], archive_name)
    checksum = _asset(checksums[0], checksum_name)
    manifest = _asset(manifests[0], manifest_name)
    signature = _asset(signatures[0], signature_name)
    wheelhouse = _asset(wheelhouses[0], wheelhouse_name)
    if (not all((archive, checksum, manifest, signature, wheelhouse))
            or len({entry["id"] for entry in (archive, checksum, manifest, signature, wheelhouse)}) != 5):
        return None
    return {"version": tag[1:], "tag": tag, "url": url,
            "assets": {"archive": archive, "checksum": checksum,
                       "manifest": manifest, "signature": signature,
                       "wheelhouse": wheelhouse},
            "compatibility": "unknown",
            "compatibility_reason": "No validated compatibility manifest is available",
            "eligible": False}


def discover(token_file: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Return at most 500 stable, complete releases in descending SemVer order."""
    token_file = token_file if token_file is not None else credential_path()
    found: Dict[str, Dict[str, Any]] = {}
    for page in range(1, 6):
        url = (API_ORIGIN + "/repos/" + REPOSITORY +
               "/releases?per_page=100&page=" + str(page))
        records = _request_public_first(url, token_file=token_file)
        if not isinstance(records, list) or len(records) > 100:
            raise DiscoveryError("invalid-release", "Unexpected releases list")
        for record in records:
            item = _release(record)
            if item is not None:
                if item["version"] in found and found[item["version"]] != item:
                    raise DiscoveryError("invalid-release", "Conflicting release versions")
                found[item["version"]] = item
        if len(records) < 100:
            break
    else:
        raise DiscoveryError("invalid-release", "Release history exceeds supported pagination")
    return sorted(found.values(), key=lambda x: _version(x["tag"]), reverse=True)


def report(installed: str, *, list_all: bool = False,
           token_file: Optional[Path] = None) -> Dict[str, Any]:
    """Read-only, JSON-stable check/list result with actionable uncertainty."""
    base: Dict[str, Any] = {
        "installed_version": installed, "latest_version": None,
        "update_available": None, "release_url": None,
        "status": "error", "performed": False, "releases": [],
    }
    try:
        releases = discover(token_file)
    except DiscoveryError as exc:
        return {**base, "status": exc.status, "message": str(exc)}
    if not releases:
        return {**base, "status": "invalid-release",
                "message": "No published stable releases with complete assets were found"}
    latest = releases[0]
    newer = _version("v" + installed)
    available = newer is not None and _version(latest["tag"]) > newer
    entries = [dict(item, installed=item["version"] == installed,
                    latest=item["version"] == latest["version"]) for item in releases]
    return {**base, "status": "update-available" if available else "up-to-date",
            "latest_version": latest["version"], "update_available": available,
            "release_url": latest["url"], "releases": entries if list_all else [],
            "message": ("A newer stable REPOCACHE release is available" if available
                        else "No newer stable REPOCACHE release was found")}
