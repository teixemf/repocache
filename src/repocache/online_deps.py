"""Pre-activation acquisition of publisher-hash-locked upstream Python wheels.

SECURITY BOUNDARY: This is a standalone, currently UNWIRED staging primitive.
Only a trusted updater that has already verified an Ed25519 release manifest
may provide the expected lock digest. A caller-supplied checksum, on its own,
is NOT publisher authentication. Production activation is gated by #84.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import ssl
import stat
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path

from repocache import wheelhouse

MAX_LOCK = 131_072
MAX_ENTRIES = 80
MAX_WHEEL = 25_000_000
MAX_TOTAL = 100_000_000
MAX_ARCHIVE_ENTRIES = 2_000
MAX_ARCHIVE_UNPACKED = 150_000_000
TARGETS = ("debian13-py313", "almalinux10-py312")
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:\.post[0-9]+)?\Z")
_TAG = re.compile(r"[A-Za-z0-9_.]{1,110}\Z")


class DependencyError(RuntimeError):
    """Fail-closed dependency lock or wheel acquisition failure; no URL leaks."""


@dataclass(frozen=True)
class Wheel:
    name: str
    version: str
    filename: str
    sha256: str
    url: str


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DependencyError("Duplicate dependency lock field")
        result[key] = value
    return result


def _valid_url(url: object, filename: str) -> bool:
    if not isinstance(url, str) or len(url) > 800 or any(ord(c) > 127 for c in url):
        return False
    try:
        value = urllib.parse.urlsplit(url)
        if (value.scheme != "https" or value.netloc != "files.pythonhosted.org"
                or value.hostname != "files.pythonhosted.org"
                or value.port is not None or value.username or value.password
                or value.query or value.fragment or "%" in value.path
                or "\\" in value.path or url != urllib.parse.urlunsplit(value)):
            return False
    except ValueError:
        return False
    # Deliberately refuse mirrors, alternate CDN hosts, path traversal and
    # encoded URL delimiters until a reviewed provider policy is implemented.
    return re.fullmatch(
        r"/packages/(?:[A-Za-z0-9]+/){1,8}" + re.escape(filename), value.path
    ) is not None


def _valid_wheel_name(name: str, version: str, filename: object) -> bool:
    if not isinstance(filename, str) or len(filename) > 225 or not filename.endswith(".whl"):
        return False
    prefix = name.replace("-", "_") + "-" + version + "-"
    if not filename.startswith(prefix):
        return False
    tags = filename[len(prefix):-4].split("-")
    if len(tags) == 4:
        if not re.fullmatch(r"[0-9][A-Za-z0-9_]{0,30}", tags[0]):
            return False
        tags = tags[1:]
    return len(tags) == 3 and all(_TAG.fullmatch(tag) for tag in tags)


def parse_verified_lock(raw: bytes, expected_signed_digest: str, target: str) -> tuple[Wheel, ...]:
    """Parse lock only after comparing its bytes with a publisher-authenticated digest.

    expected_signed_digest MUST originate in a verified signed release manifest
    (#84), not a user argument or a same-origin GitHub/PyPI .sha256 file.
    """
    if (not isinstance(raw, bytes) or not raw or len(raw) > MAX_LOCK
            or not isinstance(expected_signed_digest, str)
            or not _HEX.fullmatch(expected_signed_digest)
            or hashlib.sha256(raw).hexdigest() != expected_signed_digest):
        raise DependencyError("Publisher-bound dependency lock digest mismatch")
    if target not in TARGETS:
        raise DependencyError("Unsupported native dependency target")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DependencyError("Invalid dependency lock document") from exc
    if (not isinstance(data, dict) or set(data) != {"schema", "profiles"}
            or type(data["schema"]) is not int or data["schema"] != 1
            or not isinstance(data["profiles"], dict)
            or set(data["profiles"]) != set(TARGETS)):
        raise DependencyError("Unsupported dependency lock schema")
    plans: dict[str, tuple[Wheel, ...]] = {}
    for profile, entries in data["profiles"].items():
        if (not isinstance(entries, list) or not entries
                or len(entries) > MAX_ENTRIES):
            raise DependencyError("Missing or oversized platform dependency closure")
        selected: list[Wheel] = []
        names: set[str] = set()
        filenames: set[str] = set()
        for row in entries:
            if not isinstance(row, dict) or set(row) != {
                "name", "version", "filename", "sha256", "url"
            }:
                raise DependencyError("Incomplete locked wheel record")
            name, version, filename, sha, url = (
                row["name"], row["version"], row["filename"], row["sha256"], row["url"]
            )
            if (not isinstance(name, str) or not _NAME.fullmatch(name)
                    or not isinstance(version, str) or not _VERSION.fullmatch(version)
                    or not _valid_wheel_name(name, version, filename)
                    or not isinstance(sha, str) or not _HEX.fullmatch(sha)
                    or not _valid_url(url, filename)):
                raise DependencyError("Unsafe or unsupported locked wheel metadata")
            if name in names or filename in filenames:
                raise DependencyError("Duplicate locked package or wheel filename")
            names.add(name)
            filenames.add(filename)
            selected.append(Wheel(name, version, filename, sha, url))
        plans[profile] = tuple(selected)
    return plans[target]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open(url: str, cafile: Path):
    """No proxies or redirects; use only an explicit system CA bundle."""
    context = ssl.create_default_context(cafile=str(cafile))
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=context))
    return opener.open(
        urllib.request.Request(
            url, headers={"Accept": "application/octet-stream",
                          "User-Agent": "repocache-dependency-fetch/1"}),
        timeout=12)


def _check_archive(path: Path, wheel: Wheel) -> None:
    """Bounded read-only ZIP and METADATA checks; never extract or execute."""
    try:
        with zipfile.ZipFile(path) as zf:
            entries = zf.infolist()
            if len(entries) > MAX_ARCHIVE_ENTRIES:
                raise DependencyError("Wheel contains excessive archive entries")
            seen: set[str] = set()
            total = 0
            base = wheel.name.replace("-", "_") + "-" + wheel.version + ".dist-info/"
            meta: list[zipfile.ZipInfo] = []
            info_file: list[zipfile.ZipInfo] = []
            for item in entries:
                filename = item.filename
                segments = filename.split("/")
                mode = (item.external_attr >> 16) & 0o170000
                if (not filename or len(filename) > 300 or filename in seen
                        or filename.startswith("/") or "\\" in filename
                        or any(part in ("", ".", "..") for part in segments[:-1])
                        or (segments[-1] in ("", ".", "..") and not item.is_dir())
                        or mode not in (0, stat.S_IFREG, stat.S_IFDIR)
                        or item.flag_bits & 1
                        or item.file_size > MAX_WHEEL):
                    raise DependencyError("Unsafe downloaded wheel ZIP layout")
                seen.add(filename)
                total += item.file_size
                if total > MAX_ARCHIVE_UNPACKED:
                    raise DependencyError("Wheel exceeds unpacked size limit")
                if filename == base + "METADATA":
                    meta.append(item)
                if filename == base + "WHEEL":
                    info_file.append(item)
            if (len(meta) != 1 or len(info_file) != 1
                    or meta[0].file_size > 65_536
                    or info_file[0].file_size > 16_384):
                raise DependencyError("Missing or oversized wheel package metadata")
            metadata = BytesParser().parsebytes(zf.read(meta[0]))
            normalized = re.sub(r"[-_.]+", "-", metadata.get("Name", "").lower())
            if normalized != wheel.name or metadata.get("Version") != wheel.version:
                raise DependencyError("Wheel package identity mismatch")
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
        if isinstance(exc, DependencyError):
            raise
        raise DependencyError("Invalid downloaded wheel archive") from exc


def stage_wheels(wheels: tuple[Wheel, ...], destination: Path, *, cafile: Path) -> Path:
    """Fetch and verify wheels in a NEW private directory, returning a local lock.

    No pip execution, venv activation, publication or use of unsigned metadata.
    Caller must hold updater's exclusive transaction lock and supply only
    Wheel records from parse_verified_lock() after publisher authentication.
    """
    if os.geteuid() == 0:
        raise DependencyError("Never download or stage third-party code as root")
    parent = destination.parent
    try:
        stat_parent = parent.lstat()
        if (not stat.S_ISDIR(stat_parent.st_mode)
                or stat_parent.st_uid != os.geteuid()
                or stat.S_IMODE(stat_parent.st_mode) & 0o022
                or destination.exists() or destination.is_symlink()
                or not cafile.is_absolute() or not cafile.is_file()):
            raise DependencyError("Unsafe dependency staging or CA trust path")
        if not wheels or len(wheels) > MAX_ENTRIES:
            raise DependencyError("Missing or oversized verified wheel inventory")
    except OSError as exc:
        raise DependencyError("Unsafe dependency staging or CA trust path") from exc
    destination.mkdir(mode=0o700)
    try:
        files = destination / "wheels"
        files.mkdir(mode=0o700)
        total = 0
        lines = []
        for wheel in wheels:
            if not _valid_url(wheel.url, wheel.filename):
                raise DependencyError("Unapproved downloaded wheel URL")
            path = files / wheel.filename
            digest = hashlib.sha256()
            count = 0
            try:
                with _open(wheel.url, cafile) as remote:
                    if remote.geturl() != wheel.url or remote.status != 200:
                        raise DependencyError("Unexpected upstream wheel transport response")
                    size = remote.headers.get("Content-Length")
                    if size is not None and (
                            not size.isdecimal() or int(size) > MAX_WHEEL):
                        raise DependencyError("Upstream wheel exceeds size limit")
                    fd = os.open(
                        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                        os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                    with os.fdopen(fd, "wb") as local:
                        while True:
                            block = remote.read(64 * 1024)
                            if not block:
                                break
                            count += len(block)
                            total += len(block)
                            if count > MAX_WHEEL or total > MAX_TOTAL:
                                raise DependencyError("Downloaded wheels exceed resource limits")
                            digest.update(block)
                            local.write(block)
                        local.flush()
                        os.fsync(local.fileno())
            except (OSError, urllib.error.URLError, TimeoutError) as exc:
                raise DependencyError("Approved upstream wheel download failed") from exc
            if digest.hexdigest() != wheel.sha256:
                raise DependencyError("Downloaded wheel SHA-256 does not match signed lock")
            _check_archive(path, wheel)
            lines.append(
                "./wheels/" + wheel.filename + " --hash=sha256:" + wheel.sha256)
        lock = destination / "requirements.lock"
        lock.write_text("\n".join(lines) + "\n", encoding="ascii")
        lock.chmod(0o600)
        return lock
    except BaseException:
        shutil.rmtree(destination)
        raise


def offline_install_argv(interpreter: Path, verified_requirements: Path) -> list[str]:
    """Return, but DO NOT execute, the existing strictly offline pip invocation."""
    return wheelhouse.install_argv(interpreter, verified_requirements)
