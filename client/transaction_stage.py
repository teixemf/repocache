"""Fail-closed transaction *staging* for future APT/DNF client source changes.

This module deliberately has NO install/apply/restore source writer. Staging
preserves a trusted snapshot and an intended payload in protected state for
review. It does not prove native failover, SELinux labels or power-loss recovery.
Never load candidate bytes from an untrusted catalog without validation.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
from pathlib import Path

MAX_SOURCE_BYTES = 1024 * 1024
MAX_STAGES = 100
SOURCE_RULE = re.compile(
    r"(?:etc/apt/sources\.list|"
    r"etc/apt/sources\.list\.d/[A-Za-z0-9][A-Za-z0-9_.-]*\.(?:list|sources)|"
    r"etc/apt/mirrors/[A-Za-z0-9][A-Za-z0-9_.-]*|"
    r"etc/yum\.repos\.d/[A-Za-z0-9][A-Za-z0-9_.-]*\.repo)"
)
STAGE_ID = re.compile(r"[0-9a-f]{32}")
SHA256 = re.compile(r"[0-9a-f]{64}")
LOCK = ".stage.lock"


class StageError(RuntimeError):
    """Source validation, protected-state or transaction safety refusal."""


class StageBusy(StageError):
    """A separate process is already preparing a client transaction."""


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_dir(directory: Path, *, private: bool = False) -> None:
    try:
        metadata = directory.lstat()
    except OSError as exc:
        raise StageError("Required trusted directory is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise StageError("Unsafe directory type or ownership")
    permissions = stat.S_IMODE(metadata.st_mode)
    if private:
        if permissions != 0o700:
            raise StageError("Transaction state directory must be private")
    elif permissions & 0o022:
        raise StageError("Source directory allows untrusted modifications")


def _root(root: Path) -> Path:
    root = Path(root)
    if not root.is_absolute() or ".." in root.parts:
        raise StageError("Invalid root directory")
    if root == Path("/") and os.geteuid() != 0:
        raise StageError("Root permission required for installed sources")
    _safe_dir(root)
    return root


def _source_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not SOURCE_RULE.fullmatch(relative):
        raise StageError("Source is outside approved APT/DNF configuration paths")
    result = root
    parts = relative.split("/")
    for component in parts[:-1]:
        result = result / component
        _safe_dir(result)
    return result / parts[-1]


def _read_source(root: Path, relative: str) -> tuple[bytes, dict]:
    path = _source_path(root, relative)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise StageError("Cannot safely open repository source") from exc
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) & 0o022
                or before.st_size > MAX_SOURCE_BYTES):
            raise StageError("Unsafe repository source inode")
        observed = os.stat(path, follow_symlinks=False)
        if (observed.st_dev, observed.st_ino) != (before.st_dev, before.st_ino):
            raise StageError("Repository source was replaced")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            contents = stream.read(MAX_SOURCE_BYTES + 1)
        after = os.fstat(fd)
        if (len(contents) > MAX_SOURCE_BYTES or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns, before.st_mode, before.st_uid, before.st_gid) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                 after.st_ctime_ns, after.st_mode, after.st_uid, after.st_gid)):
            raise StageError("Repository source changed during inspection")
        observed = os.stat(path, follow_symlinks=False)
        if (observed.st_dev, observed.st_ino) != (after.st_dev, after.st_ino):
            raise StageError("Repository source changed its inode")
        return contents, {
            "device": after.st_dev, "inode": after.st_ino,
            "mtime_ns": after.st_mtime_ns, "ctime_ns": after.st_ctime_ns,
            "mode": stat.S_IMODE(after.st_mode),
            "uid": after.st_uid, "gid": after.st_gid,
        }
    finally:
        os.close(fd)


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _state(root: Path, *, create: bool) -> Path:
    base = root / "var" / "lib"
    _safe_dir(root / "var")
    _safe_dir(base)
    state = base / "repocache-client"
    staging = state / "staging"
    for directory in (state, staging):
        if create:
            try:
                directory.mkdir(mode=0o700)
                _fsync_dir(directory.parent)
            except FileExistsError:
                pass
        _safe_dir(directory, private=True)
    return staging


@contextlib.contextmanager
def _locked(staging: Path):
    path = staging / LOCK
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as exc:
        raise StageError("Cannot open protected client transaction lock") from exc
    try:
        info = os.fstat(fd)
        observed = os.stat(path, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or (info.st_dev, info.st_ino) != (observed.st_dev, observed.st_ino)):
            raise StageError("Unsafe client transaction lock inode")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise StageBusy("A client transaction is already in progress") from exc
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _read_private(path: Path, *, max_size: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise StageError("Missing or unsafe staged transaction component") from exc
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1
                or meta.st_uid != os.geteuid()
                or stat.S_IMODE(meta.st_mode) != 0o600
                or meta.st_size > max_size):
            raise StageError("Invalid protected transaction component")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(max_size + 1)
        if len(data) > max_size:
            raise StageError("Oversized transaction component")
        return data
    finally:
        os.close(fd)


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def _record(directory: Path) -> dict:
    _safe_dir(directory, private=True)
    raw = _read_private(directory / "manifest.json", max_size=4096)
    try:
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise StageError("Malformed protected transaction manifest") from exc
    if (type(record) is not dict or set(record) != {
        "schema", "source", "before_sha256", "proposed_sha256", "metadata"}
            or record["schema"] != 1
            or not isinstance(record["source"], str)
            or not SOURCE_RULE.fullmatch(record["source"])
            or not isinstance(record["before_sha256"], str)
            or not SHA256.fullmatch(record["before_sha256"])
            or not isinstance(record["proposed_sha256"], str)
            or not SHA256.fullmatch(record["proposed_sha256"])
            or not isinstance(record["metadata"], dict)
            or set(record["metadata"]) != {
                "device", "inode", "mtime_ns", "ctime_ns", "mode", "uid", "gid"}
            or any(type(v) is not int or v < 0
                   for v in record["metadata"].values())):
        raise StageError("Invalid protected transaction manifest")
    before = _read_private(directory / "original.bin", max_size=MAX_SOURCE_BYTES)
    proposed = _read_private(directory / "proposed.bin", max_size=MAX_SOURCE_BYTES)
    if (_digest(before) != record["before_sha256"]
            or _digest(proposed) != record["proposed_sha256"]):
        raise StageError("Protected transaction content checksum mismatch")
    return record


def _records(staging: Path) -> dict[str, dict]:
    records = {}
    for entry in staging.iterdir():
        if entry.name == LOCK:
            continue
        if not STAGE_ID.fullmatch(entry.name):
            raise StageError("Incomplete or unknown transaction state; manual review required")
        if len(records) >= MAX_STAGES:
            raise StageError("Too many outstanding transaction stages")
        records[entry.name] = _record(entry)
    return records


def stage(root: Path, relative: str, expected_sha256: str,
          proposed: bytes) -> dict:
    """Durably stage original and proposed bytes, NEVER change the source.

    The expected content digest must come from a separately reviewed plan.
    Staging is not an approval to activate source changes.
    """
    root = _root(root)
    if (not isinstance(expected_sha256, str)
            or not SHA256.fullmatch(expected_sha256)
            or not isinstance(proposed, bytes)
            or len(proposed) > MAX_SOURCE_BYTES):
        raise StageError("Invalid or oversized proposed transaction")
    current, _ = _read_source(root, relative)
    if _digest(current) != expected_sha256:
        raise StageError("Source content differs from approved plan")
    if current == proposed:
        return {"status": "unchanged", "source": relative}
    staging = _state(root, create=True)
    with _locked(staging):
        outstanding = _records(staging)
        if any(item["source"] == relative for item in outstanding.values()):
            raise StageError("A pending stage already owns this source")
        current, metadata = _read_source(root, relative)
        if _digest(current) != expected_sha256:
            raise StageError("Source changed before transaction staging")
        ident = secrets.token_hex(16)
        pending = staging / ("." + ident + ".partial")
        pending.mkdir(mode=0o700)
        _fsync_dir(staging)
        _write_private(pending / "original.bin", current)
        _write_private(pending / "proposed.bin", proposed)
        record = {
            "schema": 1, "source": relative,
            "before_sha256": expected_sha256,
            "proposed_sha256": _digest(proposed),
            "metadata": metadata,
        }
        _write_private(pending / "manifest.json", json.dumps(
            record, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8"))
        _fsync_dir(pending)
        os.rename(pending, staging / ident)
        _fsync_dir(staging)
        return {"status": "prepared", "id": ident, "source": relative}


def inspect(root: Path, ident: str) -> dict:
    """Verify private staged bytes, manifest and source against original inode.

    A drift result never attempts to overwrite external changes.
    """
    root = _root(root)
    if not isinstance(ident, str) or not STAGE_ID.fullmatch(ident):
        raise StageError("Invalid transaction identifier")
    staging = _state(root, create=False)
    with _locked(staging):
        records = _records(staging)
        if ident not in records:
            raise StageError("Unknown transaction identifier")
        record = records[ident]
        try:
            current, metadata = _read_source(root, record["source"])
        except StageError:
            return {"status": "drift", "id": ident, "source": record["source"]}
        status = ("prepared"
                  if _digest(current) == record["before_sha256"]
                  and metadata == record["metadata"] else "drift")
        return {"status": status, "id": ident, "source": record["source"]}
