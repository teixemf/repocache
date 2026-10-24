"""Protected, non-authoritative client managed-ID candidate registry — sandbox.

This is NOT an ownership grant and cannot be used to authorize APT/DNF
writes. No production filesystem operation is exposed: every entry point
requires a marked private /tmp fixture and never edits repository sources.

Stable candidate IDs are random and independent of discovery hashes, source
line numbers, URL and position. Each candidate binds one whole source FILE;
multi-entry files and nontrivial repository grammar remain out of scope.
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

import source_preflight as pre
import source_structure_subset as structure


HEX_ID = re.compile(r"[0-9a-f]{32}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
MANIFEST_NAME = re.compile(r"candidate-([0-9a-f]{32})\.json\Z")
LOCK_NAME = ".registry.lock"
MAX_CANDIDATES = 128
MAX_MANIFEST = 4096
SCHEMA = 1


class RegistryRefused(RuntimeError):
    """Unsafe or conflicting local candidate registry state."""


class RegistryBusy(RegistryRefused):
    """Another local registry operation currently holds the exclusive lock."""


@contextlib.contextmanager
def _registry_fd(root: Path, *, create: bool,
                 subdir: str = "managed-candidates-lab"):
    if subdir not in {"managed-candidates-lab", "entry-candidates-lab",
                       "entry-approvals-lab"}:
        raise RegistryRefused("Unrecognized private registry namespace")
    root = Path(root)
    if not root.is_absolute() or root == Path("/") or ".." in root.parts:
        raise RegistryRefused("Registry is restricted to private test roots")
    try:
        current = os.open(root, pre.DIR_FLAGS)
    except OSError as exc:
        raise RegistryRefused("Cannot open protected registry fixture") from exc
    try:
        try:
            pre._fixture(root, current, os.geteuid())
        except (OSError, pre.PreflightError) as exc:
            raise RegistryRefused("Invalid private registry fixture") from exc
        for component, private in (
            ("var", False),
            ("lib", False),
            ("repocache-client", True),
            (subdir, True),
        ):
            if create:
                try:
                    os.mkdir(component, mode=0o700 if private else 0o755,
                             dir_fd=current)
                    os.fsync(current)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise RegistryRefused("Cannot create protected registry directory") from exc
            try:
                child = os.open(component, pre.DIR_FLAGS, dir_fd=current)
            except OSError as exc:
                raise RegistryRefused("Missing or unsafe registry directory") from exc
            try:
                info = os.fstat(child)
                if (not stat.S_ISDIR(info.st_mode)
                        or info.st_uid != os.geteuid()
                        or (stat.S_IMODE(info.st_mode) != 0o700 if private else
                            bool(stat.S_IMODE(info.st_mode) & 0o022))):
                    raise RegistryRefused("Untrusted registry directory owner or mode")
            except BaseException:
                os.close(child)
                raise
            os.close(current)
            current = child
        yield current
    finally:
        os.close(current)


@contextlib.contextmanager
def _lock(registry_fd: int):
    try:
        fd = os.open(LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                     dir_fd=registry_fd)
    except FileExistsError:
        try:
            fd = os.open(LOCK_NAME, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=registry_fd)
        except OSError as exc:
            raise RegistryRefused("Unsafe registry lock") from exc
    except OSError as exc:
        raise RegistryRefused("Cannot initialize registry lock") from exc
    try:
        info = os.fstat(fd)
        linked = os.stat(LOCK_NAME, dir_fd=registry_fd, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or (info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino)):
            raise RegistryRefused("Unsafe registry lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RegistryBusy("Registry is busy") from exc
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _read_private(registry_fd: int, name: str) -> bytes:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                     os.O_CLOEXEC, dir_fd=registry_fd)
    except OSError as exc:
        raise RegistryRefused("Unsafe protected candidate file") from exc
    try:
        before = os.fstat(fd)
        at_name = os.stat(name, dir_fd=registry_fd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size > MAX_MANIFEST
                or (before.st_dev, before.st_ino) !=
                (at_name.st_dev, at_name.st_ino)):
            raise RegistryRefused("Unsafe protected candidate inode")
        data = os.read(fd, MAX_MANIFEST + 1)
        after = os.fstat(fd)
        if (len(data) != before.st_size or len(data) > MAX_MANIFEST or
                (before.st_dev, before.st_ino, before.st_size, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_ctime_ns)):
            raise RegistryRefused("Protected candidate changed during inspection")
        return data
    finally:
        os.close(fd)


def _decode(name: str, raw: bytes) -> dict:
    try:
        entry = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise RegistryRefused("Malformed protected candidate") from exc
    required = {"schema", "managed_id", "source", "source_format", "source_sha256",
                "device", "inode", "mode", "uid", "gid", "mtime_ns", "ctime_ns",
                "xattrs_present", "state", "ownership_granted", "write_eligible"}
    if (type(entry) is not dict or set(entry) != required
            or type(entry.get("schema")) is not int or entry["schema"] != SCHEMA
            or type(entry.get("managed_id")) is not str
            or not HEX_ID.fullmatch(entry["managed_id"])
            or name != "candidate-" + entry["managed_id"] + ".json"
            or type(entry.get("source")) is not str
            or not pre.SOURCE_PATH.fullmatch(entry["source"])
            or type(entry.get("source_format")) is not str
            or entry["source_format"] not in {"apt-list", "apt-deb822", "dnf-repo"}
            or type(entry.get("source_sha256")) is not str
            or not DIGEST.fullmatch(entry["source_sha256"])
            or any(type(entry.get(n)) is not int or entry[n] < 0 for n in (
                "device", "inode", "mode", "uid", "gid", "mtime_ns", "ctime_ns"))
            or type(entry.get("xattrs_present")) is not bool
            or entry.get("state") != "candidate"
            or entry.get("ownership_granted") is not False
            or entry.get("write_eligible") is not False):
        raise RegistryRefused("Invalid protected candidate schema")
    return entry


def _entries(registry_fd: int) -> list[dict]:
    results = []
    for name in os.listdir(registry_fd):
        if name == LOCK_NAME:
            continue
        if not MANIFEST_NAME.fullmatch(name):
            raise RegistryRefused("Unknown or interrupted registry state")
        if len(results) >= MAX_CANDIDATES:
            raise RegistryRefused("Registry capacity exceeded")
        results.append(_decode(name, _read_private(registry_fd, name)))
    if len({x["source"] for x in results}) != len(results):
        raise RegistryRefused("Conflicting candidate registry entries")
    return results


def _source_bytes(root: Path, relative: str, observed: dict) -> bytes:
    # All walks are anchored at FDs; no symlink is followed. The independent
    # preflight is run before AND after this read to detect source drift.
    fd = os.open(root, pre.DIR_FLAGS)
    try:
        for component in relative.split("/")[:-1]:
            child = os.open(component, pre.DIR_FLAGS, dir_fd=fd)
            try:
                pre._checked_directory(child, os.geteuid())
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        leaf = relative.split("/")[-1]
        handle = os.open(leaf, pre.FILE_FLAGS, dir_fd=fd)
        try:
            original = os.fstat(handle)
            if ((original.st_dev, original.st_ino) !=
                    (observed["device"], observed["inode"])
                    or original.st_uid != observed["uid"]
                    or original.st_gid != observed["gid"]
                    or stat.S_IMODE(original.st_mode) != observed["mode"]
                    or original.st_mtime_ns != observed["mtime_ns"]
                    or original.st_ctime_ns != observed["ctime_ns"]
                    or not stat.S_ISREG(original.st_mode) or original.st_nlink != 1):
                raise RegistryRefused("Source changed during candidate inspection")
            data = os.read(handle, pre.MAX_SOURCE_BYTES + 1)
            after = os.fstat(handle)
            named = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            if (len(data) > pre.MAX_SOURCE_BYTES
                    or (original.st_dev, original.st_ino, original.st_ctime_ns,
                        original.st_mtime_ns, original.st_size)
                    != (after.st_dev, after.st_ino, after.st_ctime_ns,
                        after.st_mtime_ns, after.st_size)
                    or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)
                    or hashlib.sha256(data).hexdigest() != observed["sha256"]):
                raise RegistryRefused("Source content or inode drift")
            return data
        finally:
            os.close(handle)
    finally:
        os.close(fd)


def _observe(root: Path, relative: str) -> tuple[dict, dict]:
    try:
        before = pre.inspect_source(relative, root=root)
        data = _source_bytes(root, relative, before)
        parsed = structure.inspect_structure(relative, data)
        after = pre.inspect_source(relative, root=root)
    except (pre.PreflightError, structure.StructureRefused,
            OSError, ValueError) as exc:
        raise RegistryRefused("Source is outside validated candidate subset") from exc
    if any(before[key] != after[key] for key in (
        "sha256", "device", "inode", "uid", "gid", "mode",
        "mtime_ns", "ctime_ns", "extended_attributes_present")):
        raise RegistryRefused("Source changed across candidate validation")
    return before, parsed


def _save(registry_fd: int, entry: dict) -> None:
    ident = entry["managed_id"]
    target = "candidate-" + ident + ".json"
    temp = ".pending-" + ident
    data = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_MANIFEST:
        raise RegistryRefused("Candidate state exceeds limit")
    handle = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=registry_fd)
    try:
        with os.fdopen(handle, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(handle)
    finally:
        os.close(handle)
    # The new target name is random and a colliding preexisting inode is a
    # conflict. Do not silently overwrite it with os.replace.
    try:
        os.stat(target, dir_fd=registry_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise RegistryRefused("Candidate ID collision")
    os.rename(temp, target, src_dir_fd=registry_fd, dst_dir_fd=registry_fd)
    os.fsync(registry_fd)


def register_candidate_sandbox(root: Path, relative: str, expected_sha256: str) -> dict:
    """Persist an explicitly requested local *candidate*, never grant ownership."""
    root = Path(root)
    if (not isinstance(relative, str)
            or not pre.SOURCE_PATH.fullmatch(relative)
            or not isinstance(expected_sha256, str)
            or not DIGEST.fullmatch(expected_sha256)):
        raise RegistryRefused("Invalid candidate input")
    # Refuse production roots before even reading any source file.
    try:
        root_fd = os.open(root, pre.DIR_FLAGS)
        try:
            pre._fixture(root, root_fd, os.geteuid())
        finally:
            os.close(root_fd)
    except (OSError, pre.PreflightError) as exc:
        raise RegistryRefused("Invalid private registry fixture") from exc
    # Validate before creating state; a mismatching plan is a true no-op.
    observed, parsed = _observe(root, relative)
    if observed["sha256"] != expected_sha256:
        raise RegistryRefused("Source differs from requested candidate baseline")
    with _registry_fd(root, create=True) as fd:
        with _lock(fd):
            existing = _entries(fd)
            if any(item["source"] == relative for item in existing):
                raise RegistryRefused("Source already has a pending candidate")
            # Recheck after obtaining the lock so records cannot be prepared
            # from a stale source without detection.
            fresh, parsed_again = _observe(root, relative)
            if fresh != observed or parsed_again != parsed:
                raise RegistryRefused("Source changed before candidate registration")
            ident = secrets.token_hex(16)
            entry = {
                "schema": SCHEMA, "managed_id": ident,
                "source": relative, "source_format": parsed["format"],
                "source_sha256": expected_sha256,
                "device": observed["device"], "inode": observed["inode"],
                "mode": observed["mode"], "uid": observed["uid"], "gid": observed["gid"],
                "mtime_ns": observed["mtime_ns"], "ctime_ns": observed["ctime_ns"],
                "xattrs_present": observed["extended_attributes_present"],
                "state": "candidate", "ownership_granted": False, "write_eligible": False,
            }
            _save(fd, entry)
            return {"id": ident, "state": "candidate", "ownership_granted": False,
                    "write_eligible": False}


def inspect_candidate_sandbox(root: Path, ident: str) -> dict:
    """Report candidate drift without modifying source, state or package manager."""
    if not isinstance(ident, str) or not HEX_ID.fullmatch(ident):
        raise RegistryRefused("Invalid managed candidate identifier")
    root = Path(root)
    with _registry_fd(root, create=False) as fd:
        with _lock(fd):
            records = _entries(fd)
            item = next((x for x in records if x["managed_id"] == ident), None)
            if item is None:
                raise RegistryRefused("Unknown managed candidate identifier")
            try:
                observed, parsed = _observe(root, item["source"])
                match = (parsed["format"] == item["source_format"]
                         and observed["sha256"] == item["source_sha256"]
                         and all(observed[key] == item[key] for key in (
                             "device", "inode", "mode", "uid", "gid",
                             "mtime_ns", "ctime_ns"))
                         and observed["extended_attributes_present"] ==
                         item["xattrs_present"])
            except RegistryRefused:
                match = False
            return {"id": ident, "state": "intact" if match else "drift",
                    "ownership_granted": False, "write_eligible": False,
                    "native_syntax_verified": False,
                    "package_signatures_verified": False,
                    "upstream_fallback_verified": False}
