"""Read-only Linux source-file trust preflight for future REPOCACHE client writes.

NO write/restore operation, privilege escalation, system configuration edit,
or installed-CLI integration is provided. Always refuse metadata that cannot
be inspected. An inspection result is NOT authorization to write.

The production entry is pinned to / and requires root. Rootless test fixtures
must be explicitly marked, private directories beneath /tmp or /var/tmp.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path

MAX_SOURCE_BYTES = 1024 * 1024
MARKER = ".repocache-source-preflight-test"
TEST_MAGIC = b"REPOCACHE_SOURCE_PREFLIGHT_TEST_V1\n"
SOURCE_PATH = re.compile(
    r"(?:etc/apt/sources\.list|"
    r"etc/apt/sources\.list\.d/[A-Za-z0-9][A-Za-z0-9_.-]*\.(?:list|sources)|"
    r"etc/apt/mirrors/[A-Za-z0-9][A-Za-z0-9_.-]*|"
    r"etc/yum\.repos\.d/[A-Za-z0-9][A-Za-z0-9_.-]*\.repo)\Z"
)

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class PreflightError(RuntimeError):
    """A source cannot be inspected under the required trust policy."""


def _checked_directory(fd: int, owner: int, *, private: bool = False) -> None:
    info = os.fstat(fd)
    perms = stat.S_IMODE(info.st_mode)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner
            or (perms != 0o700 if private else bool(perms & 0o022))):
        raise PreflightError("Unsafe source directory ownership or permissions")


def _fixture(root: Path, fd: int, owner: int) -> None:
    # Test-only override is unambiguously restricted; never treat the marker
    # as sufficient authorization for real filesystem changes.
    if (root in (Path("/"), Path("/tmp"), Path("/var/tmp"))
            or not any(p in (Path("/tmp"), Path("/var/tmp")) for p in root.parents)
            or root.resolve(strict=True) != root):
        raise PreflightError("Non-production inspection root must be private under /tmp")
    _checked_directory(fd, owner, private=True)
    try:
        marker_fd = os.open(MARKER, FILE_FLAGS, dir_fd=fd)
    except OSError as exc:
        raise PreflightError("Missing or unsafe private test marker") from exc
    try:
        info = os.fstat(marker_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size != len(TEST_MAGIC)):
            raise PreflightError("Invalid private test marker")
        if os.read(marker_fd, len(TEST_MAGIC) + 1) != TEST_MAGIC:
            raise PreflightError("Invalid private test marker")
        observed = os.stat(MARKER, dir_fd=fd, follow_symlinks=False)
        if (info.st_dev, info.st_ino) != (observed.st_dev, observed.st_ino):
            raise PreflightError("Test marker inode changed during inspection")
    finally:
        os.close(marker_fd)


def inspect_source(relative: str, *, root: Path = Path("/")) -> dict:
    """Hash and inspect one allowlisted source using anchored directory fds.

    Read-only for both native and test roots. Metadata is recorded for future
    drift comparison, but no result from this function allows an apply.
    """
    if not isinstance(relative, str) or not SOURCE_PATH.fullmatch(relative):
        raise PreflightError("Repository source path is not in the approved allowlist")
    root = Path(root)
    if not root.is_absolute() or ".." in root.parts:
        raise PreflightError("Invalid inspection root")
    owner = 0 if root == Path("/") else os.geteuid()
    if root == Path("/") and os.geteuid() != 0:
        raise PreflightError("Root authorization is required for native inspection")
    try:
        parent = os.open(root, DIR_FLAGS)
    except OSError as exc:
        raise PreflightError("Unable to open trusted inspection root") from exc
    try:
        _checked_directory(parent, owner)
        if root != Path("/"):
            _fixture(root, parent, owner)
        components = relative.split("/")
        for component in components[:-1]:
            try:
                child = os.open(component, DIR_FLAGS, dir_fd=parent)
            except OSError as exc:
                raise PreflightError("Untrusted or unavailable source directory") from exc
            try:
                _checked_directory(child, owner)
            except BaseException:
                os.close(child)
                raise
            os.close(parent)
            parent = child
        leaf = components[-1]
        try:
            source_fd = os.open(leaf, FILE_FLAGS, dir_fd=parent)
        except OSError as exc:
            raise PreflightError("Unsafe or unavailable source file") from exc
        try:
            before = os.fstat(source_fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner
                    or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) & 0o022
                    or before.st_size > MAX_SOURCE_BYTES):
                raise PreflightError("Unsafe repository source inode or permissions")
            linked = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            if (before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino):
                raise PreflightError("Repository source pathname changed")
            digest = hashlib.sha256()
            size = 0
            while True:
                data = os.read(source_fd, min(65536, MAX_SOURCE_BYTES + 1 - size))
                if not data:
                    break
                size += len(data)
                if size > MAX_SOURCE_BYTES:
                    raise PreflightError("Repository source exceeds inspection size limit")
                digest.update(data)
            try:
                names = os.listxattr(source_fd)
            except OSError as exc:
                raise PreflightError("Cannot inspect repository security attributes") from exc
            after = os.fstat(source_fd)
            relinked = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            before_identity = (
                before.st_dev, before.st_ino, before.st_uid, before.st_gid,
                before.st_mode, before.st_nlink, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns,
            )
            after_identity = (
                after.st_dev, after.st_ino, after.st_uid, after.st_gid,
                after.st_mode, after.st_nlink, after.st_size, after.st_mtime_ns,
                after.st_ctime_ns,
            )
            if (size != before.st_size or before_identity != after_identity
                    or (after.st_dev, after.st_ino) !=
                    (relinked.st_dev, relinked.st_ino)):
                raise PreflightError("Repository source drift during inspection")
            return {
                "source": relative,
                "sha256": digest.hexdigest(),
                "size": size,
                "device": after.st_dev,
                "inode": after.st_ino,
                "uid": after.st_uid,
                "gid": after.st_gid,
                "mode": stat.S_IMODE(after.st_mode),
                "mtime_ns": after.st_mtime_ns,
                "ctime_ns": after.st_ctime_ns,
                "extended_attributes_present": bool(names),
                "write_eligible": False,
                "write_blocker": ("security-metadata-preservation-not-implemented"
                                  if names else "privileged-writer-not-implemented"),
            }
        finally:
            os.close(source_fd)
    finally:
        os.close(parent)
