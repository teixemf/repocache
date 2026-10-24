"""Sandbox-only round-trip of source bytes and supported Linux file metadata.

NO native /etc writes, deployment integration, root helper or privilege
escalation. Must never be connected to repos sync --apply in this state.

POSIX access ACLs and bounded user.* xattrs are copied only inside an
explicitly marked /tmp test root. SELinux/security/trusted/unknown namespaces
cause a fail-closed refusal, not an attempt to relabel a production source.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import stat
from pathlib import Path

import source_preflight as pre

MAX_ATTRS = 32
MAX_ATTRIBUTE_BYTES = 8192
MAX_TOTAL_ATTRIBUTE_BYTES = 65536
TEMP_PREFIX = ".repocache-metadata-lab-"
FLAGS_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FLAGS_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def _allowed_attribute(name: str) -> bool:
    return name.startswith("user.") and len(name) > 5 or name == "system.posix_acl_access"


def _metadata(fd: int) -> tuple[dict, tuple[tuple[str, bytes], ...]]:
    """Capture bounded metadata from an opened regular file, not a pathname."""
    first = os.fstat(fd)
    if (not stat.S_ISREG(first.st_mode) or first.st_nlink != 1
            or first.st_uid != os.geteuid()
            or stat.S_IMODE(first.st_mode) & 0o022
            or first.st_size > pre.MAX_SOURCE_BYTES):
        raise pre.PreflightError("Unsafe metadata source inode")
    try:
        names = os.listxattr(fd)
    except OSError as exc:
        raise pre.PreflightError("Cannot enumerate file metadata") from exc
    if len(names) > MAX_ATTRS:
        raise pre.PreflightError("Too many file attributes")
    if any(not isinstance(name, str) or not _allowed_attribute(name)
           or len(name.encode("utf-8")) > 255 for name in names):
        raise pre.PreflightError("Security label or unsupported metadata namespace")
    attrs = []
    total = 0
    for name in sorted(names):
        try:
            value = os.getxattr(fd, name)
        except OSError as exc:
            raise pre.PreflightError("Cannot safely read file attribute") from exc
        total += len(value)
        if len(value) > MAX_ATTRIBUTE_BYTES or total > MAX_TOTAL_ATTRIBUTE_BYTES:
            raise pre.PreflightError("File metadata exceeds limits")
        attrs.append((name, value))
    last = os.fstat(fd)
    if (first.st_dev, first.st_ino, first.st_mode, first.st_uid,
            first.st_gid, first.st_ctime_ns, first.st_mtime_ns, first.st_size) != (
            last.st_dev, last.st_ino, last.st_mode, last.st_uid,
            last.st_gid, last.st_ctime_ns, last.st_mtime_ns, last.st_size):
        raise pre.PreflightError("File metadata changed during inspection")
    fields = {
        "device": last.st_dev, "inode": last.st_ino,
        "mode": stat.S_IMODE(last.st_mode),
        "uid": last.st_uid, "gid": last.st_gid,
        "size": last.st_size, "mtime_ns": last.st_mtime_ns,
        "ctime_ns": last.st_ctime_ns,
    }
    return fields, tuple(attrs)


def _same_source(fd: int, parent: int, name: str, metadata: dict,
                 attrs: tuple[tuple[str, bytes], ...]) -> None:
    now, current_attrs = _metadata(fd)
    observed = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (now != metadata or current_attrs != attrs
            or (observed.st_dev, observed.st_ino) !=
            (metadata["device"], metadata["inode"])):
        raise pre.PreflightError("Source changed during metadata clone")


def _open_fixture(root: Path) -> int:
    root = Path(root)
    if root == Path("/") or not root.is_absolute() or ".." in root.parts:
        raise pre.PreflightError("Metadata cloning is restricted to /tmp fixtures")
    try:
        fd = os.open(root, FLAGS_DIR)
    except OSError as exc:
        raise pre.PreflightError("Cannot open metadata test root") from exc
    try:
        pre._fixture(root, fd, os.geteuid())
        return fd
    except BaseException:
        os.close(fd)
        raise


def clone_sandbox_source(root: Path, relative: str) -> dict:
    """Make an isolated same-directory clone; NEVER replace the source name.

    Uses an actual file descriptor for each component, verifies originals
    again after creating a new file, and deletes incomplete clones on errors.
    A SIGKILL can leave a hidden test temp; no production use is authorized.
    """
    if not isinstance(relative, str) or not pre.SOURCE_PATH.fullmatch(relative):
        raise pre.PreflightError("Unapproved source pathname")
    parent = _open_fixture(root)
    target_name = None
    try:
        for item in relative.split("/")[:-1]:
            try:
                fd = os.open(item, FLAGS_DIR, dir_fd=parent)
            except OSError as exc:
                raise pre.PreflightError("Unsafe source directory") from exc
            try:
                pre._checked_directory(fd, os.geteuid())
            except BaseException:
                os.close(fd)
                raise
            os.close(parent)
            parent = fd
        leaf = relative.rsplit("/", 1)[-1]
        try:
            source_fd = os.open(leaf, FLAGS_FILE, dir_fd=parent)
        except OSError as exc:
            raise pre.PreflightError("Unable to open metadata source") from exc
        try:
            before, attrs = _metadata(source_fd)
            if before["gid"] != os.getegid():
                raise pre.PreflightError("Cannot preserve source group in unprivileged sandbox")
            found = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            if (found.st_dev, found.st_ino) != (
                    before["device"], before["inode"]):
                raise pre.PreflightError("Source inode changed before clone")
            data = bytearray()
            while len(data) <= pre.MAX_SOURCE_BYTES:
                chunk = os.read(source_fd, min(65536, pre.MAX_SOURCE_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) != before["size"]:
                raise pre.PreflightError("Source content changed during clone")
            _same_source(source_fd, parent, leaf, before, attrs)
            target_name = TEMP_PREFIX + secrets.token_hex(16)
            try:
                dest = os.open(target_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                               os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                               dir_fd=parent)
            except OSError as exc:
                raise pre.PreflightError("Cannot allocate private clone") from exc
            try:
                if os.fstat(dest).st_gid != before["gid"]:
                    raise pre.PreflightError("New file cannot preserve original group")
                with os.fdopen(dest, "wb", closefd=False) as stream:
                    stream.write(data)
                    stream.flush()
                os.fchmod(dest, before["mode"])
                # Setting the POSIX access ACL last preserves its effective mask.
                for key, value in attrs:
                    if key != "system.posix_acl_access":
                        os.setxattr(dest, key, value)
                for key, value in attrs:
                    if key == "system.posix_acl_access":
                        os.setxattr(dest, key, value)
                os.fsync(dest)
                cloned, cloned_attrs = _metadata(dest)
                if (cloned_attrs != attrs or
                        cloned["mode"] != before["mode"] or
                        cloned["uid"] != before["uid"] or
                        cloned["gid"] != before["gid"] or
                        cloned["size"] != before["size"]):
                    raise pre.PreflightError("Cloned metadata does not match the source")
            except OSError as exc:
                raise pre.PreflightError("Metadata copying not supported on test filesystem") from exc
            finally:
                os.close(dest)
            _same_source(source_fd, parent, leaf, before, attrs)
            # Nothing has replaced or modified the source. This hidden
            # disposable output must never be treated as a verified update.
            return {
                "source": relative,
                "clone_name": target_name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "attribute_count": len(attrs),
                "contains_posix_access_acl": any(
                    name == "system.posix_acl_access" for name, _ in attrs),
                "source_unmodified": True,
                "production_apply_eligible": False,
            }
        finally:
            os.close(source_fd)
    except BaseException:
        if target_name is not None:
            try:
                os.unlink(target_name, dir_fd=parent)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(parent)
