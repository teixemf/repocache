"""Trusted, standard-library-only startup recovery for CLI update transactions.

Installed independently as a root-owned, pinned bootstrap helper. Executes
with the dedicated service UID before launching ANY managed CLI executable.
Schema 1 compatibility is retained for already-prepared draft transactions.
Never execute a release binary, follow a state symlink or touch NGINX/TLS.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import pwd
import re
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path("/opt/repocache-cli/managed")
LOCK_FILE = ROOT.parent / ".updater.lock"


def acquire_update_lock(root: Path = ROOT, *, expected_owner: int = 0,
                        expected_group: int | None = None) -> int:
    """Open one root-owned immutable-by-service inode and acquire exclusive flock.

    This trusted helper must also be installed root-owned by bootstrap. The
    caller is responsible for closing the returned descriptor, which releases
    the kernel lock. The service account is never allowed to create, unlink,
    replace, or truncate this lock. Owner/group overrides exist solely for
    unprivileged isolated tests; production always calls with default owner.
    """
    parent = root.parent
    try:
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise RecoveryError("Missing or unsafe trusted lock directory") from exc
    try:
        directory = os.fstat(parent_fd)
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != expected_owner
                or stat.S_IMODE(directory.st_mode) & 0o022):
            raise RecoveryError("Unsafe updater lock parent ownership or permissions")
        if expected_group is None:
            try:
                expected_group = pwd.getpwnam("repocache").pw_gid
            except KeyError as exc:
                raise RecoveryError("Missing dedicated updater group") from exc
        try:
            fd = os.open(".updater.lock",
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=parent_fd)
        except OSError as exc:
            raise RecoveryError("Missing or unsafe root-managed updater lock") from exc
        try:
            meta = os.fstat(fd)
            if (not stat.S_ISREG(meta.st_mode)
                    or meta.st_uid != expected_owner
                    or meta.st_gid != expected_group
                    or stat.S_IMODE(meta.st_mode) != 0o440
                    or meta.st_nlink != 1):
                raise RecoveryError("Unsafe updater lock owner, group, mode or inode")
            # Verify the path still names the opened inode. A nonwritable
            # parent prevents same-service-UID path substitutions.
            path_meta = os.stat(".updater.lock", dir_fd=parent_fd,
                                follow_symlinks=False)
            if (meta.st_dev, meta.st_ino) != (path_meta.st_dev, path_meta.st_ino):
                raise RecoveryError("Updater lock inode changed while opening")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RecoveryBusy("Another REPOCACHE update is running") from exc
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent_fd)


VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SHA = re.compile(r"^[a-f0-9]{64}$")


class RecoveryError(RuntimeError):
    pass


class RecoveryBusy(RecoveryError):
    pass


def _sync(directory: Path):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _durable(target: Path, data: bytes):
    fd, filename = tempfile.mkstemp(prefix=".recovery-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(filename, 0o600)
        os.replace(filename, target)
        _sync(target.parent)
    finally:
        if os.path.lexists(filename):
            os.unlink(filename)


def _within(root: Path, name: object):
    if not isinstance(name, str) or not name.startswith(str(root) + "/"):
        raise RecoveryError("Untrusted generation pathname")
    path = Path(name)
    if (not path.is_absolute() or ".." in path.parts
            or path.parent != root or path == root or path.is_symlink()):
        raise RecoveryError("Unsafe generation path")
    return path


def _validate_manifest(data: bytes, expected_version: str | None = None):
    if len(data) > 32768:
        raise RecoveryError("Oversized installed manifest")
    try:
        state = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise RecoveryError("corrupt installed manifest") from exc
    if (type(state) is not dict or not isinstance(state.get("version"), str)
            or not VERSION.fullmatch(state["version"])
            or state["version"] == "0.0.0"
            or not isinstance(state.get("source_digest"), str)
            or not SHA.fullmatch(state["source_digest"])
            or (expected_version is not None and state["version"] != expected_version)):
        raise RecoveryError("Invalid installed manifest version/digest identity")
    return state


def _active(root: Path):
    link = root / "current"
    if link.is_symlink():
        target = os.readlink(link)
        _within(root / "releases", target)
        return target
    if link.exists():
        raise RecoveryError("Active generation is not a symlink")
    return None


def _activate(root: Path, target: str | None):
    link = root / "current"
    if target is None:
        if link.is_symlink():
            link.unlink()
            _sync(root)
        elif link.exists():
            raise RecoveryError("Non-symlink active generation")
        return
    candidate = root / (".recover-current-" + os.urandom(16).hex())
    try:
        candidate.symlink_to(target)
        os.replace(candidate, link)
        _sync(root)
    finally:
        if candidate.is_symlink():
            candidate.unlink()


def _check_generation(root: Path, name: str):
    path = _within(root / "releases", name)
    if (not path.is_dir() or path.is_symlink()
            or not (path / "bin/repocache").is_file()):
        raise RecoveryError("Trusted rollback generation is unavailable")
    return path


def _journal(root: Path):
    path = root / ".update-journal.json"
    if path.is_symlink():
        raise RecoveryError("Symlinked transaction journal")
    if not path.exists():
        return None
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
            or st.st_mode & 0o077 or st.st_size > 65536 or st.st_nlink != 1):
        raise RecoveryError("Corrupt transaction journal: unsafe metadata")
    try:
        data = json.loads(path.read_bytes())
        required = {"schema", "phase", "previous", "previous_manifest",
                    "destination", "new_version"}
        if type(data) is not dict or data.get("schema") not in (1, 2):
            raise ValueError("unsupported journal schema")
        if set(data) != (required if data["schema"] == 1
                         else required | {"transaction_id", "new_manifest_sha256"}):
            raise ValueError("unexpected journal fields")
        if data.get("phase") not in ("prepared", "activated", "committed"):
            raise ValueError("unknown phase")
        if not isinstance(data["new_version"], str) or not VERSION.fullmatch(data["new_version"]):
            raise ValueError("new version")
        _within(root / "releases", data["destination"])
        if data["previous"] is not None:
            _within(root / "releases", data["previous"])
        encoded = data["previous_manifest"]
        if (data["previous"] is None) != (encoded is None):
            raise ValueError("previous generation and manifest mismatch")
        if encoded is None:
            saved = None
        elif not isinstance(encoded, str) or len(encoded) > 44000:
            raise ValueError("manifest encoding")
        else:
            saved = base64.b64decode(encoded, validate=True)
            prior = _validate_manifest(saved)
            if not Path(data["previous"]).name.startswith(prior["version"] + "-"):
                raise ValueError("previous generation version mismatch")
        if data["schema"] == 2:
            if (not isinstance(data["transaction_id"], str)
                    or not re.fullmatch(r"[a-f0-9]{32}", data["transaction_id"])
                    or not isinstance(data["new_manifest_sha256"], str)
                    or not SHA.fullmatch(data["new_manifest_sha256"])):
                raise ValueError("invalid transaction identity")
        return data, saved
    except (OSError, TypeError, UnicodeError, ValueError, RecoveryError) as exc:
        raise RecoveryError("Corrupt transaction journal; manual recovery required") from exc


def _consistent_committed(root: Path, journal: dict):
    manifest = root / "installed.json"
    if manifest.is_symlink() or not manifest.is_file():
        return False
    try:
        contents = manifest.read_bytes()
        _validate_manifest(contents, journal["new_version"])
    except (OSError, RecoveryError):
        return False
    if journal["schema"] == 2:
        return hashlib.sha256(contents).hexdigest() == journal["new_manifest_sha256"]
    # Schema 1 predates the manifest digest binding; safest resolution
    # is rollback, never retain a partial new generation based on version.
    return False


def reconcile(root: Path):
    """Recover while caller holds exclusive kernel lock."""
    if (root.is_symlink() or not root.is_dir()
            or root.stat().st_uid != os.geteuid()):
        raise RecoveryError("Managed update root has unsafe ownership")
    releases = root / "releases"
    if releases.is_symlink():
        raise RecoveryError("Symlinked releases directory")
    record = _journal(root)
    if record is None:
        # No journal: verify only, never guess which release is trustworthy.
        active = _active(root)
        manifest = root / "installed.json"
        if manifest.is_symlink():
            raise RecoveryError("symlinked installed manifest is unsafe")
        if active is not None:
            _check_generation(root, active)
            if not manifest.is_file():
                raise RecoveryError("Active generation without installed manifest")
            state = _validate_manifest(manifest.read_bytes())
            name = Path(active).name
            if not name.startswith(state["version"] + "-"):
                raise RecoveryError("Active generation/manifest version disagreement")
            # Native managed venvs encode the first twelve SHA-256 characters
            # in the generation dirname. Preserve older pre-v0.4 path formats.
            parts = name[len(state["version"]) + 1:].split("-")
            if len(parts) >= 2 and re.fullmatch(r"[a-f0-9]{12}", parts[0]):
                if parts[0] != state["source_digest"][:12]:
                    raise RecoveryError("Active generation/manifest digest disagreement")
        elif manifest.exists():
            raise RecoveryError("Manifest exists without an active generation")
        return "consistent"
    journal, previous_manifest = record
    active = _active(root)
    if (journal["phase"] == "committed"
            and active == journal["destination"]
            and _consistent_committed(root, journal)):
        _check_generation(root, active)
    else:
        previous = journal["previous"]
        if previous is not None:
            _check_generation(root, previous)
        _activate(root, previous)
        target = root / "installed.json"
        if target.is_symlink():
            raise RecoveryError("Unsafe installed manifest")
        if previous_manifest is None:
            if target.is_file():
                target.unlink()
                _sync(root)
        else:
            _durable(target, previous_manifest)
    path = root / ".update-journal.json"
    path.unlink()
    _sync(root)
    return "recovered"


def startup(root: Path = ROOT):
    """Called from the root-owned launcher, under the repocache service UID."""
    if os.geteuid() == 0:
        raise RecoveryError("Never recover as root")
    try:
        required = pwd.getpwnam("repocache").pw_uid
    except KeyError as exc:
        raise RecoveryError("Missing repocache service UID") from exc
    if required != os.geteuid():
        raise RecoveryError("Recovery requires the dedicated service UID")
    if not root.is_dir() or root.is_symlink() or root.stat().st_uid != required:
        raise RecoveryError("Invalid managed update root")
    fd = acquire_update_lock(root)
    try:
        return reconcile(root)
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        print(startup())
    except RecoveryBusy as exc:
        print("Recovery busy: " + str(exc), file=sys.stderr)
        sys.exit(75)
    except (OSError, RecoveryError) as exc:
        print("Recovery refused: " + str(exc), file=sys.stderr)
        sys.exit(70)
