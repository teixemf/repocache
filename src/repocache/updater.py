"""Local release-bundle installation with versioned environments and atomic activation.

Does not modify NGINX, certificates, logs or cache. Update commands run offline.
"""
from __future__ import annotations

import hashlib
import base64
import uuid
import contextlib
import fcntl
import stat
import threading
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from repocache import __version__

ROOT = Path("/opt/repocache-cli/managed")
MANIFEST = ROOT / "installed.json"
CURRENT = ROOT / "current"
EXECUTABLE = CURRENT / "bin/repocache"
LINKS = (Path("/usr/local/bin/repocache"), Path("/usr/bin/repocache"))
LEGACY = Path("/opt/repocache-cli/venv/bin/repocache")
VERSION = re.compile(r'^version\s*=\s*"(\d+)\.(\d+)\.(\d+)"\s*$', re.MULTILINE)


_TX_MUTEX = threading.RLock()
_TX_LOCAL = threading.local()


@contextlib.contextmanager
def update_transaction():
    """Serialize across threads and processes, including full rollback.

    Hold before reading the installed manifest and until durable commit or
    failed-update cleanup. Reentrant only for the owning Python thread.
    """
    _require_service_account()
    if not ROOT.is_dir() or ROOT.is_symlink() or ROOT.stat().st_uid != os.geteuid():
        raise UpdateError("Unsafe rootless state; bootstrap required")
    if not _TX_MUTEX.acquire(blocking=False):
        raise UpdateBusyError("Another REPOCACHE update is running")
    try:
        if getattr(_TX_LOCAL, "active", False):
            yield
            return
        lock = ROOT / ".updater.lock"
        flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            fd = os.open(lock, flags, 0o600)
        except OSError as exc:
            raise UpdateError("Cannot open secure updater lock") from exc
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
                    or st.st_nlink != 1 or st.st_mode & 0o077):
                raise UpdateError("Updater transaction lock is insecure")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise UpdateBusyError("Another REPOCACHE update is running") from exc
            _TX_LOCAL.active = True
            try:
                yield
            finally:
                _TX_LOCAL.active = False
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
    finally:
        _TX_MUTEX.release()


class UpdateError(RuntimeError):
    """Expected installation or update error."""


class UpdateBusyError(UpdateError):
    """Temporary exclusive-transaction contention; safe to retry later."""


def _require_service_account() -> None:
    """Fail closed unless updates run as the dedicated unprivileged account.

    The root-owned POSIX launcher must drop UID *before* loading this module.
    This check is defense in depth, not a substitute for that launcher.
    """
    uid = os.geteuid()
    if uid == 0:
        raise UpdateError("Updates must never execute as root; use the root-owned launcher")
    try:
        service_uid = pwd.getpwnam("repocache").pw_uid
    except KeyError as exc:
        raise UpdateError("Missing repocache service account; bootstrap is required") from exc
    if service_uid == 0 or uid != service_uid:
        raise UpdateError("Updates require the dedicated repocache account")


def _run(argv: list[str], *, timeout: int = 90, cwd: Optional[Path] = None) -> str:
    # Never inherit PYTHONPATH, PIP_INDEX_URL, proxy, LD_PRELOAD or user pip config.
    # #49 must additionally make dependency installation fully offline/locked.
    environment = {"PATH": "/usr/local/bin:/usr/bin:/bin",
                   "HOME": "/var/lib/repocache", "LANG": "C.UTF-8",
                   "GIT_TERMINAL_PROMPT": "0",
                   "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INPUT": "1",
                   "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1"}
    try:
        result = subprocess.run(argv, cwd=cwd, env=environment, text=True,
                                capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UpdateError(f"Failed to run {argv[0]}: {exc}") from exc
    if result.returncode:
        raise UpdateError((result.stderr or result.stdout).strip()[:700] or
                          f"Command exited with status {result.returncode}")
    return result.stdout.strip()


def _version_tuple(version: str) -> tuple[int, int, int]:
    parts = version.split(".")
    if len(parts) != 3 or any(not p.isdecimal() for p in parts):
        raise UpdateError(f"Invalid version: {version}")
    return tuple(int(p) for p in parts)  # type: ignore[return-value]


def _project_version(path: Path) -> str:
    try:
        match = VERSION.search((path / "pyproject.toml").read_text(encoding="utf-8"))
    except OSError as exc:
        raise UpdateError(f"Could not read pyproject.toml: {exc}") from exc
    if not match:
        raise UpdateError("Version x.y.z not found in pyproject.toml")
    return ".".join(match.groups())


def _source_digest(source: Path) -> str:
    """Hash installable content using SHA-256 without depending on Git."""
    files = [source / "pyproject.toml", source / "install.sh",
             *([source / "release-policy.json"] if (source / "release-policy.json").exists() else []),
             *sorted((source / "src/repocache").glob("*.py"))]
    if not all(p.is_file() and not p.is_symlink() for p in files):
        raise UpdateError("Incomplete or invalid release bundle")
    digest = hashlib.sha256()
    for file in files:
        digest.update(file.relative_to(source).as_posix().encode("utf-8") + b"\0")
        digest.update(file.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _installed() -> Dict[str, Any]:
    """Fail closed on a broken active installation instead of assuming fresh."""
    if MANIFEST.is_symlink():
        raise UpdateError("Installed manifest must not be a symlink")
    if MANIFEST.exists():
        try:
            value = json.loads(MANIFEST.read_text(encoding="utf-8"))
        except (ValueError, OSError, UnicodeError) as exc:
            raise UpdateError("Installed manifest is corrupt or unreadable") from exc
        if (not isinstance(value, dict) or not isinstance(value.get("version"), str)
                or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["version"])
                or value["version"] == "0.0.0"
                or not isinstance(value.get("source_digest"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", value["source_digest"])):
            raise UpdateError("Installed manifest has invalid version or digest")
        return value

    # Never interpret an active installation without a manifest as a clean host.
    if CURRENT.is_symlink() or CURRENT.exists():
        raise UpdateError("Installed manifest is missing for an existing environment")
    if LEGACY.is_file():
        # Never execute unsigned legacy Python as a probe. An actual published
        # v0.3.0 install requires a separately authenticated migration (#55).
        raise UpdateError("Legacy installation requires reviewed authenticated bootstrap")
    return {"version": "0.0.0", "legacy": True}


CHECK_MESSAGE = "Private repository: update check unavailable (offline)."
UPDATE_MESSAGE = "Private repository: update unavailable (no changes)."


def check() -> Dict[str, Any]:
    """Discover trusted public or private releases without modifying the host."""
    from repocache.releases import report
    installed = str(_installed().get("version", __version__))
    if installed == "0.0.0":
        installed = __version__
    return report(installed)


def list_versions() -> Dict[str, Any]:
    """List stable release identifiers and conservative compatibility states."""
    from repocache.releases import report
    installed = str(_installed().get("version", __version__))
    if installed == "0.0.0":
        installed = __version__
    return report(installed, list_all=True)


def apply(version: Optional[str] = None, bundle: Optional[Path] = None,
          checksum: Optional[Path] = None,
          manifest: Optional[Path] = None, signature: Optional[Path] = None,
          wheels: Optional[Path] = None) -> Dict[str, Any]:
    """Safely install an explicitly verified GitHub Release or local bundle."""
    from repocache.upgrade import upgrade
    return upgrade(selected=version, bundle=bundle, checksum=checksum,
                   manifest=manifest, signature=signature, wheels=wheels)


def _safe_links() -> None:
    """Only root-owned, non-writable launchers may occupy global command paths.

    A previously installed v0.3.0 symlink requires a separately reviewed
    one-time bootstrap migration (#55); the updater cannot rewrite /usr/bin.
    """
    for link in LINKS:
        if not link.exists() and not link.is_symlink():
            continue
        if link.is_symlink() or not link.is_file():
            raise UpdateError(f"Unmanaged global command path: {link}")
        stat = link.stat()
        if stat.st_uid != 0 or stat.st_mode & 0o022:
            raise UpdateError(f"Insecure global launcher ownership/mode: {link}")
        try:
            with link.open("rb") as stream:
                marker = stream.read(160)
        except OSError as exc:
            raise UpdateError(f"Cannot verify global launcher: {link}") from exc
        if b"REPOCACHE ROOTLESS LAUNCHER" not in marker:
            raise UpdateError(f"Foreign launcher must not be overwritten: {link}")



def _sync_dir() -> None:
    descriptor = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _durable_file(target: Path, contents: bytes) -> None:
    descriptor, name = tempfile.mkstemp(prefix=".durable-", dir=ROOT)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o600)
        os.replace(name, target)
        _sync_dir()
    finally:
        if os.path.lexists(name):
            os.unlink(name)


def _write_manifest(data: Dict[str, Any]) -> None:
    raw = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    _durable_file(MANIFEST, raw)


def _journal_path() -> Path:
    return ROOT / ".update-journal.json"


def _write_journal(data: Dict[str, Any]) -> None:
    _durable_file(_journal_path(), (json.dumps(data, sort_keys=True) + "\n").encode())


def _clear_journal() -> None:
    journal = _journal_path()
    if journal.is_symlink():
        raise UpdateError("Unsafe updater transaction journal")
    if journal.is_file():
        journal.unlink()
        _sync_dir()


def _replace_current(target: Optional[str]) -> None:
    if target is None:
        if CURRENT.is_symlink():
            CURRENT.unlink()
            _sync_dir()
        elif CURRENT.exists():
            raise UpdateError("Active version is not a symlink")
        return
    staging = ROOT / (".current-" + uuid.uuid4().hex)
    try:
        staging.symlink_to(target)
        os.replace(staging, CURRENT)
        _sync_dir()
    finally:
        if staging.is_symlink():
            staging.unlink()


def recover_transaction() -> None:
    """Idempotent recovery under the current exclusive update transaction.

    The root-owned bootstrap helper calls the same stdlib-only algorithm
    before the managed CLI launches. Journal schema stays backward compatible.
    """
    if not getattr(_TX_LOCAL, "active", False):
        raise UpdateError("Recovery requires the exclusive updater lock")
    from repocache.recovery import RecoveryError, reconcile
    try:
        reconcile(ROOT)
    except RecoveryError as exc:
        raise UpdateError(str(exc)) from exc


def _install_source_locked(source: Path, *, approved_downgrade: bool = False,
                   release_policy: Optional[Dict[str, Any]] = None,
                   release_identity: Optional[Dict[str, str]] = None,
                   wheel_lock: Optional[Path] = None) -> Dict[str, Any]:
    """Stage a verified environment, atomically activate, and roll back on failure."""
    _require_service_account()
    # The staging directory is expected to be private to the service UID.
    os.umask(0o077)
    source = source.resolve(strict=True)
    version = _project_version(source)
    if (release_identity is not None and wheel_lock is None):
        raise UpdateError("Verified publisher releases require hash-pinned offline wheels")
    if (_version_tuple(version) >= (0, 4, 0)
            and (release_identity is None or wheel_lock is None)):
        raise UpdateError(
            "v0.4.0+ installation requires authenticated, hash-pinned offline "
            "release dependencies; source-only installation is disabled")
    digest = _source_digest(source)
    _safe_links()
    previous = _installed()
    prior_version = str(previous.get("version", "0.0.0"))
    if _version_tuple(version) < _version_tuple(prior_version) and not approved_downgrade:
        raise UpdateError("Update refused: downgrade is not permitted without compatibility approval")
    if previous.get("version") == version and previous.get("source_digest"):
        if previous["source_digest"] != digest:
            raise UpdateError("Same version with different code: increment the version")
        if EXECUTABLE.is_file():
            return {"ok": True, "version": version, "source_digest": digest,
                    "previous_version": version, "path": str(EXECUTABLE),
                    "status": "already-installed"}
        raise UpdateError("Current installation is incomplete; same-version repair requires review")

    if ROOT.is_symlink() or not ROOT.is_dir():
        raise UpdateError("Rootless managed directory is missing or unsafe; bootstrap required")
    if ROOT.stat().st_uid != os.geteuid():
        raise UpdateError("Rootless managed directory has unexpected owner")
    releases = ROOT / "releases"
    if releases.is_symlink():
        raise UpdateError("Unsafe releases directory")
    releases.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Console scripts and venv symlinks embed absolute paths. Never rename
    # an installed venv: build directly at a UNIQUE, per-run final path.
    # SIGKILL can leave an orphan, but cannot poison a later retry.
    destination = releases / f"{version}-{digest[:12]}-{uuid.uuid4().hex}"
    if destination.is_symlink():
        raise UpdateError("Unsafe versioned environment path")
    if destination.exists():
        if not (destination / "bin/repocache").is_file():
            raise UpdateError(f"An incomplete environment already exists: {destination}")
    else:
        # Versioned per-run pathname is immutable after creation. Installing
        # under a temporary name then renaming breaks pip shebangs/venv paths.
        destination.mkdir(mode=0o700)
        try:
            _run([sys.executable, "-m", "venv", str(destination)], timeout=90)
            interpreter = str(destination / "bin/python")
            if wheel_lock is None:
                # Legacy development fixture only; never an authenticated
                # v0.4.0+ release installation.
                _run([interpreter, "-m", "pip", "install", "--no-input",
                      "--disable-pip-version-check", "--no-cache-dir",
                      str(source)], timeout=300)
            else:
                from repocache.wheelhouse import install_argv
                if not wheel_lock.is_file() or wheel_lock.is_symlink():
                    raise UpdateError("Verified offline dependency lock is missing")
                _run(install_argv(Path(interpreter), wheel_lock),
                     cwd=wheel_lock.parent, timeout=300)
            verified = _run([str(destination / "bin/repocache"), "--version"], timeout=20)
            if version not in verified:
                raise UpdateError(f"Unexpected version after installation: {verified}")
            _run([interpreter, "-m", "pip", "check"], timeout=20)
            parent_fd = os.open(releases, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except BaseException:
            if destination.exists() and not destination.is_symlink():
                shutil.rmtree(destination)
            raise

    if CURRENT.exists() and not CURRENT.is_symlink():
        raise UpdateError("Current environment is not a managed symlink")
    previous_target = os.readlink(CURRENT) if CURRENT.is_symlink() else None
    previous_manifest = MANIFEST.read_bytes() if MANIFEST.is_file() else None
    manifest = {"version": version, "source_digest": digest,
                "source": "release-bundle"}
    if release_policy is not None:
        manifest["release_policy"] = release_policy
    if release_identity is not None:
        manifest.update(release_identity)
    raw_manifest = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    journal = {
        "schema": 2, "transaction_id": uuid.uuid4().hex,
        "new_manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
        "phase": "prepared", "previous": previous_target,
        "previous_manifest": (base64.b64encode(previous_manifest).decode("ascii")
                              if previous_manifest is not None else None),
        "destination": str(destination), "new_version": version,
    }
    _write_journal(journal)
    try:
        _replace_current(str(destination))
        journal["phase"] = "activated"
        _write_journal(journal)
        # Global command paths remain root-owned, outside this transaction.
        verified = _run([str(EXECUTABLE), "--version"], timeout=20)
        if version not in verified:
            raise UpdateError("Post-activation CLI verification failed")
        _write_manifest(manifest)
        journal["phase"] = "committed"
        _write_journal(journal)
        _clear_journal()
    except BaseException:
        try:
            recover_transaction()
        except BaseException as exc:
            raise UpdateError("Update interrupted; journal recovery failed") from exc
        raise
    return {"ok": True, "version": version, "source_digest": digest,
            "previous_version": previous.get("version"), "path": str(EXECUTABLE),
            "status": "installed"}


def install_source(source: Path, *, approved_downgrade: bool = False,
                   release_policy: Optional[Dict[str, Any]] = None,
                   release_identity: Optional[Dict[str, str]] = None,
                   wheel_lock: Optional[Path] = None) -> Dict[str, Any]:
    """Public entrypoint: all installer paths use the transaction lock."""
    with update_transaction():
        recover_transaction()
        return _install_source_locked(
            source, approved_downgrade=approved_downgrade,
            release_policy=release_policy, release_identity=release_identity,
            wheel_lock=wheel_lock)
