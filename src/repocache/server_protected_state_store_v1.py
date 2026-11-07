"""Crash-recoverable, non-activating protected-state storage core (#31).

This is a fixed-purpose internal Linux filesystem primitive, NOT an installer or
authorization service. The _under_root entry points exist for isolated tests.
No public CLI, root delegation, NGINX activation or catalog writer calls them.
A persisted approval reference is DATA, never proof of operator authorization.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager, ExitStack
import fcntl
import hashlib
import json
import os
import re
import stat
from typing import Any, Callable, Iterator

from repocache.server_install_v1 import MAX_INT
from repocache.server_managed_include_v1 import _metadata
from repocache.server_protected_state_inspect_v1 import (
    _STATE_SEGMENTS, _walk, _recheck, _safe_directory, _identity,
)

STATE_NAME = "state-v1.json"
LOCK_NAME = ".state-v1.lock"
JOURNAL_NAME = ".state-v1.pending"
JOURNAL_TMP_NAME = ".state-v1.pending-tmp"
STAGE_NAME = ".state-v1.stage"
ROLLBACK_NAME = ".state-v1.rollback"
MAX_STATE_BYTES = 1024 * 1024
MAX_JOURNAL_BYTES = 2 * MAX_STATE_BYTES + 2048
_INCLUDE_PATH = "/etc/nginx/conf.d/repocache-managed.conf"
_HEX = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z", re.ASCII)
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
_CREATE = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
           getattr(os, "O_CLOEXEC", 0))


class ProtectedStateStoreError(ValueError):
    """Redacted fixed-code refusal, never arbitrary file contents or paths."""


def _fail(code: str) -> None:
    raise ProtectedStateStoreError(code)


def _closed(value: Any, names: set[str]) -> None:
    if type(value) is not dict or set(value) != names:
        _fail("PROTECTED_SCHEMA_INVALID")


def _number(value: Any, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= MAX_INT


def _hex(value: Any) -> bool:
    return type(value) is str and bool(_HEX.fullmatch(value))


def validate_protected_state(value: Any) -> dict[str, Any]:
    """Validate closed v1 state without interpreting provenance as authority."""
    _closed(value, {"state_schema_version", "state_generation",
                    "configuration_sha256", "repositories", "ownership_manifest"})
    if (type(value["state_schema_version"]) is not int
            or value["state_schema_version"] != 1
            or not _number(value["state_generation"], 1)
            or not _hex(value["configuration_sha256"])):
        _fail("PROTECTED_SCHEMA_INVALID")
    repos = value["repositories"]
    if type(repos) is not list or len(repos) > 32:
        _fail("PROTECTED_REPOSITORIES_INVALID")
    ids: set[str] = set()
    identities: set[str] = set()
    for repo in repos:
        _closed(repo, {"id", "canonical_identity_sha256", "approval",
                       "desired_state", "observed_state"})
        identifier = repo["id"]
        identity = repo["canonical_identity_sha256"]
        if (type(identifier) is not str or not _ID.fullmatch(identifier)
                or identifier in ids or not _hex(identity)
                or identity in identities or repo["desired_state"] not in ("active", "disabled")
                or type(repo["desired_state"]) is not str
                or repo["observed_state"] != "not-activated"):
            _fail("PROTECTED_REPOSITORIES_INVALID")
        _closed(repo["approval"], {"source", "decision_sha256"})
        if (type(repo["approval"]["source"]) is not str
                or repo["approval"]["source"] not in ("operator", "audited-request")
                or not _hex(repo["approval"]["decision_sha256"])):
            _fail("PROTECTED_APPROVAL_REFERENCE_INVALID")
        ids.add(identifier)
        identities.add(identity)
    manifest = value["ownership_manifest"]
    if type(manifest) is not list or len(manifest) > 1:
        _fail("PROTECTED_MANIFEST_INVALID")
    for item in manifest:
        try:
            _metadata(item, manifest=True, path=_INCLUDE_PATH)
        except ValueError:
            _fail("PROTECTED_MANIFEST_INVALID")
        if item["generation"] > value["state_generation"]:
            _fail("PROTECTED_MANIFEST_INVALID")
    return value


def _canonical(value: Any, *, limit: int) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=True, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
        _fail("PROTECTED_SERIALIZATION_INVALID")
    if not 1 <= len(raw) <= limit:
        _fail("PROTECTED_SERIALIZATION_SIZE_INVALID")
    return raw


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in items:
        if key in obj:
            _fail("PROTECTED_DUPLICATE_KEY")
        obj[key] = value
    return obj


def _json(raw: bytes, *, limit: int) -> Any:
    if not 1 <= len(raw) <= limit:
        _fail("PROTECTED_SERIALIZATION_SIZE_INVALID")
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: _fail("PROTECTED_JSON_INVALID"))
    except ProtectedStateStoreError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _fail("PROTECTED_JSON_INVALID")
    if _canonical(value, limit=limit) != raw:
        _fail("PROTECTED_NONCANONICAL_JSON")
    return value


def _hash(raw: bytes | None) -> str | None:
    return None if raw is None else hashlib.sha256(raw).hexdigest()


def _safe_file(fd: int, directory: int, owner_uid: int,
               maximum: int) -> os.stat_result:
    try:
        info = os.fstat(fd)
        parent = _safe_directory(directory, owner_uid)
    except OSError:
        _fail("PROTECTED_FILE_UNAVAILABLE")
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_dev != parent.st_dev or info.st_size > maximum
            or info.st_ino <= 0):
        _fail("PROTECTED_FILE_UNSAFE")
    return info


def _read_file(directory: int, name: str, owner_uid: int,
               maximum: int) -> bytes | None:
    try:
        # A missing entry is distinguishable from an existing dangling symlink.
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        _fail("PROTECTED_FILE_UNAVAILABLE")
    try:
        fd = os.open(name, _READ, dir_fd=directory)
    except OSError:
        _fail("PROTECTED_FILE_OPEN_REFUSED")
    try:
        before = _safe_file(fd, directory, owner_uid, maximum)
        if _identity(named) != _identity(before):
            _fail("PROTECTED_FILE_CHANGED")
        parts = []
        count = 0
        while count <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - count))
            if not chunk:
                break
            parts.append(chunk)
            count += len(chunk)
        after = os.fstat(fd)
        again = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (count != before.st_size or count > maximum
                or _identity(before) != _identity(after)
                or _identity(after) != _identity(again)):
            _fail("PROTECTED_FILE_CHANGED")
        return b"".join(parts)
    except ProtectedStateStoreError:
        raise
    except OSError:
        _fail("PROTECTED_FILE_READ_REFUSED")
    finally:
        os.close(fd)


def _write_exclusive(directory: int, name: str, raw: bytes,
                     owner_uid: int, maximum: int) -> None:
    if not 1 <= len(raw) <= maximum:
        _fail("PROTECTED_SERIALIZATION_SIZE_INVALID")
    try:
        fd = os.open(name, _CREATE, 0o600, dir_fd=directory)
    except OSError:
        _fail("PROTECTED_STAGE_CONFLICT")
    try:
        _safe_file(fd, directory, owner_uid, maximum)
        if os.fstat(fd).st_size != 0:
            _fail("PROTECTED_STAGE_CONFLICT")
        position = 0
        while position < len(raw):
            size = os.write(fd, raw[position:])
            if size <= 0:
                _fail("PROTECTED_WRITE_REFUSED")
            position += size
        os.fsync(fd)
        _safe_file(fd, directory, owner_uid, maximum)
    except ProtectedStateStoreError:
        raise
    except OSError:
        _fail("PROTECTED_WRITE_REFUSED")
    finally:
        os.close(fd)
    try:
        os.fsync(directory)
    except OSError:
        _fail("PROTECTED_FSYNC_REFUSED")


def _unlink_known(directory: int, name: str, raw: bytes | None,
                  owner_uid: int, maximum: int) -> None:
    if _read_file(directory, name, owner_uid, maximum) != raw or raw is None:
        _fail("PROTECTED_STAGE_CHANGED")
    try:
        os.unlink(name, dir_fd=directory)
        os.fsync(directory)
    except OSError:
        _fail("PROTECTED_RECOVERY_IO_REFUSED")


def _recheck_after_mutation(
    chain: list[tuple[int, str, int, tuple[int, ...]]],
    owner_uid: int,
) -> None:
    # The state directory's own mtime/ctime/size change after legitimate
    # create/rename/unlink. Its ancestors must remain byte-for-byte identical,
    # while the leaf directory must preserve pinned structural identity.
    _recheck(chain[:-1], owner_uid)
    parent, name, child, original = chain[-1]
    try:
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        opened = _safe_directory(child, owner_uid)
        structural = lambda st: (
            st.st_dev, st.st_ino, st.st_mode,
            st.st_uid, st.st_gid, st.st_nlink,
        )
        expected = original[:6]
        if structural(named) != expected or structural(opened) != expected:
            _fail("PROTECTED_DIRECTORY_CHANGED")
    except ProtectedStateStoreError:
        raise
    except OSError:
        _fail("PROTECTED_DIRECTORY_CHANGED")



# The private proposed v2 fixture store reuses this state lock. V1 must
# reciprocally refuse *any* proposed v2 file before reading or modifying
# v1 state, including incomplete/stale files and dangling symlinks.
# This is a migration safety interlock, NOT authorization to migrate.
_V2_NAMES = (
    "state-v2.json", ".state-v2.pending", ".state-v2.pending-tmp",
    ".state-v2.stage", ".state-v2.rollback",
)


def _refuse_proposed_v2_coexistence(directory: int) -> None:
    for name in _V2_NAMES:
        try:
            os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            _fail("PROTECTED_V2_COHABITATION_UNVERIFIED")
        _fail("PROTECTED_V2_COHABITATION_REFUSED")


@contextmanager
def _locked(root_fd: int, owner_uid: int) -> Iterator[int]:
    """Fixture-only pinned path. Lock inode must be preprovisioned, never created here."""
    if type(root_fd) is not int or root_fd < 0 or type(owner_uid) is not int:
        _fail("PROTECTED_ROOT_INVALID")
    with ExitStack() as stack:
        try:
            state_fd, chain = _walk(root_fd, _STATE_SEGMENTS, stack, owner_uid)
            parent = _safe_directory(state_fd, owner_uid)
            if stat.S_IMODE(parent.st_mode) != 0o700:
                _fail("PROTECTED_DIRECTORY_MODE_INVALID")
            lock_fd = os.open(LOCK_NAME, _READ, dir_fd=state_fd)
            stack.callback(os.close, lock_fd)
            info = _safe_file(lock_fd, state_fd, owner_uid, 0)
            if info.st_size != 0:
                _fail("PROTECTED_LOCK_INVALID")
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            named = os.stat(LOCK_NAME, dir_fd=state_fd, follow_symlinks=False)
            if _identity(info) != _identity(named):
                _fail("PROTECTED_LOCK_CHANGED")
            _recheck(chain, owner_uid)
        except ProtectedStateStoreError:
            raise
        except (OSError, ValueError):
            _fail("PROTECTED_LOCK_UNAVAILABLE")
        try:
            yield state_fd
            _recheck_after_mutation(chain, owner_uid)
            if _identity(named) != _identity(os.stat(LOCK_NAME, dir_fd=state_fd,
                                                      follow_symlinks=False)):
                _fail("PROTECTED_LOCK_CHANGED")
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)


def _read_state(directory: int, uid: int) -> tuple[dict[str, Any] | None, bytes | None]:
    _refuse_proposed_v2_coexistence(directory)
    raw = _read_file(directory, STATE_NAME, uid, MAX_STATE_BYTES)
    if raw is None:
        return None, None
    state = _json(raw, limit=MAX_STATE_BYTES)
    validate_protected_state(state)
    return state, raw


def _journal(previous: bytes | None, proposed: bytes) -> bytes:
    value = {
        "journal_schema_version": 1,
        "previous_sha256": _hash(previous),
        "next_sha256": _hash(proposed),
        "previous_base64": None if previous is None else
            base64.b64encode(previous).decode("ascii"),
    }
    return _canonical(value, limit=MAX_JOURNAL_BYTES)


def _install_journal(directory: int, uid: int, previous: bytes | None,
                     proposed: bytes,
                     inject_fault: Callable[[str], None] | None) -> None:
    # The journal file is published ONLY after a complete fsynced temporary
    # inode exists. A crash during temporary creation leaves state unchanged.
    raw = _journal(previous, proposed)
    _write_exclusive(directory, JOURNAL_TMP_NAME, raw, uid, MAX_JOURNAL_BYTES)
    if inject_fault is not None:
        inject_fault("journal_tmp_durable")
    try:
        if _read_file(directory, JOURNAL_NAME, uid, MAX_JOURNAL_BYTES) is not None:
            _fail("PROTECTED_JOURNAL_CONFLICT")
        os.replace(JOURNAL_TMP_NAME, JOURNAL_NAME,
                   src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    except ProtectedStateStoreError:
        raise
    except OSError:
        _fail("PROTECTED_JOURNAL_IO_REFUSED")


def _read_journal(directory: int, uid: int) -> tuple[bytes | None, str, bytes] | None:
    raw = _read_file(directory, JOURNAL_NAME, uid, MAX_JOURNAL_BYTES)
    if raw is None:
        return None
    value = _json(raw, limit=MAX_JOURNAL_BYTES)
    _closed(value, {"journal_schema_version", "previous_sha256",
                    "next_sha256", "previous_base64"})
    if (type(value["journal_schema_version"]) is not int
            or value["journal_schema_version"] != 1 or not _hex(value["next_sha256"])):
        _fail("PROTECTED_JOURNAL_INVALID")
    prev = value["previous_base64"]
    if prev is None:
        if value["previous_sha256"] is not None:
            _fail("PROTECTED_JOURNAL_INVALID")
        previous = None
    else:
        if type(prev) is not str or len(prev) > 4 * ((MAX_STATE_BYTES + 2) // 3):
            _fail("PROTECTED_JOURNAL_INVALID")
        try:
            previous = base64.b64decode(prev, validate=True)
        except (ValueError, base64.binascii.Error):
            _fail("PROTECTED_JOURNAL_INVALID")
        if not _hex(value["previous_sha256"]) or _hash(previous) != value["previous_sha256"]:
            _fail("PROTECTED_JOURNAL_INVALID")
        validate_protected_state(_json(previous, limit=MAX_STATE_BYTES))
    return previous, value["next_sha256"], raw


def _recover_locked(directory: int, uid: int) -> str:
    journal = _read_journal(directory, uid)
    temp = _read_file(directory, JOURNAL_TMP_NAME, uid, MAX_JOURNAL_BYTES)
    if journal is None:
        if _read_file(directory, STAGE_NAME, uid, MAX_STATE_BYTES) is not None:
            _fail("PROTECTED_ORPHAN_STAGE_REQUIRES_REVIEW")
        if _read_file(directory, ROLLBACK_NAME, uid, MAX_STATE_BYTES) is not None:
            _fail("PROTECTED_ORPHAN_ROLLBACK_REQUIRES_REVIEW")
        if temp is not None:
            # No published journal means the state rename cannot have started.
            # Verify the current state and discard ONLY the owned fixed temp.
            _read_state(directory, uid)
            _unlink_known(directory, JOURNAL_TMP_NAME, temp, uid, MAX_JOURNAL_BYTES)
            return "DISCARDED_UNPUBLISHED_JOURNAL"
        return "CLEAN"
    if temp is not None:
        _fail("PROTECTED_ORPHAN_JOURNAL_TEMP_REQUIRES_REVIEW")
    previous, next_digest, journal_bytes = journal
    current = _read_file(directory, STATE_NAME, uid, MAX_STATE_BYTES)
    if _hash(current) not in (next_digest, _hash(previous)):
        _fail("PROTECTED_RECOVERY_DRIFT")
    stage = _read_file(directory, STAGE_NAME, uid, MAX_STATE_BYTES)
    if stage is not None and current != previous:
        # The stage inode is consumed by rename when the new state becomes
        # visible. A second stage is unexpected even if its bytes happen to
        # match the candidate digest: never silently delete unexpected drift.
        # A partial stage is recoverable only while the old state is present.
        _fail("PROTECTED_RECOVERY_DRIFT")
    rollback = _read_file(directory, ROLLBACK_NAME, uid, MAX_STATE_BYTES)
    if rollback is not None and rollback != previous:
        # A prior recovery can crash while writing its replacement backup.
        # The fixed root-owned temp can be discarded and rebuilt; NEVER
        # discard drift in the authoritative state file itself.
        _unlink_known(directory, ROLLBACK_NAME, rollback, uid, MAX_STATE_BYTES)
        rollback = None
    if current != previous:
        if previous is None:
            if current is None:
                _fail("PROTECTED_RECOVERY_DRIFT")
            _unlink_known(directory, STATE_NAME, current, uid, MAX_STATE_BYTES)
        else:
            if rollback is None:
                _write_exclusive(directory, ROLLBACK_NAME, previous, uid, MAX_STATE_BYTES)
            try:
                os.replace(ROLLBACK_NAME, STATE_NAME, src_dir_fd=directory,
                           dst_dir_fd=directory)
                os.fsync(directory)
            except OSError:
                # The durable journal remains the recovery authority. Never
                # surface raw OS paths/errors or silently mark recovery clean.
                _fail("PROTECTED_RECOVERY_IO_REFUSED")
    if stage is not None:
        _unlink_known(directory, STAGE_NAME, stage, uid, MAX_STATE_BYTES)
    if rollback is not None and current == previous:
        _unlink_known(directory, ROLLBACK_NAME, rollback, uid, MAX_STATE_BYTES)
    _unlink_known(directory, JOURNAL_NAME, journal_bytes, uid, MAX_JOURNAL_BYTES)
    return "ROLLED_BACK"


def _recover_under_root(root_fd: int, *, owner_uid: int) -> dict[str, Any]:
    """Private, non-activating recovery; refuse unexpected filesystem drift."""
    with _locked(root_fd, owner_uid) as directory:
        _refuse_proposed_v2_coexistence(directory)
        status = _recover_locked(directory, owner_uid)
        state, _ = _read_state(directory, owner_uid)
        return {"status": status, "state_generation": 0 if state is None
                else state["state_generation"], "authorizes_nginx_reload": False,
                "authorizes_catalog_publication": False}


def _commit_under_root(root_fd: int, candidate: dict[str, Any], *,
                       expected_generation: int, owner_uid: int,
                       inject_fault: Callable[[str], None] | None = None) -> dict[str, Any]:
    """Private storage-only transaction; NOT exposed as a privileged command.

    Caller approval, NGINX activation and real manifest provenance are unverified.
    Never wire an untrusted installation document directly into this primitive.
    """
    validate_protected_state(candidate)
    if not _number(expected_generation):
        _fail("PROTECTED_EXPECTED_GENERATION_INVALID")
    raw = _canonical(candidate, limit=MAX_STATE_BYTES)
    # Do not consult mutable caller-owned objects after serializing: a separate
    # thread must not change generation/identity checks for the bytes committed.
    candidate = _json(raw, limit=MAX_STATE_BYTES)
    validate_protected_state(candidate)
    with _locked(root_fd, owner_uid) as directory:
        _refuse_proposed_v2_coexistence(directory)
        if _read_journal(directory, owner_uid) is not None:
            _fail("PROTECTED_RECOVERY_REQUIRED")
        if (_read_file(directory, STAGE_NAME, owner_uid, MAX_STATE_BYTES) is not None
                or _read_file(directory, ROLLBACK_NAME, owner_uid, MAX_STATE_BYTES) is not None
                or _read_file(directory, JOURNAL_TMP_NAME, owner_uid,
                              MAX_JOURNAL_BYTES) is not None):
            _fail("PROTECTED_ORPHAN_STAGE_REQUIRES_REVIEW")
        existing, previous = _read_state(directory, owner_uid)
        generation = 0 if existing is None else existing["state_generation"]
        if generation != expected_generation:
            _fail("PROTECTED_STALE_GENERATION")
        if generation == MAX_INT:
            _fail("PROTECTED_GENERATION_EXHAUSTED")
        if candidate["state_generation"] != generation + 1:
            _fail("PROTECTED_NEXT_GENERATION_INVALID")
        if existing is not None:
            old = dict(existing)
            old["state_generation"] = candidate["state_generation"]
            if old == candidate:
                return {"status": "NO_CHANGE", "state_generation": generation,
                        "authorizes_nginx_reload": False,
                        "authorizes_catalog_publication": False}
            old_ids = {r["id"]: r["canonical_identity_sha256"]
                       for r in existing["repositories"]}
            new_ids = {r["id"]: r["canonical_identity_sha256"]
                       for r in candidate["repositories"]}
            if any(new_ids.get(key) != identity for key, identity in old_ids.items()):
                _fail("PROTECTED_REPOSITORY_ID_REASSIGNMENT_OR_REMOVAL")
        # Journalling BEFORE replacing the protected state makes an uncommitted
        # state always recoverable to its exact prior canonical bytes.
        _install_journal(directory, owner_uid, previous, raw, inject_fault)
        if inject_fault is not None:
            inject_fault("journal_durable")
        _write_exclusive(directory, STAGE_NAME, raw, owner_uid, MAX_STATE_BYTES)
        if inject_fault is not None:
            inject_fault("stage_durable")
        _, rechecked = _read_state(directory, owner_uid)
        if rechecked != previous:
            _fail("PROTECTED_CONCURRENT_DRIFT")
        try:
            os.replace(STAGE_NAME, STATE_NAME, src_dir_fd=directory,
                       dst_dir_fd=directory)
            os.fsync(directory)
        except OSError:
            _fail("PROTECTED_COMMIT_IO_REFUSED")
        if inject_fault is not None:
            inject_fault("replace_durable")
        pending = _read_file(directory, JOURNAL_NAME, owner_uid, MAX_JOURNAL_BYTES)
        if pending != _journal(previous, raw):
            _fail("PROTECTED_JOURNAL_CHANGED")
        _unlink_known(directory, JOURNAL_NAME, pending, owner_uid, MAX_JOURNAL_BYTES)
        return {"status": "COMMITTED_INERT_STATE",
                "state_generation": candidate["state_generation"],
                "authorizes_nginx_reload": False,
                "authorizes_catalog_publication": False}
