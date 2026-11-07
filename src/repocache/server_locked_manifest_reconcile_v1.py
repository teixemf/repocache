"""Locked, non-authorizing live managed-include drift inspection (#31).

The public root-UID entry is READ-ONLY and anchors '/' only in the current
mount namespace. It cannot authenticate host-root context or an operator.
No function in this module grants authority to write, reload or publish.
The caller-FD entry remains private and intended only for Linux fixtures.
"""
from __future__ import annotations

import base64
import binascii
from contextlib import ExitStack
import hashlib
import json
import re
import os
from typing import Any

from repocache.server_install_v1 import (
    ID, MAX_DOCUMENT_BYTES, MAX_INT, parse_install_bytes,
)
from repocache.server_repository_plan_v1 import _canonical_identity
from repocache.server_managed_include_v1 import MAX_CANDIDATE_BYTES
from repocache.server_managed_include_fd_v1 import observe_managed_include_at
from repocache.server_protected_state_inspect_v1 import (
    _DIRECTORY_FLAGS, _INCLUDE_SEGMENTS, _identity,
    _recheck, _safe_directory, _walk,
)
from repocache.server_protected_state_store_v1 import (
    JOURNAL_NAME, JOURNAL_TMP_NAME, MAX_JOURNAL_BYTES,
    MAX_STATE_BYTES, ROLLBACK_NAME, STAGE_NAME,
    _locked, _read_file, _read_journal, _read_state, _hash,
)

_COMPARE_FIELDS = ("sha256", "uid", "gid", "mode", "dev", "ino")


class LockedManifestInspectionError(ValueError):
    """Fixed symbolic refusal; no host paths, metadata, or file bytes."""


def _deny(code: str) -> None:
    raise LockedManifestInspectionError(code)


def _match_manifest(
    manifest: list[dict[str, Any]],
    observation: dict[str, Any] | None,
    *,
    expected_owner_uid: int,
) -> str:
    """Compare only the already validated fixed-path manifest and live inode.

    This pure inner step does not establish the caller's filesystem ancestry,
    root privilege, ACL or operator approval. It never returns content/hashes.
    """
    if not manifest:
        if observation is not None:
            _deny("FOREIGN_MANAGED_INCLUDE_REFUSED")
        return "NO_MANAGED_INCLUDE"
    if observation is None:
        _deny("RECORDED_MANAGED_INCLUDE_MISSING")
    if observation["uid"] != expected_owner_uid:
        _deny("MANAGED_INCLUDE_OWNER_MISMATCH")
    recorded = manifest[0]
    if any(recorded[k] != observation[k] for k in _COMPARE_FIELDS):
        _deny("MANAGED_INCLUDE_DRIFT")
    if observation["kind"] != "regular" or observation["nlink"] != 1:
        _deny("MANAGED_INCLUDE_UNSAFE")
    return "MANIFEST_MATCHES_OBSERVED_INCLUDE"


def _validate_candidate_bytes(value: Any) -> None:
    """Bounded input validation, not an NGINX syntax check."""
    if (type(value) is not bytes
            or not 1 <= len(value) <= MAX_CANDIDATE_BYTES
            or b"\x00" in value):
        _deny("MANAGED_CANDIDATE_INVALID")
    try:
        value.decode("utf-8", "strict")
    except UnicodeError:
        _deny("MANAGED_CANDIDATE_NOT_UTF8")


def _candidate_action(candidate: bytes, observation: dict[str, Any] | None) -> str:
    """Inert comparison after live manifest checks under a held lock."""
    if observation is None:
        return "WOULD_CREATE"
    return ("UNCHANGED" if hashlib.sha256(candidate).hexdigest()
            == observation["sha256"] else "WOULD_REPLACE")


def _inspect_locked_under_root(
    root_fd: int, *, owner_uid: int, expected_generation: int,
    candidate_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Private fixture-only entry, never a privileged authorization oracle.

    A caller-provided FD is NOT evidence of the OS root. The caller must not
    use the result as authority for mutation or NGINX/certificate operations.
    """
    if (type(root_fd) is not int or root_fd < 0 or type(owner_uid) is not int
            or owner_uid < 0 or type(expected_generation) is not int
            or not 0 <= expected_generation <= MAX_INT):
        _deny("MANIFEST_INSPECTION_ARGUMENT_INVALID")
    if candidate_bytes is not None:
        _validate_candidate_bytes(candidate_bytes)
    with _locked(root_fd, owner_uid) as state_dir:
        # Never silently recover on a read-only check. If an interrupted
        # transaction exists, the designated recovery operation must run first.
        if _read_journal(state_dir, owner_uid) is not None:
            _deny("PROTECTED_STATE_RECOVERY_REQUIRED")
        for name, limit in (
            (JOURNAL_TMP_NAME, MAX_JOURNAL_BYTES),
            (STAGE_NAME, MAX_STATE_BYTES),
            (ROLLBACK_NAME, MAX_STATE_BYTES),
        ):
            if _read_file(state_dir, name, owner_uid, limit) is not None:
                _deny("PROTECTED_STATE_RECOVERY_REQUIRED")
        state, raw = _read_state(state_dir, owner_uid)
        generation = 0 if state is None else state["state_generation"]
        if generation != expected_generation:
            _deny("PROTECTED_STATE_GENERATION_STALE")

        with ExitStack() as stack:
            include_dir, chain = _walk(
                root_fd, _INCLUDE_SEGMENTS, stack, owner_uid
            )
            include = observe_managed_include_at(include_dir)
            observation = include["observation"]
            if observation is not None and observation["uid"] != owner_uid:
                _deny("MANAGED_INCLUDE_OWNER_MISMATCH")
            manifest = [] if state is None else state["ownership_manifest"]
            status = _match_manifest(
                manifest, observation, expected_owner_uid=owner_uid
            )
            action = (_candidate_action(candidate_bytes, observation)
                      if candidate_bytes is not None else None)
            # A writer that does not honor flock (e.g. another root actor)
            # may change the include after the first bounded inode read.
            # Reobserve under the same lock before returning any preview.
            # This detects covered same-inode, same-size content drift too,
            # which checking the parent directory alone cannot detect.
            second = observe_managed_include_at(include_dir)["observation"]
            if second != observation:
                _deny("MANAGED_INCLUDE_CHANGED_DURING_INSPECTION")
            # Re-read the exact same protected content under the held lock,
            # even if another root-capable actor modified it without flock.
            _, after = _read_state(state_dir, owner_uid)
            if raw != after:
                _deny("PROTECTED_STATE_CHANGED_DURING_INSPECTION")
            _recheck(chain, owner_uid)
            _safe_directory(root_fd, owner_uid)
        report = {
            "schema_version": 1,
            "status": "LOCKED_READ_ONLY_RECONCILIATION",
            "include_status": status,
            "state_generation": generation,
            "manifest_entry_present": bool(manifest),
            "include_file_present": observation is not None,
            "exclusive_state_lock_held_during_inspection": True,
            # The presence of a stored record or its SHA-256 is NOT trusted
            # administrator provenance, user consent, or NGINX live exposure.
            "operator_authorization_verified": False,
            "protected_manifest_provenance_verified": False,
            "mount_namespace_acl_selinux_verified": False,
            "nginx_syntax_verified": False,
            "nginx_live_exposure_verified": False,
            "authorizes_write": False,
            "authorizes_nginx_reload": False,
            "authorizes_catalog_publication": False,
        }
        if candidate_bytes is not None:
            # Never return an inode lease or authorization beyond the lock.
            report["candidate_action"] = action
            report["candidate_preview_only"] = True
        return report




def _preview_recovery_under_root(
    root_fd: int, *, owner_uid: int,
) -> dict[str, Any]:
    """Fixture-only locked recovery diagnosis: no mutation or authorization."""
    if (type(root_fd) is not int or root_fd < 0
            or type(owner_uid) is not int or owner_uid < 0):
        _deny("PROTECTED_RECOVERY_PREVIEW_ARGUMENT_INVALID")
    with _locked(root_fd, owner_uid) as state_dir:
        journal = _read_journal(state_dir, owner_uid)
        temp = _read_file(
            state_dir, JOURNAL_TMP_NAME, owner_uid, MAX_JOURNAL_BYTES
        )
        stage = _read_file(state_dir, STAGE_NAME, owner_uid, MAX_STATE_BYTES)
        rollback = _read_file(
            state_dir, ROLLBACK_NAME, owner_uid, MAX_STATE_BYTES
        )
        state, current = _read_state(state_dir, owner_uid)
        if journal is None:
            if stage is not None:
                _deny("PROTECTED_ORPHAN_STAGE_REQUIRES_REVIEW")
            if rollback is not None:
                _deny("PROTECTED_ORPHAN_ROLLBACK_REQUIRES_REVIEW")
            action = ("DISCARD_UNPUBLISHED_JOURNAL" if temp is not None
                      else "CLEAN")
        else:
            if temp is not None:
                _deny("PROTECTED_ORPHAN_JOURNAL_TEMP_REQUIRES_REVIEW")
            previous, next_digest, _ = journal
            if _hash(current) not in (next_digest, _hash(previous)):
                _deny("PROTECTED_RECOVERY_DRIFT")
            if stage is not None and current != previous:
                _deny("PROTECTED_RECOVERY_DRIFT")
            action = "ROLLBACK_PENDING_STATE"
        # Refuse detectable races with writers that do not honor flock.
        if (
            _read_journal(state_dir, owner_uid) != journal
            or _read_file(
                state_dir, JOURNAL_TMP_NAME, owner_uid, MAX_JOURNAL_BYTES
            ) != temp
            or _read_file(
                state_dir, STAGE_NAME, owner_uid, MAX_STATE_BYTES
            ) != stage
            or _read_file(
                state_dir, ROLLBACK_NAME, owner_uid, MAX_STATE_BYTES
            ) != rollback
            or _read_state(state_dir, owner_uid) != (state, current)
        ):
            _deny("PROTECTED_RECOVERY_INPUT_CHANGED")
        _safe_directory(root_fd, owner_uid)
        return {
            "schema_version": 1,
            "status": "LOCKED_READ_ONLY_RECOVERY_PREVIEW",
            "recovery_action": action,
            "recovery_required": action != "CLEAN",
            "observed_state_generation": (
                0 if state is None else state["state_generation"]
            ),
            "exclusive_state_lock_held_during_inspection": True,
            "recovery_executed": False,
            "operator_authorization_verified": False,
            "protected_manifest_provenance_verified": False,
            "mount_namespace_acl_selinux_verified": False,
            "nginx_syntax_verified": False,
            "authorizes_state_mutation": False,
            "authorizes_nginx_reload": False,
            "authorizes_catalog_publication": False,
        }



# Proposed v2 persistence BRIDGE. This is NOT an adopted on-disk schema,
# writer, migration tool or trusted authorization interface.
_V2_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_V2_MAX_RESERVATIONS = 10000  # Same fail-closed bound as #95's pure planner.


def _v2_refuse(code: str) -> None:
    _deny("PROPOSED_V2_" + code)


def _v2_digest(value: Any) -> bool:
    return type(value) is str and _V2_DIGEST.fullmatch(value) is not None


def _v2_closed(value: Any, keys: set[str]) -> None:
    if type(value) is not dict or set(value) != keys:
        _v2_refuse("SCHEMA_INVALID")


def _validate_proposed_v2_snapshot(value: Any) -> dict[str, Any]:
    """Validate an untrusted, self-contained snapshot without I/O or authority.

    This is a *proposed contract*, not a new format understood by #222's v1
    file reader, writer or journal. Do not persist it with v1 primitives.
    """
    _v2_closed(value, {
        "state_schema_version", "state_generation", "configuration_base64",
        "configuration_sha256", "repository_records", "id_reservations",
        "approval_reference",
    })
    generation = value["state_generation"]
    if (type(value["state_schema_version"]) is not int
            or value["state_schema_version"] != 2
            or type(generation) is not int
            or not 1 <= generation <= MAX_INT):
        _v2_refuse("GENERATION_INVALID")
    raw_b64 = value["configuration_base64"]
    if (type(raw_b64) is not str
            or not 1 <= len(raw_b64) <= 4 * ((MAX_DOCUMENT_BYTES + 2) // 3)
            or not raw_b64.isascii()):
        _v2_refuse("CONFIGURATION_SIZE_INVALID")
    try:
        payload = base64.b64decode(raw_b64, validate=True)
    except (ValueError, binascii.Error):
        _v2_refuse("CONFIGURATION_ENCODING_INVALID")
    if (not 1 <= len(payload) <= MAX_DOCUMENT_BYTES
            or base64.b64encode(payload).decode("ascii") != raw_b64):
        _v2_refuse("CONFIGURATION_ENCODING_INVALID")
    if (not _v2_digest(value["configuration_sha256"])
            or hashlib.sha256(payload).hexdigest()
            != value["configuration_sha256"]):
        _v2_refuse("CONFIGURATION_DIGEST_MISMATCH")
    try:
        document = parse_install_bytes(payload, for_apply=True)
        canonical = json.dumps(
            document, sort_keys=True, ensure_ascii=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (ValueError, TypeError, OverflowError, UnicodeError, RecursionError):
        _v2_refuse("CONFIGURATION_INVALID")
    if canonical != payload or document["expected_state_generation"] != generation:
        _v2_refuse("CONFIGURATION_NOT_CANONICAL")
    declared = document["repositories"]
    if any("id" not in row for row in declared):
        _v2_refuse("REPOSITORY_ID_REQUIRED")
    records = value["repository_records"]
    reservations = value["id_reservations"]
    if (type(records) is not list or len(records) > 500
            or type(reservations) is not list
            or len(reservations) > _V2_MAX_RESERVATIONS):
        _v2_refuse("CAPACITY_INVALID")
    by_id: dict[str, dict[str, Any]] = {}
    identity_set: set[str] = set()
    for record in records:
        _v2_closed(record, {
            "id", "canonical_identity_sha256", "desired_state",
            "observed_state",
        })
        rid = record["id"]
        digest = record["canonical_identity_sha256"]
        if (type(rid) is not str or ID.fullmatch(rid) is None
                or rid in by_id or not _v2_digest(digest)
                or digest in identity_set
                or type(record["desired_state"]) is not str
                or record["desired_state"] not in ("active", "disabled")
                or record["observed_state"] != "not-activated"
                or type(record["observed_state"]) is not str):
            _v2_refuse("REPOSITORY_RECORD_INVALID")
        by_id[rid] = record
        identity_set.add(digest)
    if set(by_id) != {row["id"] for row in declared}:
        _v2_refuse("REPOSITORY_SET_MISMATCH")
    for row in declared:
        record = by_id[row["id"]]
        digest = hashlib.sha256(
            _canonical_identity(row).encode("utf-8")
        ).hexdigest()
        if (record["canonical_identity_sha256"] != digest
                or record["desired_state"] != row["desired_state"]):
            _v2_refuse("REPOSITORY_IDENTITY_OR_INTENT_MISMATCH")
    reserved: dict[str, dict[str, Any]] = {}
    reserved_identities: set[str] = set()
    for item in reservations:
        _v2_closed(item, {"id", "canonical_identity_sha256", "status"})
        rid = item["id"]
        digest = item["canonical_identity_sha256"]
        if (type(rid) is not str or ID.fullmatch(rid) is None
                or rid in reserved or not _v2_digest(digest)
                or digest in reserved_identities
                or type(item["status"]) is not str
                or item["status"] not in ("allocated", "retired")):
            _v2_refuse("RESERVATION_INVALID")
        reserved[rid] = item
        reserved_identities.add(digest)
    allocated = {rid for rid, item in reserved.items()
                 if item["status"] == "allocated"}
    if allocated != set(by_id) or any(
        reserved[rid]["canonical_identity_sha256"]
        != record["canonical_identity_sha256"]
        for rid, record in by_id.items()
    ):
        _v2_refuse("RESERVATION_LEDGER_MISMATCH")
    decision = value["approval_reference"]
    _v2_closed(decision, {
        "source", "decision_sha256", "configuration_sha256",
        "expected_generation",
    })
    if (type(decision["source"]) is not str
            or decision["source"] not in ("operator", "audited-request")
            or not _v2_digest(decision["decision_sha256"])
            or decision["configuration_sha256"] != value["configuration_sha256"]
            or type(decision["expected_generation"]) is not int
            or decision["expected_generation"] != generation - 1):
        _v2_refuse("APPROVAL_REFERENCE_MISMATCH")
    # These are independent snapshots; do NOT expose a mutable caller object
    # or any configuration bytes as the result of the preview.
    return {"generation": generation, "ids": reserved,
            "present": frozenset(by_id)}


def preview_proposed_v2_state_transition(
    proposed_snapshot: Any, *, expected_generation: int,
    previous_snapshot: Any = None,
) -> dict[str, Any]:
    """Pure proposed v2 CAS/ID retention check, never a privileged apply."""
    if (type(expected_generation) is not int
            or not 0 <= expected_generation < MAX_INT):
        _v2_refuse("EXPECTED_GENERATION_INVALID")
    new = _validate_proposed_v2_snapshot(proposed_snapshot)
    if new["generation"] != expected_generation + 1:
        _v2_refuse("STALE_GENERATION")
    if previous_snapshot is None:
        if expected_generation != 0:
            _v2_refuse("PREVIOUS_STATE_REQUIRED")
        removed_count = 0
    else:
        old = _validate_proposed_v2_snapshot(previous_snapshot)
        if old["generation"] != expected_generation:
            _v2_refuse("STALE_GENERATION")
        # Never permit historic ID reuse or identity reassignment. A removed
        # repository must remain reserved forever; saturation refuses
        # further additions instead of dropping tombstones.
        for rid, item in old["ids"].items():
            successor = new["ids"].get(rid)
            if (successor is None
                    or successor["canonical_identity_sha256"]
                    != item["canonical_identity_sha256"]
                    or (item["status"] == "retired"
                        and successor["status"] != "retired")):
                _v2_refuse("RESERVATION_HISTORY_CHANGED")
        removed_count = len(old["present"] - new["present"])
        if any(new["ids"][rid]["status"] != "retired"
               for rid in old["present"] - new["present"]):
            _v2_refuse("REMOVAL_TOMBSTONE_MISSING")
    return {
        "schema_version": 2,
        "status": "PROPOSED_UNTRUSTED_V2_CONTRACT_ONLY",
        "expected_generation": expected_generation,
        "proposed_generation": new["generation"],
        "repository_count": len(new["present"]),
        "reserved_id_count": len(new["ids"]),
        "removed_repository_count": removed_count,
        "configuration_digest_matches_canonical_payload": True,
        "operator_authorization_verified": False,
        "protected_snapshot_provenance_verified": False,
        "reservation_history_authoritative": False,
        "observed_nginx_exposure_verified": False,
        "native_transaction_verified": False,
        "requires_locked_root_revalidation": True,
        "authorizes_write": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
        "authorizes_cache_cleanup": False,
    }


def _verify_current_root_fd(root_fd: int) -> None:
    """Require identity with '/' in the *current mount namespace*.

    This is not a host namespace attestation or an operator authorization.
    """
    try:
        opened = _safe_directory(root_fd, 0)
        named = os.stat("/", follow_symlinks=False)
        if _identity(opened) != _identity(named):
            _deny("CURRENT_NAMESPACE_ROOT_CHANGED")
    except LockedManifestInspectionError:
        raise
    except (OSError, ValueError):
        _deny("CURRENT_NAMESPACE_ROOT_UNVERIFIED")


def inspect_current_namespace_locked_manifest(
    *, expected_generation: int
) -> dict[str, Any]:
    """Read only the current namespace's fixed root-owned NGINX/state paths.

    Unlike _inspect_locked_under_root, no caller supplies an arbitrary root
    FD or UID. Even a successful read never authenticates an administrator,
    proves host mount namespace isolation, or authorizes root writes/reloads.
    """
    if type(expected_generation) is not int or not 0 <= expected_generation <= MAX_INT:
        _deny("MANIFEST_INSPECTION_ARGUMENT_INVALID")
    if os.geteuid() != 0:
        _deny("CURRENT_NAMESPACE_ROOT_PRIVILEGE_REQUIRED")
    try:
        root_fd = os.open("/", _DIRECTORY_FLAGS)
    except OSError:
        _deny("CURRENT_NAMESPACE_ROOT_OPEN_REFUSED")
    try:
        _verify_current_root_fd(root_fd)
        result = _inspect_locked_under_root(
            root_fd, owner_uid=0, expected_generation=expected_generation
        )
        _verify_current_root_fd(root_fd)
        # Only describes the root path opened in this process's namespace.
        # It does not prove trusted host ancestry, privilege delegation,
        # SELinux/ACL correctness or operator provenance.
        return {**result, "current_namespace_root_path_verified": True}
    finally:
        os.close(root_fd)



def inspect_current_namespace_locked_recovery() -> dict[str, Any]:
    """Read-only protected-state recovery diagnosis at the current '/'.

    No caller-supplied path, descriptor, owner or recovery command is
    accepted. Root UID and current-namespace '/' do not establish trusted
    host-root authority, operator approval or permission to mutate files.
    """
    if os.geteuid() != 0:
        _deny("CURRENT_NAMESPACE_ROOT_PRIVILEGE_REQUIRED")
    try:
        root_fd = os.open("/", _DIRECTORY_FLAGS)
    except OSError:
        _deny("CURRENT_NAMESPACE_ROOT_OPEN_REFUSED")
    try:
        _verify_current_root_fd(root_fd)
        result = _preview_recovery_under_root(root_fd, owner_uid=0)
        _verify_current_root_fd(root_fd)
        # A momentary, namespace-local path observation is not an
        # authorization that survives the release of the state lock.
        return {**result, "current_namespace_root_path_verified": True}
    finally:
        os.close(root_fd)

def preview_current_namespace_locked_candidate(
    *, expected_generation: int, candidate_bytes: bytes
) -> dict[str, Any]:
    """Preview only; root UID in a container is not trusted host authority."""
    _validate_candidate_bytes(candidate_bytes)
    if type(expected_generation) is not int or not 0 <= expected_generation <= MAX_INT:
        _deny("MANIFEST_INSPECTION_ARGUMENT_INVALID")
    if os.geteuid() != 0:
        _deny("CURRENT_NAMESPACE_ROOT_PRIVILEGE_REQUIRED")
    try:
        root_fd = os.open("/", _DIRECTORY_FLAGS)
    except OSError:
        _deny("CURRENT_NAMESPACE_ROOT_OPEN_REFUSED")
    try:
        _verify_current_root_fd(root_fd)
        result = _inspect_locked_under_root(
            root_fd, owner_uid=0, expected_generation=expected_generation,
            candidate_bytes=candidate_bytes,
        )
        _verify_current_root_fd(root_fd)
        return {**result, "current_namespace_root_path_verified": True}
    finally:
        os.close(root_fd)
