"""Explicit entry-bound sandbox atomic apply/rollback on whole shared files.

Depends on the already-integrated #131/#132 transaction_stage and
transaction_atomic_lab; this PR tests that dependency from an immutable
main commit. It is a LAB adapter, never imported by the installed CLI.
Neither UID=0 nor an approval file permits use on a production filesystem.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import entry_approval_plan_sandbox as approval
import managed_registry_sandbox as registry
import source_entry_boundaries as boundaries


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _verify(root: Path, candidate_id: str, stage_id: str,
            new_https_url: str, *, rollback: bool) -> tuple[object, object]:
    # Do not inspect registry state, source paths or stage data without
    # establishing the actual (not recorded) root privilege requirement.
    if os.geteuid() != 0:
        raise approval.ApprovalRefused("Root required for sandbox source replacement")
    import transaction_stage as stage
    import transaction_atomic_lab as atomic

    # An explicit marker, a private root under /tmp, and the #132 guards
    # are mandatory even when a valid approval intent already exists.
    root = atomic._sandbox(root)
    approval._name(candidate_id)
    if not isinstance(stage_id, str) or not stage.STAGE_ID.fullmatch(stage_id):
        raise approval.ApprovalRefused("Invalid staged transaction identifier")
    candidate = approval._candidate(root, candidate_id)
    approved = approval._read_approval(root, candidate_id)
    if (approved["source_file_sha256"] != candidate["file_sha256"]
            or approved["source_entry_sha256"] != candidate["entry_sha256"]
            or candidate["xattrs_present"]):
        raise approval.ApprovalRefused("Approval or metadata policy changed")

    # Revalidate the transaction snapshot against one exact candidate before
    # granting even a LAB operation. Never trust a stage_id alone.
    state = stage._state(root, create=False)
    records = stage._records(state)
    record = records.get(stage_id)
    if record is None or record["source"] != candidate["source"]:
        raise approval.ApprovalRefused("Stage is not bound to approved source")
    original = stage._read_private(state / stage_id / "original.bin",
                                   max_size=stage.MAX_SOURCE_BYTES)
    proposal = stage._read_private(state / stage_id / "proposed.bin",
                                   max_size=stage.MAX_SOURCE_BYTES)
    if (record["before_sha256"] != _sha(original)
            or record["proposed_sha256"] != _sha(proposal)
            or candidate["file_sha256"] != _sha(original)):
        raise approval.ApprovalRefused("Invalid protected shared-file bytes")
    for from_key, to_key in (
        ("device", "file_device"), ("inode", "file_inode"),
        ("mode", "file_mode"), ("uid", "file_uid"), ("gid", "file_gid"),
        ("mtime_ns", "file_mtime_ns"), ("ctime_ns", "file_ctime_ns")
    ):
        if record["metadata"].get(from_key) != candidate[to_key]:
            raise approval.ApprovalRefused("Protected source metadata mismatch")
    try:
        original_entries = boundaries.boundaries(candidate["source"], original)
    except boundaries.EntryRefused as exc:
        raise approval.ApprovalRefused("Invalid staged original source") from exc
    matching = [entry for entry in original_entries
                if entry["sha256"] == candidate["entry_sha256"]
                and entry["kind"] == candidate["kind"]
                and entry["key"] == candidate["entry_key"]
                and entry["start"] == candidate["entry_start"]
                and entry["end"] == candidate["entry_end"]
                and entry["structure_subset_pass"]]
    if len(matching) != 1:
        raise approval.ApprovalRefused("Staged target entry no longer unique")
    target = matching[0]
    new_uri = approval._replacement_url(new_https_url)
    transformed = approval._change_entry(
        candidate["source"], candidate["kind"],
        original[target["start"]:target["end"]], new_uri)
    expected = (original[:target["start"]] + transformed +
                original[target["end"]:])
    if expected != proposal or expected == original:
        raise approval.ApprovalRefused("Stage proposes unapproved shared-file changes")
    try:
        changed_entries = boundaries.boundaries(candidate["source"], proposal)
    except boundaries.EntryRefused as exc:
        raise approval.ApprovalRefused("Stage changes source entry boundaries") from exc
    if len(changed_entries) != len(original_entries):
        raise approval.ApprovalRefused("Stage changes the number of repository entries")
    for old, new in zip(original_entries, changed_entries):
        if old is target:
            if (old["kind"] != new["kind"] or old["key"] != new["key"]
                    or not new["structure_subset_pass"]):
                raise approval.ApprovalRefused("Stage changes selected entry policy")
        elif (old["sha256"] != new["sha256"]
              or old["kind"] != new["kind"]
              or old["key"] != new["key"]):
            raise approval.ApprovalRefused("Stage modifies another repository entry")
    # The atomic lab itself verifies exact source inode, content, mode,
    # pending intent and source drift under its private transaction lock.
    # This outer snapshot check does NOT solve equal-UID rename races.
    if not rollback:
        approval._snapshot(root, candidate)
        if stage.inspect(root, stage_id)["status"] != "prepared":
            raise approval.ApprovalRefused("Shared source drifted before sandbox apply")
    return stage, atomic


def apply_entry_sandbox(root: Path, candidate_id: str,
                        stage_id: str, new_https_url: str) -> dict:
    """Replace one approved entry's URL atomically, TEST SANDBOX ONLY."""
    _, atomic = _verify(Path(root), candidate_id, stage_id,
                        new_https_url, rollback=False)
    done = atomic.apply_sandbox(Path(root), stage_id)
    if done.get("status") != "installed":
        raise approval.ApprovalRefused("Unexpected sandbox atomic apply result")
    return {"state": "installed", "stage_id": stage_id,
            "candidate_id": candidate_id, "production_write_eligible": False}


def rollback_entry_sandbox(root: Path, candidate_id: str,
                           stage_id: str, new_https_url: str) -> dict:
    """Restore entire original shared file ONLY if unchanged since our apply."""
    _, atomic = _verify(Path(root), candidate_id, stage_id,
                        new_https_url, rollback=True)
    done = atomic.rollback_sandbox(Path(root), stage_id)
    if done.get("status") != "restored":
        raise approval.ApprovalRefused("Unexpected sandbox rollback result")
    return {"state": "restored", "stage_id": stage_id,
            "candidate_id": candidate_id, "production_write_eligible": False}


def recover_entry_sandbox(root: Path, candidate_id: str,
                          stage_id: str, new_https_url: str) -> dict:
    """Attempt #132's bounded recovery only for the verified exact stage."""
    _, atomic = _verify(Path(root), candidate_id, stage_id,
                        new_https_url, rollback=True)
    outcome = atomic.recover_sandbox(Path(root), stage_id)
    return {"state": outcome["status"], "stage_id": stage_id,
            "candidate_id": candidate_id, "production_write_eligible": False}
