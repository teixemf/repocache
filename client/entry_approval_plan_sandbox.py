"""Explicit root-only *sandbox intent* for selecting one entry in a shared source.

This is not privileged production authorization. Only files under an
explicitly marked, disposable /tmp or /var/tmp fixture are inspected. The
only writes are 0600 private intent records; APT/DNF sources are NEVER
modified, and no installed CLI uses this module.

A write-eligible flag is intentionally never returned or stored as true.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from pathlib import Path
from urllib.parse import urlsplit

import entry_candidate_sandbox as entries
import managed_registry_sandbox as registry
import source_entry_boundaries as segment
import source_preflight as pre
import source_structure_subset as structure

APPROVAL_DIR = "entry-approvals-lab"
APPROVAL_PREFIX = "approval-"
MAX_RECORD = 4096
MAX_URL = 2048


class ApprovalRefused(registry.RegistryRefused):
    """A requested private test-only approval/plan is not safe."""


def _name(ident: str) -> str:
    if not isinstance(ident, str) or not registry.HEX_ID.fullmatch(ident):
        raise ApprovalRefused("Invalid entry identifier")
    return APPROVAL_PREFIX + ident + ".json"


def _candidate(root: Path, ident: str) -> dict:
    with registry._registry_fd(root, create=False,
                               subdir=entries.DIRECTORY) as fd:
        with registry._lock(fd):
            records = entries._all(fd)
            result = next((r for r in records if r["id"] == ident), None)
            if result is None:
                raise ApprovalRefused("Unknown candidate")
            return result


def _snapshot(root: Path, record: dict) -> tuple[dict, list[dict], bytes]:
    """Prove the WHOLE FILE baseline, including metadata, not just entry SHA."""
    observed, chunks = entries._read_entries(root, record["source"])
    keys = {
        "sha256": "file_sha256", "device": "file_device",
        "inode": "file_inode", "mode": "file_mode",
        "uid": "file_uid", "gid": "file_gid",
        "mtime_ns": "file_mtime_ns", "ctime_ns": "file_ctime_ns",
        "extended_attributes_present": "xattrs_present",
    }
    if any(observed[key] != record[field] for key, field in keys.items()):
        raise ApprovalRefused("Shared source baseline changed")
    matched = [x for x in chunks if x["sha256"] == record["entry_sha256"]
               and x["kind"] == record["kind"]
               and x["key"] == record["entry_key"]]
    if (len(matched) != 1 or not matched[0]["structure_subset_pass"]
            or matched[0]["start"] != record["entry_start"]
            or matched[0]["end"] != record["entry_end"]):
        raise ApprovalRefused("Selected entry changed or became ambiguous")
    # registry._source_bytes opens the path by dirfds and verifies inode,
    # stat, and SHA against the independently observed preflight snapshot.
    source = registry._source_bytes(root, record["source"], observed)
    if hashlib.sha256(source).hexdigest() != record["file_sha256"]:
        raise ApprovalRefused("Shared source changed while reading")
    return observed, chunks, source


def _parse_approval(name: str, data: bytes) -> dict:
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise ApprovalRefused("Invalid protected approval") from exc
    required = {"schema", "candidate_id", "source_file_sha256",
                "source_entry_sha256", "decision", "approver_euid",
                "scope", "production_write_eligible"}
    if (type(doc) is not dict or set(doc) != required
            or type(doc["schema"]) is not int or doc["schema"] != 1
            or type(doc["candidate_id"]) is not str
            or _name(doc["candidate_id"]) != name
            or type(doc["source_file_sha256"]) is not str
            or not registry.DIGEST.fullmatch(doc["source_file_sha256"])
            or type(doc["source_entry_sha256"]) is not str
            or not registry.DIGEST.fullmatch(doc["source_entry_sha256"])
            or doc["decision"] != "approve-entry-plan"
            or type(doc["approver_euid"]) is not int
            or doc["approver_euid"] != 0
            or doc["scope"] != "sandbox-only"
            or doc["production_write_eligible"] is not False):
        raise ApprovalRefused("Invalid protected approval schema")
    return doc


def _read_approval(root: Path, ident: str) -> dict:
    # Root-only issuance is insufficient if an unprivileged actor can forge
    # test-state JSON and later have it consumed as an approved decision.
    if os.geteuid() != 0:
        raise ApprovalRefused("Root required to consume sandbox entry approval")
    with registry._registry_fd(root, create=False, subdir=APPROVAL_DIR) as fd:
        with registry._lock(fd):
            found = []
            for name in os.listdir(fd):
                if name == registry.LOCK_NAME:
                    continue
                if not (name.startswith(APPROVAL_PREFIX)
                        and name.endswith(".json")):
                    raise ApprovalRefused("Unknown or interrupted approval state")
                if len(found) >= 128:
                    raise ApprovalRefused("Too many approval records")
                found.append(_parse_approval(
                    name, registry._read_private(fd, name)))
            approved = [item for item in found if item["candidate_id"] == ident]
            if len(approved) != 1:
                raise ApprovalRefused("No unambiguous explicit approval")
            return approved[0]


def approve_entry_plan_sandbox(root: Path, candidate_id: str,
                               expected_file_sha256: str,
                               expected_entry_sha256: str) -> dict:
    """Root-only explicit decision for a specific candidate baseline.

    This creates only a private non-authoritative laboratory record.
    EUID=0 is required for the positive path, even in disposable containers.
    """
    _name(candidate_id)
    if os.geteuid() != 0:
        raise ApprovalRefused("Root is required for explicit sandbox decision")
    if (not isinstance(expected_file_sha256, str)
            or not registry.DIGEST.fullmatch(expected_file_sha256)
            or not isinstance(expected_entry_sha256, str)
            or not registry.DIGEST.fullmatch(expected_entry_sha256)):
        raise ApprovalRefused("Invalid approval preconditions")
    candidate = _candidate(Path(root), candidate_id)
    if (candidate["file_sha256"] != expected_file_sha256
            or candidate["entry_sha256"] != expected_entry_sha256):
        raise ApprovalRefused("Approval differs from candidate baseline")
    _snapshot(Path(root), candidate)
    approval = {
        "schema": 1, "candidate_id": candidate_id,
        "source_file_sha256": expected_file_sha256,
        "source_entry_sha256": expected_entry_sha256,
        "decision": "approve-entry-plan", "approver_euid": 0,
        "scope": "sandbox-only", "production_write_eligible": False,
    }
    with registry._registry_fd(root, create=True, subdir=APPROVAL_DIR) as fd:
        with registry._lock(fd):
            # Unknown, corrupted or partial state always blocks additions.
            prior = [n for n in os.listdir(fd) if n != registry.LOCK_NAME]
            if prior:
                for name in prior:
                    if not name.startswith(APPROVAL_PREFIX) or not name.endswith(".json"):
                        raise ApprovalRefused("Unknown approval state")
                    _parse_approval(name, registry._read_private(fd, name))
            if _name(candidate_id) in prior:
                raise ApprovalRefused("Entry already has explicit approval")
            # Independent final source re-check immediately before writing
            # the private *intent*, not a package-source file.
            if _candidate(Path(root), candidate_id) != candidate:
                raise ApprovalRefused("Candidate changed during approval")
            _snapshot(Path(root), candidate)
            encoded = json.dumps(approval, sort_keys=True,
                                 separators=(",", ":")).encode("utf-8")
            if len(encoded) > MAX_RECORD:
                raise ApprovalRefused("Approval record exceeds size bound")
            name = _name(candidate_id)
            pending = ".approval-pending-" + secrets.token_hex(16)
            out = os.open(pending, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                          | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
            try:
                with os.fdopen(out, "wb", closefd=False) as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(out)
            finally:
                os.close(out)
            # Private approval namespace is locked; use hard-link create
            # (no-replace semantics) rather than overwrite an existing name.
            try:
                os.link(pending, name, src_dir_fd=fd, dst_dir_fd=fd,
                        follow_symlinks=False)
                os.fsync(fd)
                os.unlink(pending, dir_fd=fd)
                os.fsync(fd)
            except FileExistsError as exc:
                raise ApprovalRefused("Approval record already exists") from exc
    return {"id": candidate_id, "decision": "approve-entry-plan",
            "scope": "sandbox-only", "production_write_eligible": False}


def _replacement_url(value: str) -> bytes:
    if (type(value) is not str or len(value) > MAX_URL
            or not value.startswith("https://")
            or any(ord(c) < 33 or ord(c) > 126 for c in value)
            or any(c in value for c in ('"', "'", "\\", "#", "?"))):
        raise ApprovalRefused("Unapproved proposed HTTPS URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ApprovalRefused("Invalid proposed HTTPS URL") from exc
    if (parsed.scheme != "https" or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment or parsed.query
            or (port is not None and port == 0)
            or "%" in value or ".." in parsed.path.split("/")):
        raise ApprovalRefused("Unapproved proposed HTTPS URL")
    return value.encode("ascii")


def _change_entry(relative: str, kind: str, before: bytes, https_url: bytes) -> bytes:
    """Replace exactly the URL token, never package trust/suite/options."""
    if kind == "apt-list":
        try:
            match = structure.APT_LINE.fullmatch(before.decode("utf-8").strip())
        except UnicodeDecodeError as exc:
            raise ApprovalRefused("Unsupported source encoding") from exc
        if not match:
            raise ApprovalRefused("Unrecognized APT line")
        uri = match.group(3).encode("utf-8")
        if before.count(uri) != 1:
            raise ApprovalRefused("Ambiguous APT URI")
        changed = before.replace(uri, https_url, 1)
    elif kind == "apt-deb822":
        regex = re.compile(rb"(?m)^(URIs:[ \t]*)(\S+)([ \t]*)(?=\n|$)")
        spans = list(regex.finditer(before))
        if len(spans) != 1:
            raise ApprovalRefused("Ambiguous deb822 URI field")
        match = spans[0]
        changed = before[:match.start(2)] + https_url + before[match.end(2):]
    elif kind == "dnf-repo":
        regex = re.compile(rb"(?im)^([ \t]*baseurl[ \t]*=[ \t]*)(\S+)([ \t]*)(?=\n|$)")
        spans = list(regex.finditer(before))
        if len(spans) != 1:
            raise ApprovalRefused("Ambiguous DNF baseurl")
        match = spans[0]
        changed = before[:match.start(2)] + https_url + before[match.end(2):]
    else:
        raise ApprovalRefused("Unrecognized repository entry family")
    # Both sides must remain in the deliberately restrictive grammar.
    try:
        if (not structure.inspect_structure(relative, changed)
                ["structure_subset_pass"]):
            raise ApprovalRefused("Replacement outside structural subset")
    except structure.StructureRefused as exc:
        raise ApprovalRefused("Replacement outside structural subset") from exc
    return changed


def _build_plan(root: Path, candidate_id: str, https_url: str) -> dict:
    """Private in-memory plan. Output bytes MUST NOT be used for native writes."""
    _name(candidate_id)
    candidate = _candidate(root, candidate_id)
    approved = _read_approval(root, candidate_id)
    if (approved["source_file_sha256"] != candidate["file_sha256"]
            or approved["source_entry_sha256"] != candidate["entry_sha256"]):
        raise ApprovalRefused("Approval and candidate baseline disagree")
    if candidate["xattrs_present"]:
        # This planner is not a metadata-preservation engine.
        raise ApprovalRefused("Security metadata requires transaction integration")
    observed, chunks, source = _snapshot(root, candidate)
    selected = [item for item in chunks
                if item["sha256"] == candidate["entry_sha256"]
                and item["start"] == candidate["entry_start"]
                and item["end"] == candidate["entry_end"]
                and item["key"] == candidate["entry_key"]]
    if len(selected) != 1:
        raise ApprovalRefused("Ambiguous candidate target")
    old = selected[0]
    uri = _replacement_url(https_url)
    part = source[old["start"]:old["end"]]
    new = _change_entry(candidate["source"], candidate["kind"], part, uri)
    proposed = source[:old["start"]] + new + source[old["end"]:]
    if len(proposed) > pre.MAX_SOURCE_BYTES or proposed == source:
        raise ApprovalRefused("Oversized or ineffective candidate change")
    try:
        recalculated = segment.boundaries(candidate["source"], proposed)
    except segment.EntryRefused as exc:
        raise ApprovalRefused("Proposed shared source has ambiguous boundaries") from exc
    if len(chunks) != len(recalculated):
        raise ApprovalRefused("Proposed edit changes entry count")
    for index, (before, after) in enumerate(zip(chunks, recalculated)):
        if before is old:
            if (not after["structure_subset_pass"]
                    or before["key"] != after["key"]
                    or before["kind"] != after["kind"]):
                raise ApprovalRefused("Selected entry identity or trust fields changed")
        elif (before["sha256"] != after["sha256"]
              or before["kind"] != after["kind"]
              or before["key"] != after["key"]):
            raise ApprovalRefused("Unselected entry was modified")
    # Verify complete source file, including inode and ctime, has not
    # changed since the initial read. This is NOT an atomic write CAS.
    fresh, _, current = _snapshot(root, candidate)
    if observed != fresh or current != source:
        raise ApprovalRefused("Source changed while planning")
    return {
        "candidate_id": candidate_id,
        "source": candidate["source"],
        "original": source,
        "proposed": proposed,
        "original_sha256": hashlib.sha256(source).hexdigest(),
        "proposed_sha256": hashlib.sha256(proposed).hexdigest(),
        "other_entries_preserved": len(chunks) - 1,
        "production_write_eligible": False,
    }


def preview_entry_change_sandbox(root: Path, candidate_id: str,
                                 new_https_url: str) -> dict:
    """Present an approved sandbox-only plan, not source bytes or authority."""
    result = _build_plan(Path(root), candidate_id, new_https_url)
    return {
        "id": result["candidate_id"],
        "state": "planned",
        "original_sha256": result["original_sha256"],
        "proposed_sha256": result["proposed_sha256"],
        "other_entries_preserved": result["other_entries_preserved"],
        "native_syntax_verified": False,
        "signature_trust_verified": False,
        "upstream_fallback_verified": False,
        "production_write_eligible": False,
    }
