"""Non-authoritative, protected PER-ENTRY candidates for mixed APT/DNF files.

The only writes are private candidate metadata in explicitly marked /tmp
fixtures. No public client CLI, edit permissions or source-file replacement.
Any change to the enclosing file blocks a future file-level commit, even
when the selected entry bytes still match exactly.

Candidate identity is random, not a parser ordinal or upstream URL.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from pathlib import Path

import managed_registry_sandbox as registry
import source_entry_boundaries as segment
import source_preflight as pre


MAX_RECORDS = 128
MAX_DOC = 4096
PREFIX = "entry-"
DIRECTORY = "entry-candidates-lab"


def _read_entries(root: Path, relative: str):
    try:
        before = pre.inspect_source(relative, root=root)
        body = registry._source_bytes(root, relative, before)
        found = segment.boundaries(relative, body)
        after = pre.inspect_source(relative, root=root)
    except (pre.PreflightError, registry.RegistryRefused,
            segment.EntryRefused, OSError, ValueError) as exc:
        raise registry.RegistryRefused("Cannot safely inspect repository entries") from exc
    if before != after:
        raise registry.RegistryRefused("Source changed during entry inspection")
    return before, found


def _name(ident: str) -> str:
    if not isinstance(ident, str) or not registry.HEX_ID.fullmatch(ident):
        raise registry.RegistryRefused("Invalid entry candidate identifier")
    return PREFIX + ident + ".json"


def _parse(raw: bytes, name: str):
    try:
        record = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise registry.RegistryRefused("Invalid entry candidate metadata") from exc
    fields = {
        "schema", "id", "source", "kind", "entry_sha256", "entry_key",
        "entry_start", "entry_end", "file_sha256", "file_device",
        "file_inode", "file_mode", "file_uid", "file_gid",
        "file_mtime_ns", "file_ctime_ns", "xattrs_present",
        "state", "ownership_granted", "write_eligible",
    }
    if (type(record) is not dict or set(record) != fields
            or type(record["schema"]) is not int or record["schema"] != 1
            or type(record["id"]) is not str or _name(record["id"]) != name
            or type(record["source"]) is not str
            or not pre.SOURCE_PATH.fullmatch(record["source"])
            or record["source"].startswith("etc/apt/mirrors/")
            or record["kind"] not in {"apt-list", "apt-deb822", "dnf-repo"}
            or type(record["entry_sha256"]) is not str
            or not registry.DIGEST.fullmatch(record["entry_sha256"])
            or type(record["file_sha256"]) is not str
            or not registry.DIGEST.fullmatch(record["file_sha256"])
            or type(record["entry_key"]) is not str or len(record["entry_key"]) > 128
            or any(type(record[key]) is not int or record[key] < 0 for key in (
                "entry_start", "entry_end", "file_device", "file_inode",
                "file_mode", "file_uid", "file_gid", "file_mtime_ns",
                "file_ctime_ns"))
            or record["entry_end"] <= record["entry_start"]
            or type(record["xattrs_present"]) is not bool
            or record["state"] != "candidate"
            or record["ownership_granted"] is not False
            or record["write_eligible"] is not False):
        raise registry.RegistryRefused("Invalid entry candidate schema")
    return record


def _all(fd):
    entries = []
    for name in os.listdir(fd):
        if name == registry.LOCK_NAME:
            continue
        if not name.startswith(PREFIX) or not name.endswith(".json"):
            raise registry.RegistryRefused("Unrecognized or interrupted entry candidate state")
        if len(entries) >= MAX_RECORDS:
            raise registry.RegistryRefused("Entry candidate registry capacity exceeded")
        entries.append(_parse(registry._read_private(fd, name), name))
    identities = {(e["source"], e["entry_sha256"]) for e in entries}
    if len(identities) != len(entries):
        raise registry.RegistryRefused("Duplicate entry candidates are ambiguous")
    return entries


def _save(fd, record):
    name = _name(record["id"])
    raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_DOC:
        raise registry.RegistryRefused("Entry candidate exceeds private state bound")
    temporary = ".entry-pending-" + record["id"]
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as dest:
            dest.write(raw)
            dest.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise registry.RegistryRefused("Entry candidate ID collision")
    os.rename(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
    os.fsync(fd)


def register_entry_candidate_sandbox(root: Path, relative: str,
                                     expected_file_sha256: str,
                                     chosen_entry_sha256: str) -> dict:
    """Stage one explicit, unique, structurally recognized entry candidate.

    No approval or native repo file write results from this operation.
    """
    if (type(relative) is not str or not pre.SOURCE_PATH.fullmatch(relative)
            or not isinstance(expected_file_sha256, str)
            or not registry.DIGEST.fullmatch(expected_file_sha256)
            or not isinstance(chosen_entry_sha256, str)
            or not registry.DIGEST.fullmatch(chosen_entry_sha256)):
        raise registry.RegistryRefused("Invalid entry candidate request")
    # Gate before opening even a native /etc filename, without requiring an
    # unrelated whole-file candidate registry to exist.
    try:
        root_fd = os.open(root, pre.DIR_FLAGS)
        try:
            pre._fixture(Path(root), root_fd, os.geteuid())
        finally:
            os.close(root_fd)
    except (OSError, pre.PreflightError) as exc:
        raise registry.RegistryRefused("Invalid private entry candidate fixture") from exc
    observed, items = _read_entries(Path(root), relative)
    if observed["sha256"] != expected_file_sha256:
        raise registry.RegistryRefused("File baseline mismatch")
    matches = [x for x in items if x["sha256"] == chosen_entry_sha256]
    if len(matches) != 1 or not matches[0]["structure_subset_pass"]:
        raise registry.RegistryRefused("Entry is ambiguous or unsupported")
    chosen = matches[0]
    with registry._registry_fd(root, create=True, subdir=DIRECTORY) as fd:
        with registry._lock(fd):
            existing = _all(fd)
            if any(x["source"] == relative and
                   (x["entry_sha256"] == chosen_entry_sha256
                    or (x["entry_key"] and x["entry_key"] == chosen["key"]))
                   for x in existing):
                raise registry.RegistryRefused("Entry already has a candidate")
            fresh, options = _read_entries(Path(root), relative)
            current = [x for x in options if x["sha256"] == chosen_entry_sha256]
            if (fresh != observed or len(current) != 1 or current[0] != chosen):
                raise registry.RegistryRefused("Entry changed before candidate registration")
            ident = secrets.token_hex(16)
            record = {
                "schema": 1, "id": ident, "source": relative,
                "kind": chosen["kind"], "entry_sha256": chosen_entry_sha256,
                "entry_key": chosen["key"],
                "entry_start": chosen["start"], "entry_end": chosen["end"],
                "file_sha256": observed["sha256"],
                "file_device": observed["device"], "file_inode": observed["inode"],
                "file_mode": observed["mode"], "file_uid": observed["uid"],
                "file_gid": observed["gid"],
                "file_mtime_ns": observed["mtime_ns"],
                "file_ctime_ns": observed["ctime_ns"],
                "xattrs_present": observed["extended_attributes_present"],
                "state": "candidate", "ownership_granted": False,
                "write_eligible": False,
            }
            _save(fd, record)
            return {"id": ident, "state": "candidate",
                    "ownership_granted": False, "write_eligible": False}


def inspect_entry_candidate_sandbox(root: Path, ident: str) -> dict:
    """Distinguish entry drift from shared-file drift; never rebaseline."""
    target = _name(ident)
    with registry._registry_fd(root, create=False, subdir=DIRECTORY) as fd:
        with registry._lock(fd):
            entries = _all(fd)
            record = next((x for x in entries if x["id"] == ident), None)
            if record is None or _name(record["id"]) != target:
                raise registry.RegistryRefused("Unknown entry candidate")
            try:
                current_file, candidates = _read_entries(Path(root), record["source"])
            except registry.RegistryRefused:
                return _result(ident, "conflict", False, False)
            same = [x for x in candidates if
                    x["sha256"] == record["entry_sha256"]
                    and x["kind"] == record["kind"]
                    and x["key"] == record["entry_key"]]
            if len(same) != 1:
                return _result(ident, "entry-drift", False, False)
            same_file = (
                current_file["sha256"] == record["file_sha256"]
                and current_file["device"] == record["file_device"]
                and current_file["inode"] == record["file_inode"]
                and current_file["mode"] == record["file_mode"]
                and current_file["uid"] == record["file_uid"]
                and current_file["gid"] == record["file_gid"]
                and current_file["mtime_ns"] == record["file_mtime_ns"]
                and current_file["ctime_ns"] == record["file_ctime_ns"]
                and current_file["extended_attributes_present"] == record["xattrs_present"]
            )
            exact_span = (same[0]["start"] == record["entry_start"]
                          and same[0]["end"] == record["entry_end"])
            if same_file and exact_span:
                return _result(ident, "intact", True, True)
            # Exact entry is still present, but another section or its
            # position/file inode changed. File-scoped commit must refuse.
            return _result(ident, "file-drift", True, False)


def _result(ident, state, entry_intact, file_intact):
    return {
        "id": ident, "state": state,
        "entry_intact": entry_intact, "file_intact": file_intact,
        "ownership_granted": False, "write_eligible": False,
        "native_syntax_verified": False,
        "package_signatures_verified": False,
        "upstream_fallback_verified": False,
    }
