"""Entry approval and sibling byte preservation — pure tests, no source writes.

Positive root-only approval is exercised with real UID 0 in disposable
Debian 13/AlmaLinux 10 Docker CI; ordinary unprivileged pytest cannot mint
approval by mocking credentials.
"""
from __future__ import annotations

import hashlib
import importlib
import os
from pathlib import Path
import sys

import pytest

CLIENT = Path(__file__).resolve().parents[1] / "client"
sys.path.insert(0, str(CLIENT))
approval = importlib.import_module("entry_approval_plan_sandbox")
candidate = importlib.import_module("entry_candidate_sandbox")
pre = importlib.import_module("source_preflight")
registry = importlib.import_module("managed_registry_sandbox")
boundaries = importlib.import_module("source_entry_boundaries")

APT = "etc/apt/sources.list.d/hosts.list"
DEB822 = "etc/apt/sources.list.d/hosts.sources"
DNF = "etc/yum.repos.d/hosts.repo"
APT_DATA = (
    b"# Ansible-managed; do not change\n"
    b"deb [signed-by=/etc/apt/keyrings/test.gpg] https://one.invalid/deb trixie main\n"
    b"deb https://two.invalid/deb trixie main\n"
)
DEB822_DATA = (
    b"Types: deb\nURIs: https://one.invalid/deb\nSuites: trixie\n"
    b"Components: main\nSigned-By: /etc/apt/keyrings/test.gpg\n\n"
    b"Types: deb\nURIs: https://two.invalid/deb\nSuites: trixie\nComponents: main\n"
)
DNF_DATA = (
    b"[base]\nbaseurl=https://one.invalid/repo\n"
    b"enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n\n"
    b"[operator]\nbaseurl=https://two.invalid/repo\n"
    b"enabled=1\ngpgcheck=1\n"
)
CASES = ((APT, APT_DATA), (DEB822, DEB822_DATA), (DNF, DNF_DATA))


@pytest.fixture()
def root(tmp_path):
    tmp_path.chmod(0o700)
    marker = tmp_path / pre.MARKER
    marker.write_bytes(pre.TEST_MAGIC)
    marker.chmod(0o600)
    for rel, body in CASES:
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    return tmp_path


def digest(contents):
    return hashlib.sha256(contents).hexdigest()


def register(root, path, data):
    first = boundaries.boundaries(path, data)[0]
    return candidate.register_entry_candidate_sandbox(
        root, path, digest(data), first["sha256"])["id"]


@pytest.mark.parametrize("path,data", CASES)
def test_url_only_replacement_preserves_existing_options_and_grammar(path, data):
    selected = boundaries.boundaries(path, data)[0]
    original = data[selected["start"]:selected["end"]]
    changed = approval._change_entry(
        path, selected["kind"], original, b"https://cache.invalid/repo/")
    assert changed != original
    assert b"https://cache.invalid/repo/" in changed
    if path == APT:
        assert b"signed-by=/etc/apt/keyrings/test.gpg" in changed
    if path == DEB822:
        assert b"Signed-By: /etc/apt/keyrings/test.gpg" in changed
    if path == DNF:
        assert b"gpgcheck=1\nrepo_gpgcheck=1" in changed
    proposed = data[:selected["start"]] + changed + data[selected["end"]:]
    original_bounds = boundaries.boundaries(path, data)
    after_bounds = boundaries.boundaries(path, proposed)
    assert len(original_bounds) == len(after_bounds) == 2
    assert after_bounds[1]["sha256"] == original_bounds[1]["sha256"]
    assert all(not item["write_eligible"] for item in after_bounds)


@pytest.mark.parametrize("uri", [
    "http://example.org/repo", "https://user:secret@example.org/repo",
    "https://example.org/../other", "https://example.org/%2e%2e/other",
    "https://example.org/repo?token=secret", "https://example.org/repo#fragment",
    "https://example.org/repo\n[malicious]", "file:///etc/passwd",
    "HTTPS://example.org/repo", "https://example.org/\u202e",
])
def test_unknown_or_unsafe_proposed_url_is_refused(uri):
    with pytest.raises(approval.ApprovalRefused):
        approval._replacement_url(uri)


@pytest.mark.parametrize("path,data", CASES)
def test_non_root_cannot_create_explicit_approval(root, monkeypatch, path, data):
    ident = register(root, path, data)
    # A genuine non-root refusal: do not forge root to mint approval.
    monkeypatch.setattr(approval.os, "geteuid", lambda: 65534)
    with pytest.raises(approval.ApprovalRefused, match="Root"):
        approval.approve_entry_plan_sandbox(
            root, ident, digest(data),
            boundaries.boundaries(path, data)[0]["sha256"])
    assert (root / path).read_bytes() == data
    assert not (root / "var/lib/repocache-client/entry-approvals-lab").exists()


def test_non_root_cannot_bypass_approval_using_only_candidate(root):
    ident = register(root, APT, APT_DATA)
    with pytest.raises(registry.RegistryRefused):
        approval.preview_entry_change_sandbox(
            root, ident, "https://cache.invalid/repo/")
    assert (root / APT).read_bytes() == APT_DATA


def test_rootless_fixture_cannot_grant_source_write_capability(root):
    ident = register(root, DEB822, DEB822_DATA)
    item = candidate.inspect_entry_candidate_sandbox(root, ident)
    assert item["ownership_granted"] is False
    assert item["write_eligible"] is False


def test_approval_schema_never_accepts_production_authority():
    ident = "a" * 32
    doc = {
        "schema": 1, "candidate_id": ident,
        "source_file_sha256": "b" * 64,
        "source_entry_sha256": "c" * 64,
        "decision": "approve-entry-plan", "approver_euid": 0,
        "scope": "sandbox-only", "production_write_eligible": False,
    }
    import json
    raw = json.dumps(doc).encode()
    assert approval._parse_approval("approval-" + ident + ".json", raw) == doc
    for key, value in (
        ("approver_euid", 1001),
        ("scope", "production"),
        ("production_write_eligible", True),
        ("decision", "commit"),
    ):
        wrong = dict(doc, **{key: value})
        with pytest.raises(approval.ApprovalRefused):
            approval._parse_approval("approval-" + ident + ".json",
                                     json.dumps(wrong).encode())


def test_refuse_nonstandard_invalid_repository_entries():
    with pytest.raises(approval.ApprovalRefused):
        approval._change_entry(
            APT, "apt-list",
            b"deb [trusted=yes] https://one.invalid/repo trixie main\n",
            b"https://cache.invalid/new")
    with pytest.raises(approval.ApprovalRefused):
        approval._change_entry(
            DNF, "dnf-repo",
            b"[repo]\nbaseurl=https://one.invalid/repo\ngpgcheck=0\n",
            b"https://cache.invalid/new")


def test_new_url_not_exposed_from_unapproved_registry(root):
    ident = register(root, APT, APT_DATA)
    with pytest.raises(registry.RegistryRefused):
        approval.preview_entry_change_sandbox(
            root, ident, "https://user:secret@cache.invalid/repo")
    assert (root / APT).read_bytes() == APT_DATA



def test_forged_sandbox_approval_cannot_be_consumed_as_non_root(
        root, monkeypatch):
    """A valid-looking local JSON file must not replace OS authorization."""
    import json
    ident = register(root, APT, APT_DATA)
    with registry._registry_fd(root, create=True,
                               subdir=approval.APPROVAL_DIR):
        pass
    directory = root / "var/lib/repocache-client" / approval.APPROVAL_DIR
    record = {
        "schema": 1, "candidate_id": ident,
        "source_file_sha256": digest(APT_DATA),
        "source_entry_sha256": boundaries.boundaries(APT, APT_DATA)[0]["sha256"],
        "decision": "approve-entry-plan", "approver_euid": 0,
        "scope": "sandbox-only", "production_write_eligible": False,
    }
    forged = directory / ("approval-" + ident + ".json")
    forged.write_text(json.dumps(record))
    forged.chmod(0o600)
    monkeypatch.setattr(approval.os, "geteuid", lambda: 65534)
    with pytest.raises(approval.ApprovalRefused, match="Root required"):
        approval.preview_entry_change_sandbox(
            root, ident, "https://cache.invalid/repo/")
    assert (root / APT).read_bytes() == APT_DATA
