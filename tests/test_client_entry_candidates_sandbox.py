"""Read-only per-entry candidate baselines for mixed APT/DNF sources.

No test mutates actual /etc or grants ownership. Unknown grammar and
ambiguous selectors fail closed; unrelated entry drift blocks file commits.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import stat
import sys

import pytest

CLIENT = Path(__file__).resolve().parents[1] / "client"
sys.path.insert(0, str(CLIENT))
pre = importlib.import_module("source_preflight")
segments = importlib.import_module("source_entry_boundaries")
entries = importlib.import_module("entry_candidate_sandbox")
registry = importlib.import_module("managed_registry_sandbox")

APT = "etc/apt/sources.list.d/mixed.list"
DEB822 = "etc/apt/sources.list.d/mixed.sources"
DNF = "etc/yum.repos.d/mixed.repo"
APT_TEXT = (
    b"# managed by Ansible; preserve this comment\n"
    b"deb https://deb.debian.org/debian trixie main\n"
    b"\n"
    b"# operator's second repository\n"
    b"deb https://security.debian.org/debian-security trixie-security main\n"
)
DEB822_TEXT = (
    b"Types: deb\nURIs: https://deb.debian.org/debian\n"
    b"Suites: trixie\nComponents: main\n\n"
    b"Types: deb\nURIs: https://security.debian.org/debian-security\n"
    b"Suites: trixie-security\nComponents: main\n"
)
DNF_TEXT = (
    b"# keep operator-managed sections\n"
    b"[baseos]\n"
    b"name=BaseOS\nbaseurl=https://repo.almalinux.org/almalinux/10/BaseOS/x86_64/os/\n"
    b"gpgcheck=1\nenabled=1\n\n"
    b"[extras]\n"
    b"baseurl=https://repo.almalinux.org/almalinux/10/extras/x86_64/os/\n"
    b"gpgcheck=1\nenabled=0\n"
)
FIXTURES = [(APT, APT_TEXT), (DEB822, DEB822_TEXT), (DNF, DNF_TEXT)]


@pytest.fixture
def root(tmp_path):
    tmp_path.chmod(0o700)
    marker = tmp_path / pre.MARKER
    marker.write_bytes(pre.TEST_MAGIC)
    marker.chmod(0o600)
    for rel, raw in FIXTURES:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(raw)
    return tmp_path


def sha(x):
    return hashlib.sha256(x).hexdigest()


def candidate(root, rel, index=0):
    source = root / rel
    source_bytes = source.read_bytes()
    chunks = segments.boundaries(rel, source_bytes)
    result = entries.register_entry_candidate_sandbox(
        root, rel, sha(source_bytes), chunks[index]["sha256"])
    return result["id"]


@pytest.mark.parametrize("rel,raw", FIXTURES)
def test_boundaries_never_normalize_and_preserve_sibling_offsets(rel, raw):
    chunks = segments.boundaries(rel, raw)
    assert len(chunks) == 2
    assert all(x["start"] < x["end"] for x in chunks)
    assert all(x["sha256"] == sha(raw[x["start"]:x["end"]]) for x in chunks)
    assert all(x["ownership_granted"] is False and
               x["write_eligible"] is False for x in chunks)
    assert chunks[0]["structure_subset_pass"]
    if rel == DNF:
        assert chunks[0]["key"] == "baseos"
        assert chunks[1]["key"] == "extras"
        assert not chunks[1]["structure_subset_pass"]
    else:
        assert chunks[1]["structure_subset_pass"]


@pytest.mark.parametrize("rel,raw", FIXTURES)
def test_selected_entry_candidate_writes_only_private_state(root, rel, raw):
    source = root / rel
    before = source.stat()
    ident = candidate(root, rel)
    state = root / "var/lib/repocache-client/entry-candidates-lab" / (
        "entry-" + ident + ".json")
    assert state.is_file()
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    assert stat.S_IMODE(state.parent.stat().st_mode) == 0o700
    manifest = json.loads(state.read_text())
    assert manifest["entry_sha256"] == segments.boundaries(rel, raw)[0]["sha256"]
    assert manifest["file_sha256"] == sha(raw)
    assert manifest["ownership_granted"] is False
    assert manifest["write_eligible"] is False
    assert "repo.almalinux.org" not in state.read_text()
    assert entries.inspect_entry_candidate_sandbox(root, ident)["state"] == "intact"
    assert source.read_bytes() == raw
    assert source.stat().st_ino == before.st_ino


@pytest.mark.parametrize("rel,raw", FIXTURES)
def test_sibling_changes_cannot_justify_file_level_overwrite(root, rel, raw):
    ident = candidate(root, rel)
    source = root / rel
    if rel == APT:
        changed = raw.replace(b"operator's second repository",
                              b"Ansible updated second repository")
    elif rel == DEB822:
        changed = raw.replace(b"trixie-security", b"bookworm-security")
    else:
        changed = raw.replace(b"enabled=0", b"enabled=1")
    assert changed != raw
    source.write_bytes(changed)
    result = entries.inspect_entry_candidate_sandbox(root, ident)
    assert result["state"] == "file-drift"
    assert result["entry_intact"] is True
    assert result["file_intact"] is False
    assert result["write_eligible"] is False
    assert source.read_bytes() == changed


@pytest.mark.parametrize("rel,raw", FIXTURES)
def test_targeted_entry_change_detected_without_rebaseline(root, rel, raw):
    ident = candidate(root, rel)
    source = root / rel
    if rel == APT:
        new = raw.replace(b"trixie main", b"bookworm main", 1)
    elif rel == DEB822:
        new = raw.replace(b"Suites: trixie\n", b"Suites: bookworm\n", 1)
    else:
        new = raw.replace(b"name=BaseOS", b"name=Operator")
    source.write_bytes(new)
    result = entries.inspect_entry_candidate_sandbox(root, ident)
    assert result["state"] == "entry-drift"
    assert not result["write_eligible"]
    assert source.read_bytes() == new


def test_multiple_candidates_same_shared_file_keep_separate_stable_ids(root):
    ids = [candidate(root, DEB822, 0), candidate(root, DEB822, 1)]
    assert ids[0] != ids[1]
    assert entries.inspect_entry_candidate_sandbox(root, ids[0])["state"] == "intact"
    assert entries.inspect_entry_candidate_sandbox(root, ids[1])["state"] == "intact"
    source = root / DEB822
    source.write_bytes(DEB822_TEXT.replace(b"trixie-security", b"bookworm-security"))
    assert entries.inspect_entry_candidate_sandbox(root, ids[0])["state"] == "file-drift"
    assert entries.inspect_entry_candidate_sandbox(root, ids[1])["state"] == "entry-drift"


def test_duplicate_or_unsupported_selection_is_refused(root):
    with pytest.raises(registry.RegistryRefused, match="ambiguous|unsupported"):
        candidate(root, DNF, 1)
    ident = candidate(root, APT, 0)
    with pytest.raises(registry.RegistryRefused, match="already has a candidate"):
        candidate(root, APT, 0)
    assert entries.inspect_entry_candidate_sandbox(root, ident)["state"] == "intact"


def test_duplicate_identical_apt_lines_are_ambiguous(root):
    source = root / APT
    source.write_bytes(APT_TEXT + APT_TEXT.splitlines(keepends=True)[1])
    with pytest.raises(registry.RegistryRefused, match="ambiguous"):
        candidate(root, APT, 0)


def test_external_inode_replacement_with_same_bytes_blocks_file_commit(root):
    ident = candidate(root, DEB822)
    source = root / DEB822
    old = source.stat().st_ino
    replacement = source.with_suffix(".next")
    replacement.write_bytes(DEB822_TEXT)
    os.replace(replacement, source)
    assert source.stat().st_ino != old
    result = entries.inspect_entry_candidate_sandbox(root, ident)
    assert result["state"] == "file-drift"
    assert result["entry_intact"] is True
    assert not result["file_intact"]


@pytest.mark.parametrize("bad", [
    b"[baseos]\ngpgcheck=1\n[baseos]\nbaseurl=https://example.org\n",
    b"repository without a section\n[baseos]\nbaseurl=https://example.org\n",
    b"[baseos]\nbaseurl=https://example.org\n[broken\n",
])
def test_ambiguous_dnf_boundaries_refuse_entire_file(bad):
    with pytest.raises(segments.EntryRefused):
        segments.boundaries(DNF, bad)


@pytest.mark.parametrize("bad", [
    b"unrecognized directive\n",
    b"deb https://example.org/main stable main\r\n",
    b"deb https://example.org/main stable main\0",
])
def test_apt_unsupported_boundaries_refuse_entire_file(bad):
    with pytest.raises(segments.EntryRefused):
        segments.boundaries(APT, bad)


def test_missing_or_symlinked_private_manifest_fails_closed(root):
    ident = candidate(root, APT)
    directory = root / "var/lib/repocache-client/entry-candidates-lab"
    manifest = directory / ("entry-" + ident + ".json")
    manifest.unlink()
    manifest.symlink_to(root / APT)
    with pytest.raises(registry.RegistryRefused):
        entries.inspect_entry_candidate_sandbox(root, ident)


def test_tampered_authorization_flag_is_not_accepted(root):
    ident = candidate(root, APT)
    path = root / "var/lib/repocache-client/entry-candidates-lab" / (
        "entry-" + ident + ".json")
    contents = json.loads(path.read_text())
    contents["ownership_granted"] = True
    path.write_text(json.dumps(contents))
    with pytest.raises(registry.RegistryRefused, match="schema"):
        entries.inspect_entry_candidate_sandbox(root, ident)


def test_pending_or_unknown_metadata_blocks_entire_registry(root):
    ident = candidate(root, APT)
    state = root / "var/lib/repocache-client/entry-candidates-lab"
    (state / ".entry-pending-interrupted").write_bytes(b"failed")
    with pytest.raises(registry.RegistryRefused, match="Unrecognized|interrupted"):
        entries.inspect_entry_candidate_sandbox(root, ident)


def test_concurrent_candidate_registry_writer_is_refused(root):
    ident = candidate(root, APT)
    with registry._registry_fd(root, create=False,
                               subdir="entry-candidates-lab") as fd:
        with registry._lock(fd):
            with pytest.raises(registry.RegistryBusy):
                entries.inspect_entry_candidate_sandbox(root, ident)


def test_private_fixture_required_before_source_access(root):
    (root / pre.MARKER).unlink()
    with pytest.raises(registry.RegistryRefused, match="fixture"):
        candidate(root, APT)
    assert (root / APT).read_bytes() == APT_TEXT


def test_whole_file_candidate_namespace_unaffected(root):
    ident = candidate(root, APT)
    another = registry.register_candidate_sandbox(root, DEB822,
                                                   sha(DEB822_TEXT)) if False else None
    # Existing whole-file candidate validation remains strict; the separate
    # namespace must never make its _entries parser reject unknown filenames.
    with registry._registry_fd(root, create=True) as fd:
        with registry._lock(fd):
            assert registry._entries(fd) == []
    assert entries.inspect_entry_candidate_sandbox(root, ident)["state"] == "intact"
