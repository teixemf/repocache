"""Candidate managed-ID registry and conservative source structure tests.

No test modifies real APT/DNF source files; candidate registry writes ONLY
private marked /tmp fixtures. Candidate IDs do NOT authorize source updates.
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
subset = importlib.import_module("source_structure_subset")
registry = importlib.import_module("managed_registry_sandbox")

APT = "etc/apt/sources.list.d/fixture.list"
DEB822 = "etc/apt/sources.list.d/fixture.sources"
DNF = "etc/yum.repos.d/fixture.repo"
APT_SOURCE = b"deb [arch=amd64 signed-by=/etc/apt/keyrings/fixture.gpg] https://deb.debian.org/debian trixie main\n"
DEB822_SOURCE = (b"Types: deb\nURIs: https://deb.debian.org/debian\n"
                 b"Suites: trixie\nComponents: main\n"
                 b"Signed-By: /etc/apt/keyrings/fixture.gpg\n")
DNF_SOURCE = (b"[fixture]\nname=Fixture\n"
              b"baseurl=https://repo.almalinux.org/almalinux/10/BaseOS/x86_64/os/\n"
              b"enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n")


@pytest.fixture
def root(tmp_path):
    tmp_path.chmod(0o700)
    marker = tmp_path / pre.MARKER
    marker.write_bytes(pre.TEST_MAGIC)
    marker.chmod(0o600)
    for rel, data in ((APT, APT_SOURCE), (DEB822, DEB822_SOURCE), (DNF, DNF_SOURCE)):
        file = tmp_path / rel
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)
    return tmp_path


def digest(data):
    return hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("relative,data,family", [
    (APT, APT_SOURCE, "apt-list"),
    (DEB822, DEB822_SOURCE, "apt-deb822"),
    (DNF, DNF_SOURCE, "dnf-repo"),
])
def test_structure_subset_is_explicitly_not_semantic_trust(relative, data, family):
    result = subset.inspect_structure(relative, data)
    assert result["format"] == family
    assert result["source_entries"] == 1
    assert result["structure_subset_pass"] is True
    assert result["native_syntax_verified"] is False
    assert result["repository_signature_verified"] is False
    assert result["fallback_verified"] is False
    assert result["write_eligible"] is False


@pytest.mark.parametrize("relative,data", [
    (APT, b"deb https://user:secret@deb.example.org/repo trixie main\n"),
    (APT, b"deb https://repo.example.org/repo trixie main\n"
          b"deb https://another.example.org/repo trixie main\n"),
    (APT, b"# All entries are disabled\n"),
    (APT, b"deb https://example.org/repo trixie main # inline not reviewed\n"),
    (APT, b"deb [trusted=yes] https://example.org/repo trixie main\n"),
    (APT, b"deb [arch=amd64] file:///mnt/repo trixie main\n"),
    (DEB822, b"Types: deb\nURIs: https://example.org/deb\n"
             b"Suites: trixie\nComponents: main\nEnabled: no\n"),
    (DEB822, b"Types: deb\nURIs: https://one.invalid/ https://two.invalid/\n"
             b"Suites: trixie\nComponents: main\n"),
    (DEB822, b"Types: deb\nTypes: deb-src\nURIs: https://example.org/repo\n"
             b"Suites: trixie\nComponents: main\n"),
    (DEB822, b"Types: deb\nURIs: https://example.org/repo\n"
             b"Suites: trixie\nComponents: main\n\n"
             b"Types: deb\nURIs: https://example.org/repo2\n"
             b"Suites: trixie\nComponents: main\n"),
    (DNF, b"[fixture]\nbaseurl=https://example.org/repo/\ngpgcheck=0\n"),
    (DNF, b"[fixture]\nbaseurl=https://example.org/repo/\ngpgcheck=1\n"
          b"[second]\nbaseurl=https://other.invalid/\ngpgcheck=1\n"),
    (DNF, b"[fixture]\nmirrorlist=https://example.org/list\n"
          b"gpgcheck=1\n"),
    (DNF, b"[fixture]\nbaseurl=https://user:secret@example.org/repo\n"
          b"gpgcheck=1\n"),
    (DNF, b"[fixture]\nbaseurl=https://example.org/repo\n"
          b"gpgcheck=1\nrepo_gpgcheck=0\n"),
    (DNF, b"[fixture]\nbaseurl=https://example.org/repo\n"
          b"gpgcheck=1\nbaseurl=https://other.invalid/repo\n"),
])
def test_uncertain_or_unsafe_syntax_is_refused(relative, data):
    with pytest.raises(subset.StructureRefused):
        subset.inspect_structure(relative, data)


def test_registration_creates_protected_candidate_and_preserves_source(root):
    before = (root / APT).stat()
    result = registry.register_candidate_sandbox(root, APT, digest(APT_SOURCE))
    assert result["state"] == "candidate"
    assert len(result["id"]) == 32
    assert result["ownership_granted"] is False
    assert result["write_eligible"] is False
    stored = root / "var/lib/repocache-client/managed-candidates-lab" / (
        "candidate-" + result["id"] + ".json")
    state = json.loads(stored.read_text())
    assert state["managed_id"] == result["id"]
    assert state["source"] == APT
    assert state["source_sha256"] == digest(APT_SOURCE)
    assert state["ownership_granted"] is False
    assert state["write_eligible"] is False
    assert state["source_format"] == "apt-list"
    assert "deb.debian.org" not in stored.read_text()
    assert stat.S_IMODE(stored.stat().st_mode) == 0o600
    assert stat.S_IMODE(stored.parent.stat().st_mode) == 0o700
    assert registry.inspect_candidate_sandbox(root, result["id"]) == {
        "id": result["id"], "state": "intact",
        "ownership_granted": False, "write_eligible": False,
        "native_syntax_verified": False,
        "package_signatures_verified": False,
        "upstream_fallback_verified": False,
    }
    assert (root / APT).read_bytes() == APT_SOURCE
    assert (root / APT).stat().st_ino == before.st_ino


def test_distinct_candidate_ids_are_not_discovery_hashes_or_path_positions(root):
    ids = [registry.register_candidate_sandbox(root, rel, digest(data))["id"]
           for rel, data in ((APT, APT_SOURCE), (DEB822, DEB822_SOURCE), (DNF, DNF_SOURCE))]
    assert len(set(ids)) == 3
    assert all(registry.HEX_ID.fullmatch(ident) for ident in ids)
    assert not any(ident in rel for ident in ids for rel in (APT, DEB822, DNF))


def test_duplicate_registration_does_not_overwrite_original_candidate(root):
    ident = registry.register_candidate_sandbox(root, APT, digest(APT_SOURCE))["id"]
    state = root / "var/lib/repocache-client/managed-candidates-lab" / (
        "candidate-" + ident + ".json")
    original = state.read_bytes()
    with pytest.raises(registry.RegistryRefused, match="pending candidate"):
        registry.register_candidate_sandbox(root, APT, digest(APT_SOURCE))
    assert state.read_bytes() == original
    assert registry.inspect_candidate_sandbox(root, ident)["state"] == "intact"


def test_wrong_expected_digest_fails_before_creating_any_registry(root):
    with pytest.raises(registry.RegistryRefused, match="baseline"):
        registry.register_candidate_sandbox(root, APT, "0" * 64)
    assert not (root / "var/lib").exists()


@pytest.mark.parametrize("mutation", ["content", "inode", "permissions", "deleted"])
def test_external_source_drift_never_updates_candidate(root, mutation):
    ident = registry.register_candidate_sandbox(root, APT, digest(APT_SOURCE))["id"]
    source = root / APT
    if mutation == "content":
        source.write_bytes(b"deb https://operator.invalid/repo trixie main\n")
    elif mutation == "inode":
        other = source.with_suffix(".new")
        other.write_bytes(APT_SOURCE)
        os.replace(other, source)
    elif mutation == "permissions":
        source.chmod(0o600)
    else:
        source.unlink()
    assert registry.inspect_candidate_sandbox(root, ident)["state"] == "drift"
    assert registry.inspect_candidate_sandbox(root, ident)["ownership_granted"] is False


def test_invalid_syntax_refused_without_state_creation(root):
    (root / APT).write_bytes(b"deb https://user:secret@example.org/repo trixie main\n")
    with pytest.raises(registry.RegistryRefused, match="validated candidate subset"):
        registry.register_candidate_sandbox(
            root, APT, digest((root / APT).read_bytes()))
    assert not (root / "var/lib").exists()


@pytest.mark.parametrize("mutation", ("unknown", "symlink", "world-writable", "corrupt", "grant"))
def test_corrupt_or_malicious_registry_state_fails_closed(root, mutation):
    ident = registry.register_candidate_sandbox(root, APT, digest(APT_SOURCE))["id"]
    state_dir = root / "var/lib/repocache-client/managed-candidates-lab"
    record = state_dir / ("candidate-" + ident + ".json")
    if mutation == "unknown":
        (state_dir / ".pending-orphan").write_text("abandoned")
    elif mutation == "symlink":
        record.unlink()
        record.symlink_to(root / APT)
    elif mutation == "world-writable":
        record.chmod(0o666)
    elif mutation == "corrupt":
        record.write_text('{"schema": 1}')
    else:
        obj = json.loads(record.read_text())
        obj["ownership_granted"] = True
        record.write_text(json.dumps(obj))
    with pytest.raises(registry.RegistryRefused):
        registry.inspect_candidate_sandbox(root, ident)
    assert (root / APT).read_bytes() == APT_SOURCE


def test_state_parent_symlink_is_refused(root):
    ident = registry.register_candidate_sandbox(root, APT, digest(APT_SOURCE))["id"]
    state = root / "var/lib/repocache-client"
    state.rename(root / "var/lib/actual-private")
    state.symlink_to(root / "var/lib/actual-private")
    with pytest.raises(registry.RegistryRefused):
        registry.inspect_candidate_sandbox(root, ident)


def test_lock_contention_is_fail_fast(root):
    ident = registry.register_candidate_sandbox(root, APT, digest(APT_SOURCE))["id"]
    with registry._registry_fd(root, create=False) as fd:
        with registry._lock(fd):
            with pytest.raises(registry.RegistryBusy):
                registry.inspect_candidate_sandbox(root, ident)


def test_xattr_presence_is_not_silently_treated_as_authority(root):
    path = root / APT
    try:
        os.setxattr(path, "user.synthetic-secret", b"do-not-log")
    except OSError:
        pytest.skip("Filesystem lacks user xattrs")
    ident = registry.register_candidate_sandbox(root, APT, digest(APT_SOURCE))["id"]
    status = registry.inspect_candidate_sandbox(root, ident)
    assert status["state"] == "intact"
    assert status["write_eligible"] is False
    obj = (root / "var/lib/repocache-client/managed-candidates-lab" /
           ("candidate-" + ident + ".json")).read_text()
    assert "do-not-log" not in obj
    assert "user.synthetic-secret" not in obj


def test_unmarked_test_root_refused_without_touching_source(root):
    (root / pre.MARKER).unlink()
    with pytest.raises(registry.RegistryRefused):
        registry.register_candidate_sandbox(root, APT, digest(APT_SOURCE))
    assert (root / APT).read_bytes() == APT_SOURCE



@pytest.mark.parametrize("relative,data", [
    ("../etc/apt/sources.list.d/fixture.list", APT_SOURCE),
    ("/etc/apt/sources.list.d/fixture.list", APT_SOURCE),
    ("etc/yum.repos.d/../../shadow.repo", DNF_SOURCE),
    ("etc/apt/sources.list.d/nonexistent.conf", APT_SOURCE),
    ("etc/apt/sources.list.d/subdir/file.sources", DEB822_SOURCE),
])
def test_pure_structure_validator_rejects_unapproved_paths(relative, data):
    with pytest.raises(subset.StructureRefused, match="allowlist"):
        subset.inspect_structure(relative, data)


@pytest.mark.parametrize("relative,data", [
    (APT, b"deb https://example.org/debian ../ main\n"),
    (APT, b"deb https://example.org/debian a/../b main\n"),
    (DEB822, b"Types: deb\nURIs: https://example.org/debian\n"
             b"Suites: ../\nComponents: main\n"),
])
def test_structure_validator_rejects_ambiguous_suite_paths(relative, data):
    with pytest.raises(subset.StructureRefused):
        subset.inspect_structure(relative, data)
