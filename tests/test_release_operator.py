"""Security and command-surface tests for workstation Release Operator (#88)."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import zipfile
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "workstation/src"))
from repocache_release import cli as release


def paths():
    def walk(parser, prefix=()):
        out = set()
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, child in action.choices.items():
                    parts = (*prefix, name)
                    out.add(" ".join(parts))
                    out.update(walk(child, parts))
        return out
    return walk(release.build_parser())


def test_registered_release_commands_match_reviewed_architecture_inventory():
    inv = json.loads((ROOT / "tests/cli_surface_inventory.json").read_text())
    assert inv["release_operator"]["status"] == "partial-workstation-only"
    assert paths() == set(inv["release_operator"]["paths"])
    assert {"candidate stage", "candidate publish"} <= paths()
    assert "candidate key" not in paths()
    # Do not accidentally add this maintainer-only tool to production server.
    assert "repocache-release" not in (ROOT / "pyproject.toml").read_text()
    assert (ROOT / "workstation/pyproject.toml").is_file()


@pytest.mark.parametrize("args", [
    [], ["candidate"], ["environment"],
    ["--help"], ["candidate", "--help"], ["candidate", "status", "--help"],
])
def test_help_without_network_key_or_mutation(monkeypatch, capsys, args):
    monkeypatch.setattr(release, "command", lambda *a, **kw: 1 / 0)
    assert release.main(args) == 0
    assert "usage" in capsys.readouterr().out.lower()


def test_json_global_option_before_object_and_after_action_is_identical(monkeypatch, capsys):
    monkeypatch.setattr(release, "status", lambda version, acceptance_run_id=None: {
        "version": version, "acceptance": "NOT VERIFIED",
        "ready_to_publish": False})
    for args in (
        ["--json", "candidate", "status", "v0.5.0"],
        ["candidate", "status", "v0.5.0", "--json"],
    ):
        assert release.main(args) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["ok"] is True
        assert payload["result"]["ready_to_publish"] is False


def test_json_error_is_one_document_with_nonzero_exit(monkeypatch, capsys):
    assert release.main(["--json", "candidate", "unknown"]) == 2
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["ok"] is False
    assert parsed["error"]["code"] == "INVALID_ARGUMENT"
    assert release.main(["candidate", "status", "latest", "--json"]) == 1
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["error"]["code"] == "INVALID_RELEASE"


def test_old_flat_commands_not_registered(capsys):
    for command in ("doctor", "prepare", "sign", "stage", "status", "publish"):
        assert release.main([command, "--json"]) == 2
        assert json.loads(capsys.readouterr().out)["error"]["code"] == "INVALID_ARGUMENT"


def test_reject_unapproved_subprocess_and_github_endpoint():
    with pytest.raises(release.OperatorError, match="Unapproved"):
        release.command(["bash", "-c", "true"])
    with pytest.raises(release.OperatorError, match="Unapproved"):
        release.gh_json("repos/attacker/repo/secrets")


@pytest.mark.parametrize("bad", ["v0.5", "latest", "0.5.0", "v00.5.0", "v0.5.0/../x", "v0.5.0\n"])
def test_release_version_input_strict(bad):
    with pytest.raises(release.OperatorError):
        release.check_tag(bad)


def test_pinned_workflow_identity_rejects_unreviewed_or_ambiguous(monkeypatch):
    def remote(status="ahead", runs=1):
        def fake(endpoint):
            if "/git/ref/tags/" in endpoint:
                return {"ref": "refs/tags/v0.5.0"}
            if "/commits/" in endpoint:
                return {"sha": "a" * 40}
            if "/compare/" in endpoint:
                return {"status": status}
            if "/jobs?" in endpoint:
                return {"total_count": 5, "jobs": [
                    {"name": str(n), "status": "completed", "conclusion": "success"}
                    for n in range(5)]}
            if "/runs?" in endpoint:
                return {"total_count": runs, "workflow_runs": [{
                    "head_sha": "a" * 40, "head_branch": "v0.5.0",
                    "event": "workflow_dispatch", "status": "completed",
                    "conclusion": "success", "actor": {"login": "teixemf"},
                    "id": i + 1, "run_attempt": 1}
                    for i in range(runs)]}
            raise AssertionError(endpoint)
        return fake
    monkeypatch.setattr(release, "gh_json", remote())
    assert release.approved_build("v0.5.0") == ("a" * 40, 1, 1)
    monkeypatch.setattr(release, "gh_json", remote("behind"))
    with pytest.raises(release.OperatorError, match="reviewed main"):
        release.approved_build("v0.5.0")
    monkeypatch.setattr(release, "gh_json", remote("ahead", 2))
    with pytest.raises(release.OperatorError, match="exactly one"):
        release.approved_build("v0.5.0")


def test_unsigned_candidate_checksum_strict_and_no_executed_download(monkeypatch, tmp_path):
    assets = tmp_path / "assets"
    assets.mkdir()
    version = "v0.5.0"
    names = release.files_for(version)
    base = "repocache-v0.5.0.tar.gz"
    (assets / base).write_bytes(b"source")
    (assets / (base + ".wheelhouse.tar.gz")).write_bytes(b"wheels")
    for name in (base, base + ".wheelhouse.tar.gz"):
        (assets / (name + ".sha256")).write_text(
            hashlib.sha256((assets / name).read_bytes()).hexdigest() + "  " + name + "\n")
    called = []
    monkeypatch.setattr(release.subprocess, "run", lambda *a, **kw:
                        called.append(a) or SimpleNamespace(returncode=0))
    release.verify_unsigned(tmp_path, assets, version)
    assert len(called) == 1
    (assets / (base + ".sha256")).write_text("0" * 64 + "  " + base + "\n")
    with pytest.raises(release.OperatorError, match="Checksum|checksum"):
        release.verify_unsigned(tmp_path, assets, version)
    assert len(called) == 1


def test_candidate_state_private_atomic_and_bytes_pinned(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    version = "v0.5.0"
    release.state_root().mkdir(mode=0o700)
    folder = release.candidate_dir(version) / "assets"
    folder.mkdir(parents=True, mode=0o700)
    for name in release.files_for(version):
        (folder / name).write_bytes(name.encode())
    record = {"schema": 1, "version": version, "commit": "a" * 40,
              "run_id": 123, "attempt": 1, "phase": "prepared",
              "assets": {name: release.digest(folder / name)
                         for name in release.files_for(version)}}
    release.save_state(version, record)
    assert stat.S_IMODE(release.state_file(version).stat().st_mode) == 0o600
    assert release.read_state(version) == record
    assert release.verify_state(version, record) == record["assets"]
    (folder / release.files_for(version)[0]).write_bytes(b"tampered")
    with pytest.raises(release.OperatorError, match="bytes"):
        release.verify_state(version, record)


def test_symlinked_state_refused(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    outside = tmp_path / "outsider.json"
    outside.write_text("{}")
    base = release.state_root()
    base.mkdir(mode=0o700)
    release.state_file("v0.5.0").symlink_to(outside)
    with pytest.raises(release.OperatorError, match="symlink"):
        release.read_state("v0.5.0")
    assert outside.read_text() == "{}"


def test_missing_or_invalid_signing_fd_fails_without_prompt():
    for fd in (-1, 0, 1, 2):
        with pytest.raises(release.OperatorError):
            release.read_passphrase(fd)
    r, w = os.pipe()
    try:
        os.write(w, b"a-secret-passphrase\n")
        os.close(w)
        assert release.read_passphrase(r) == b"a-secret-passphrase"
    finally:
        os.close(r)


def test_signing_fd_rejects_controls_and_oversized_secret():
    for password in (b"a\nb", b"\0" * 10, b"x" * 4098):
        r, w = os.pipe()
        try:
            os.write(w, password)
            os.close(w)
            with pytest.raises(release.OperatorError):
                release.read_passphrase(r)
        finally:
            os.close(r)


def test_preparation_refuses_unverified_run_before_downloading(monkeypatch):
    monkeypatch.setattr(release, "root_path", lambda: Path("/tmp/source"))
    monkeypatch.setattr(release, "approved_build", lambda version:
                        (_ for _ in ()).throw(release.OperatorError(
                            "BUILD_NOT_VERIFIED", "No authorized CI")))
    monkeypatch.setattr(release, "command", lambda *a, **kw: 1 / 0)
    with pytest.raises(release.OperatorError, match="authorized"):
        release.prepare("v0.5.0")


def test_status_does_not_claim_acceptance_without_signed_candidate_gate(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert release.status("v0.5.0") == {
        "version": "v0.5.0", "phase": "absent",
        "acceptance": "NOT VERIFIED", "ready_to_publish": False}


def test_cli_sign_fails_closed_without_prepared_candidate(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    result = release.main(["candidate", "sign", "v0.5.0",
                           "--passphrase-fd", "3", "--json"])
    assert result != 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["error"]["code"] == "CANDIDATE_NOT_PREPARED"
    assert "passphrase" not in json.dumps(payload)


def test_zip_extraction_accepts_only_expected_regular_leaves(tmp_path):
    archive = tmp_path / "candidate.zip"
    target = tmp_path / "assets"
    target.mkdir()
    names = release.files_for("v0.5.0")
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name in names:
            z.writestr(name, ("payload-for-" + name).encode())
    release.extract_candidate_zip(archive, target, "v0.5.0")
    assert sorted(p.name for p in target.iterdir()) == sorted(names)


@pytest.mark.parametrize("malicious", [
    "../escape.pem", "nested/manifest.json", "extra-signed.sig",
    "/absolute/path",
])
def test_zip_extraction_rejects_extra_or_traversal_members(tmp_path, malicious):
    archive = tmp_path / "candidate.zip"
    target = tmp_path / "assets"
    target.mkdir()
    with zipfile.ZipFile(archive, "w") as z:
        for name in release.files_for("v0.5.0"):
            z.writestr(name, "payload")
        z.writestr(malicious, "attacker")
    with pytest.raises(release.OperatorError, match="unexpected"):
        release.extract_candidate_zip(archive, target, "v0.5.0")
    assert not (tmp_path / "escape.pem").exists()


def test_zip_extraction_rejects_untrusted_symlink(tmp_path):
    archive = tmp_path / "candidate.zip"
    target = tmp_path / "assets"
    target.mkdir()
    names = release.files_for("v0.5.0")
    with zipfile.ZipFile(archive, "w") as z:
        for name in names:
            info = zipfile.ZipInfo(name)
            if name == names[0]:
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, b"../../secrets")
    with pytest.raises(release.OperatorError, match="unsafe member"):
        release.extract_candidate_zip(archive, target, "v0.5.0")


def test_modified_signer_worktree_refused_before_reading_passphrase(monkeypatch, tmp_path):
    version = "v0.5.0"
    repo = tmp_path / "candidate"
    (repo / "checkout").mkdir(parents=True)
    keydir = tmp_path / "repocache-signing"
    keydir.mkdir()
    key = keydir / "repocache-release-private.pem"
    key.write_bytes(b"encrypted private key placeholder")
    key.chmod(0o600)
    monkeypatch.setattr(release.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(release, "candidate_dir", lambda _: repo)
    monkeypatch.setattr(release, "read_state", lambda _: {
        "schema": 1, "version": version, "commit": "a" * 40,
        "run_id": 1, "attempt": 1, "phase": "prepared", "assets": {}})
    monkeypatch.setattr(release, "verify_state", lambda *args: {})
    def fake_command(args, **kw):
        if "rev-parse" in args:
            return ("a" * 40 + "\n").encode()
        if "status" in args:
            return b" M scripts/offline_sign_release.py\n"
        raise AssertionError(args)
    monkeypatch.setattr(release, "command", fake_command)
    monkeypatch.setattr(release, "read_passphrase", lambda _: 1 / 0)
    with pytest.raises(release.OperatorError, match="unreviewed"):
        release.sign(version, 3)


def test_local_sign_dispatch_preserves_fd_only_secret_and_no_publication(monkeypatch, tmp_path):
    version = "v0.5.0"
    release_dir = tmp_path / "candidate"
    scripts = release_dir / "checkout" / "scripts"
    assets = release_dir / "assets"
    scripts.mkdir(parents=True)
    assets.mkdir(mode=0o700)
    for name in release.files_for(version):
        (assets / name).write_bytes(("approved " + name).encode())
    original = {p.name: release.digest(p) for p in assets.iterdir()}
    signer = scripts / "offline_sign_release.py"
    signer.write_text(
        "from pathlib import Path\n"
        "def sign_candidate(bundle, private, *, commit, run_id, attempt, password):\n"
        "    assert password == b'correct-secret' and run_id == '21' and attempt == '2'\n"
        "    for suffix in ('.manifest.json', '.manifest.json.sig', '.provenance.json', '.provenance.json.sig'):\n"
        "        bundle.with_name(bundle.name + suffix).write_bytes(b'signed fixture')\n"
    )
    keydir = tmp_path / "repocache-signing"
    keydir.mkdir()
    private = keydir / "repocache-release-private.pem"
    private.write_bytes(b"encrypted test fixture")
    private.chmod(0o600)
    monkeypatch.setattr(release.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(release, "candidate_dir", lambda _: release_dir)
    record = {"schema": 1, "version": version, "commit": "a" * 40,
              "run_id": 21, "attempt": 2, "phase": "prepared",
              "assets": original}
    monkeypatch.setattr(release, "read_state", lambda _: record)
    monkeypatch.setattr(release, "verify_state", lambda *args: original)
    monkeypatch.setattr(release, "read_passphrase", lambda fd:
                        b"correct-secret" if fd == 3 else 1 / 0)
    monkeypatch.setattr(release, "command", lambda args, **kw:
                        (("a" * 40 + "\n").encode() if "rev-parse" in args else b""))
    saved = []
    monkeypatch.setattr(release, "save_state", lambda _, data: saved.append(data))
    assert release.sign(version, 3)["phase"] == "signed"
    assert len(saved) == 1
    assert saved[0]["phase"] == "signed"
    assert len(saved[0]["assets"]) == 8
    assert "correct-secret" not in json.dumps(saved[0])
    assert set(saved[0]["assets"]).issuperset(original)


def test_workstation_package_entrypoint_is_isolated_from_server_distribution():
    metadata = tomllib.loads((ROOT / "workstation/pyproject.toml").read_text())
    assert metadata["project"]["name"] == "repocache-release-operator"
    assert metadata["project"]["scripts"] == {
        "repocache-release": "repocache_release.cli:main"}
    assert metadata["project"]["dependencies"] == []
    server = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert "repocache-release" not in server["project"]["scripts"]


def test_candidate_lock_rejects_parallel_local_writes(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    with release.candidate_lock("v0.5.0"):
        with pytest.raises(release.OperatorError) as caught:
            with release.candidate_lock("v0.5.0"):
                pass
        assert caught.value.code == "BUSY"
    with release.candidate_lock("v0.5.0"):
        pass


def test_candidate_lock_rejects_symlink_to_foreign_file(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    release.state_root().mkdir(mode=0o700)
    target = tmp_path / "outside"
    target.write_text("no changes")
    (release.state_root() / "v0.5.0.lock").symlink_to(target)
    with pytest.raises((OSError, release.OperatorError)):
        with release.candidate_lock("v0.5.0"):
            pass
    assert target.read_text() == "no changes"


def test_build_run_must_prove_all_jobs_completed(monkeypatch):
    def remote(endpoint):
        if "/git/ref/tags/" in endpoint:
            return {"ref": "refs/tags/v0.5.0"}
        if "/commits/" in endpoint:
            return {"sha": "a" * 40}
        if "/compare/" in endpoint:
            return {"status": "ahead"}
        if "/runs?" in endpoint:
            return {"total_count": 1, "workflow_runs": [
                {"head_sha": "a" * 40, "head_branch": "v0.5.0",
                 "event": "workflow_dispatch", "status": "completed",
                 "conclusion": "success", "actor": {"login": "teixemf"},
                 "id": 4, "run_attempt": 1}]}
        if "/jobs?" in endpoint:
            return {"total_count": 5, "jobs": [
                {"name": str(n), "status": "completed",
                 "conclusion": "failure" if n == 2 else "success"}
                for n in range(5)]}
        raise AssertionError(endpoint)
    monkeypatch.setattr(release, "gh_json", remote)
    with pytest.raises(release.OperatorError) as caught:
        release.approved_build("v0.5.0")
    assert caught.value.code == "BUILD_NOT_VERIFIED"


def test_release_stage_requires_reviewed_gate_before_any_remote_write(monkeypatch, tmp_path):
    from repocache_release import publication
    record = {"version": "v0.5.0", "phase": "signed",
              "commit": "a" * 40, "run_id": 1, "attempt": 1, "assets": {}}
    monkeypatch.setattr(release, "read_state", lambda _: record)
    monkeypatch.setattr(publication, "reviewed_gate",
                        lambda *_: (_ for _ in ()).throw(release.OperatorError(
                            "GATE_NOT_AVAILABLE", "Not merged on protected main")))
    monkeypatch.setattr(publication, "token", lambda *_: 1 / 0)
    monkeypatch.setattr(release, "command", lambda *a, **kw: 1 / 0)
    with pytest.raises(release.OperatorError) as caught:
        release.stage("v0.5.0")
    assert caught.value.code == "GATE_NOT_AVAILABLE"


def test_stage_refuses_existing_publication_before_any_upload(monkeypatch):
    from repocache_release import publication
    record = {"schema": 1, "version": "v0.5.0", "phase": "signed",
              "commit": "a" * 40, "run_id": 1, "attempt": 1, "assets": {}}
    monkeypatch.setattr(release, "read_state", lambda _: record)
    monkeypatch.setattr(publication, "reviewed_gate", lambda *_: object())
    monkeypatch.setattr(publication, "token", lambda *_: "dummy")
    monkeypatch.setattr(publication, "local_proof", lambda *args: None)
    monkeypatch.setattr(publication, "release_metadata", lambda *_:
                        {"id": 4, "draft": False, "immutable": True})
    monkeypatch.setattr(release, "command", lambda *a, **kw: 1 / 0)
    with pytest.raises(release.OperatorError) as caught:
        release.stage("v0.5.0")
    assert caught.value.code == "DRAFT_CONFLICT"


def test_stage_records_only_exact_readback_after_single_remote_upload(monkeypatch):
    from repocache_release import publication
    record = {"schema": 1, "version": "v0.5.0", "phase": "signed",
              "commit": "a" * 40, "run_id": 1, "attempt": 1,
              "assets": {item: "b" * 64 for item in release.files_for("v0.5.0", True)}}
    monkeypatch.setattr(release, "read_state", lambda _: record)
    monkeypatch.setattr(publication, "reviewed_gate", lambda *_: object())
    monkeypatch.setattr(publication, "token", lambda *_: "dummy")
    monkeypatch.setattr(publication, "local_proof", lambda *args: None)
    monkeypatch.setattr(publication, "release_metadata", lambda *_: None)
    monkeypatch.setattr(publication, "remote_exact", lambda *_: (42, {}))
    monkeypatch.setattr(release, "candidate_dir", lambda _: Path("/trusted/fake"))
    calls, saved = [], []
    monkeypatch.setattr(release, "command", lambda args, **kw: calls.append(args) or b"")
    monkeypatch.setattr(release, "save_state", lambda _, data: saved.append(data))
    outcome = release.stage("v0.5.0")
    assert outcome["release_id"] == 42 and outcome["acceptance"] == "NOT VERIFIED"
    assert len(calls) == 1
    assert calls[0][:4] == ["gh", "release", "create", "v0.5.0"]
    assert "--draft" in calls[0] and "--verify-tag" in calls[0]
    assert saved[0]["phase"] == "staged"


def test_publish_requires_owner_exact_candidate_hash_before_gate_access(monkeypatch):
    from repocache_release import publication
    record = {"version": "v0.5.0", "phase": "staged", "commit": "a" * 40,
              "run_id": 4, "attempt": 1, "assets": {}}
    monkeypatch.setattr(release, "read_state", lambda _: record)
    monkeypatch.setattr(publication, "reviewed_gate", lambda *_: 1 / 0)
    with pytest.raises(release.OperatorError) as caught:
        release.publish("v0.5.0", 100, "f" * 64)
    assert caught.value.code == "APPROVAL_REQUIRED"


def test_publish_refuses_wrong_remote_evidence_before_release_write(monkeypatch):
    from repocache_release import publication
    record = {"version": "v0.5.0", "phase": "staged", "commit": "a" * 40,
              "run_id": 4, "attempt": 1, "release_id": 42, "assets": {}}
    monkeypatch.setattr(release, "read_state", lambda _: record)
    monkeypatch.setattr(publication, "reviewed_gate", lambda *_: object())
    monkeypatch.setattr(publication, "token", lambda *_: "dummy")
    monkeypatch.setattr(publication, "local_proof", lambda *args: None)
    monkeypatch.setattr(publication, "signed_acceptance",
                        lambda *args: (_ for _ in ()).throw(
                            release.OperatorError("ACCEPTANCE_MISMATCH",
                                                  "Changed signed CI digest")))
    monkeypatch.setattr(release, "command", lambda *a, **kw: 1 / 0)
    with pytest.raises(release.OperatorError) as caught:
        release.publish("v0.5.0", 100, publication.fingerprint(release, record))
    assert caught.value.code == "ACCEPTANCE_MISMATCH"


def test_publish_readback_requires_immutable_same_assets_after_one_write(monkeypatch):
    from repocache_release import publication
    record = {"version": "v0.5.0", "phase": "staged", "commit": "a" * 40,
              "run_id": 4, "attempt": 1, "release_id": 42, "assets": {}}
    monkeypatch.setattr(release, "read_state", lambda _: record)
    monkeypatch.setattr(publication, "reviewed_gate", lambda *_: object())
    monkeypatch.setattr(publication, "token", lambda *_: "dummy")
    monkeypatch.setattr(publication, "local_proof", lambda *args: None)
    monkeypatch.setattr(publication, "signed_acceptance",
                        lambda *args: {"release_id": 42, "assets": {}})
    monkeypatch.setattr(publication, "release_metadata", lambda *_: {
        "id": 42, "tag_name": "v0.5.0",
        "draft": False, "immutable": False, "assets": []})
    calls = []
    monkeypatch.setattr(release, "command", lambda args, **kw:
                        calls.append(args) or b"")
    monkeypatch.setattr(release, "save_state", lambda *args: 1 / 0)
    with pytest.raises(release.OperatorError) as caught:
        release.publish("v0.5.0", 100, publication.fingerprint(release, record))
    assert caught.value.code == "POST_PUBLISH_UNVERIFIED"
    assert calls == [["gh", "release", "edit", "v0.5.0", "--repo",
                      "teixemf/repocache", "--draft=false"]]


def test_authenticated_ci_record_must_match_local_release_id_and_hashes(monkeypatch):
    from repocache_release import publication
    record = {"version": "v0.5.0", "phase": "staged", "commit": "a" * 40,
              "run_id": 4, "attempt": 1, "release_id": 42, "assets": {}}
    bad = {"tag": "v0.5.0", "commit": "a" * 40,
           "release_id": 43, "build_run_id": 4, "build_run_attempt": 1,
           "assets": {}}
    class FakeGate:
        def authenticated_ci_evidence(self, run, token):
            return bad
        def guard(self, report, token):
            raise AssertionError("Guard must not execute for mismatched candidate")
    monkeypatch.setattr(publication, "remote_exact", lambda *args: (42, {}))
    with pytest.raises(release.OperatorError) as caught:
        publication.signed_acceptance(release, FakeGate(), "v0.5.0",
                                      record, 777, "dummy")
    assert caught.value.code == "ACCEPTANCE_MISMATCH"
