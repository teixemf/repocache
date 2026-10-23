"""Security and command-surface tests for workstation Release Operator (#88)."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
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
    assert "candidate stage" not in paths() and "candidate publish" not in paths()
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
    monkeypatch.setattr(release, "status", lambda version: {
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
            if "/runs?" in endpoint:
                return {"workflow_runs": [{
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
