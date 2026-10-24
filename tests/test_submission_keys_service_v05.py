"""Keyring lifecycle, service guard, and administrative fail-closed tests."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from repocache import intake_service, submission_admin, submission_keys
from repocache.intake import load_keyring
from repocache.submissions import SubmissionError


@pytest.fixture
def keys(tmp_path, monkeypatch):
    keydir = tmp_path / "keyring"
    clientdir = tmp_path / "handoff"
    for path in (keydir, clientdir):
        path.mkdir(mode=0o700)
        path.chmod(0o700)
    monkeypatch.setattr(submission_keys, "_root_only", lambda: None)
    monkeypatch.setattr(submission_keys, "_service_uid", os.geteuid)
    # The parent UID is synthetic; its access mode and no-symlink checks remain.
    original = submission_keys._trusted_directory
    def trusted(path, *, for_client):
        assert not path.is_symlink()
        assert path.stat().st_mode & (0o077 if for_client else 0o022) == 0
    monkeypatch.setattr(submission_keys, "_trusted_directory", trusted)
    return keydir / "keyring.json", clientdir


def test_credentials_can_be_issued_rotated_and_revoked_offline(keys):
    keyring, handoff = keys
    client_a, client_b = handoff / "a.json", handoff / "b.json"
    submission_keys.issue_key(keyring, client_a, "client_A", approved=True)
    assert keyring.stat().st_mode & 0o077 == 0
    assert client_a.stat().st_mode & 0o077 == 0
    first = json.loads(client_a.read_text())
    assert len(load_keyring(keyring)["client_A"]) == 32
    assert first["secret"] not in keyring.name
    submission_keys.issue_key(keyring, client_b, "client_B", approved=True)
    assert set(load_keyring(keyring)) == {"client_A", "client_B"}
    submission_keys.revoke_key(keyring, "client_A", approved=True)
    assert set(load_keyring(keyring)) == {"client_B"}
    with pytest.raises(SubmissionError, match="last_key_refused"):
        submission_keys.revoke_key(keyring, "client_B", approved=True)
    assert "client_B" in load_keyring(keyring)


def test_duplicate_and_missing_approval_cannot_replace_client_file(keys):
    keyring, handoff = keys
    client = handoff / "client.json"
    with pytest.raises(SubmissionError):
        submission_keys.issue_key(keyring, client, "id1", approved=False)
    assert not client.exists()
    submission_keys.issue_key(keyring, client, "id1", approved=True)
    old = client.read_bytes()
    with pytest.raises(SubmissionError, match="duplicate_or_full_keyring"):
        submission_keys.issue_key(keyring, handoff / "new.json", "id1", approved=True)
    with pytest.raises(SubmissionError):
        submission_keys.issue_key(keyring, client, "id2", approved=True)
    assert client.read_bytes() == old
    assert "id2" not in load_keyring(keyring)


def test_untrusted_keyring_symlink_is_refused(keys):
    keyring, handoff = keys
    submission_keys.issue_key(keyring, handoff / "client.json", "good", approved=True)
    target = keyring.parent / "elsewhere.json"
    keyring.rename(target)
    keyring.symlink_to(target)
    with pytest.raises((SubmissionError, OSError)):
        submission_keys.issue_key(keyring, handoff / "another.json", "new", approved=True)


def test_disabled_service_never_binds_without_approval(monkeypatch, capsys):
    monkeypatch.setattr(intake_service, "build_intake",
                        lambda: pytest.fail("Without flag, service must never validate or bind"))
    assert intake_service.main([]) == 2
    assert "disabled" in capsys.readouterr().out

    monkeypatch.setattr(intake_service, "build_intake", lambda: object())
    monkeypatch.setattr(intake_service, "make_loopback_server",
                        lambda *args, **kwargs: pytest.fail("Config check must not bind"))
    assert intake_service.main(["--enable-local-only", "--check-config"]) == 0


def test_service_identity_refuses_root_or_wrong_user(monkeypatch):
    monkeypatch.setattr(intake_service.pwd, "getpwnam",
                        lambda name: SimpleNamespace(pw_uid=12345))
    monkeypatch.setattr(intake_service.os, "geteuid", lambda: 0)
    with pytest.raises(SubmissionError, match="service_identity_required"):
        intake_service.require_service_identity()
    monkeypatch.setattr(intake_service.os, "geteuid", lambda: 1001)
    with pytest.raises(SubmissionError, match="service_identity_required"):
        intake_service.require_service_identity()


@pytest.mark.parametrize("code,out,expected", [
    (0, "active\n", False), (3, "inactive\n", True),
    (4, "unknown\n", False), (1, "failed\n", False),
])
def test_restore_requires_systemd_confirmed_inactive(monkeypatch, code, out, expected):
    monkeypatch.setattr(submission_admin.subprocess, "run",
                        lambda *args, **kwargs: SimpleNamespace(returncode=code, stdout=out))
    assert submission_admin.intake_is_inactive() is expected


def test_admin_command_rejects_nonroot(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(submission_admin.os, "geteuid", lambda: 1001)
    assert submission_admin.main(["backup", "--output", str(tmp_path / "backup"), "--approve"]) == 3
    assert "operator_required" in capsys.readouterr().err


def test_deployment_examples_are_not_install_hooks():
    root = Path(__file__).resolve().parents[1]
    unit = (root / "deploy/examples/repocache-intake.service").read_text()
    nginx = (root / "deploy/examples/nginx-intake-location.conf.example").read_text()
    installer = (root / "install.sh").read_text()
    assert "User=repocache-intake" in unit
    assert "NoNewPrivileges=true" in unit
    assert "ProtectSystem=strict" in unit
    assert "ConditionPathExists" in unit
    assert "127.0.0.1:8765" in nginx
    assert "client_max_body_size" in nginx
    assert "repocache-intake.service" not in installer


def test_keyring_replacement_between_lstat_and_open_is_refused(
    keys, monkeypatch
):
    from repocache import intake
    keyring, handoff = keys
    submission_keys.issue_key(keyring, handoff / "client.json", "good", approved=True)
    alternate = keyring.parent / "alternate.json"
    alternate.write_bytes(keyring.read_bytes())
    alternate.chmod(0o600)
    original_open = intake.os.open
    replaced = []

    def swap_keyring(path, flags, *args, **kwargs):
        if Path(path) == keyring and not replaced:
            replaced.append(True)
            keyring.unlink()
            alternate.rename(keyring)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(intake.os, "open", swap_keyring)
    with pytest.raises(SubmissionError, match="invalid_credentials"):
        load_keyring(keyring)
    assert replaced
