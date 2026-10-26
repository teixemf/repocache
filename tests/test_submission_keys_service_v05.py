"""Keyring lifecycle, service guard, and administrative fail-closed tests."""
from __future__ import annotations

import base64
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from repocache import intake, intake_service, submission_admin, submission_keys
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
    # Real file-lock operations; root identity is synthetic in this fixture.
    monkeypatch.setattr(submission_keys, "_verify_keyring_lock", lambda fd: None)
    monkeypatch.setattr(submission_keys, "_service_gid", os.getegid)
    monkeypatch.setattr(intake, "_service_gid", os.getegid)
    # Synthetic non-root fixture: use real temp file operations, but model
    # root-owned inode identity separately with explicit policy tests below.
    def synthetic_file_safe(info, group):
        return (stat.S_ISREG(info.st_mode) and info.st_gid == group and
                stat.S_IMODE(info.st_mode) == 0o640 and info.st_nlink == 1)
    monkeypatch.setattr(submission_keys, "_keyring_file_valid", synthetic_file_safe)
    monkeypatch.setattr(intake, "_keyring_file_valid", synthetic_file_safe)
    monkeypatch.setattr(intake, "_trusted_keyring_directory", lambda path, gid: None)
    monkeypatch.setattr(submission_keys, "_set_keyring_ownership",
                        lambda fd, gid: os.fchmod(fd, 0o600))
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
    assert stat.S_IMODE(keyring.stat().st_mode) == 0o640
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
    alternate.chmod(0o640)
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


@pytest.mark.parametrize("for_client", (True, False))
@pytest.mark.parametrize(("ancestor_uid", "ancestor_mode", "reject"), (
    (12345, 0o700, True),
    (0, 0o777, True),
    (0, 0o1777, False),
))
def test_root_keyring_and_client_handoff_reject_renamable_ancestors(
    tmp_path, monkeypatch, for_client, ancestor_uid, ancestor_mode, reject
):
    """Root secret writes may never traverse an attacker-renamable ancestor."""
    attacker = tmp_path / "attacker-controlled"
    protected = attacker / "root-owned-handoff"
    protected.mkdir(parents=True, mode=0o700)
    protected.chmod(0o700 if for_client else 0o750)
    monkeypatch.setattr(submission_keys, "_service_gid", os.getegid)
    original_lstat = Path.lstat

    def model_ownership(path, *args, **kwargs):
        details = original_lstat(path, *args, **kwargs)
        if path == attacker:
            return SimpleNamespace(st_mode=stat.S_IFDIR | ancestor_mode,
                                   st_uid=ancestor_uid)
        if path == protected:
            return SimpleNamespace(st_mode=stat.S_IFDIR | (0o700 if for_client else 0o750),
                                   st_uid=0, st_gid=os.getegid())
        if path == tmp_path or path in tmp_path.parents:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
        return details

    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", model_ownership)
        if reject:
            with pytest.raises(SubmissionError, match="unsafe_credentials_directory"):
                submission_keys._trusted_directory(protected, for_client=for_client)
        else:
            submission_keys._trusted_directory(protected, for_client=for_client)



@pytest.mark.parametrize(("uid", "gid", "mode", "nlink", "valid"), [
    (0, 101, 0o640, 1, True),
    (1001, 101, 0o640, 1, False),  # service-owned: never trust persistence
    (0, 102, 0o640, 1, False),
    (0, 101, 0o660, 1, False),
    (0, 101, 0o600, 1, False),   # unreadable by the dedicated service
    (0, 101, 0o644, 1, False),
    (0, 101, 0o640, 2, False),   # refuse unexpected hard links
])
def test_root_controlled_keyring_inode_policy(uid, gid, mode, nlink, valid):
    policy = intake._keyring_file_valid
    info = SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=uid, st_gid=gid,
                           st_nlink=nlink, st_size=128)
    assert policy(info, 101) is valid


@pytest.mark.parametrize(("uid", "gid", "mode", "valid"), [
    (0, 101, 0o750, True),
    (1001, 101, 0o750, False),
    (0, 102, 0o750, False),
    (0, 101, 0o770, False),
    (0, 101, 0o700, False),  # cannot traverse with service identity
    (0, 101, 0o755, False),
])
def test_keyring_directory_policy(uid, gid, mode, valid):
    info = SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=uid, st_gid=gid)
    assert intake._keyring_directory_valid(info, 101) is valid


def test_old_service_owned_keyring_is_not_silently_migrated(monkeypatch):
    # Both readers and operator lifecycle operations must refuse the
    # vulnerable previous ownership rather than silently trusting it.
    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=101,
                           st_gid=101, st_nlink=1, st_size=100)
    assert not intake._keyring_file_valid(info, 101)
    assert not submission_keys._keyring_file_valid(info, 101)


def test_issue_fsyncs_handoff_directory_before_publishing_keyring(
    keys, monkeypatch,
):
    keyring, handoff = keys
    events = []
    original_sync = submission_keys._fsync_directory
    original_write = submission_keys._write_keyring

    def sync(directory):
        events.append(("sync", str(directory)))
        return original_sync(directory)

    def publish(*args):
        events.append(("publish", str(keyring)))
        assert ("sync", str(handoff)) in events
        return original_write(*args)

    monkeypatch.setattr(submission_keys, "_fsync_directory", sync)
    monkeypatch.setattr(submission_keys, "_write_keyring", publish)
    submission_keys.issue_key(keyring, handoff / "a.json", "a", approved=True)
    assert ("publish", str(keyring)) in events
    assert ("sync", str(keyring.parent)) in events


def test_prepublication_failure_cleans_uncommitted_client_secret(
    keys, monkeypatch,
):
    keyring, handoff = keys

    def fail_before_rename(*args):
        raise OSError("synthetic prepublication failure")

    monkeypatch.setattr(submission_keys, "_write_keyring", fail_before_rename)
    with pytest.raises(SubmissionError, match="credential_write_unavailable"):
        submission_keys.issue_key(keyring, handoff / "a.json", "a", approved=True)
    assert not (handoff / "a.json").exists()
    assert not keyring.exists()


def test_after_publish_fsync_failure_retains_reconcilable_client_secret(
    keys, monkeypatch,
):
    keyring, handoff = keys
    original_sync = submission_keys._fsync_directory
    def fault(directory):
        if directory == keyring.parent:
            raise OSError("synthetic durability ambiguity")
        return original_sync(directory)

    with monkeypatch.context() as patch:
        patch.setattr(submission_keys, "_fsync_directory", fault)
        with pytest.raises(
            SubmissionError, match="credential_publication_uncertain"
        ):
            submission_keys.issue_key(keyring, handoff / "a.json", "a", approved=True)

    credential = json.loads((handoff / "a.json").read_text())
    assert set(load_keyring(keyring)) == {"a"}
    assert base64.urlsafe_b64decode(credential["secret"] + "=") == load_keyring(keyring)["a"]
    # An operator must not silently re-issue an ambiguous credential.
    with pytest.raises(SubmissionError, match="duplicate_or_full_keyring"):
        submission_keys.issue_key(keyring, handoff / "b.json", "a", approved=True)
    assert not (handoff / "b.json").exists()


def test_failed_revoke_after_publication_reports_uncertain(
    keys, monkeypatch,
):
    keyring, handoff = keys
    submission_keys.issue_key(keyring, handoff / "a.json", "a", approved=True)
    submission_keys.issue_key(keyring, handoff / "b.json", "b", approved=True)
    original_sync = submission_keys._fsync_directory
    with monkeypatch.context() as patch:
        def fail(directory):
            if directory == keyring.parent:
                raise OSError("synthetic publication ambiguity")
            return original_sync(directory)
        patch.setattr(submission_keys, "_fsync_directory", fail)
        with pytest.raises(
            SubmissionError, match="credential_publication_uncertain"
        ):
            submission_keys.revoke_key(keyring, "a", approved=True)
    assert set(load_keyring(keyring)) == {"b"}


def test_issuance_serializes_concurrent_root_read_modify_writes(
    keys, monkeypatch,
):
    keyring, handoff = keys
    original_write = submission_keys._write_keyring
    entered = threading.Event()
    release = threading.Event()
    first = [True]

    def slowed(*args):
        if first[0]:
            first[0] = False
            entered.set()
            assert release.wait(6), "first transaction never released"
        return original_write(*args)

    monkeypatch.setattr(submission_keys, "_write_keyring", slowed)
    with ThreadPoolExecutor(max_workers=2) as executor:
        one = executor.submit(
            submission_keys.issue_key, keyring, handoff / "a.json",
            "a", approved=True,
        )
        assert entered.wait(6), "first transaction did not enter"
        two = executor.submit(
            submission_keys.issue_key, keyring, handoff / "b.json",
            "b", approved=True,
        )
        time.sleep(0.05)
        release.set()
        one.result(timeout=8)
        two.result(timeout=8)
    assert set(load_keyring(keyring)) == {"a", "b"}


def test_revoke_and_issue_are_serialized_without_revocation_rollback(
    keys, monkeypatch,
):
    keyring, handoff = keys
    submission_keys.issue_key(keyring, handoff / "a.json", "a", approved=True)
    submission_keys.issue_key(keyring, handoff / "b.json", "b", approved=True)
    original_write = submission_keys._write_keyring
    entered = threading.Event()
    release = threading.Event()
    first = [True]

    def slowed(*args):
        if first[0]:
            first[0] = False
            entered.set()
            assert release.wait(6)
        return original_write(*args)

    monkeypatch.setattr(submission_keys, "_write_keyring", slowed)
    with ThreadPoolExecutor(max_workers=2) as executor:
        revoked = executor.submit(
            submission_keys.revoke_key, keyring, "a", approved=True,
        )
        assert entered.wait(6)
        issued = executor.submit(
            submission_keys.issue_key, keyring, handoff / "c.json",
            "c", approved=True,
        )
        time.sleep(0.05)
        release.set()
        revoked.result(timeout=8)
        issued.result(timeout=8)
    assert set(load_keyring(keyring)) == {"b", "c"}


def test_keyring_refuses_symlinked_or_unsafe_root_lock(
    keys,
):
    keyring, handoff = keys
    lock = keyring.parent / ".keyring.lock"
    protected = keyring.parent / "other-file"
    protected.write_text("test")
    lock.symlink_to(protected)
    with pytest.raises((SubmissionError, OSError)):
        submission_keys.issue_key(
            keyring, handoff / "a.json", "a", approved=True,
        )
    assert not (handoff / "a.json").exists()
    assert not keyring.exists()
