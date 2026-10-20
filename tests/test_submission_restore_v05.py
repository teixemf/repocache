"""Offline restore and rollback tests; root ownership is synthetic in CI.

The mocked root guards establish algorithmic correctness only, not native
systemd/SELinux permission or power-loss acceptance (issue #49).
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import nullcontext
from pathlib import Path

import pytest

from repocache import submission_recovery as recovery
from repocache.submissions import SubmissionError, SubmissionQueue


@pytest.fixture
def restored_state(tmp_path, monkeypatch):
    state = tmp_path / "service-state"
    backups = tmp_path / "root-backups"
    for directory in (state, backups):
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
    dbfile, backup = state / "queue.sqlite3", backups / "snapshot.sqlite3"
    queue = SubmissionQueue(dbfile)
    item = {"os": {"id": "debian", "version": "13"},
            "repositories": [{"type": "apt-list",
                              "url": "https://mirror.example.org/debian/",
                              "insecure_http": False}]}
    old_id = queue.enqueue("k", "nonce-a", "digest-a", item, now=100)
    with sqlite3.connect(dbfile) as source, sqlite3.connect(backup) as target:
        source.backup(target)
    backup.chmod(0o600)
    new_id = queue.enqueue("k", "nonce-b", "digest-b", item, now=101)

    # Simulate root-owned directories and lock only; independent tests check
    # refusal behavior, but these do not claim native OS permission coverage.
    monkeypatch.setattr(recovery, "_require_root", lambda: None)
    original_private = recovery._trusted_private_dir
    def private_mode(path, *, service_owned=False):
        details = path.lstat()
        assert details.st_mode & 0o077 == 0
        assert not path.is_symlink()
    monkeypatch.setattr(recovery, "_trusted_private_dir", private_mode)
    monkeypatch.setattr(recovery, "_exclusive_restore_lock", lambda directory: nullcontext())

    original_check = recovery._check_backup_stat
    def protected_backup(details):
        assert details.st_size > 0
        if details.st_mode & 0o077:
            raise SubmissionError("unsafe_restore_backup", 403)
    monkeypatch.setattr(recovery, "_check_backup_stat", protected_backup)
    return dbfile, backup, old_id, new_id


def _ids(path):
    with sqlite3.connect(path) as db:
        return {row[0] for row in db.execute("SELECT id FROM proposals")}


def test_restore_refuses_without_authorization_or_proven_stop(restored_state):
    dbfile, backup, first, second = restored_state
    for approved, stopped in [(False, lambda: True),
                              (True, None), (True, lambda: False)]:
        with pytest.raises(SubmissionError, match="offline_restore_not_approved"):
            recovery.restore_offline(dbfile, backup, approved=approved,
                                     service_stopped=stopped)
    assert _ids(dbfile) == {first, second}


def test_restore_preserves_previous_state_and_supports_audited_rollback(restored_state):
    dbfile, backup, first, second = restored_state
    previous = recovery.restore_offline(
        dbfile, backup, approved=True, service_stopped=lambda: True)
    assert _ids(dbfile) == {first}
    assert _ids(previous) == {first, second}
    assert previous.parent == backup.parent
    assert previous.stat().st_mode & 0o077 == 0
    # An explicit *second* authorized offline operation uses the previous
    # root-only snapshot to reverse the restore; no automatic rollback.
    newer_backup = previous
    recovery.restore_offline(
        dbfile, newer_backup, approved=True, service_stopped=lambda: True)
    assert _ids(dbfile) == {first, second}


def test_corrupt_source_never_replaces_working_queue(restored_state):
    dbfile, backup, first, second = restored_state
    backup.write_bytes(b"not-sqlite-database")
    with pytest.raises(SubmissionError, match="corrupt_restore_backup"):
        recovery.restore_offline(dbfile, backup, approved=True,
                                 service_stopped=lambda: True)
    assert _ids(dbfile) == {first, second}


def test_interrupted_atomic_swap_keeps_original_queue(restored_state, monkeypatch):
    dbfile, backup, first, second = restored_state
    def fail_replace(*args, **kwargs):
        raise OSError("synthetic interrupted replacement")
    monkeypatch.setattr(recovery.os, "replace", fail_replace)
    with pytest.raises(SubmissionError, match="restore_unavailable"):
        recovery.restore_offline(dbfile, backup, approved=True,
                                 service_stopped=lambda: True)
    assert _ids(dbfile) == {first, second}
    retained = list(backup.parent.glob("repocache-before-restore-*.sqlite3"))
    assert len(retained) == 1 and _ids(retained[0]) == {first, second}


def test_backup_permission_refusal_in_synthetic_restore(restored_state):
    dbfile, backup, first, second = restored_state
    backup.chmod(0o644)
    with pytest.raises(SubmissionError, match="unsafe_restore_backup"):
        recovery.restore_offline(dbfile, backup, approved=True,
                                 service_stopped=lambda: True)
    assert _ids(dbfile) == {first, second}


def test_real_root_requirement_fails_for_nonroot(monkeypatch):
    monkeypatch.setattr(recovery.os, "geteuid", lambda: 1001)
    with pytest.raises(SubmissionError, match="operator_required"):
        recovery._require_root()
