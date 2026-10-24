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


def test_restore_never_stages_or_locks_in_intake_writable_directory(
    restored_state, monkeypatch
):
    dbfile, backup, first, second = restored_state
    observed = {"locks": [], "verified": [], "replacements": []}
    original_verify = recovery._verify_sqlite
    original_replace = recovery.os.replace

    def lock(directory):
        observed["locks"].append(directory)
        return nullcontext()

    def verify(path):
        observed["verified"].append(path)
        assert path.parent == backup.parent
        assert path.parent != dbfile.parent
        return original_verify(path)

    def replace(source, destination):
        observed["replacements"].append((Path(source), Path(destination)))
        assert Path(source).parent == backup.parent
        assert Path(destination) == dbfile
        return original_replace(source, destination)

    monkeypatch.setattr(recovery, "_exclusive_restore_lock", lock)
    monkeypatch.setattr(recovery, "_verify_sqlite", verify)
    monkeypatch.setattr(recovery.os, "replace", replace)
    recovery.restore_offline(dbfile, backup, approved=True,
                             service_stopped=lambda: True)
    assert observed["locks"] == [backup.parent]
    assert len(observed["verified"]) == 1
    assert len(observed["replacements"]) == 1
    assert _ids(dbfile) == {first}


def test_cross_device_restore_fails_closed_and_keeps_old_queue(
    restored_state, monkeypatch
):
    import errno
    dbfile, backup, first, second = restored_state
    def fail_cross_device(*_args, **_kwargs):
        raise OSError(errno.EXDEV, "different filesystems")
    monkeypatch.setattr(recovery.os, "replace", fail_cross_device)
    with pytest.raises(SubmissionError, match="restore_unavailable"):
        recovery.restore_offline(dbfile, backup, approved=True,
                                 service_stopped=lambda: True)
    assert _ids(dbfile) == {first, second}
    assert not list(backup.parent.glob(".repocache-restore-*"))


def test_privileged_copy_rejects_inode_swap_and_oversized_file(tmp_path, monkeypatch):
    original = tmp_path / "original.db"
    replacement = tmp_path / "replacement.db"
    output = tmp_path / "output.db"
    original.write_bytes(b"original data")
    replacement.write_bytes(b"attacker data")
    expected = original.stat()
    with replacement.open("rb") as source, output.open("wb") as destination:
        with pytest.raises(SubmissionError, match="restore_source_changed"):
            recovery._copy_verified_regular(source.fileno(), destination.fileno(), expected)
    monkeypatch.setattr(recovery, "MAX_RESTORE_BYTES", 4)
    with original.open("rb") as source, output.open("wb") as destination:
        with pytest.raises(SubmissionError, match="restore_source_changed"):
            recovery._copy_verified_regular(source.fileno(), destination.fileno(), expected)


def test_privileged_copy_refuses_concurrent_service_file_growth(tmp_path, monkeypatch):
    original = tmp_path / "queue.db"
    output = tmp_path / "rollback.db"
    original.write_bytes(b"old database contents")
    original_read = recovery.os.read
    touched = []
    source_fd = None

    def grow_after_read(fd, length):
        data = original_read(fd, length)
        if fd == source_fd and data and not touched:
            touched.append(True)
            with original.open("ab") as writer:
                writer.write(b"attacker append after stat")
        return data

    with original.open("rb") as source, output.open("wb") as destination:
        source_fd = source.fileno()
        expected = os.fstat(source_fd)
        with monkeypatch.context() as patch:
            patch.setattr(recovery.os, "read", grow_after_read)
            with pytest.raises(SubmissionError, match="restore_source_changed"):
                recovery._copy_verified_regular(source_fd, destination.fileno(), expected)
    assert touched


def test_restore_refuses_replaced_queue_inode_before_root_rollback_copy(
    restored_state, monkeypatch
):
    import shutil
    dbfile, backup, first, second = restored_state
    original_verify = recovery._verify_sqlite
    replacement = dbfile.parent / "replacement.sqlite3"

    def swap_after_source_verification(staged):
        original_verify(staged)
        shutil.copy2(dbfile, replacement)
        os.replace(replacement, dbfile)

    monkeypatch.setattr(recovery, "_verify_sqlite", swap_after_source_verification)
    with pytest.raises(SubmissionError, match="restore_source_changed"):
        recovery.restore_offline(
            dbfile, backup, approved=True, service_stopped=lambda: True
        )
    assert _ids(dbfile) == {first, second}
    assert not list(backup.parent.glob("repocache-before-restore-*.sqlite3"))


def test_restore_refuses_attacker_renameable_ancestor(tmp_path, monkeypatch):
    import stat
    from types import SimpleNamespace
    private = tmp_path / "protected"
    private.mkdir(mode=0o700)
    real_lstat = Path.lstat

    def fake_lstat(path, *args, **kwargs):
        result = real_lstat(path, *args, **kwargs)
        if path == private:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
        if path == private.parent:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=12345)
        return result

    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", fake_lstat)
        with pytest.raises(SubmissionError, match="unsafe_restore_ancestor"):
            recovery._trusted_private_dir(private)


def test_restore_refuses_service_owned_directory_below_sticky_parent(
    tmp_path, monkeypatch
):
    import stat
    from types import SimpleNamespace
    private = tmp_path / "service-owned"
    private.mkdir(mode=0o700)
    real_lstat = Path.lstat

    def fake_lstat(path, *args, **kwargs):
        result = real_lstat(path, *args, **kwargs)
        if path == private:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=12345)
        if path == private.parent:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o1777, st_uid=0)
        return result

    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", fake_lstat)
        patch.setattr(
            recovery.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=12345)
        )
        with pytest.raises(SubmissionError, match="unsafe_restore_ancestor"):
            recovery._trusted_private_dir(private, service_owned=True)


def test_restore_refuses_service_planted_fifo_without_blocking(
    restored_state, monkeypatch
):
    dbfile, backup, first, second = restored_state
    dbfile.unlink()
    os.mkfifo(dbfile, 0o600)
    # A FIFO opened without O_NONBLOCK would hang the privileged restore.
    real_open = recovery.os.open
    opened_fifo = []

    def verify_nonblocking(path, flags, *args, **kwargs):
        if Path(path) == dbfile:
            opened_fifo.append(True)
            assert flags & os.O_NONBLOCK
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(recovery.os, "open", verify_nonblocking)
    with pytest.raises(SubmissionError, match="unsafe_current_store"):
        recovery.restore_offline(
            dbfile, backup, approved=True, service_stopped=lambda: True
        )
    assert opened_fifo and dbfile.is_fifo()
