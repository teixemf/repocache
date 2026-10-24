"""Issue #17: controlled retention and trusted backup regression coverage."""
from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import replace

import pytest

from repocache import submissions
from repocache.submissions import SubmissionError, SubmissionQueue


def test_retention_requires_operator_approval_and_preserves_pending(tmp_path, monkeypatch):
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    from repocache import submission_decisions as decisions
    journal_dir = tmp_path / "decisions"
    journal_dir.mkdir(mode=0o700)
    journal_dir.chmod(0o700)
    monkeypatch.setattr(decisions, "_trusted_dir", lambda _path: None)
    monkeypatch.setattr(decisions, "_verify_lock_fd", lambda _fd: None)
    monkeypatch.setattr(decisions, "_open_trusted", lambda path: os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)))
    queue = SubmissionQueue(parent / "state.db", journal_dir=journal_dir)
    item = {"os": {"id": "debian", "version": "13"},
            "repositories": [{"type": "apt-list",
                              "url": "https://mirror.example.org/debian/",
                              "insecure_http": False}]}
    # One pending, one decided; retention must never erase pending.
    pending = queue.enqueue("k", "n1", "h1", item, now=100)
    decided = queue.enqueue("k", "n2", "h2", item, now=100)
    with pytest.raises(SubmissionError):
        queue.maintain(approved=False, now=19000000)
    monkeypatch.setattr(submissions.os, "geteuid", lambda: 0)
    # Authoritative retention time is the root receipt, not SQLite.changed.
    with monkeypatch.context() as clock:
        clock.setattr(decisions.time, "time", lambda: 100)
        queue.decide(decided, "reject", expected_version=0)
    # An operator may request retention; the trusted receipt is old enough.
    with queue._connect() as db:
        db.execute("UPDATE proposals SET changed=100 WHERE id=?", (decided,))
    result = queue.maintain(approved=True, now=19000000, decided_retention_days=180)
    assert result["purged_decided"] == 1
    assert result["purged_nonces"] == 2
    with queue._connect() as db:
        assert db.execute("SELECT id FROM proposals").fetchall() == [(pending,)]
        assert db.execute("SELECT count(*) FROM audit WHERE proposal_id=?", (decided,)).fetchone()[0] == 0


def test_backup_rejects_nonroot_or_unsafe_destination(tmp_path, monkeypatch):
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    queue = SubmissionQueue(parent / "state.db")
    with pytest.raises(SubmissionError, match="operator_required"):
        queue.backup(parent / "state-backup.db")

    monkeypatch.setattr(submissions.os, "geteuid", lambda: 0)
    # The parent is owned by a non-root CI worker, so even a simulated
    # root identity must not bypass strict destination checks.
    if os.getuid() != 0:
        with pytest.raises(SubmissionError, match="unsafe_backup_destination"):
            queue.backup(parent / "state-backup.db")


def test_backup_refuses_relative_path_and_untrusted_indirect_ancestor(
    tmp_path, monkeypatch
):
    outer = tmp_path / "untrusted"
    outer.mkdir(mode=0o700)
    private = outer / "root-private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    queue = SubmissionQueue(private / "state.db")
    monkeypatch.setattr(submissions.os, "geteuid", lambda: 0)

    # Relative paths must never be interpreted against a root process cwd.
    with pytest.raises(SubmissionError, match="unsafe_backup_destination"):
        queue.backup(submissions.Path("relative-backup.db"))

    # Simulate a private root-owned final directory nested under a
    # user-controlled ancestor. Reject before opening/creating backup files.
    original = submissions.Path.lstat

    def unsafe_ancestor_stat(path):
        result = original(path)
        if path == private or path == outer:
            class OwnerStat:
                st_mode = result.st_mode
                st_uid = 0 if path == private else 12345
            return OwnerStat()
        return result

    monkeypatch.setattr(submissions.Path, "lstat", unsafe_ancestor_stat)
    backup = private / "backup.db"
    with pytest.raises(SubmissionError, match="unsafe_backup_destination"):
        queue.backup(backup)
    assert not backup.exists()
    assert not list(private.glob(".repocache-backup-*"))


def test_backup_is_valid_and_never_overwrites_existing(tmp_path, monkeypatch):
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    queue = SubmissionQueue(parent / "state.db")
    item = {"os": {"id": "debian", "version": "13"},
            "repositories": [{"type": "apt-list",
                              "url": "https://mirror.example.org/debian/",
                              "insecure_http": False}]}
    queue.enqueue("k", "nonce", "digest", item, now=100)
    monkeypatch.setattr(submissions.os, "geteuid", lambda: 0)

    # CI workers are normally non-root; simulate a root-owned backup
    # directory at the Path.lstat trust check only. This is a synthetic
    # correctness test, NOT proof of actual root/SELinux permissions.
    original = submissions.Path.lstat
    def trusted_stat(path):
        result = original(path)
        if path == parent or path in parent.parents:
            # Simulate the complete trusted root-owned ancestor chain,
            # not just a private final directory under an untrusted path.
            class RootStat:
                st_mode = result.st_mode
                st_uid = 0
            return RootStat()
        return result
    monkeypatch.setattr(submissions.Path, "lstat", trusted_stat)
    backup = parent / "safe-backup.db"
    queue.backup(backup)
    assert backup.is_file()
    assert backup.stat().st_mode & 0o077 == 0
    with sqlite3.connect(backup) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT COUNT(*) FROM proposals").fetchone()[0] == 1
    with pytest.raises(SubmissionError):
        queue.backup(backup)


def test_sqlite_connection_closes_after_transaction(tmp_path):
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    queue = SubmissionQueue(root / "queue.db")
    with queue._connect() as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    # sqlite3.Connection's native context manager commits but does not close:
    # our wrapper must close explicitly to avoid leaking FDs under HTTP load.
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")


def _privileged_retention_queue(tmp_path, monkeypatch):
    """Synthetic root/journal setup; not native permission evidence."""
    from repocache import submission_decisions as decisions
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    journal_dir = tmp_path / "decisions"
    journal_dir.mkdir(mode=0o700)
    journal_dir.chmod(0o700)
    monkeypatch.setattr(decisions, "_trusted_dir", lambda _path: None)
    monkeypatch.setattr(decisions, "_verify_lock_fd", lambda _fd: None)
    monkeypatch.setattr(decisions, "_open_trusted", lambda path: os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)))
    queue = SubmissionQueue(parent / "state.db", journal_dir=journal_dir)
    monkeypatch.setattr(submissions.os, "geteuid", lambda: 0)
    return queue, decisions


def _retention_item():
    return {"os": {"id": "debian", "version": "13"},
            "repositories": [{"type": "apt-list",
                              "url": "https://mirror.example.org/debian/",
                              "insecure_http": False}]}


def test_retention_refuses_forged_sqlite_decision_without_root_receipt(
    tmp_path, monkeypatch
):
    queue, _decisions = _privileged_retention_queue(tmp_path, monkeypatch)
    ident = queue.enqueue("k", "nonce", "digest", _retention_item(), now=100)
    with queue._connect() as db:
        db.execute("UPDATE proposals SET state='REJECTED',version=1,"
                   " changed=100 WHERE id=?", (ident,))
    with pytest.raises(SubmissionError, match="unaudited_decision_state"):
        queue.maintain(approved=True, now=19_000_000, decided_retention_days=180)
    with queue._connect() as db:
        assert db.execute("SELECT state FROM proposals WHERE id=?",
                          (ident,)).fetchone() == ("REJECTED",)
        # A failed maintenance transaction must not delete replay history.
        assert db.execute("SELECT COUNT(*) FROM nonces").fetchone()[0] == 1


def test_retention_uses_root_receipt_time_not_intake_backdated_sqlite(
    tmp_path, monkeypatch
):
    queue, decisions = _privileged_retention_queue(tmp_path, monkeypatch)
    ident = queue.enqueue("k", "nonce", "digest", _retention_item(), now=100)
    with monkeypatch.context() as clock:
        clock.setattr(decisions.time, "time", lambda: 19_000_000)
        queue.decide(ident, "reject", expected_version=0)
    # Intake may backdate this convenience column but cannot backdate the
    # already-durable root receipt.
    with queue._connect() as db:
        db.execute("UPDATE proposals SET changed=100 WHERE id=?", (ident,))
    result = queue.maintain(approved=True, now=19_000_001,
                            decided_retention_days=180)
    assert result["purged_decided"] == 0
    with queue._connect() as db:
        assert db.execute("SELECT state FROM proposals WHERE id=?",
                          (ident,)).fetchone() == ("REJECTED",)
