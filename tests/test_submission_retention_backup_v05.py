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
    queue = SubmissionQueue(parent / "state.db")
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
    queue.decide(decided, "reject")
    # Force only this synthetic decided row to be older than the policy;
    # an actual operator still must authorize the retention change.
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
        if str(path) == str(parent):
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
