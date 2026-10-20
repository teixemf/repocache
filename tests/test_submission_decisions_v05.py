"""Issue #57: administrator receipts stay independent of intake-writable SQLite.

Root identity/ownership are simulated only in the positive CI fixtures.
Negative tests exercise real mode/owner validators without bypassing them.
Live systemd/SELinux/UID testing remains exclusively in #49.
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from repocache import submission_decisions as decisions, submissions
from repocache.submission_decisions import DecisionError, DecisionJournal
from repocache.submissions import SubmissionError, SubmissionQueue

ITEM = {
    "os": {"id": "debian", "version": "13"},
    "repositories": [{"type": "apt-list",
                      "url": "https://mirror.example.org/debian/",
                      "insecure_http": False}],
}


@pytest.fixture
def setup(tmp_path, monkeypatch):
    private = tmp_path / "intake"
    protected = tmp_path / "root-journal"
    for directory in (private, protected):
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
    queue = SubmissionQueue(private / "queue.db", journal_dir=protected)
    ident = queue.enqueue("keyhash", "nonce", "digest", ITEM, now=100000)
    # Positive tests simulate a root operator on a non-root CI worker.
    monkeypatch.setattr(submissions.os, "geteuid", lambda: 0)
    monkeypatch.setattr(decisions, "_trusted_dir", lambda _path: None)
    monkeypatch.setattr(decisions, "_verify_lock_fd", lambda _fd: None)
    monkeypatch.setattr(decisions, "_open_trusted", lambda path: os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)))
    return queue, ident, protected


def test_receipts_are_durable_chain_and_independent_of_writable_audit(setup):
    queue, ident, protected = setup
    assert queue.pending()[0]["version"] == 0
    queue.decide(ident, "review", expected_version=0)
    assert queue.audit(ident)[0][0] == "review"
    with queue._connect() as db:
        db.execute("DELETE FROM audit")
        db.execute("INSERT INTO audit(proposal_id,changed,actor_uid,action,result) "
                   "VALUES(?,?,?,?,?)",
                   (ident, 100, 0, "reopen", "PENDING"))
    # Root receipts, not the intake-controlled audit convenience table,
    # determine the verified administrative outcome.
    assert [r[0] for r in queue.audit(ident)] == ["review"]
    assert queue.pending() == []
    receipts = list(protected.glob(f"{ident}.*.json"))
    assert len(receipts) == 1
    assert receipts[0].stat().st_mode & 0o077 == 0
    queue.decide(ident, "reopen", expected_version=1)
    queue.decide(ident, "reject", expected_version=2)
    chain = DecisionJournal(protected).read(ident)
    assert [r["action"] for r in chain] == ["review", "reopen", "reject"]
    assert chain[1]["previous_hash"] == chain[0]["hash"]
    assert chain[2]["previous_hash"] == chain[1]["hash"]
    assert queue.audit(ident)[-1][0] == "reject"


def test_attacker_cannot_forge_approved_state_using_sqlite(setup):
    queue, ident, _ = setup
    with queue._connect() as db:
        db.execute("UPDATE proposals SET state='REVIEWED',version=1 WHERE id=?", (ident,))
        db.execute("INSERT INTO audit(proposal_id,changed,actor_uid,action,result) "
                   "VALUES(?,?,?,?,?)", (ident, 10, 0, "review", "REVIEWED"))
    # Trustworthy history remains empty. No DB-only decision is accepted.
    assert queue.audit(ident) == []
    with pytest.raises(SubmissionError, match="unaudited_decision_state"):
        queue.decide(ident, "reopen", expected_version=1)


def test_restored_old_state_cannot_erase_valid_receipt(setup):
    queue, ident, _ = setup
    queue.decide(ident, "reject", expected_version=0)
    # A rollback/replaced service DB may roll back the mutable row.
    with queue._connect() as db:
        db.execute("UPDATE proposals SET state='PENDING',version=0 WHERE id=?", (ident,))
    with pytest.raises(SubmissionError, match="decision_reconcile_required"):
        queue.pending()
    assert queue.audit(ident)[0][0] == "reject"
    queue.reconcile(ident, approved=True)
    assert queue.pending() == []
    with queue._connect() as db:
        row = db.execute("SELECT state,version FROM proposals WHERE id=?", (ident,)).fetchone()
    assert row == ("REJECTED", 1)


def test_failed_sqlite_commit_has_no_phantom_success_and_can_reconcile(setup):
    queue, ident, _ = setup
    with queue._connect() as db:
        db.execute("CREATE TRIGGER deny_update BEFORE UPDATE ON proposals "
                   "BEGIN SELECT RAISE(ABORT, 'synthetic disk error'); END")
    with pytest.raises(SubmissionError, match="decision_reconcile_required"):
        queue.decide(ident, "review", expected_version=0)
    assert queue.audit(ident)[0][0] == "review"
    with pytest.raises(SubmissionError, match="decision_reconcile_required"):
        queue.pending()
    with pytest.raises(SubmissionError, match="operator_approval_required"):
        queue.reconcile(ident, approved=False)
    with queue._connect() as db:
        db.execute("DROP TRIGGER deny_update")
    queue.reconcile(ident, approved=True)
    assert queue.pending() == []
    with queue._connect() as db:
        assert db.execute("SELECT state,version FROM proposals WHERE id=?",
                          (ident,)).fetchone() == ("REVIEWED", 1)


def test_metadata_tampering_blocks_new_admin_decision(setup):
    queue, ident, _ = setup
    queue.decide(ident, "review", expected_version=0)
    with queue._connect() as db:
        db.execute("UPDATE proposals SET items=? WHERE id=?", ("[]", ident))
    with pytest.raises(SubmissionError, match="decision_reconcile_required"):
        queue.decide(ident, "reopen", expected_version=1)
    with pytest.raises(SubmissionError, match="decision_metadata_conflict"):
        queue.reconcile(ident, approved=True)
    assert queue.audit(ident)[0][0] == "review"


def test_journal_tamper_and_missing_history_fail_closed(setup):
    queue, ident, directory = setup
    queue.decide(ident, "review", expected_version=0)
    queue.decide(ident, "reopen", expected_version=1)
    receipt = directory / f"{ident}.0001.json"
    changed = receipt.read_text().replace('"state":"REVIEWED"', '"state":"PENDING"')
    receipt.write_text(changed)
    with pytest.raises(SubmissionError, match="decision_journal_corrupt"):
        queue.audit(ident)
    receipt.unlink()
    with pytest.raises(SubmissionError, match="decision_journal_gap"):
        queue.audit(ident)


def test_root_owned_directory_is_mandatory_without_fixture_override(tmp_path, monkeypatch):
    root_dir = tmp_path / "not-owned-by-root"
    root_dir.mkdir(mode=0o700)
    root_dir.chmod(0o700)
    # This tests *real* mode/UID checking; current CI runner does not own
    # root-only directory. A privileged runner might actually be root.
    monkeypatch.setattr(decisions.os, "geteuid", lambda: 0)
    root_info = root_dir.lstat()
    if root_info.st_uid != 0:
        with pytest.raises(DecisionError, match="unsafe_decision_directory"):
            with DecisionJournal(root_dir).locked():
                pass
    root_dir.chmod(0o777)
    with pytest.raises(DecisionError, match="unsafe_decision_directory"):
        with DecisionJournal(root_dir).locked():
            pass


def test_nonroot_cannot_access_root_decision_journal(setup, monkeypatch):
    queue, ident, _ = setup
    monkeypatch.setattr(decisions.os, "geteuid", lambda: 1001)
    with pytest.raises(SubmissionError, match="operator_required"):
        queue.audit(ident)
    with pytest.raises(SubmissionError, match="operator_required"):
        queue.decide(ident, "review", expected_version=0)
