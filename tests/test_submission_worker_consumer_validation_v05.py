"""SEC-169-01: hostile worker row projections fail closed in root consumers.

The synthetic fixtures use a real SQLite queue and root decision journal with
a deliberately forged result cursor. They do NOT exercise real setpriv,
worker process termination, booted systemd or SELinux (issue #49).
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from repocache import submission_decisions as decisions, submissions
from repocache.submissions import SubmissionError, SubmissionQueue


@pytest.fixture
def operator_queue(tmp_path, monkeypatch):
    private = tmp_path / "intake"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    journal = tmp_path / "root-decisions"
    journal.mkdir(mode=0o700)
    journal.chmod(0o700)

    # Simulate the root identity, not native root/service UID confinement.
    monkeypatch.setattr(decisions, "_trusted_dir", lambda _path: None)
    monkeypatch.setattr(decisions, "_verify_lock_fd", lambda _fd: None)
    monkeypatch.setattr(
        decisions, "_open_trusted",
        lambda path: os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)),
    )
    queue = SubmissionQueue(private / "queue.sqlite3", journal_dir=journal)
    item = {
        "os": {"id": "debian", "version": "13"},
        "repositories": [{
            "type": "apt-list", "url": "https://mirror.example.org/debian/",
            "insecure_http": False,
        }],
    }
    ident = queue.enqueue("key", "nonce", "digest", item, now=100000)
    monkeypatch.setattr(submissions.os, "geteuid", lambda: 0)
    return queue, ident


def _row(queue, ident):
    with queue._connect() as db:
        return db.execute(
            "SELECT id,os_id,os_version,items,created,state,version "
            "FROM proposals WHERE id=?", (ident,),
        ).fetchone()


def _tamper(row, mutation):
    fields = list(row)
    if mutation == "truncated":
        return tuple(fields[:3])
    if mutation == "extra_column":
        return tuple(fields + ["unexpected"])
    if mutation == "wrong_id":
        fields[0] = "f" * 32 if fields[0] != "f" * 32 else "e" * 32
    elif mutation == "invalid_id":
        fields[0] = "not-an-id"
    elif mutation == "wrong_platform":
        fields[1] = "ubuntu"
    elif mutation == "wrong_os_version":
        fields[2] = "14"
    elif mutation == "wrong_items":
        fields[3] = None
    elif mutation == "wrong_created_type":
        fields[4] = str(fields[4])
    elif mutation == "wrong_state_type":
        fields[5] = 123
    elif mutation == "wrong_version_type":
        fields[6] = True
    elif mutation == "negative_version":
        fields[6] = -1
    else:
        raise AssertionError(mutation)
    return tuple(fields)


def _inject_result(queue, monkeypatch, *, statement, response, operation):
    """Replace only a selected SQLite projection; retain real transactions."""
    original = queue._connect
    cleanup = []

    @contextmanager
    def hostile_connect():
        try:
            with original() as db:
                class Proxy:
                    def execute(self, sql, params=()):
                        result = db.execute(sql, params)
                        if statement in sql:
                            if operation == "fetchone":
                                return SimpleNamespace(fetchone=lambda: response)
                            return SimpleNamespace(fetchall=lambda: response)
                        return result

                yield Proxy()
        finally:
            # Verifies the consumer leaves its DB context on errors, not that
            # a real subprocess was killed; actual UID/process tests are #49.
            cleanup.append(True)

    monkeypatch.setattr(queue, "_connect", hostile_connect)
    return original, cleanup


@pytest.mark.parametrize("mutation", [
    "truncated", "extra_column", "wrong_id", "invalid_id",
    "wrong_platform", "wrong_os_version", "wrong_items",
    "wrong_created_type", "wrong_state_type", "wrong_version_type",
    "negative_version",
])
def test_decide_rejects_hostile_worker_row_before_journal_append(
    operator_queue, monkeypatch, mutation,
):
    queue, ident = operator_queue
    poisoned = _tamper(_row(queue, ident), mutation)
    real_connect, cleanup = _inject_result(
        queue, monkeypatch, statement="FROM proposals WHERE id=?",
        response=poisoned, operation="fetchone",
    )
    with pytest.raises(SubmissionError) as exc:
        queue.decide(ident, "review", expected_version=0)
    assert (exc.value.code, exc.value.status) == ("invalid_stored_proposal", 503)
    assert cleanup == [True]
    assert queue.audit(ident) == []
    with real_connect() as db:
        assert db.execute(
            "SELECT state,version FROM proposals WHERE id=?", (ident,)
        ).fetchone() == ("PENDING", 0)


@pytest.mark.parametrize("mutation", ["truncated", "wrong_platform", "wrong_version_type"])
def test_pending_rejects_invalid_fixed_projection(operator_queue, monkeypatch, mutation):
    queue, ident = operator_queue
    poisoned = _tamper(_row(queue, ident), mutation)
    _real, cleanup = _inject_result(
        queue, monkeypatch, statement="WHERE state='PENDING' ORDER BY",
        response=[poisoned], operation="fetchall",
    )
    with pytest.raises(SubmissionError) as exc:
        queue.pending()
    assert (exc.value.code, exc.value.status) == ("invalid_stored_proposal", 503)
    assert cleanup == [True]
    assert queue.audit(ident) == []


@pytest.mark.parametrize("decided_row", [
    ("f" * 32, "REVIEWED"),                 # truncated projection
    ("f" * 32, "PENDING", 1),              # WHERE clause contradicted
    ("f" * 32, "REVIEWED", True),          # bool is not SQLite version
])
def test_pending_rejects_forged_decided_preflight(
    operator_queue, monkeypatch, decided_row,
):
    queue, ident = operator_queue
    _real, cleanup = _inject_result(
        queue, monkeypatch, statement="WHERE (state!='PENDING' OR state IS NULL)",
        response=[decided_row], operation="fetchall",
    )
    with pytest.raises(SubmissionError) as exc:
        queue.pending()
    assert (exc.value.code, exc.value.status) == ("unaudited_decision_state", 503)
    assert cleanup == [True]
    assert queue.audit(ident) == []


@pytest.mark.parametrize("mutation", ["truncated", "wrong_id", "wrong_created_type"])
def test_reconcile_rejects_bad_worker_row_without_state_change(
    operator_queue, monkeypatch, mutation,
):
    queue, ident = operator_queue
    queue.decide(ident, "review", expected_version=0)
    row = _row(queue, ident)
    real_connect, cleanup = _inject_result(
        queue, monkeypatch, statement="FROM proposals WHERE id=?",
        response=_tamper(row, mutation), operation="fetchone",
    )
    with pytest.raises(SubmissionError) as exc:
        queue.reconcile(ident, approved=True)
    assert (exc.value.code, exc.value.status) == ("invalid_stored_proposal", 503)
    assert cleanup == [True]
    assert len(queue.audit(ident)) == 1
    with real_connect() as db:
        assert db.execute(
            "SELECT state,version FROM proposals WHERE id=?", (ident,)
        ).fetchone() == ("REVIEWED", 1)


@pytest.mark.parametrize("mutation", ["truncated", "wrong_id", "wrong_state_type"])
def test_maintain_rejects_bad_worker_row_without_purge(
    operator_queue, monkeypatch, mutation,
):
    queue, ident = operator_queue
    queue.decide(ident, "reject", expected_version=0)
    poisoned = _tamper(_row(queue, ident), mutation)
    real_connect, cleanup = _inject_result(
        queue, monkeypatch, statement="WHERE state!='PENDING' AND changed <",
        response=[poisoned], operation="fetchall",
    )
    with pytest.raises(SubmissionError) as exc:
        queue.maintain(approved=True, now=2_000_000_000, decided_retention_days=180)
    # The new unique-ID preflight rejects even a syntactically valid
    # forged ID before consulting the root journal. All malformed worker
    # projections now fail with the same conservative storage error.
    assert (exc.value.code, exc.value.status) == ("invalid_stored_proposal", 503)
    assert cleanup == [True]
    assert len(queue.audit(ident)) == 1
    with real_connect() as db:
        assert db.execute(
            "SELECT state,version FROM proposals WHERE id=?", (ident,)
        ).fetchone() == ("REJECTED", 1)
        assert db.execute("SELECT COUNT(*) FROM nonces").fetchone()[0] == 1


def test_legitimate_fixed_projections_remain_usable(operator_queue):
    queue, ident = operator_queue
    proposals = queue.pending()
    assert [proposal["id"] for proposal in proposals] == [ident]
    queue.decide(ident, "review", expected_version=0)
    assert queue.pending() == []
    assert queue.audit(ident)[0][1] == "REVIEWED"
    queue.reconcile(ident, approved=True)


@pytest.mark.parametrize("field,value", [
    ("items", '[{"type":"apt-list","url":"https://mirror.example.org/changed/","insecure_http":false}]'),
    ("os_version", "13.1"),
    ("created", 100001),
])
def test_pending_refuses_decided_metadata_drift_against_root_receipt(
    operator_queue, field, value,
):
    queue, ident = operator_queue
    queue.decide(ident, "review", expected_version=0)
    with queue._connect() as db:
        # Fixed test-only column names; a compromised intake UID may mutate
        # these columns without being able to edit the protected root receipt.
        db.execute(f"UPDATE proposals SET {field}=? WHERE id=?", (value, ident))
    with pytest.raises(SubmissionError) as exc:
        queue.pending()
    assert (exc.value.code, exc.value.status) == ("unaudited_decision_state", 503)
    assert queue.audit(ident)[0][1] == "REVIEWED"


def test_pending_refuses_replayed_decided_worker_page(operator_queue, monkeypatch):
    queue, ident = operator_queue
    queue.decide(ident, "review", expected_version=0)
    decided = _row(queue, ident)
    _real, cleanup = _inject_result(
        queue, monkeypatch, statement="WHERE (state!='PENDING' OR state IS NULL)",
        response=[decided, decided], operation="fetchall",
    )
    with pytest.raises(SubmissionError) as exc:
        queue.pending()
    assert (exc.value.code, exc.value.status) == ("unaudited_decision_state", 503)
    assert cleanup == [True]


def test_pending_refuses_oversized_decided_worker_page(operator_queue, monkeypatch):
    queue, ident = operator_queue
    queue.decide(ident, "reject", expected_version=0)
    decided = _row(queue, ident)
    _real, cleanup = _inject_result(
        queue, monkeypatch, statement="WHERE (state!='PENDING' OR state IS NULL)",
        response=[decided] * 65, operation="fetchall",
    )
    with pytest.raises(SubmissionError) as exc:
        queue.pending()
    assert (exc.value.code, exc.value.status) == ("unaudited_decision_state", 503)
    assert cleanup == [True]


@pytest.mark.parametrize("field,value", [
    ("state", None),
    ("id", None),
    ("id", ""),
])
def test_pending_refuses_decided_row_hidden_by_compromised_sqlite_schema(
    operator_queue, field, value,
):
    """Intake-writable SQLite schema can be replaced, removing constraints.

    NULL state is excluded by SQL equality/inequality. NULL/empty IDs sort
    before a keyset cursor initialized to an empty string. None may hide a
    forged decision from root. This is synthetic, not native UID proof.
    """
    queue, ident = operator_queue
    with queue._connect() as db:
        db.executescript("""
            ALTER TABLE proposals RENAME TO original_proposals;
            CREATE TABLE proposals AS SELECT * FROM original_proposals WHERE 0;
            INSERT INTO proposals SELECT * FROM original_proposals;
            DROP TABLE original_proposals;
        """)
        db.execute("UPDATE proposals SET state='REVIEWED' WHERE id=?", (ident,))
        db.execute(f"UPDATE proposals SET {field}=? WHERE id=?", (value, ident))
        if field == "state":
            assert db.execute(
                "SELECT COUNT(*) FROM proposals WHERE state='PENDING' OR state!='PENDING'"
            ).fetchone()[0] == 0
    with pytest.raises(SubmissionError) as exc:
        queue.pending()
    assert (exc.value.code, exc.value.status) == ("unaudited_decision_state", 503)
    assert queue.audit(ident) == []


@pytest.mark.parametrize("operation", ["decide", "reconcile", "maintain"])
def test_root_refuses_duplicate_ids_after_intake_drops_primary_key(
    operator_queue, operation,
):
    """One journal receipt must never authorize two service-owned SQL rows.

    A compromised intake UID can replace the table and remove its PRIMARY
    KEY. The pre-fix decision UPDATE affected both rows; retention DELETE
    could even remove a PENDING duplicate when purging a decided row.
    """
    queue, ident = operator_queue
    if operation != "decide":
        queue.decide(ident, "review", expected_version=0)
    before_audit = queue.audit(ident)

    with queue._connect() as db:
        db.executescript("""
            ALTER TABLE proposals RENAME TO original_proposals;
            CREATE TABLE proposals AS SELECT * FROM original_proposals;
            DROP TABLE original_proposals;
        """)
        if operation == "maintain":
            # Only the authorized decided row is expired. The second row is
            # PENDING, but DELETE WHERE id=? would previously remove both.
            db.execute("UPDATE proposals SET changed=0 WHERE id=?", (ident,))
            db.execute(
                "INSERT INTO proposals "
                "SELECT id,os_id,os_version,items,'PENDING',0,created,0 "
                "FROM proposals WHERE id=?", (ident,),
            )
        else:
            db.execute(
                "INSERT INTO proposals SELECT * FROM proposals WHERE id=?",
                (ident,),
            )
        assert db.execute(
            "SELECT COUNT(*) FROM proposals WHERE id=?", (ident,),
        ).fetchone()[0] == 2

    with pytest.raises(SubmissionError) as exc:
        if operation == "decide":
            queue.decide(ident, "review", expected_version=0)
        elif operation == "reconcile":
            queue.reconcile(ident, approved=True)
        else:
            queue.maintain(
                approved=True, now=2_000_000_000, decided_retention_days=180,
            )
    assert (exc.value.code, exc.value.status) == ("invalid_stored_proposal", 503)
    assert queue.audit(ident) == before_audit
    with queue._connect() as db:
        rows = db.execute(
            "SELECT state,version FROM proposals WHERE id=? ORDER BY rowid",
            (ident,),
        ).fetchall()
        assert len(rows) == 2
        if operation == "decide":
            assert rows == [("PENDING", 0), ("PENDING", 0)]
        elif operation == "reconcile":
            assert rows == [("REVIEWED", 1), ("REVIEWED", 1)]
        else:
            assert rows == [("REVIEWED", 1), ("PENDING", 0)]
            assert db.execute("SELECT COUNT(*) FROM nonces").fetchone()[0] == 1
