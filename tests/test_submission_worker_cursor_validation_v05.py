"""Gate A: malformed service-UID SQLite IPC rows must fail closed (#17/#57).

These protocol-only tests do not prove native SELinux, live credentials,
production backup custody or owner-signed release acceptance.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from repocache import submission_db_worker as worker


def _cursor(reply: dict, *, operation: str) -> worker.WorkerCursor:
    def request(message):
        assert message == {"op": operation, "cursor": 7}
        return reply

    return worker.WorkerCursor(SimpleNamespace(_request=request), 7, 0)


@pytest.mark.parametrize("reply, expected", [
    ({"ok": True, "row": None}, None),
    ({"ok": True, "row": []}, ()),
    ({"ok": True, "row": ["a", 1, 2.5, None]}, ("a", 1, 2.5, None)),
])
def test_worker_fetchone_accepts_sqlite_row_or_explicit_null(reply, expected):
    assert _cursor(reply, operation="fetchone").fetchone() == expected


@pytest.mark.parametrize("reply", [
    {"ok": True},
    {"ok": True, "row": False},
    {"ok": True, "row": 0},
    {"ok": True, "row": "not a row"},
    {"ok": True, "row": {"id": "forged"}},
    {"ok": True, "row": ["id", {"unexpected": "nested"}]},
    {"ok": True, "row": [True]},
    {"ok": True, "row": [float("nan")]},
    {"ok": True, "row": [float("inf")]},
    {"ok": True, "row": [float("-inf")]},
    {"ok": True, "row": None, "ignored": "metadata"},
])
def test_worker_fetchone_never_treats_malformed_reply_as_missing_proposal(reply):
    with pytest.raises(worker.WorkerError, match="invalid_worker_row"):
        _cursor(reply, operation="fetchone").fetchone()


@pytest.mark.parametrize("reply, expected", [
    ({"ok": True, "rows": []}, []),
    ({"ok": True, "rows": [["a", 1], ["b", None]]},
     [("a", 1), ("b", None)]),
])
def test_worker_fetchall_accepts_only_sqlite_row_lists(reply, expected):
    assert _cursor(reply, operation="fetchall").fetchall() == expected


@pytest.mark.parametrize("reply", [
    {"ok": True},
    {"ok": True, "rows": None},
    {"ok": True, "rows": {"id": "forged"}},
    {"ok": True, "rows": ["not a row"]},
    {"ok": True, "rows": [[1], None]},
    {"ok": True, "rows": [[1], {"unexpected": "nested"}]},
    {"ok": True, "rows": [[1], [[2]]]},
    {"ok": True, "rows": [[1]], "ignored": "metadata"},
    {"ok": True, "rows": [[float("nan")]]},
    {"ok": True, "rows": [[float("inf")]]},
])
def test_worker_fetchall_rejects_entire_malformed_result(reply):
    with pytest.raises(worker.WorkerError, match="invalid_worker_rows"):
        _cursor(reply, operation="fetchall").fetchall()


@pytest.mark.parametrize("reply", [
    {"ok": True, "cursor": 0, "rowcount": -1},
    {"ok": True, "cursor": -1, "rowcount": 0},
    {"ok": True, "cursor": 1, "rowcount": -2},
    {"ok": True, "cursor": True, "rowcount": 0},
    {"ok": True, "cursor": 1, "rowcount": False},
    {"ok": True, "cursor": 1, "rowcount": 0, "ignored": "forged"},
    {"ok": False, "cursor": 1, "rowcount": 0},
])
def test_worker_execute_rejects_forged_control_reply(reply):
    """Root must not trust malformed service-UID cursor acknowledgements."""
    connection = object.__new__(worker.WorkerConnection)
    connection._request = lambda _request: reply
    with pytest.raises(worker.WorkerError, match="invalid_worker_cursor"):
        connection.execute("SELECT 1")


def test_worker_execute_accepts_real_sqlite_cursor_semantics():
    connection = object.__new__(worker.WorkerConnection)
    connection._request = lambda _request: {
        "ok": True, "cursor": 1, "rowcount": -1,
    }
    cursor = connection.execute("SELECT 1")
    assert cursor.cursor == 1
    assert cursor.rowcount == -1


@pytest.mark.parametrize("reply", [
    {"ok": True, "ignored": "forged"},
    {"ok": False},
    {},
])
def test_worker_script_refuses_ambiguous_ack(reply):
    connection = object.__new__(worker.WorkerConnection)
    connection._request = lambda _request: reply
    with pytest.raises(worker.WorkerError, match="invalid_worker_ack"):
        connection.executescript("CREATE TABLE example(value INTEGER);")


def test_worker_script_accepts_exact_ack():
    connection = object.__new__(worker.WorkerConnection)
    requests = []
    connection._request = lambda request: requests.append(request) or {"ok": True}
    connection.executescript("CREATE TABLE example(value INTEGER);")
    assert requests == [{"op": "script", "sql": "CREATE TABLE example(value INTEGER);"}]


@pytest.mark.parametrize("reply", [
    {"ok": True, "ignored": "forged"},
    {"ok": False},
    {},
])
def test_worker_commit_refuses_ambiguous_ack(reply):
    connection = object.__new__(worker.WorkerConnection)
    connection._closed = False
    connection._request = lambda _request: reply
    connection.process = SimpleNamespace(
        stdin=None, stdout=None, wait=lambda timeout: None, returncode=0,
    )
    with pytest.raises(worker.WorkerError, match="invalid_worker_ack"):
        connection.close(commit=True)
    assert connection._closed


def test_worker_rollback_accepts_exact_ack():
    connection = object.__new__(worker.WorkerConnection)
    connection._closed = False
    requests = []
    connection._request = lambda request: requests.append(request) or {"ok": True}
    connection.process = SimpleNamespace(
        stdin=None, stdout=None, wait=lambda timeout: None, returncode=0,
    )
    connection.close(commit=False)
    assert requests == [{"op": "rollback"}]
    assert connection._closed
