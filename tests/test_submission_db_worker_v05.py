"""Gate A: SQLite service-UID worker protocol and root path refusal.

These are synthetic protocol/negative tests. Actual setpriv UID transitions,
SELinux and host-side sidecar isolation require native Gate B (#49).
"""
from __future__ import annotations

import io
import json
import os
import sqlite3
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from repocache import submission_db_worker as worker, submissions
from repocache.submissions import SubmissionQueue, SubmissionError


def test_worker_protocol_executes_and_commits_only_with_service_identity(
    tmp_path, monkeypatch
):
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    path = parent / "queue.sqlite3"
    monkeypatch.setattr(
        worker, "_service_account",
        lambda: SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid()),
    )
    requests = [
        {"op": "ping"},
        {"op": "script", "sql": "CREATE TABLE example(value TEXT NOT NULL);"},
        {"op": "execute", "sql": "BEGIN IMMEDIATE", "params": []},
        {"op": "execute", "sql": "INSERT INTO example(value) VALUES(?)",
         "params": ["safe"]},
        {"op": "execute", "sql": "SELECT value FROM example", "params": []},
        {"op": "fetchone", "cursor": 3},
        {"op": "commit"},
    ]
    input_stream = io.BytesIO(
        b"".join((json.dumps(r) + "\n").encode() for r in requests)
    )
    output_stream = io.StringIO()
    monkeypatch.setattr(worker.sys, "stdin", SimpleNamespace(buffer=input_stream))
    monkeypatch.setattr(worker.sys, "stdout", output_stream)
    assert worker._worker_main(path) == 0
    replies = [json.loads(line) for line in output_stream.getvalue().splitlines()]
    assert len(replies) == len(requests)
    assert all(r["ok"] is True for r in replies)
    assert replies[5]["row"] == ["safe"]
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT value FROM example").fetchone() == ("safe",)


def test_worker_rejects_root_or_wrong_identity(tmp_path, monkeypatch):
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    monkeypatch.setattr(
        worker, "_service_account",
        lambda: SimpleNamespace(pw_uid=os.geteuid() + 12345,
                                pw_gid=os.getegid() + 12345),
    )
    assert worker._worker_main(parent / "queue.db") == 3
    assert not (parent / "queue.db").exists()


def test_root_sqlite_transport_never_opens_service_path_in_parent(
    tmp_path, monkeypatch
):
    queue = object.__new__(SubmissionQueue)
    queue.path = tmp_path / "untrusted.sqlite3"
    monkeypatch.setattr(queue, "_needs_worker", lambda: True)
    called = []

    class Stub:
        def __init__(self, path):
            called.append(path)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def execute(self, sql):
            return "delegated"

    monkeypatch.setattr(worker, "WorkerConnection", Stub)
    original_connect = submissions.sqlite3.connect

    def refuse_root_sqlite(path, *args, **kwargs):
        if str(path) == str(queue.path):
            raise AssertionError("root attempted to open service-owned SQLite")
        return original_connect(path, *args, **kwargs)

    monkeypatch.setattr(submissions.sqlite3, "connect", refuse_root_sqlite)
    with queue._connect() as db:
        assert db.execute("SELECT 1") == "delegated"
    assert called == [queue.path]


def test_worker_refuses_symlink_queue_and_untrusted_directory(tmp_path):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    link = directory / "queue.db"
    link.symlink_to(tmp_path / "target")
    with pytest.raises(worker.WorkerError, match="unsafe_worker_queue"):
        worker._check_queue(link, os.geteuid())
    directory.chmod(0o777)
    with pytest.raises(worker.WorkerError, match="unsafe_worker_directory"):
        worker._check_directory(directory, os.geteuid())


def test_worker_rejects_oversized_sql_and_malformed_cursor_without_ipc():
    connection = object.__new__(worker.WorkerConnection)
    with pytest.raises(worker.WorkerError, match="invalid_worker_sql"):
        connection.execute("A" * (worker.MAX_SQL + 1))
    connection._request = lambda request: {"cursor": "bad", "rowcount": 0}
    with pytest.raises(worker.WorkerError, match="invalid_worker_cursor"):
        connection.execute("SELECT 1")


def test_operator_root_guard_cannot_use_arbitrary_service_uid(tmp_path, monkeypatch):
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    queue = object.__new__(SubmissionQueue)
    queue.path = parent / "queue.db"
    # Simulate actual root without ever granting root in the test process.
    monkeypatch.setattr(submissions, "_REAL_GETEUID", lambda: 0)
    monkeypatch.setattr(submissions.os, "geteuid", lambda: 0)
    if parent.stat().st_uid != 0:
        monkeypatch.setattr(worker, "_service_account",
                            lambda: SimpleNamespace(pw_uid=parent.stat().st_uid + 1))
        with pytest.raises(SubmissionError, match="unsafe_store"):
            queue._needs_worker()


def test_root_refuses_relative_queue_path_before_sqlite(monkeypatch):
    queue = object.__new__(SubmissionQueue)
    queue.path = Path("relative-queue.db")
    monkeypatch.setattr(submissions, "_REAL_GETEUID", lambda: 0)
    monkeypatch.setattr(submissions.os, "geteuid", lambda: 0)
    with pytest.raises(SubmissionError, match="unsafe_store_path"):
        queue._needs_worker()


def test_privileged_worker_ipc_write_is_bounded_and_handles_partial_writes(
    monkeypatch
):
    connection = object.__new__(worker.WorkerConnection)
    connection.process = SimpleNamespace(
        stdin=SimpleNamespace(fileno=lambda: 77)
    )
    writes = []
    monkeypatch.setattr(
        worker.select, "select", lambda readers, writers, errors, timeout:
        ([], writers, []),
    )

    def short_write(fd, payload):
        assert fd == 77
        chunk = bytes(payload[:3])
        writes.append(chunk)
        return len(chunk)

    monkeypatch.setattr(worker.os, "write", short_write)
    connection._send({"op": "ping"})
    assert b"".join(writes) == b'{"op":"ping"}\n'


def test_privileged_worker_ipc_send_refuses_stalled_pipe(monkeypatch):
    connection = object.__new__(worker.WorkerConnection)
    connection.process = SimpleNamespace(
        stdin=SimpleNamespace(fileno=lambda: 77)
    )
    monkeypatch.setattr(
        worker.select, "select", lambda readers, writers, errors, timeout:
        ([], [], []),
    )
    monkeypatch.setattr(
        worker.os, "write", lambda *args: pytest.fail("must not write"),
    )
    with pytest.raises(worker.WorkerError, match="worker_send_timeout"):
        connection._send({"op": "ping"})


def test_privileged_worker_ipc_send_handles_full_pipe_until_deadline(
    monkeypatch
):
    connection = object.__new__(worker.WorkerConnection)
    connection.process = SimpleNamespace(
        stdin=SimpleNamespace(fileno=lambda: 77)
    )
    ticks = iter((0, 1, 11))
    monkeypatch.setattr(worker, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    monkeypatch.setattr(
        worker.select, "select", lambda readers, writers, errors, timeout:
        ([], writers, []),
    )

    def full_pipe(*args):
        raise BlockingIOError()

    monkeypatch.setattr(worker.os, "write", full_pipe)
    with pytest.raises(worker.WorkerError, match="worker_send_timeout"):
        connection._send({"op": "ping"})
