"""Gate A: root backup IPC must make bounded progress under a hostile worker.

Protocol-only tests: native UID/SELinux, filesystem and power-loss behavior
remain separately gated by #49. No release or service activation is involved.
"""
from __future__ import annotations

import base64
import os
from types import SimpleNamespace

import pytest

from repocache import submission_db_worker as worker


def _staging(tmp_path, monkeypatch):
    path = tmp_path / "private-backup-stage"
    path.write_bytes(b"")
    path.chmod(0o600)
    real_fstat = os.fstat

    def root_owned_fstat(fd):
        st = real_fstat(fd)
        return SimpleNamespace(st_mode=st.st_mode, st_uid=0)

    monkeypatch.setattr(worker.os, "fstat", root_owned_fstat)
    return path


def _connection(responses):
    connection = object.__new__(worker.WorkerConnection)
    requests = []
    connection._send = lambda request: requests.append(request)
    if callable(responses):
        connection._recv = responses
    else:
        iterator = iter(responses)
        connection._recv = lambda: next(iterator)
    return connection, requests


def test_backup_ipc_accepts_bounded_chunk_and_terminal_frame(tmp_path, monkeypatch):
    stage = _staging(tmp_path, monkeypatch)
    payload = b"SQLite format 3\x00" + b"x" * 16
    connection, requests = _connection([
        {"ok": True, "chunk": base64.b64encode(payload).decode("ascii")},
        {"ok": True, "done": True},
    ])
    connection.backup_file(stage)
    assert requests == [{"op": "backup"}]
    assert stage.read_bytes() == payload


def test_backup_ipc_rejects_empty_progress_frame(tmp_path, monkeypatch):
    stage = _staging(tmp_path, monkeypatch)
    connection, _ = _connection([{"ok": True, "chunk": ""}])
    with pytest.raises(worker.WorkerError, match="invalid_backup_chunk"):
        connection.backup_file(stage)
    assert stage.stat().st_size == 0


def test_backup_ipc_rejects_chunk_larger_than_child_protocol(tmp_path, monkeypatch):
    stage = _staging(tmp_path, monkeypatch)
    oversized = base64.b64encode(b"x" * (worker.BACKUP_CHUNK_SIZE + 1))
    connection, _ = _connection([
        {"ok": True, "chunk": oversized.decode("ascii")},
    ])
    with pytest.raises(worker.WorkerError, match="invalid_backup_chunk"):
        connection.backup_file(stage)


def test_backup_ipc_refuses_unbounded_tiny_frame_stream(tmp_path, monkeypatch):
    stage = _staging(tmp_path, monkeypatch)
    frame = {"ok": True, "chunk": base64.b64encode(b"x").decode("ascii")}
    seen = []

    def endless_worker():
        seen.append(1)
        return frame

    connection, _ = _connection(endless_worker)
    with pytest.raises(worker.WorkerError, match="too_many_worker_backup_chunks"):
        connection.backup_file(stage)
    assert len(seen) == worker.MAX_BACKUP_FRAMES + 1
    assert stage.stat().st_size == worker.MAX_BACKUP_FRAMES


def test_backup_ipc_enforces_total_deadline_across_progress(tmp_path, monkeypatch):
    stage = _staging(tmp_path, monkeypatch)
    frame = {"ok": True, "chunk": base64.b64encode(b"x").decode("ascii")}
    connection, _ = _connection([frame])
    ticks = iter((0, 0, worker.BACKUP_TIMEOUT + 1))
    monkeypatch.setattr(worker, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    with pytest.raises(worker.WorkerError, match="worker_backup_timeout"):
        connection.backup_file(stage)
    assert stage.stat().st_size == 0
