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
        return SimpleNamespace(st_mode=st.st_mode, st_uid=0,
                               st_nlink=st.st_nlink, st_size=st.st_size)

    monkeypatch.setattr(worker.os, "fstat", root_owned_fstat)
    return path


def _connection(responses):
    connection = object.__new__(worker.WorkerConnection)
    requests = []
    connection._send = lambda request: requests.append(request)
    if callable(responses):
        connection._recv = lambda *, deadline=None: responses()
    else:
        iterator = iter(responses)
        connection._recv = lambda *, deadline=None: next(iterator)
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


def test_backup_ipc_refuses_hardlinked_root_stage(tmp_path, monkeypatch):
    stage = _staging(tmp_path, monkeypatch)
    os.link(stage, stage.with_name("unexpected-second-link"))
    connection, requests = _connection([{"ok": True, "done": True}])
    with pytest.raises(worker.WorkerError, match="unsafe_backup_staging"):
        connection.backup_file(stage)
    assert requests == []


def test_backup_ipc_refuses_nonempty_root_stage(tmp_path, monkeypatch):
    stage = _staging(tmp_path, monkeypatch)
    stage.write_bytes(b"stale backup bytes")
    connection, requests = _connection([{"ok": True, "done": True}])
    with pytest.raises(worker.WorkerError, match="unsafe_backup_staging"):
        connection.backup_file(stage)
    assert requests == []
    assert stage.read_bytes() == b"stale backup bytes"


def test_backup_ipc_refuses_fifo_substitution_without_blocking(tmp_path, monkeypatch):
    stage = _staging(tmp_path, monkeypatch)
    original_open = os.open
    swapped = False

    def swap_before_open(file, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if os.fspath(file) == os.fspath(stage) and not swapped:
            swapped = True
            assert flags & os.O_NONBLOCK, "privileged backup must never block on a FIFO"
            stage.unlink()
            os.mkfifo(stage, mode=0o600)
        if dir_fd is None:
            return original_open(file, flags, mode)
        return original_open(file, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(worker.os, "open", swap_before_open)
    connection, requests = _connection([{"ok": True, "done": True}])
    with pytest.raises(worker.WorkerError, match="unsafe_backup_staging"):
        connection.backup_file(stage)
    assert swapped
    assert stage.is_fifo()
    assert requests == []


def test_backup_pipe_read_respects_remaining_overall_deadline(monkeypatch):
    """A final stalled frame cannot consume a fresh ten-second timeout."""
    connection = object.__new__(worker.WorkerConnection)
    connection.process = SimpleNamespace(stdout=SimpleNamespace(fileno=lambda: 77))
    connection._buffer = bytearray()
    ticks = iter((100.0, 100.0, 102.0))
    monkeypatch.setattr(worker, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    observed = []

    def stalled_pipe(readers, writers, errors, timeout):
        assert readers == [77] and not writers and not errors
        observed.append(timeout)
        return [], [], []

    monkeypatch.setattr(worker.select, "select", stalled_pipe)
    with pytest.raises(worker.WorkerError, match="worker_backup_timeout"):
        connection._recv(deadline=102.0)
    assert observed == [2.0]


def test_backup_ipc_reuses_one_deadline_across_all_frames(tmp_path, monkeypatch):
    stage = _staging(tmp_path, monkeypatch)
    connection, _ = _connection([
        {"ok": True, "chunk": base64.b64encode(b"data").decode("ascii")},
        {"ok": True, "done": True},
    ])
    original_recv = connection._recv
    deadlines = []

    def inspect_deadline(*, deadline=None):
        deadlines.append(deadline)
        return original_recv(deadline=deadline)

    connection._recv = inspect_deadline
    connection.backup_file(stage)
    assert len(deadlines) == 2
    assert isinstance(deadlines[0], float)
    assert deadlines[0] == deadlines[1]
    assert stage.read_bytes() == b"data"

def test_backup_deadline_includes_request_send_time(tmp_path, monkeypatch):
    """A slow request send consumes the same budget as all backup frames."""
    stage = _staging(tmp_path, monkeypatch)
    clock = {"now": 100.0}
    monkeypatch.setattr(worker, "time",
                        SimpleNamespace(monotonic=lambda: clock["now"]))
    connection, requests = _connection([
        {"ok": True, "chunk": base64.b64encode(b"valid").decode("ascii")},
        {"ok": True, "done": True},
    ])
    original_send = connection._send
    original_recv = connection._recv
    deadlines = []

    def delayed_send(request):
        original_send(request)
        clock["now"] += 9.0

    def inspect_recv(*, deadline=None):
        deadlines.append(deadline)
        return original_recv(deadline=deadline)

    connection._send = delayed_send
    connection._recv = inspect_recv
    connection.backup_file(stage)
    assert requests == [{"op": "backup"}]
    assert deadlines == [220.0, 220.0]
    assert stage.read_bytes() == b"valid"


def test_backup_refuses_send_that_exhausted_global_deadline(tmp_path, monkeypatch):
    """Never read frames after the absolute backup budget expires."""
    stage = _staging(tmp_path, monkeypatch)
    clock = {"now": 100.0}
    monkeypatch.setattr(worker, "time",
                        SimpleNamespace(monotonic=lambda: clock["now"]))
    connection, requests = _connection([])
    original_send = connection._send

    def stalled_send(request):
        original_send(request)
        clock["now"] += worker.BACKUP_TIMEOUT + 1

    connection._send = stalled_send
    connection._recv = lambda *, deadline=None: pytest.fail(
        "expired backup must not read any worker frames")
    with pytest.raises(worker.WorkerError, match="worker_backup_timeout"):
        connection.backup_file(stage)
    assert requests == [{"op": "backup"}]
    assert stage.stat().st_size == 0
