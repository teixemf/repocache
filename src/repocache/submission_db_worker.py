"""Privilege-separated SQLite transport for root administrator operations.

The root UI and journal never open a service-UID-writable SQLite database or
its sidecars. A fixed root-owned setpriv binary drops to the dedicated intake
UID *before* importing SQLite and opening the queue. The child has no access
to the root-owned decision journal. This is an IPC trust boundary, not a claim
that intake-owned proposal data is authentic or durable.

No worker is installed as a service; each connection is a short-lived process.
Native systemd/SELinux, binary ownership and UID tests remain Gate B (#49).
"""
from __future__ import annotations

import base64
import json
import os
import pwd
import select
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path

SETPRIV = Path("/usr/bin/setpriv")
SERVICE_USER = "repocache-intake"
MAX_MESSAGE = 16 * 1024 * 1024
MAX_BACKUP = 128 * 1024 * 1024
BACKUP_CHUNK_SIZE = 65536
MAX_BACKUP_FRAMES = (MAX_BACKUP + BACKUP_CHUNK_SIZE - 1) // BACKUP_CHUNK_SIZE
BACKUP_TIMEOUT = 120  # Overall deadline; per-message TIMEOUT alone is insufficient.
MAX_SQL = 8192
TIMEOUT = 10


class WorkerError(sqlite3.OperationalError):
    """Fail closed on missing/compromised privilege separation or IPC."""


def _service_account():
    try:
        account = pwd.getpwnam(SERVICE_USER)
    except KeyError as exc:
        raise WorkerError("service_identity_missing") from exc
    if account.pw_uid <= 0 or account.pw_gid <= 0:
        raise WorkerError("unsafe_service_identity")
    return account


def _check_directory(path: Path, uid: int) -> None:
    try:
        st = path.lstat()
    except OSError as exc:
        raise WorkerError("unsafe_worker_directory") from exc
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid or st.st_mode & 0o077:
        raise WorkerError("unsafe_worker_directory")


def _check_binary(path: Path) -> None:
    try:
        st = path.lstat()
    except OSError as exc:
        raise WorkerError("worker_binary_unavailable") from exc
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise WorkerError("unsafe_worker_binary")


def _check_queue(path: Path, uid: int) -> None:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise WorkerError("unsafe_worker_queue") from exc
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != uid or
            st.st_mode & 0o077 or st.st_size > MAX_BACKUP):
        raise WorkerError("unsafe_worker_queue")


class WorkerCursor:
    def __init__(self, owner: "WorkerConnection", cursor: int, rowcount: int):
        self.owner = owner
        self.cursor = cursor
        self.rowcount = rowcount

    def fetchone(self):
        result = self.owner._request({"op": "fetchone", "cursor": self.cursor})
        row = result.get("row")
        return tuple(row) if isinstance(row, list) else None

    def fetchall(self):
        result = self.owner._request({"op": "fetchall", "cursor": self.cursor})
        rows = result.get("rows")
        if not isinstance(rows, list):
            raise WorkerError("invalid_worker_rows")
        return [tuple(row) for row in rows]


class WorkerConnection:
    """SQLite-like connection; all SQL executes after the child drops UID."""

    def __init__(self, path: Path):
        if os.geteuid() != 0:
            raise WorkerError("operator_required")
        self.path = Path(path)
        account = _service_account()
        _check_directory(self.path.parent, account.pw_uid)
        _check_queue(self.path, account.pw_uid)
        _check_binary(SETPRIV)
        # A local venv must be root-managed; no PYTHONPATH, user site, shell
        # or ambient proxy/credentials are inherited by the service worker.
        executable = Path(sys.executable)
        try:
            resolved = executable.resolve(strict=True)
            exe_stat = resolved.stat()
            venv_parent = executable.parent.lstat()
        except OSError as exc:
            raise WorkerError("unsafe_worker_python") from exc
        if (not stat.S_ISREG(exe_stat.st_mode) or exe_stat.st_uid != 0 or
                exe_stat.st_mode & 0o022 or
                not stat.S_ISDIR(venv_parent.st_mode) or
                venv_parent.st_uid != 0 or venv_parent.st_mode & 0o022):
            raise WorkerError("unsafe_worker_python")
        argv = [
            str(SETPRIV), "--reuid=" + str(account.pw_uid),
            "--regid=" + str(account.pw_gid), "--clear-groups",
            "--no-new-privs", "--", str(executable), "-I", "-m",
            "repocache.submission_db_worker", str(self.path),
        ]
        try:
            self.process = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, close_fds=True, cwd="/",
                env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
                     "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"},
            )
        except OSError as exc:
            raise WorkerError("worker_spawn_failed") from exc
        # Keep stdin nonblocking: a stalled or hostile worker must not trap
        # the privileged parent inside a buffered pipe write indefinitely.
        try:
            if self.process.stdin is None:
                raise OSError("missing worker stdin")
            os.set_blocking(self.process.stdin.fileno(), False)
        except OSError as exc:
            self.process.kill()
            self.process.wait()
            raise WorkerError("worker_pipe_unavailable") from exc
        self._buffer = bytearray()
        self._closed = False
        try:
            self._request({"op": "ping"})
        except BaseException:
            self.close(commit=False, suppress=True)
            raise

    def _recv(self, *, deadline: float | None = None) -> dict:
        if self.process.stdout is None:
            raise WorkerError("worker_pipe_missing")
        fd = self.process.stdout.fileno()
        message_deadline = time.monotonic() + TIMEOUT
        if deadline is not None:
            message_deadline = min(message_deadline, deadline)
        while b"\n" not in self._buffer:
            if len(self._buffer) > MAX_MESSAGE:
                raise WorkerError("oversized_worker_response")
            remaining = message_deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                # A stalled child cannot extend the backup's overall deadline
                # by entering a fresh TIMEOUT-length pipe read near its end.
                if deadline is not None and time.monotonic() >= deadline:
                    raise WorkerError("worker_backup_timeout")
                raise WorkerError("worker_timeout")
            chunk = os.read(fd, 65536)
            if not chunk:
                raise WorkerError("worker_closed")
            self._buffer.extend(chunk)
        line, _, rest = self._buffer.partition(b"\n")
        self._buffer = bytearray(rest)
        if len(line) > MAX_MESSAGE:
            raise WorkerError("oversized_worker_response")
        try:
            response = json.loads(line.decode("ascii"))
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise WorkerError("invalid_worker_response") from exc
        if not isinstance(response, dict) or response.get("ok") is not True:
            raise WorkerError("worker_operation_failed")
        return response

    def _send(self, request: dict) -> None:
        """Write a bounded request without blocking on an unresponsive child."""
        try:
            raw = json.dumps(request, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode("ascii") + b"\n"
        except (TypeError, ValueError, RecursionError) as exc:
            raise WorkerError("invalid_worker_request") from exc
        if len(raw) > MAX_MESSAGE or self.process.stdin is None:
            raise WorkerError("oversized_worker_request")
        fd = self.process.stdin.fileno()
        view = memoryview(raw)
        deadline = time.monotonic() + TIMEOUT
        while view:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WorkerError("worker_send_timeout")
            try:
                if not select.select([], [fd], [], remaining)[1]:
                    raise WorkerError("worker_send_timeout")
                count = os.write(fd, view)
                if count <= 0:
                    raise WorkerError("worker_send_failed")
                view = view[count:]
            except BlockingIOError:
                # The pipe can fill between select and write. Retry only
                # until the same fixed deadline, never extend it.
                continue
            except OSError as exc:
                raise WorkerError("worker_send_failed") from exc

    def _request(self, request: dict) -> dict:
        self._send(request)
        return self._recv()

    def execute(self, sql: str, parameters=()) -> WorkerCursor:
        if not isinstance(sql, str) or len(sql) > MAX_SQL:
            raise WorkerError("invalid_worker_sql")
        reply = self._request({"op": "execute", "sql": sql,
                               "params": list(parameters)})
        if type(reply.get("cursor")) is not int or type(reply.get("rowcount")) is not int:
            raise WorkerError("invalid_worker_cursor")
        return WorkerCursor(self, reply["cursor"], reply["rowcount"])

    def executescript(self, script: str) -> None:
        if not isinstance(script, str) or len(script) > MAX_SQL:
            raise WorkerError("invalid_worker_sql")
        self._request({"op": "script", "sql": script})

    def backup_file(self, destination: Path) -> None:
        """Stream a consistent SQLite snapshot to a ROOT-PRIVATE staging inode."""
        path = Path(destination)
        # A path can be substituted between the caller's mkstemp and this
        # reopen. Refuse FIFOs without blocking before the inode is checked.
        try:
            fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK |
                         getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_CLOEXEC", 0))
        except OSError as exc:
            raise WorkerError("unsafe_backup_staging") from exc
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or
                    st.st_mode & 0o077 or st.st_nlink != 1 or st.st_size != 0):
                raise WorkerError("unsafe_backup_staging")
            # Include request sending in the absolute backup time budget.
            # A stalled child cannot gain a fresh deadline after _send().
            deadline = time.monotonic() + BACKUP_TIMEOUT
            self._send({"op": "backup"})
            total = 0
            frames = 0
            while True:
                # A compromised or stalled service-UID worker must not keep a
                # privileged backup open forever by sending tiny/empty frames
                # just before each per-message timeout expires.
                if time.monotonic() >= deadline:
                    raise WorkerError("worker_backup_timeout")
                reply = self._recv(deadline=deadline)
                if time.monotonic() >= deadline:
                    raise WorkerError("worker_backup_timeout")
                if reply.get("done") is True:
                    # The unprivileged worker must not smuggle an ignored
                    # payload or status into an apparently final frame.
                    if set(reply) != {"ok", "done"}:
                        raise WorkerError("invalid_backup_terminal")
                    break
                if set(reply) != {"ok", "chunk"}:
                    raise WorkerError("invalid_backup_frame")
                encoded = reply.get("chunk")
                if not isinstance(encoded, str) or len(encoded) > 131072:
                    raise WorkerError("invalid_backup_chunk")
                try:
                    data = base64.b64decode(encoded, validate=True)
                except ValueError as exc:
                    raise WorkerError("invalid_backup_chunk") from exc
                # The child sends 64 KiB chunks (last chunk may be shorter).
                # Bound frame count as well as byte count to reject a stream
                # of arbitrarily many one-byte progress messages.
                frames += 1
                if not data or len(data) > BACKUP_CHUNK_SIZE:
                    raise WorkerError("invalid_backup_chunk")
                if frames > MAX_BACKUP_FRAMES:
                    raise WorkerError("too_many_worker_backup_chunks")
                total += len(data)
                if total > MAX_BACKUP:
                    raise WorkerError("oversized_worker_backup")
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise WorkerError("backup_write_failed")
                    view = view[written:]
            if total == 0:
                raise WorkerError("empty_worker_backup")
            os.fsync(fd)
        finally:
            os.close(fd)

    def close(self, *, commit: bool, suppress: bool = False) -> None:
        if self._closed:
            return
        self._closed = True
        error = None
        try:
            self._request({"op": "commit" if commit else "rollback"})
        except (WorkerError, OSError) as exc:
            error = exc
        try:
            if self.process.stdin:
                self.process.stdin.close()
            if self.process.stdout:
                self.process.stdout.close()
            self.process.wait(timeout=3)
            if self.process.returncode != 0:
                error = error or WorkerError("worker_exit_failed")
        except (subprocess.TimeoutExpired, OSError):
            self.process.kill()
            self.process.wait(timeout=3)
            error = error or WorkerError("worker_shutdown_failed")
        if error is not None and not suppress:
            raise error

    def __enter__(self):
        return self

    def __exit__(self, typ, value, tb):
        self.close(commit=typ is None, suppress=typ is not None)
        return False


def _send_reply(reply: dict) -> None:
    sys.stdout.write(json.dumps({"ok": True, **reply},
                                sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _worker_main(path: Path) -> int:
    account = _service_account()
    if os.geteuid() != account.pw_uid or os.getegid() != account.pw_gid:
        return 3
    _check_directory(path.parent, account.pw_uid)
    _check_queue(path, account.pw_uid)
    previous_umask = os.umask(0o077)
    try:
        connection = sqlite3.connect(path, timeout=3, isolation_level=None)
        _check_queue(path, account.pw_uid)
        connection.execute("PRAGMA busy_timeout=3000")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA journal_mode=DELETE")
        cursors = {}
        next_cursor = 0
        while True:
            raw = sys.stdin.buffer.readline(MAX_MESSAGE + 1)
            if not raw or len(raw) > MAX_MESSAGE:
                return 3
            try:
                request = json.loads(raw.decode("ascii"))
                if not isinstance(request, dict):
                    return 3
                op = request.get("op")
                if op == "ping":
                    _send_reply({})
                elif op == "execute":
                    sql, params = request.get("sql"), request.get("params")
                    if (not isinstance(sql, str) or len(sql) > MAX_SQL or
                            not isinstance(params, list) or len(params) > 64 or
                            any(type(x) not in (str, int, float, type(None)) or
                                (isinstance(x, str) and len(x) > 131072)
                                for x in params)):
                        return 3
                    cursor = connection.execute(sql, params)
                    next_cursor += 1
                    cursors = {next_cursor: cursor}
                    _send_reply({"cursor": next_cursor, "rowcount": cursor.rowcount})
                elif op == "script":
                    script = request.get("sql")
                    if not isinstance(script, str) or len(script) > MAX_SQL:
                        return 3
                    connection.executescript(script)
                    _send_reply({})
                elif op in {"fetchone", "fetchall"}:
                    cursor = cursors.get(request.get("cursor"))
                    if cursor is None:
                        return 3
                    if op == "fetchone":
                        _send_reply({"row": cursor.fetchone()})
                    else:
                        rows = cursor.fetchall()
                        if len(json.dumps(rows)) > MAX_MESSAGE - 1024:
                            return 3
                        _send_reply({"rows": rows})
                elif op == "backup":
                    target = sqlite3.connect(":memory:")
                    try:
                        connection.backup(target)
                        payload = target.serialize()
                    finally:
                        target.close()
                    if not 0 < len(payload) <= MAX_BACKUP:
                        return 3
                    for offset in range(0, len(payload), 65536):
                        _send_reply({"chunk": base64.b64encode(
                            payload[offset:offset + 65536]).decode("ascii")})
                    _send_reply({"done": True})
                elif op in {"commit", "rollback"}:
                    if connection.in_transaction:
                        connection.execute("COMMIT" if op == "commit" else "ROLLBACK")
                    _send_reply({})
                    return 0
                else:
                    return 3
            except (sqlite3.Error, ValueError, TypeError, OSError):
                return 3
    except (sqlite3.Error, OSError):
        return 3
    finally:
        if "connection" in locals():
            connection.close()
        os.umask(previous_umask)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(3)
    try:
        raise SystemExit(_worker_main(Path(sys.argv[1])))
    except WorkerError:
        raise SystemExit(3)
