#!/usr/bin/env python3
"""Disposable-container REAL-UID SQLite privilege boundary smoke (#127).

Runs only in an ephemeral Debian13/Alma10 Docker container with network
disabled. It is not a booted native kernel/systemd/SELinux host or an
independent security audit. Never run against production state.
"""
from __future__ import annotations

import os
import pwd
import shutil
import site
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path


def _run_as_intake(uid: int, gid: int, code: str) -> None:
    subprocess.run([
        "/usr/bin/setpriv", f"--reuid={uid}", f"--regid={gid}",
        "--clear-groups", "--no-new-privs", "--",
        sys.executable, "-I", "-c", code,
    ], check=True, timeout=15, cwd="/",
       env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
            "PYTHONNOUSERSITE": "1"})


def main() -> int:
    if os.geteuid() != 0 or not Path("/usr/bin/setpriv").is_file():
        raise RuntimeError("requires disposable root container with setpriv")
    if Path("/var/lib/repocache").exists():
        raise RuntimeError("refusing preexisting repository state")
    # Install only the current candidate package code in root-owned system
    # site-packages, not dependencies or a production service.
    source = Path("/src/repocache")
    if not (source / "submission_db_worker.py").is_file():
        raise RuntimeError("candidate source not mounted")
    candidates = [Path(p) for p in site.getsitepackages()]
    target_parent = next((p for p in candidates if p.is_dir() and os.access(p, os.W_OK)),
                         None)
    if target_parent is None:
        target_parent = candidates[0]
        target_parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    target = target_parent / "repocache"
    if target.exists():
        raise RuntimeError("refusing preexisting installed package")
    shutil.copytree(source, target)
    for item in target.rglob("*"):
        if item.is_dir():
            item.chmod(0o755)
        elif item.is_file():
            item.chmod(0o644)
    target.chmod(0o755)

    subprocess.run(["useradd", "-r", "-M", "-s", "/usr/sbin/nologin",
                    "repocache-intake"], check=True, timeout=10)
    account = pwd.getpwnam("repocache-intake")
    root = Path("/var/lib/repocache")
    root.mkdir(mode=0o755)
    state = root / "submissions"
    state.mkdir(mode=0o700)
    os.chown(state, account.pw_uid, account.pw_gid)
    state.chmod(0o700)
    journal = root / "decisions"
    journal.mkdir(mode=0o700)
    journal.chmod(0o700)
    backupdir = root / "backups"
    backupdir.mkdir(mode=0o700)
    backupdir.chmod(0o700)
    queue_path = state / "queue.sqlite3"

    from repocache.submissions import SubmissionQueue, SubmissionError
    from repocache.submission_db_worker import WorkerError

    # A root SQLite call on an intake-owned queue path is a test failure.
    native_connect = sqlite3.connect
    def forbid_root_queue(path, *args, **kwargs):
        if str(path) == str(queue_path):
            raise AssertionError("root SQLite opened intake-controlled database")
        return native_connect(path, *args, **kwargs)
    sqlite3.connect = forbid_root_queue
    try:
        queue = SubmissionQueue(queue_path, journal_dir=journal)
        assert queue_path.stat().st_uid == account.pw_uid
        assert queue_path.stat().st_mode & 0o077 == 0
        item = {"os": {"id": "debian", "version": "13"},
                "repositories": [{"type": "apt-list",
                                  "url": "https://mirror.example.org/debian/",
                                  "insecure_http": False}]}
        ident = queue.enqueue("keyhash", "nonce", "digest", item)
        assert queue.pending()[0]["id"] == ident
        queue.decide(ident, "review", expected_version=0)
        assert queue.pending() == []
        assert queue.audit(ident)[-1][0] == "review"
        dest = backupdir / "snapshot.sqlite3"
        queue.backup(dest)
        assert dest.stat().st_uid == 0 and dest.stat().st_mode & 0o077 == 0
        with native_connect(dest) as db:
            assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        # A service UID can falsify its own convenience database; root must
        # repair only from the independently protected journal.
        _run_as_intake(account.pw_uid, account.pw_gid,
                       "import sqlite3; c=sqlite3.connect(" +
                       repr(str(queue_path)) +
                       "); c.execute(\"UPDATE proposals SET state='PENDING',version=0\"); c.commit(); c.close()")
        queue.reconcile(ident, approved=True)
        assert queue.pending() == []
        # Malicious SQLite journal symlink must never overwrite root secrets:
        # only the unprivileged worker can open the SQLite sidecar.
        sentinel = root / "sentinel"
        sentinel.write_bytes(b"ROOT_SECRET_SENTINEL")
        sentinel.chmod(0o600)
        sidecar = state / "queue.sqlite3-journal"
        _run_as_intake(account.pw_uid, account.pw_gid,
                       "import os; os.symlink(" + repr(str(sentinel)) + "," +
                       repr(str(sidecar)) + ")")
        try:
            try:
                queue.enqueue("keyhash", "nonce2", "digest2", item)
            except (SubmissionError, WorkerError):
                pass  # Refusal is acceptable; root sentinel must be intact.
            assert sentinel.read_bytes() == b"ROOT_SECRET_SENTINEL"
        finally:
            _run_as_intake(account.pw_uid, account.pw_gid,
                           "import os; p=" + repr(str(sidecar)) +
                           "; os.unlink(p) if os.path.lexists(p) else None")
    finally:
        sqlite3.connect = native_connect
    print("PASS: real dropped UID, no root SQLite, decision journal, backup and hostile sidecar")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
