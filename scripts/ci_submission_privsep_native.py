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
    from repocache.submission_keys import issue_key, revoke_key
    from repocache.intake import load_keyring

    # Real OS-account check for root-owned credential integrity. Only a
    # disposable container is used; never load any operator key material.
    keydir = Path("/etc/repocache-intake")
    if keydir.exists():
        raise RuntimeError("refusing preexisting intake configuration")
    keydir.mkdir(mode=0o750)
    os.chown(keydir, 0, account.pw_gid)
    keydir.chmod(0o750)
    keyring = keydir / "keyring.json"
    handoff = root / "handoff"
    handoff.mkdir(mode=0o700)
    client_a = handoff / "client-a.json"
    client_b = handoff / "client-b.json"
    issue_key(keyring, client_a, "client_A", approved=True)
    info = keyring.stat()
    assert info.st_uid == 0 and info.st_gid == account.pw_gid
    assert stat.S_IMODE(info.st_mode) == 0o640 and info.st_nlink == 1
    assert set(load_keyring(keyring)) == {"client_A"}

    unprivileged_probe = (
        "from pathlib import Path\n"
        "from repocache.intake import load_keyring\n"
        "p=Path(" + repr(str(keyring)) + ")\n"
        "assert set(load_keyring(p)) == {'client_A'}\n"
        "for op in (lambda: p.write_text('unexpected'),"
        " lambda: p.chmod(0o600), lambda: p.unlink()):\n"
        "    try: op()\n"
        "    except PermissionError: pass\n"
        "    else: raise AssertionError('intake altered protected keyring')\n"
    )
    _run_as_intake(account.pw_uid, account.pw_gid, unprivileged_probe)
    issue_key(keyring, client_b, "client_B", approved=True)
    revoke_key(keyring, "client_A", approved=True)
    assert set(load_keyring(keyring)) == {"client_B"}
    _run_as_intake(
        account.pw_uid, account.pw_gid,
        "from repocache.intake import load_keyring; from pathlib import Path;"
        " assert set(load_keyring(Path(" + repr(str(keyring)) + "))) == {'client_B'}",
    )
    # Previous service-owned layout is rejected, never implicitly accepted
    # or modified by the root helper or unprivileged intake reader.
    os.chown(keyring, account.pw_uid, account.pw_gid)
    os.chmod(keyring, 0o600)
    try:
        load_keyring(keyring)
    except SubmissionError as exc:
        assert exc.code == "invalid_credentials"
    else:
        raise AssertionError("old service-owned keyring was accepted")
    os.chown(keyring, 0, account.pw_gid)
    os.chmod(keyring, 0o640)
    print("PASS: real service UID reads root-controlled keyring but cannot modify it; rotation and legacy refusal")

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
        # Exercise the real root-only staging/rollback copy and atomic
        # handoff, still with no privileged SQLite open on the intake path.
        from repocache.submission_recovery import restore_offline
        rollback = restore_offline(queue_path, dest, approved=True,
                                   service_stopped=lambda: True)
        assert rollback.parent == backupdir and rollback.stat().st_uid == 0
        assert queue.pending() == []
        # A compromised intake UID can replace the DB with a FIFO. Root
        # must refuse without blocking on a writer for the named pipe.
        queue_path.unlink()
        os.mkfifo(queue_path, 0o600)
        try:
            restore_offline(queue_path, dest, approved=True,
                            service_stopped=lambda: True)
        except SubmissionError as exc:
            assert exc.code == "unsafe_current_store"
        else:
            raise AssertionError("root accepted service-planted FIFO")
        finally:
            queue_path.unlink()
    finally:
        sqlite3.connect = native_connect
    print("PASS: real dropped UID, no root SQLite, protected restore/rollback, FIFO refusal, journal, backup and hostile sidecar")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
