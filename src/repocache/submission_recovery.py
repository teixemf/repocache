"""Offline, explicitly authorized restoration of a trusted submission queue.

This module never starts/stops services; callers MUST establish that intake is
stopped and retain the previous SQLite file for rollback. Nothing in the
normal install/upgrade process calls this function.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import pwd
import shutil
import sqlite3
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

from repocache.submissions import SubmissionError, _url, _check_json_depth, _pairs, _invalid_constant

MAX_RESTORE_BYTES = 128 * 1024 * 1024
REQUIRED_TABLES = frozenset({"proposals", "nonces", "audit"})


def _require_root() -> None:
    if os.geteuid() != 0:
        raise SubmissionError("operator_required", 403)


def _trusted_private_dir(path: Path, *, service_owned: bool = False) -> None:
    details = path.lstat()
    owners = {0}
    if service_owned:
        try:
            owners.add(pwd.getpwnam("repocache-intake").pw_uid)
        except KeyError:
            pass
    if (not stat.S_ISDIR(details.st_mode) or details.st_uid not in owners
            or details.st_mode & 0o077):
        raise SubmissionError("unsafe_restore_directory", 403)
    # A private final directory is not enough: an intake-writable ancestor
    # can be renamed to a symlink between validation and root os.replace().
    # A service-owned directory also cannot be trusted directly below a
    # sticky /tmp-style parent: its owner can rename it there.
    if details.st_uid != 0:
        immediate = path.parent.lstat()
        if (not stat.S_ISDIR(immediate.st_mode) or immediate.st_uid != 0
                or immediate.st_mode & 0o022):
            raise SubmissionError("unsafe_restore_ancestor", 403)
    for ancestor in path.parents:
        st = ancestor.lstat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or
                (st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX)):
            raise SubmissionError("unsafe_restore_ancestor", 403)


def _check_backup_stat(details: os.stat_result) -> None:
    if (not stat.S_ISREG(details.st_mode) or details.st_uid != 0
            or details.st_mode & 0o077 or
            not 0 < details.st_size <= MAX_RESTORE_BYTES):
        raise SubmissionError("unsafe_restore_backup", 403)


def _verify_sqlite(path: Path) -> None:
    """Check both SQLite integrity and the expected submission schema."""
    try:
        uri = "file:" + str(path) + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=3) as db:
            if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise SubmissionError("corrupt_restore_backup", 422)
            tables = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            if not REQUIRED_TABLES.issubset(tables):
                raise SubmissionError("invalid_restore_schema", 422)
            proposal_columns = {row[1] for row in db.execute("PRAGMA table_info(proposals)")}
            if not {"id", "os_id", "os_version", "items", "state", "version",
                    "created", "changed"}.issubset(proposal_columns):
                raise SubmissionError("invalid_restore_schema", 422)
            # The required tables must also retain the columns consumed by
            # replay protection and administrative audit writes. A service-owned
            # backup can have been rebuilt with arbitrary table definitions.
            # The nonce composite primary key must remain enforced on restore.
            nonce_columns = {row[1]: row for row in
                             db.execute("PRAGMA table_info(nonces)")}
            audit_columns = {row[1]: row for row in
                             db.execute("PRAGMA table_info(audit)")}
            if (not {"key_hash", "nonce", "digest", "proposal_id", "created"}.issubset(
                        nonce_columns)
                    or not {"seq", "proposal_id", "changed", "actor_uid",
                            "action", "result"}.issubset(audit_columns)
                    or nonce_columns["key_hash"][5] != 1
                    or nonce_columns["nonce"][5] != 2
                    or audit_columns["seq"][5] != 1):
                raise SubmissionError("invalid_restore_schema", 422)
            # SQLite NULL does not satisfy NOT IN (three-valued logic).
            # A service-owned queue can have its NOT NULL constraint removed;
            # never restore a backup with a hidden invalid proposal state.
            if db.execute(
                "SELECT COUNT(*) FROM proposals WHERE state IS NULL OR state NOT IN "
                "('PENDING','REVIEWED','REJECTED')").fetchone()[0]:
                raise SubmissionError("invalid_restore_schema", 422)
            # A rowid table's TEXT PRIMARY KEY can accept NULL, and a
            # service-owned backup may have its uniqueness constraint removed.
            # GLOB stops at embedded NUL even when the BLOB byte length is 32.
            # Check all identifier bytes (including NUL) and duplicates before swap.
            if db.execute(
                "SELECT 1 FROM proposals WHERE id IS NULL OR "
                "typeof(id) != 'text' OR length(CAST(id AS BLOB)) != 32 OR "
                "id GLOB '*[^0-9a-f]*' OR "
                "instr(CAST(id AS BLOB), X'00') > 0 LIMIT 1"
            ).fetchone() is not None:
                raise SubmissionError("invalid_restore_schema", 422)
            if db.execute(
                "SELECT 1 FROM proposals GROUP BY id HAVING COUNT(*) > 1 LIMIT 1"
            ).fetchone() is not None:
                raise SubmissionError("invalid_restore_schema", 422)
            # The intake-owned SQLite schema may also be rebuilt without
            # NOT NULL or CHECK constraints. A malformed version or timestamp
            # must not be accepted as a restorable queue simply because the
            # SQLite pages are structurally intact. SQLite's dynamic typing
            # makes a declared INTEGER column insufficient for this check.
            if db.execute(
                "SELECT 1 FROM proposals WHERE "
                "typeof(version) != 'integer' OR version < 0 OR "
                "(state IN ('REVIEWED','REJECTED') AND version = 0) OR "
                "typeof(created) != 'integer' OR "
                "typeof(changed) != 'integer' LIMIT 1"
            ).fetchone() is not None:
                raise SubmissionError("invalid_restore_schema", 422)
            # Restore is a privileged operation consuming intake-controlled
            # records. Reject unusable metadata before installing the backup.
            for os_id, os_version, items in db.execute(
                    "SELECT os_id,os_version,items FROM proposals"):
                if (type(os_id) is not str or type(os_version) is not str or
                        not ((os_id == "debian" and re.fullmatch(
                            r"13(?:\.[0-9]{1,4})?", os_version)) or
                            (os_id == "almalinux" and re.fullmatch(
                                r"10(?:\.[0-9]{1,4})?", os_version))) or
                        type(items) is not str or not 0 < len(items) <= 131072):
                    raise SubmissionError("invalid_restore_schema", 422)
                try:
                    raw = items.encode("utf-8")
                    _check_json_depth(raw, code="invalid_restore_schema", status=422)
                    repos = json.loads(items, object_pairs_hook=_pairs,
                                       parse_constant=_invalid_constant)
                except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
                    raise SubmissionError("invalid_restore_schema", 422) from exc
                if type(repos) is not list or not 1 <= len(repos) <= 32:
                    raise SubmissionError("invalid_restore_schema", 422)
                seen = set()
                for repo in repos:
                    if (type(repo) is not dict or
                            set(repo) != {"type", "url", "insecure_http"} or
                            type(repo["type"]) is not str or
                            type(repo["url"]) is not str or
                            type(repo["insecure_http"]) is not bool or
                            (os_id == "debian" and
                             repo["type"] not in {"apt-list", "apt-deb822"}) or
                            (os_id == "almalinux" and repo["type"] != "dnf")):
                        raise SubmissionError("invalid_restore_schema", 422)
                    try:
                        canonical = _url(repo["url"])
                    except SubmissionError as exc:
                        raise SubmissionError("invalid_restore_schema", 422) from exc
                    pair = (repo["type"], canonical)
                    if (canonical != repo["url"] or
                            repo["insecure_http"] != canonical.startswith("http://") or
                            pair in seen):
                        raise SubmissionError("invalid_restore_schema", 422)
                    seen.add(pair)
    except sqlite3.Error as exc:
        raise SubmissionError("corrupt_restore_backup", 422) from exc


def _copy_verified_regular(source_fd: int, destination_fd: int,
                           expected: os.stat_result) -> None:
    """Bound a privileged copy of an untrusted SQLite inode.

    A service UID may grow or replace its database while intake is stopped.
    Never follow a second path unchecked or copy until an attacker-chosen EOF.
    """
    def identity(st: os.stat_result) -> tuple:
        return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode,
                st.st_size, st.st_mtime_ns, st.st_ctime_ns)

    if (not stat.S_ISREG(expected.st_mode) or
            not 0 < expected.st_size <= MAX_RESTORE_BYTES or
            identity(os.fstat(source_fd)) != identity(expected)):
        raise SubmissionError("restore_source_changed", 409)
    remaining = expected.st_size
    while remaining:
        data = os.read(source_fd, min(1024 * 1024, remaining))
        if not data:
            raise SubmissionError("restore_source_changed", 409)
        remaining -= len(data)
        view = memoryview(data)
        while view:
            count = os.write(destination_fd, view)
            if count <= 0:
                raise SubmissionError("restore_copy_failed", 503)
            view = view[count:]
    if os.read(source_fd, 1) or identity(os.fstat(source_fd)) != identity(expected):
        raise SubmissionError("restore_source_changed", 409)


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def _exclusive_restore_lock(directory: Path):
    """Prevent concurrent restore processes; not a substitute for stopping intake."""
    name = directory / ".repocache-restore.lock"
    fd = os.open(name, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        details = os.fstat(fd)
        if (not stat.S_ISREG(details.st_mode) or details.st_uid != 0
                or details.st_mode & 0o077):
            raise SubmissionError("unsafe_restore_lock", 403)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SubmissionError("restore_busy", 409) from exc
        yield
    finally:
        os.close(fd)


def restore_offline(queue_path: Path, backup_path: Path, *,
                    approved: bool = False,
                    service_stopped: Callable[[], bool] | None = None) -> Path:
    """Restore a trusted snapshot, retaining an immutable-in-place old-file copy.

    Preconditions: root, explicit operator approval, verified stopped service,
    both directories trusted and backup owned by root with mode <=0600.
    Atomic replacement cannot protect against a real disk/power failure; a
    retained original inode is available for an explicitly approved rollback.
    """
    _require_root()
    if not approved or service_stopped is None or not service_stopped():
        raise SubmissionError("offline_restore_not_approved", 403)

    target, source = Path(queue_path), Path(backup_path)
    try:
        _trusted_private_dir(target.parent, service_owned=True)
        _trusted_private_dir(source.parent)
        if target == source or target.is_symlink() or source.is_symlink():
            raise SubmissionError("unsafe_restore_source", 403)
        if target.parent.resolve() == source.parent.resolve() and target.name == source.name:
            raise SubmissionError("unsafe_restore_source", 403)
        # The intake UID can unlink a lock in its own directory. Keep the
        # serialization lock in the independently root-controlled backup dir.
        with _exclusive_restore_lock(source.parent):
            # Both paths are opened without following the final symlink.
            # O_NONBLOCK prevents an intake UID from hanging privileged
            # restore forever by swapping the queue path for a FIFO.
            flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))
            source_fd = os.open(source, flags)
            try:
                _check_backup_stat(os.fstat(source_fd))
                old_fd = os.open(target, flags)
                try:
                    old_stat = os.fstat(old_fd)
                    if (not stat.S_ISREG(old_stat.st_mode) or old_stat.st_mode & 0o077
                            or not 0 < old_stat.st_size <= MAX_RESTORE_BYTES):
                        raise SubmissionError("unsafe_current_store", 403)
                    uid, gid = old_stat.st_uid, old_stat.st_gid
                finally:
                    os.close(old_fd)

                # Never stage or run SQLite as root inside a directory the
                # intake UID can rename or replace. The source backup parent
                # is root-only; cross-filesystem replacement fails closed.
                staging_fd, staging = tempfile.mkstemp(prefix=".repocache-restore-",
                                                       dir=source.parent)
                staged = Path(staging)
                try:
                    os.fchmod(staging_fd, 0o600)
                    try:
                        _copy_verified_regular(source_fd, staging_fd, os.fstat(source_fd))
                        os.fsync(staging_fd)
                    finally:
                        os.close(staging_fd)
                    _verify_sqlite(staged)
                    rollback = source.parent / ("repocache-before-restore-" +
                                                os.urandom(12).hex() + ".sqlite3")
                    # Preserve prior bytes in a ROOT-OWNED backup directory,
                    # not the service-writable directory. This is a separate
                    # file copy, so it also works across filesystems.
                    old_fd = os.open(target, flags)
                    previous_fd = None
                    try:
                        previous_fd = os.open(
                            rollback, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                            getattr(os, "O_NOFOLLOW", 0), 0o600)
                        _copy_verified_regular(old_fd, previous_fd, old_stat)
                        os.fsync(previous_fd)
                    except BaseException:
                        rollback.unlink(missing_ok=True)
                        raise
                    finally:
                        os.close(old_fd)
                        if previous_fd is not None:
                            os.close(previous_fd)
                    _fsync_dir(source.parent)
                    # The verified file remains inaccessible to the intake
                    # UID until the final atomic replacement. No root SQLite
                    # handle or root-writable temporary inode is exposed in
                    # the intake-owned directory.
                    if os.geteuid() == 0 and uid != os.geteuid():
                        os.chown(staged, uid, gid, follow_symlinks=False)
                    os.replace(staged, target)
                    _fsync_dir(target.parent)
                    return rollback
                finally:
                    if staged.exists():
                        staged.unlink()
            finally:
                os.close(source_fd)
    except SubmissionError:
        raise
    except (OSError, sqlite3.Error) as exc:
        raise SubmissionError("restore_unavailable", 503) from exc
