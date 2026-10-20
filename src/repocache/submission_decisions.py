"""Root-owned, append-only decision receipts independent from intake SQLite.

A compromised intake service UID must not be able to create, replace, or
delete verified administrator decisions. Root is the trust anchor: this is
NOT tamper-proof against root, hostile storage, or a rollback of this entire
protected directory. Native permissions/SELinux are issue #49.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DECISION_DIR = Path("/var/lib/repocache/decisions")
MAX_EVENTS = 1024
_HEX_ID = re.compile(r"[0-9a-f]{32}\Z")
_HEX_HASH = re.compile(r"[0-9a-f]{64}\Z")
STATES = {"review": "REVIEWED", "reject": "REJECTED", "reopen": "PENDING"}


class DecisionError(ValueError):
    def __init__(self, code: str, status: int = 503):
        super().__init__(code)
        self.code, self.status = code, status


def _require_root() -> None:
    if os.geteuid() != 0:
        raise DecisionError("operator_required", 403)


def _trusted_dir(path: Path) -> None:
    # Root-only parent must be provisioned explicitly. No auto-created
    # directory can accidentally inherit a service-writable ancestor.
    try:
        st = path.lstat()
        ancestor = path.parent.lstat()
    except OSError as exc:
        raise DecisionError("decision_store_unavailable") from exc
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or
            st.st_mode & 0o077 or
            not stat.S_ISDIR(ancestor.st_mode) or ancestor.st_uid != 0 or
            ancestor.st_mode & 0o022):
        raise DecisionError("unsafe_decision_directory")


def _open_trusted(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077 or st.st_size > 4096:
        os.close(fd)
        raise DecisionError("unsafe_decision_record")
    return fd


def _verify_lock_fd(fd: int) -> None:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise DecisionError("unsafe_decision_lock")


def _canonical(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


class DecisionJournal:
    """Read and append root-authored receipts with a hash-linked chain."""

    def __init__(self, directory: Path = DEFAULT_DECISION_DIR):
        self.directory = Path(directory)

    @contextmanager
    def locked(self):
        _require_root()
        _trusted_dir(self.directory)
        lockfile = self.directory / ".decision.lock"
        flags = (os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_CLOEXEC", 0))
        try:
            fd = os.open(lockfile, flags, 0o600)
            try:
                _verify_lock_fd(fd)
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield self
            finally:
                os.close(fd)
        except OSError as exc:
            raise DecisionError("decision_store_unavailable") from exc

    def read(self, ident: str) -> list[dict]:
        """Read and validate all historical receipts; requires journal lock."""
        if not isinstance(ident, str) or not _HEX_ID.fullmatch(ident):
            raise DecisionError("invalid_decision_id", 400)
        chain = []
        expected_prev = "0" * 64
        for version in range(1, MAX_EVENTS + 1):
            path = self.directory / f"{ident}.{version:04d}.json"
            try:
                fd = _open_trusted(path)
            except FileNotFoundError:
                break
            except OSError as exc:
                raise DecisionError("decision_store_unavailable") from exc
            try:
                with os.fdopen(fd, "rb") as file:
                    raw = file.read(4097)
            except OSError as exc:
                raise DecisionError("decision_store_unavailable") from exc
            try:
                record = json.loads(raw.decode("ascii"))
                if (not isinstance(record, dict) or set(record) !=
                    {"id", "version", "action", "state", "actor_uid", "at",
                     "proposal_digest", "previous_hash", "hash"}):
                    raise ValueError("invalid fields")
                check = dict(record)
                checksum = check.pop("hash")
                if (record["id"] != ident or type(record["version"]) is not int or
                        record["version"] != version or record["action"] not in STATES or
                        record["state"] != STATES[record["action"]] or
                        type(record["actor_uid"]) is not int or record["actor_uid"] < 0 or
                        type(record["at"]) is not int or
                        not isinstance(record["proposal_digest"], str) or
                        not _HEX_HASH.fullmatch(record["proposal_digest"]) or
                        record["previous_hash"] != expected_prev or
                        not isinstance(checksum, str) or
                        not _HEX_HASH.fullmatch(checksum) or
                        hashlib.sha256(_canonical(check)).hexdigest() != checksum):
                    raise ValueError("invalid receipt")
                if version == 1 and record["action"] == "reopen":
                    raise ValueError("cannot reopen absent decision")
                if version > 1:
                    last = chain[-1]
                    if (record["proposal_digest"] != last["proposal_digest"] or
                            (record["action"] == "reopen") !=
                            (last["state"] != "PENDING")):
                        raise ValueError("invalid transition or metadata")
                chain.append(record)
                expected_prev = checksum
            except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
                raise DecisionError("decision_journal_corrupt") from exc
        # Refuse an overlong chain or hidden later receipts; never ignore a
        # corrupt/noncontiguous sequence and silently trust an older version.
        for item in self.directory.iterdir():
            name = item.name
            if name.startswith(ident + ".") and name.endswith(".json"):
                if name not in {f"{ident}.{i:04d}.json" for i in range(1, len(chain) + 1)}:
                    raise DecisionError("decision_journal_gap")
        return chain

    def append(self, ident: str, action: str, metadata_digest: str,
               previous: list[dict]) -> dict:
        """Durably create next receipt *before* touching intake SQLite."""
        _require_root()
        if action not in STATES or not _HEX_HASH.fullmatch(metadata_digest):
            raise DecisionError("invalid_decision", 400)
        if len(previous) >= MAX_EVENTS:
            raise DecisionError("decision_history_full")
        if previous and previous[-1]["proposal_digest"] != metadata_digest:
            raise DecisionError("decision_metadata_conflict", 409)
        if ((action == "reopen") != (bool(previous) and previous[-1]["state"] != "PENDING")):
            raise DecisionError("invalid_transition", 409)
        version = len(previous) + 1
        record = {
            "id": ident, "version": version, "action": action,
            "state": STATES[action], "actor_uid": os.getuid(),
            "at": int(time.time()), "proposal_digest": metadata_digest,
            "previous_hash": previous[-1]["hash"] if previous else "0" * 64,
        }
        record["hash"] = hashlib.sha256(_canonical(record)).hexdigest()
        payload = _canonical(record) + b"\n"
        fd, staging = tempfile.mkstemp(prefix=".decision-stage-", dir=self.directory)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as file:
                file.write(payload)
                file.flush()
                os.fsync(file.fileno())
            final = self.directory / f"{ident}.{version:04d}.json"
            os.link(staging, final, follow_symlinks=False)  # EXCL, no overwrite
            df = os.open(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(df)
            finally:
                os.close(df)
            return record
        except (OSError, FileExistsError) as exc:
            raise DecisionError("decision_write_failed") from exc
        finally:
            if os.path.exists(staging):
                os.unlink(staging)
