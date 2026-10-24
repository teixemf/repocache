"""Pending-only, isolated repository submission storage.

No network lookups, NGINX modifications, or catalog publication are performed.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import pwd
import re
import secrets
import sqlite3
import stat
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from repocache.submission_decisions import (
    DEFAULT_DECISION_DIR, DecisionJournal, DecisionError,
)


class SubmissionError(ValueError):
    def __init__(self, code: str, status: int = 422):
        super().__init__(code)
        self.code = code
        self.status = status


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise SubmissionError("invalid_json", 400)
        result[key] = value
    return result


def _invalid_constant(value):
    raise SubmissionError("invalid_json", 400)


def _url(value: object) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 2048
            or not value.isascii() or any(ord(char) < 33 or ord(char) == 127 for char in value)
            or "\\" in value or "%" in value):
        raise SubmissionError("invalid_repository")
    try:
        url = urlsplit(value)
        port = url.port
        hostname = url.hostname
    except ValueError as exc:
        raise SubmissionError("invalid_repository") from exc
    if (url.scheme not in {"http", "https"} or not hostname or
            url.username is not None or url.password is not None or
            url.query or url.fragment or "@" in url.netloc or
            url.netloc.endswith(":") or not value.startswith(url.scheme + "://")):
        raise SubmissionError("invalid_repository")
    if port is not None and not 1 <= port <= 65535:
        raise SubmissionError("invalid_repository")
    host = hostname.lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise SubmissionError("invalid_repository")
    labels = host.split(".")
    if (len(labels) < 2 or len(host) > 253 or
            host.endswith((".local", ".internal", ".localhost", ".invalid"))
            or host in {"localhost", "metadata.google.internal"}
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                   for label in labels)
            or any(label.startswith("xn--") for label in labels)
            or labels[-1].isdigit()):
        raise SubmissionError("invalid_repository")
    path = url.path or "/"
    if ("//" in path or not path.startswith("/") or
            any(part in (".", "..") for part in path.split("/"))):
        raise SubmissionError("invalid_repository")
    netloc = host + (":" + str(port) if port is not None else "")
    return urlunsplit((url.scheme, netloc, path, "", ""))


# A small and intentionally generous bound: valid v1 metadata has at most
# three nested JSON containers. Do not depend on CPython recursion defaults,
# which differ by runtime/build.
MAX_JSON_DEPTH = 32


def _check_json_depth(raw: bytes, *, code: str = "invalid_json",
                      status: int = 400) -> None:
    """Bound nesting without counting structural characters inside strings."""
    depth = 0
    quoted = False
    escaped = False
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:  # backslash
                escaped = True
            elif char == 34:  # quote
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (91, 123):  # [ or {
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise SubmissionError(code, status)
        elif char in (93, 125):  # ] or }
            depth -= 1
            if depth < 0:
                raise SubmissionError(code, status)


def validate_payload(raw: bytes) -> dict:
    """Validate inert metadata without DNS resolution or external I/O."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 65536:
        raise SubmissionError("invalid_size", 413)
    _check_json_depth(raw)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                         parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        if isinstance(exc, SubmissionError):
            raise
        # A 64 KiB signed request can still contain thousands of nested
        # arrays/objects. JSON decoder recursion must fail closed, not escape
        # into the HTTP request handler or expose a traceback.
        raise SubmissionError("invalid_json", 400) from exc
    if (not isinstance(doc, dict) or set(doc) != {"schema", "os", "repositories"}
            or type(doc["schema"]) is not int or doc["schema"] != 1):
        raise SubmissionError("invalid_schema")
    platform = doc["os"]
    if not isinstance(platform, dict) or set(platform) != {"id", "version"}:
        raise SubmissionError("invalid_platform")
    os_id, version = platform["id"], platform["version"]
    if (not isinstance(os_id, str) or not isinstance(version, str)
            or not ((os_id == "debian" and re.fullmatch(r"13(?:\.[0-9]{1,4})?", version))
                    or (os_id == "almalinux" and re.fullmatch(r"10(?:\.[0-9]{1,4})?", version)))):
        raise SubmissionError("invalid_platform")
    repos = doc["repositories"]
    if not isinstance(repos, list) or not 1 <= len(repos) <= 32:
        raise SubmissionError("invalid_repositories")
    valid = []
    seen = set()
    for record in repos:
        if not isinstance(record, dict) or set(record) != {"type", "url"}:
            raise SubmissionError("invalid_repository")
        kind = record["type"]
        if not isinstance(kind, str) or kind not in {"apt-list", "apt-deb822", "dnf"}:
            raise SubmissionError("invalid_repository")
        if (os_id == "debian" and kind == "dnf") or (os_id == "almalinux" and kind != "dnf"):
            raise SubmissionError("invalid_repository")
        url = _url(record["url"])
        pair = (kind, url)
        if pair not in seen:
            seen.add(pair)
            valid.append({"type": kind, "url": url, "insecure_http": url.startswith("http://")})
    return {"schema": 1, "os": {"id": os_id, "version": version}, "repositories": valid}


# The real OS function is captured before synthetic non-root test fixtures
# monkeypatch os.geteuid; production root still enforces UID separation.
_REAL_GETEUID = os.geteuid


class SubmissionQueue:
    """Local SQLite state; root delegates service-writable SQLite to its UID."""

    def __init__(self, path: Path, *, journal_dir: Path = DEFAULT_DECISION_DIR):
        self.path = Path(path)
        # This directory is NOT accessible to the intake identity. Explicit
        # root-only provisioning is required before administrator review.
        self.journal_dir = Path(journal_dir)
        parent = self.path.parent
        st = parent.lstat()
        # A privileged operator may access a directory owned by the fixed
        # service identity, but never one owned by an arbitrary local user.
        owners = {0, os.geteuid()}
        if os.geteuid() == 0:
            try:
                owners.add(pwd.getpwnam("repocache-intake").pw_uid)
            except KeyError:
                pass
        if (not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o077
                or st.st_uid not in owners):
            raise SubmissionError("unsafe_store", 503)
        if self.path.is_symlink():
            raise SubmissionError("unsafe_store", 503)
        delegated = self._needs_worker()
        if not self.path.exists() and not delegated:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
                os.close(fd)
            except FileExistsError:
                pass
            except OSError as exc:
                raise SubmissionError("store_unavailable", 503) from exc
        try:
            if not delegated:
                fst = self.path.lstat()
                if (not stat.S_ISREG(fst.st_mode) or fst.st_mode & 0o077
                        or fst.st_uid not in owners):
                    raise SubmissionError("unsafe_store", 503)
            with self._connect() as connection:
                connection.executescript("""
                    CREATE TABLE IF NOT EXISTS proposals(
                        id TEXT PRIMARY KEY, os_id TEXT NOT NULL,
                        os_version TEXT NOT NULL, items TEXT NOT NULL,
                        state TEXT NOT NULL CHECK(state IN ('PENDING','REVIEWED','REJECTED')),
                        version INTEGER NOT NULL DEFAULT 0,
                        created INTEGER NOT NULL, changed INTEGER NOT NULL);
                    CREATE TABLE IF NOT EXISTS nonces(
                        key_hash TEXT NOT NULL, nonce TEXT NOT NULL,
                        digest TEXT NOT NULL, proposal_id TEXT NOT NULL,
                        created INTEGER NOT NULL,
                        PRIMARY KEY(key_hash, nonce));
                    CREATE TABLE IF NOT EXISTS audit(
                        seq INTEGER PRIMARY KEY, proposal_id TEXT NOT NULL,
                        changed INTEGER NOT NULL, actor_uid INTEGER NOT NULL,
                        action TEXT NOT NULL, result TEXT NOT NULL);
                    """)
            if delegated:
                from repocache.submission_db_worker import _check_queue, _service_account
                _check_queue(self.path, _service_account().pw_uid)
        except (OSError, sqlite3.Error) as exc:
            raise SubmissionError("store_unavailable", 503) from exc

    def _needs_worker(self) -> bool:
        # Never open SQLite or sidecars as real root in an intake-owned dir.
        # Simulated non-root test identities retain their temporary DB path.
        if os.geteuid() != 0 or _REAL_GETEUID() != 0:
            return False
        parent = self.path.parent.lstat()
        if parent.st_uid == 0:
            return False
        from repocache.submission_db_worker import _service_account
        if parent.st_uid != _service_account().pw_uid:
            raise SubmissionError("unsafe_store", 503)
        return True

    @contextmanager
    def _connect(self):
        """Close every connection; service-writable paths use a UID worker."""
        if self._needs_worker():
            from repocache.submission_db_worker import WorkerConnection
            with WorkerConnection(self.path) as connection:
                yield connection
            return
        connection = sqlite3.connect(self.path, timeout=3, isolation_level=None)
        try:
            connection.execute("PRAGMA busy_timeout=3000")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA journal_mode=DELETE")
            with connection:
                yield connection
        finally:
            connection.close()

    def enqueue(self, key_hash: str, nonce: str, digest: str, item: dict,
                *, now: int | None = None) -> str:
        current = int(time.time()) if now is None else int(now)
        try:
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                existing = db.execute(
                    "SELECT digest, proposal_id FROM nonces WHERE key_hash=? AND nonce=?",
                    (key_hash, nonce)).fetchone()
                if existing:
                    if existing[0] != digest:
                        raise SubmissionError("conflicting_nonce", 409)
                    return existing[1]
                count = db.execute(
                    "SELECT COUNT(*) FROM nonces WHERE key_hash=? AND created>?",
                    (key_hash, current - 60)).fetchone()[0]
                if count >= 10:
                    raise SubmissionError("rate_limited", 429)
                if (self.path.stat().st_size > 128 * 1024 * 1024
                        or db.execute("SELECT COUNT(*) FROM proposals").fetchone()[0] >= 50000
                        or db.execute("SELECT COUNT(*) FROM proposals WHERE state='PENDING'").fetchone()[0] >= 5000
                        or db.execute("SELECT COUNT(*) FROM audit").fetchone()[0] >= 100000):
                    raise SubmissionError("queue_full", 503)
                ident = secrets.token_hex(16)
                db.execute(
                    "INSERT INTO proposals(id,os_id,os_version,items,state,created,changed)"
                    " VALUES(?,?,?,?,'PENDING',?,?)",
                    (ident, item["os"]["id"], item["os"]["version"],
                     json.dumps(item["repositories"], sort_keys=True), current, current))
                db.execute(
                    "INSERT INTO nonces(key_hash,nonce,digest,proposal_id,created)"
                    " VALUES(?,?,?,?,?)",
                    (key_hash, nonce, digest, ident, current))
                return ident
        except sqlite3.Error as exc:
            raise SubmissionError("store_unavailable", 503) from exc

    @staticmethod
    def _proposal_digest(row: tuple) -> str:
        # Bind administrator receipt to the exact persisted proposal metadata,
        # not to a mutable state/version/audit field controlled by intake.
        ident, os_id, os_version, items, created = row[:5]
        payload = json.dumps([ident, os_id, os_version, items, created],
                             sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _journal(self) -> DecisionJournal:
        return DecisionJournal(self.journal_dir)

    @staticmethod
    def _verify_state(state: str, version: int, digest: str, chain: list[dict]) -> None:
        if chain:
            last = chain[-1]
            if (last["proposal_digest"] != digest or
                    last["state"] != state or last["version"] != version):
                raise SubmissionError("decision_reconcile_required", 409)
        elif state != "PENDING" or version != 0:
            # An intake-writable DB row cannot claim a trusted review.
            raise SubmissionError("unaudited_decision_state", 503)

    def pending(self, *, limit: int = 100) -> list[dict]:
        if os.geteuid() != 0:
            raise SubmissionError("operator_required", 403)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise SubmissionError("invalid_limit", 400)
        proposals = []
        try:
            with self._journal().locked() as journal:
                with self._connect() as db:
                    # Verify all returned rows against root-owned receipts.
                    # The intake may not forge a REVIEWED state by editing DB.
                    rows = db.execute(
                        "SELECT id,os_id,os_version,items,created,state,version "
                        "FROM proposals WHERE state='PENDING' ORDER BY created,id LIMIT ?",
                        (limit,)).fetchall()
                    for ident, os_id, os_version, items, created, state, version in rows:
                        if (not isinstance(items, str) or len(items) > 131072 or
                                not isinstance(ident, str) or
                                not re.fullmatch(r"[a-f0-9]{32}", ident)):
                            raise SubmissionError("invalid_stored_proposal", 503)
                        _check_json_depth(items.encode("utf-8"),
                                          code="invalid_stored_proposal", status=503)
                        try:
                            repositories = json.loads(items)
                        except (ValueError, RecursionError, UnicodeError, TypeError) as exc:
                            raise SubmissionError("invalid_stored_proposal", 503) from exc
                        if not isinstance(repositories, list) or not 1 <= len(repositories) <= 32:
                            raise SubmissionError("invalid_stored_proposal", 503)
                        digest = self._proposal_digest(
                            (ident, os_id, os_version, items, created))
                        self._verify_state(state, version, digest, journal.read(ident))
                        proposals.append({"id": ident, "os": os_id,
                                          "version_os": os_version,
                                          "repositories": repositories,
                                          "version": version})
            return proposals
        except DecisionError as exc:
            raise SubmissionError(exc.code, exc.status) from exc
        except sqlite3.Error as exc:
            raise SubmissionError("store_unavailable", 503) from exc

    def decide(self, ident: str, action: str, *, expected_version: int | None = None) -> None:
        if os.geteuid() != 0:
            raise SubmissionError("operator_required", 403)
        if (action not in {"review", "reject", "reopen"} or
                not isinstance(ident, str) or
                not re.fullmatch(r"[a-f0-9]{32}", ident)):
            raise SubmissionError("invalid_decision", 400)
        if type(expected_version) is not int or expected_version < 0:
            raise SubmissionError("version_required", 400)
        try:
            with self._journal().locked() as journal:
                with self._connect() as db:
                    db.execute("BEGIN IMMEDIATE")
                    row = db.execute(
                        "SELECT id,os_id,os_version,items,created,state,version "
                        "FROM proposals WHERE id=?", (ident,)).fetchone()
                    if not row:
                        raise SubmissionError("proposal_missing", 404)
                    proposal_digest = self._proposal_digest(row)
                    chain = journal.read(ident)
                    self._verify_state(row[5], row[6], proposal_digest, chain)
                    state, version = row[5], row[6]
                    if version != expected_version:
                        raise SubmissionError("stale_decision", 409)
                    if ((action in {"review", "reject"} and state != "PENDING")
                            or (action == "reopen" and state == "PENDING")):
                        raise SubmissionError("invalid_transition", 409)
                    # The root-controlled durable receipt is authoritative.
                    # If SQLite fails AFTER this write, the caller gets an
                    # error and must explicitly reconcile before further
                    # review (never show an unverified success).
                    receipt = journal.append(ident, action, proposal_digest, chain)
                    db.execute(
                        "UPDATE proposals SET state=?,version=?,changed=? WHERE id=?",
                        (receipt["state"], receipt["version"], receipt["at"], ident))
                    # Historical audit rows here are a convenience only.
                    # Never use this service-writable table as trusted proof.
                    db.execute(
                        "INSERT INTO audit(proposal_id,changed,actor_uid,action,result)"
                        " VALUES(?,?,?,?,?)",
                        (ident, receipt["at"], receipt["actor_uid"],
                         action, receipt["state"]))
        except DecisionError as exc:
            raise SubmissionError(exc.code, exc.status) from exc
        except sqlite3.Error as exc:
            raise SubmissionError("decision_reconcile_required", 409) from exc

    def audit(self, ident: str) -> list[tuple]:
        """Authoritative history comes only from root-owned receipts."""
        if os.geteuid() != 0:
            raise SubmissionError("operator_required", 403)
        try:
            with self._journal().locked() as journal:
                return [(entry["action"], entry["state"], entry["actor_uid"])
                        for entry in journal.read(ident)]
        except DecisionError as exc:
            raise SubmissionError(exc.code, exc.status) from exc

    def reconcile(self, ident: str, *, approved: bool = False) -> None:
        """Explicitly repair SQLite only when it lags a valid durable receipt.

        No automatic state-changing recovery is performed by the intake or TUI.
        The original proposal metadata must still match the root receipt.
        """
        if os.geteuid() != 0 or not approved:
            raise SubmissionError("operator_approval_required", 403)
        if not isinstance(ident, str) or not re.fullmatch(r"[a-f0-9]{32}", ident):
            raise SubmissionError("invalid_decision_id", 400)
        try:
            with self._journal().locked() as journal:
                with self._connect() as db:
                    db.execute("BEGIN IMMEDIATE")
                    row = db.execute(
                        "SELECT id,os_id,os_version,items,created,state,version "
                        "FROM proposals WHERE id=?", (ident,)).fetchone()
                    if not row:
                        raise SubmissionError("proposal_missing", 404)
                    chain = journal.read(ident)
                    if not chain:
                        raise SubmissionError("no_authoritative_decision", 409)
                    last = chain[-1]
                    if self._proposal_digest(row) != last["proposal_digest"]:
                        raise SubmissionError("decision_metadata_conflict", 409)
                    if (type(row[6]) is not int or row[6] > last["version"]
                            or (row[6] == last["version"] and
                                row[5] != last["state"])):
                        raise SubmissionError("decision_state_tampered", 409)
                    if row[6] < last["version"]:
                        if row[6] and (row[6] > len(chain) or
                                       row[5] != chain[row[6] - 1]["state"]):
                            raise SubmissionError("decision_state_tampered", 409)
                        if row[6] == 0 and row[5] != "PENDING":
                            raise SubmissionError("decision_state_tampered", 409)
                        db.execute(
                            "UPDATE proposals SET state=?,version=?,changed=? WHERE id=?",
                            (last["state"], last["version"], last["at"], ident))
        except DecisionError as exc:
            raise SubmissionError(exc.code, exc.status) from exc
        except sqlite3.Error as exc:
            raise SubmissionError("decision_reconcile_failed", 503) from exc

    def maintain(self, *, approved: bool = False, now: int | None = None,
                 decided_retention_days: int = 180) -> dict[str, int]:
        """Explicit operator-approved retention. Pending records are never purged."""
        if os.geteuid() != 0 or not approved:
            raise SubmissionError("operator_approval_required", 403)
        if (not isinstance(decided_retention_days, int) or
                not 30 <= decided_retention_days <= 3650):
            raise SubmissionError("invalid_retention_policy", 400)
        current = int(time.time()) if now is None else int(now)
        cutoff = current - decided_retention_days * 86400
        try:
            # Intake can edit SQLite state, timestamps and audit rows. Never
            # let a forged REVIEWED/REJECTED flag or backdated 'changed'
            # delete an undecided or recently decided proposal. Serialize
            # with privileged decisions and use the root receipt's time.
            with self._journal().locked() as journal:
                with self._connect() as db:
                    db.execute("BEGIN IMMEDIATE")
                    candidates = db.execute(
                        "SELECT id,os_id,os_version,items,created,state,version "
                        "FROM proposals WHERE state!='PENDING' AND changed < ?",
                        (cutoff,)).fetchall()
                    expired = []
                    for row in candidates:
                        ident = row[0]
                        if (not isinstance(ident, str) or
                                not re.fullmatch(r"[a-f0-9]{32}", ident)):
                            raise SubmissionError("invalid_stored_proposal", 503)
                        chain = journal.read(ident)
                        self._verify_state(row[5], row[6],
                                           self._proposal_digest(row), chain)
                        if not chain:
                            raise SubmissionError("unaudited_decision_state", 503)
                        # The SQLite timestamp is untrusted; an intake writer
                        # cannot shorten retention of root-authorized decisions.
                        if chain[-1]["at"] < cutoff:
                            expired.append(ident)
                    # All replay windows are shorter than one day (30 seconds
                    # timestamp skew); retain nonces at least 24 hours.
                    dropped_nonces = db.execute(
                        "DELETE FROM nonces WHERE created < ?",
                        (current - 86400,)).rowcount
                    for ident in expired:
                        db.execute("DELETE FROM audit WHERE proposal_id=?", (ident,))
                        db.execute("DELETE FROM proposals WHERE id=?", (ident,))
                    return {"purged_decided": len(expired),
                            "purged_nonces": dropped_nonces}
        except DecisionError as exc:
            raise SubmissionError(exc.code, exc.status) from exc
        except sqlite3.Error as exc:
            raise SubmissionError("retention_unavailable", 503) from exc

    def backup(self, destination: Path) -> None:
        """Atomic operator-only backup of the committed database state.

        Never replaces existing backup data. No application log or public file
        includes backup content. An external operator must protect the media.
        """
        if os.geteuid() != 0:
            raise SubmissionError("operator_required", 403)
        destination = Path(destination)
        try:
            parent = destination.parent.lstat()
            if (not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o077
                    or parent.st_uid != 0 or destination.exists() or
                    destination.is_symlink()):
                raise SubmissionError("unsafe_backup_destination", 403)
            descriptor, temp = tempfile.mkstemp(prefix=".repocache-backup-", dir=destination.parent)
            try:
                os.fchmod(descriptor, 0o600)
                os.close(descriptor)
                with self._connect() as source:
                    if hasattr(source, "backup_file"):
                        # Service UID streams a consistent snapshot; root
                        # writes only to the protected destination staging.
                        source.backup_file(temp)
                    else:
                        with sqlite3.connect(temp) as target:
                            source.backup(target)
                with sqlite3.connect(temp) as target:
                    if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                        raise SubmissionError("invalid_backup", 503)
                with open(temp, "rb") as stream:
                    os.fsync(stream.fileno())
                os.link(temp, destination)
                directory = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            finally:
                if os.path.exists(temp):
                    os.unlink(temp)
        except (OSError, sqlite3.Error) as exc:
            raise SubmissionError("backup_unavailable", 503) from exc
