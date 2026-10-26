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

# Single trusted schema contract for initialization and privileged offline restore.
# Restores fail closed on noncanonical constraints, indexes or schema objects.
SUBMISSION_QUEUE_SCHEMA_SQL = """
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
"""


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
                connection.executescript(SUBMISSION_QUEUE_SCHEMA_SQL)
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
        if not self.path.is_absolute():
            raise SubmissionError("unsafe_store_path", 503)
        # Every ancestor must be root-controlled. A root-owned 0700 queue
        # under an intake-renamable ancestor is NOT a safe root SQLite path.
        # Root-owned sticky directories (e.g. /tmp) protect root-owned child
        # names from replacement by another UID.
        for ancestor in self.path.parent.parents:
            st = ancestor.lstat()
            if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or
                    (st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX)):
                raise SubmissionError("unsafe_store_ancestor", 503)
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
    def _checked_proposal_row(row: tuple, *, requested_id: str | None = None,
                              expected_state: str | None = None) -> tuple:
        """Validate fixed SQL projections before any privileged decision.

        A service-UID worker can return a scalar-only row with the wrong
        number, order or meaning of fields. The generic cursor cannot know
        this schema. Refuse malformed rows before hashing or journal writes.
        """
        if type(row) is not tuple or len(row) != 7:
            raise SubmissionError("invalid_stored_proposal", 503)
        ident, os_id, os_version, items, created, state, version = row
        if (type(ident) is not str or
                not re.fullmatch(r"[a-f0-9]{32}", ident) or
                (requested_id is not None and ident != requested_id) or
                type(os_id) is not str or type(os_version) is not str or
                not ((os_id == "debian" and
                      re.fullmatch(r"13(?:\.[0-9]{1,4})?", os_version)) or
                     (os_id == "almalinux" and
                      re.fullmatch(r"10(?:\.[0-9]{1,4})?", os_version))) or
                type(items) is not str or not 0 < len(items) <= 131072 or
                type(created) is not int or
                type(state) is not str or
                state not in {"PENDING", "REVIEWED", "REJECTED"} or
                (expected_state is not None and state != expected_state) or
                type(version) is not int or version < 0):
            raise SubmissionError("invalid_stored_proposal", 503)
        # Escaped lone Unicode surrogates are legal worker JSON strings, but
        # not UTF-8 text. Refuse them here for pending views and journal paths.
        try:
            items.encode("utf-8")
        except UnicodeError as exc:
            raise SubmissionError("invalid_stored_proposal", 503) from exc
        return row

    @staticmethod
    def _checked_decided_row(row: tuple) -> tuple:
        """Reject forged decided metadata, not only state/version fields."""
        try:
            row = SubmissionQueue._checked_proposal_row(row)
        except SubmissionError as exc:
            raise SubmissionError("unaudited_decision_state", 503) from exc
        if row[5] not in {"REVIEWED", "REJECTED"} or row[6] < 1:
            raise SubmissionError("unaudited_decision_state", 503)
        return row

    @staticmethod
    def _proposal_digest(row: tuple) -> str:
        # Bind administrator receipt to the exact persisted proposal metadata,
        # not to a mutable state/version/audit field controlled by intake.
        ident, os_id, os_version, items, created = row[:5]
        payload = json.dumps([ident, os_id, os_version, items, created],
                             sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _require_unique_proposal(db, ident: str) -> None:
        """Refuse duplicate IDs even if intake replaced SQLite PRIMARY KEY.

        A root receipt authorizes exactly one proposal. Without this check,
        UPDATE/DELETE WHERE id=? can affect additional service-controlled rows
        after a compromised intake UID drops the uniqueness constraint.
        Call under BEGIN IMMEDIATE before any journal write or deletion.
        """
        count = db.execute(
            "SELECT COUNT(*) FROM proposals WHERE id=?", (ident,)
        ).fetchone()
        if (type(count) is not tuple or len(count) != 1 or
                type(count[0]) is not int or count[0] != 1):
            raise SubmissionError("invalid_stored_proposal", 503)

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
                    # Read one SQLite snapshot. Without this, an intake writer
                    # could flip a row between our two root-authenticated
                    # visibility checks and hide an undecided proposal.
                    db.execute("BEGIN")
                    # Refuse a service-UID-forged REVIEWED/REJECTED row that
                    # would otherwise disappear from the pending-only query.
                    # The root journal decides which transitions are valid.
                    # A compromised intake UID may also replace the SQLite
                    # schema and set state=NULL, which ordinary SQL != and =
                    # comparisons both omit. Treat NULL as an invalid decided
                    # row rather than hiding it from administrator review.
                    # The intake UID can retain REVIEWED state/version
                    # while replacing metadata. Bind every decided row to its
                    # root receipt; page to bound worker IPC response sizes.
                    last_id = None
                    checked = 0
                    known = None
                    while True:
                        # The first page has no id>? predicate: a compromised
                        # SQLite schema may contain NULL/empty/numeric IDs that
                        # would otherwise sort before the empty-string cursor
                        # and evade both pending and decided preflights.
                        query = (
                            "SELECT id,os_id,os_version,items,created,state,version "
                            "FROM proposals WHERE (state!='PENDING' OR state IS NULL)"
                        )
                        if last_id is not None:
                            query += " AND id>?"
                        # Fetch one lookahead row. Without it, an intake
                        # attacker can drop the primary key and place the
                        # second copy of the 64th ID just beyond the page:
                        # the next id>? query would silently skip that copy.
                        query += " ORDER BY id LIMIT 65"
                        decided = db.execute(
                            query, () if last_id is None else (last_id,)
                        ).fetchall()
                        if type(decided) is not list or len(decided) > 65:
                            raise SubmissionError("unaudited_decision_state", 503)
                        if not decided:
                            break
                        if known is None:
                            known = {}
                            # Enumerate root-protected receipts once.
                            for entry in journal.directory.iterdir():
                                name = entry.name
                                if name.endswith(".json"):
                                    known.setdefault(name.split(".", 1)[0], set()).add(name)
                        for result in decided[:64]:
                            row = self._checked_decided_row(result)
                            ident, state, version = row[0], row[5], row[6]
                            if last_id is not None and ident <= last_id:
                                raise SubmissionError("unaudited_decision_state", 503)
                            last_id = ident
                            checked += 1
                            if checked > 50000:
                                raise SubmissionError("unaudited_decision_state", 503)
                            chain = journal.read(ident, known_names=known.get(ident, set()))
                            if (not chain or chain[-1]["state"] != state or
                                    chain[-1]["version"] != version or
                                    chain[-1]["proposal_digest"] != self._proposal_digest(row)):
                                raise SubmissionError("unaudited_decision_state", 503)
                        if len(decided) == 65:
                            # A duplicate at the page boundary is not
                            # visited by a strict id>? cursor on the next
                            # page. Reject it before returning a pending view.
                            lookahead = self._checked_decided_row(decided[64])
                            if lookahead[0] <= last_id:
                                raise SubmissionError("unaudited_decision_state", 503)
                        else:
                            break
                    # Verify all returned rows against root-owned receipts.
                    # The intake may not forge a REVIEWED state by editing DB.
                    rows = db.execute(
                        "SELECT id,os_id,os_version,items,created,state,version "
                        "FROM proposals WHERE state='PENDING' ORDER BY created,id LIMIT ?",
                        (limit,)).fetchall()
                    if type(rows) is not list or len(rows) > limit:
                        raise SubmissionError("invalid_stored_proposal", 503)
                    for result in rows:
                        (ident, os_id, os_version, items, created, state,
                         version) = self._checked_proposal_row(
                             result, expected_state="PENDING")
                        _check_json_depth(items.encode("utf-8"),
                                          code="invalid_stored_proposal", status=503)
                        try:
                            repositories = json.loads(items)
                        except (ValueError, RecursionError, UnicodeError, TypeError) as exc:
                            raise SubmissionError("invalid_stored_proposal", 503) from exc
                        if not isinstance(repositories, list) or not 1 <= len(repositories) <= 32:
                            raise SubmissionError("invalid_stored_proposal", 503)
                        # SQLite is writable by the unprivileged intake UID.
                        # Do not hand its unchecked nested objects to a root
                        # administrator TUI (including Rich markup or control
                        # sequences). Revalidate ALL entries, not just the
                        # first displayed upstream.
                        try:
                            original = [
                                {"type": record["type"], "url": record["url"]}
                                for record in repositories
                                if isinstance(record, dict) and
                                set(record) == {"type", "url", "insecure_http"}
                            ]
                            if len(original) != len(repositories):
                                raise ValueError("malformed stored repository")
                            raw = json.dumps({
                                "schema": 1,
                                "os": {"id": os_id, "version": os_version},
                                "repositories": original,
                            }, separators=(",", ":"), ensure_ascii=True).encode("ascii")
                            normalized = validate_payload(raw)["repositories"]
                            if normalized != repositories:
                                raise ValueError("stored repository differs from validated input")
                        except (SubmissionError, ValueError, TypeError, KeyError,
                                UnicodeError, RecursionError) as exc:
                            raise SubmissionError("invalid_stored_proposal", 503) from exc
                        digest = self._proposal_digest(
                            (ident, os_id, os_version, items, created))
                        self._verify_state(state, version, digest, journal.read(ident))
                        proposals.append({"id": ident, "os": os_id,
                                          "version_os": os_version,
                                          "repositories": normalized,
                                          "version": version,
                                          "metadata_digest": digest})
            return proposals
        except DecisionError as exc:
            raise SubmissionError(exc.code, exc.status) from exc
        except sqlite3.Error as exc:
            raise SubmissionError("store_unavailable", 503) from exc

    def decide(self, ident: str, action: str, *, expected_version: int | None = None,
               expected_digest: str | None = None) -> None:
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
                    if row is None:
                        raise SubmissionError("proposal_missing", 404)
                    row = self._checked_proposal_row(row, requested_id=ident)
                    self._require_unique_proposal(db, ident)
                    proposal_digest = self._proposal_digest(row)
                    # The root UI binds the approval to the exact metadata
                    # displayed earlier, not merely its mutable SQLite version.
                    if expected_digest is not None and (
                            not isinstance(expected_digest, str) or
                            not re.fullmatch(r"[a-f0-9]{64}", expected_digest) or
                            proposal_digest != expected_digest):
                        raise SubmissionError("stale_decision", 409)
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
                    if row is None:
                        raise SubmissionError("proposal_missing", 404)
                    row = self._checked_proposal_row(row, requested_id=ident)
                    self._require_unique_proposal(db, ident)
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
                    # Keep every worker response below the bounded IPC limit.
                    # A 50,000-row queue with 128 KiB metadata per proposal
                    # must not be fetched as one unbounded JSON reply.
                    expired = []
                    last_id = None
                    checked = 0
                    while True:
                        query = (
                            "SELECT id,os_id,os_version,items,created,state,version "
                            "FROM proposals WHERE state!='PENDING' AND changed < ?"
                        )
                        params = (cutoff,)
                        if last_id is not None:
                            query += " AND id>?"
                            params = (cutoff, last_id)
                        # One lookahead detects a duplicate at the keyset
                        # boundary even if intake dropped the PRIMARY KEY.
                        query += " ORDER BY id LIMIT 65"
                        candidates = db.execute(query, params).fetchall()
                        if type(candidates) is not list or len(candidates) > 65:
                            raise SubmissionError("invalid_stored_proposal", 503)
                        if not candidates:
                            break
                        for result in candidates[:64]:
                            row = self._checked_proposal_row(result)
                            if row[5] == "PENDING":
                                raise SubmissionError("invalid_stored_proposal", 503)
                            ident = row[0]
                            if last_id is not None and ident <= last_id:
                                raise SubmissionError("invalid_stored_proposal", 503)
                            last_id = ident
                            checked += 1
                            if checked > 50000:
                                raise SubmissionError("invalid_stored_proposal", 503)
                            # A forged duplicate PENDING row with the same ID
                            # must never be removed by DELETE WHERE id.
                            self._require_unique_proposal(db, ident)
                            chain = journal.read(ident)
                            self._verify_state(row[5], row[6],
                                               self._proposal_digest(row), chain)
                            if not chain:
                                raise SubmissionError("unaudited_decision_state", 503)
                            # Intake timestamps cannot shorten root retention.
                            if chain[-1]["at"] < cutoff:
                                expired.append(ident)
                        if len(candidates) == 65:
                            lookahead = self._checked_proposal_row(candidates[64])
                            if lookahead[0] <= last_id:
                                raise SubmissionError("invalid_stored_proposal", 503)
                        else:
                            break
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
        # A root-private final directory is insufficient when an untrusted
        # ancestor can rename it. Refuse relative paths and inspect every
        # ancestor before creating or reading a privileged backup.
        if not destination.is_absolute():
            raise SubmissionError("unsafe_backup_destination", 403)
        try:
            parent = destination.parent.lstat()
            if (not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o077
                    or parent.st_uid != 0 or destination.exists() or
                    destination.is_symlink()):
                raise SubmissionError("unsafe_backup_destination", 403)
            for ancestor in destination.parent.parents:
                st = ancestor.lstat()
                if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or
                        (st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX)):
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
