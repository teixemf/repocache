"""Pending-only, isolated repository submission storage.

No network lookups, NGINX modifications, or catalog publication are performed.
"""
from __future__ import annotations

import ipaddress
import json
import os
import pwd
import re
import secrets
import sqlite3
import stat
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


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


def validate_payload(raw: bytes) -> dict:
    """Validate inert metadata without DNS resolution or external I/O."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 65536:
        raise SubmissionError("invalid_size", 413)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                         parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, TypeError) as exc:
        if isinstance(exc, SubmissionError):
            raise
        raise SubmissionError("invalid_json", 400) from exc
    if (not isinstance(doc, dict) or set(doc) != {"schema", "os", "repositories"}
            or type(doc["schema"]) is not int or doc["schema"] != 1):
        raise SubmissionError("invalid_schema")
    platform = doc["os"]
    if not isinstance(platform, dict) or set(platform) != {"id", "version"}:
        raise SubmissionError("invalid_platform")
    os_id, version = platform["id"], platform["version"]
    if (not isinstance(os_id, str) or not isinstance(version, str)
            or not ((os_id == "debian" and re.fullmatch(r"13(?:\\.[0-9]{1,4})?", version))
                    or (os_id == "almalinux" and re.fullmatch(r"10(?:\\.[0-9]{1,4})?", version)))):
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


class SubmissionQueue:
    """Local SQLite state; operator decisions require real root OS identity."""

    def __init__(self, path: Path):
        self.path = Path(path)
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
        if not self.path.exists():
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
                os.close(fd)
            except FileExistsError:
                pass
            except OSError as exc:
                raise SubmissionError("store_unavailable", 503) from exc
        try:
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
        except (OSError, sqlite3.Error) as exc:
            raise SubmissionError("store_unavailable", 503) from exc

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=3, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=3000")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA journal_mode=DELETE")
        return connection

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
                if db.execute("SELECT COUNT(*) FROM proposals WHERE state='PENDING'").fetchone()[0] >= 5000:
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

    def pending(self, *, limit: int = 100) -> list[dict]:
        if os.geteuid() != 0:
            raise SubmissionError("operator_required", 403)
        with self._connect() as db:
            rows = db.execute(
                "SELECT id,os_id,os_version,items,version FROM proposals "
                "WHERE state='PENDING' ORDER BY created,id LIMIT ?", (min(limit, 100),))
            return [{"id": row[0], "os": row[1], "version_os": row[2],
                     "repositories": json.loads(row[3]), "version": row[4]} for row in rows]

    def decide(self, ident: str, action: str, *, expected_version: int | None = None) -> None:
        if os.geteuid() != 0:
            raise SubmissionError("operator_required", 403)
        if action not in {"review", "reject", "reopen"} or not re.fullmatch(r"[a-f0-9]{32}", ident):
            raise SubmissionError("invalid_decision", 400)
        now = int(time.time())
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state,version FROM proposals WHERE id=?", (ident,)).fetchone()
            if not row:
                raise SubmissionError("proposal_missing", 404)
            current_state, version = row
            if expected_version is not None and version != expected_version:
                raise SubmissionError("stale_decision", 409)
            if ((action in {"review", "reject"} and current_state != "PENDING")
                    or (action == "reopen" and current_state == "PENDING")):
                raise SubmissionError("invalid_transition", 409)
            next_state = {"review": "REVIEWED", "reject": "REJECTED", "reopen": "PENDING"}[action]
            db.execute("UPDATE proposals SET state=?,version=version+1,changed=? WHERE id=?",
                       (next_state, now, ident))
            db.execute("INSERT INTO audit(proposal_id,changed,actor_uid,action,result)"
                       " VALUES(?,?,?,?,?)", (ident, now, os.getuid(), action, next_state))

    def audit(self, ident: str) -> list[tuple]:
        if os.geteuid() != 0:
            raise SubmissionError("operator_required", 403)
        with self._connect() as db:
            return db.execute(
                "SELECT action,result,actor_uid FROM audit WHERE proposal_id=? ORDER BY seq",
                (ident,)).fetchall()
