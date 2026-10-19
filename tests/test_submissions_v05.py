"""Adversarial, offline tests for the governed submission intake (#16)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from repocache.intake import (
    ENDPOINT, SubmissionIntake, canonical_request, load_keyring, make_loopback_server,
)
from repocache.submissions import SubmissionError, SubmissionQueue, validate_payload

KEY = b"c" * 32
NOW = 1792447200


@pytest.fixture
def queue(tmp_path):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return SubmissionQueue(directory / "queue.sqlite3")


def payload(url="https://mirror.example.org/debian/", platform="debian", kind="apt-deb822"):
    return json.dumps({"schema": 1, "os": {
        "id": platform, "version": "13" if platform == "debian" else "10"},
        "repositories": [{"type": kind, "url": url}]},
        sort_keys=True, separators=(",", ":")).encode()


def signed(raw: bytes, *, nonce=None, now=NOW, key=KEY, key_id="test"):
    nonce = nonce or base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")
    stamp = str(now)
    return {
        "content-type": "application/json",
        "x-repocache-key-id": key_id,
        "x-repocache-timestamp": stamp,
        "x-repocache-nonce": nonce,
        "x-repocache-signature": hmac.new(key, canonical_request(stamp, nonce, raw),
                                           hashlib.sha256).hexdigest(),
    }


def test_known_canonical_signature_and_pending_only(queue):
    raw = payload()
    canonical = canonical_request(str(NOW), "AQEBAQEBAQEBAQEBAQEBAQ", raw)
    assert canonical == (
        f"repocache-v1\nPOST\n{ENDPOINT}\n{NOW}\nAQEBAQEBAQEBAQEBAQEBAQ\n"
        + hashlib.sha256(raw).hexdigest()).encode("ascii")
    intake = SubmissionIntake(queue, {"test": KEY})
    headers = signed(raw)
    status, result, _ = intake.handle("POST", ENDPOINT, headers, raw, now=NOW)
    assert status == 202
    assert result["status"] == "pending"
    assert len(result["proposal_id"]) == 32
    assert queue.path.read_bytes().find(KEY) < 0


def test_identical_nonce_retries_reuse_same_record(queue):
    intake = SubmissionIntake(queue, {"test": KEY})
    raw = payload()
    headers = signed(raw)
    first = intake.handle("POST", ENDPOINT, headers, raw, now=NOW)
    repeated = intake.handle("POST", ENDPOINT, headers, raw, now=NOW)
    assert first == repeated
    other = payload("https://other.example.org/debian/")
    conflict = intake.handle("POST", ENDPOINT, signed(other, nonce=headers["x-repocache-nonce"]),
                             other, now=NOW)
    assert conflict[0] == 409


@pytest.mark.parametrize("bad", [
    "http://127.0.0.1/", "http://[::1]/", "http://localhost/",
    "https://a.local/", "https://metadata.google.internal/",
    "https://user:pass@mirror.example.org/", "https://mirror.example.org/?token=secret",
    "https://mirror.example.org/#hello", "https://mirror.example.org/a/../b",
    "https://mirror.example.org/%2fetc/", "https://mirror.example.org\\@evil.org/",
    "https://xn--nxd.example.org/", "https://mirror.example.org:0/repo",
])
def test_bad_urls_rejected_without_dns_or_queue_changes(queue, bad, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs:
                        pytest.fail("Intake must never make DNS queries"))
    raw = payload(bad)
    intake = SubmissionIntake(queue, {"test": KEY})
    assert intake.handle("POST", ENDPOINT, signed(raw), raw, now=NOW)[0] == 422
    with queue._connect() as db:
        assert db.execute("SELECT count(*) FROM proposals").fetchone()[0] == 0


def test_parser_rejects_duplicate_keys_wrong_platform_and_malformed_json():
    for raw in (
        b'{"schema":1,"schema":1,"os":{},"repositories":[]}',
        b'{"schema":NaN,"os":{},"repositories":[]}',
        b'{"schema":1',
        payload(platform="almalinux"),
        payload(kind="dnf"),
        payload(url="ftp://bad.example.org/"),
        b"\xff",
    ):
        with pytest.raises(SubmissionError):
            validate_payload(raw)
    assert validate_payload(payload("http://mirror.example.org/debian/"))[
        "repositories"][0]["insecure_http"] is True


def test_bad_authorization_and_method_do_not_insert(queue):
    raw = payload()
    intake = SubmissionIntake(queue, {"test": KEY})
    valid = signed(raw)
    cases = [
        ("GET", ENDPOINT, valid),
        ("POST", "/other", valid),
        ("POST", ENDPOINT, dict(valid, **{"content-type": "text/plain"})),
        ("POST", ENDPOINT, signed(raw, key=b"d" * 32)),
        ("POST", ENDPOINT, signed(raw, now=NOW - 31)),
        ("POST", ENDPOINT, signed(raw, key_id="unknown")),
    ]
    for method, path, headers in cases:
        assert intake.handle(method, path, headers, raw, now=NOW)[0] != 202
    with queue._connect() as db:
        assert db.execute("SELECT count(*) FROM proposals").fetchone()[0] == 0


def test_limit_retry_and_rate_windows(queue):
    intake = SubmissionIntake(queue, {"test": KEY})
    raw = payload()
    for _ in range(10):
        assert intake.handle("POST", ENDPOINT, signed(raw), raw, now=NOW)[0] == 202
    limited = intake.handle("POST", ENDPOINT, signed(raw), raw, now=NOW)
    assert limited[0] == 429 and limited[2].get("Retry-After") == "60"


def test_parallel_submission_is_atomic(queue):
    intake = SubmissionIntake(queue, {"test": KEY})
    raw = payload()
    headers = signed(raw)
    def submit(_):
        return intake.handle("POST", ENDPOINT, headers, raw, now=NOW)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(submit, range(30)))
    assert all(status == 202 for status, _, _ in results)
    assert len({body["proposal_id"] for _, body, _ in results}) == 1
    with queue._connect() as db:
        assert db.execute("SELECT count(*) FROM proposals").fetchone()[0] == 1


def test_permission_check_audit_and_reopen(queue, monkeypatch):
    from repocache import submissions
    raw = payload()
    intake = SubmissionIntake(queue, {"test": KEY})
    ident = intake.handle("POST", ENDPOINT, signed(raw), raw, now=NOW)[1]["proposal_id"]
    monkeypatch.setattr(submissions.os, "geteuid", lambda: 1001)
    with pytest.raises(SubmissionError, match="operator_required"):
        queue.pending()
    with pytest.raises(SubmissionError, match="operator_required"):
        queue.decide(ident, "review")
    monkeypatch.setattr(submissions.os, "geteuid", lambda: 0)
    pending = queue.pending()
    assert len(pending) == 1 and pending[0]["id"] == ident
    queue.decide(ident, "review", expected_version=0)
    with pytest.raises(SubmissionError, match="stale_decision"):
        queue.decide(ident, "reopen", expected_version=0)
    with pytest.raises(SubmissionError, match="invalid_transition"):
        queue.decide(ident, "review")
    queue.decide(ident, "reopen", expected_version=1)
    queue.decide(ident, "reject", expected_version=2)
    assert [x[0] for x in queue.audit(ident)] == ["review", "reopen", "reject"]
    assert not queue.pending()


def test_listener_requires_explicit_enablement(queue):
    intake = SubmissionIntake(queue, {"test": KEY})
    with pytest.raises(SubmissionError, match="listener_disabled"):
        make_loopback_server(intake)
    server = make_loopback_server(intake, enabled=True, port=0)
    try:
        assert server.server_address[0] == "127.0.0.1"
    finally:
        server.server_close()


def test_keyring_rejects_unsafe_permissions(tmp_path):
    parent = tmp_path / "keys"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    keyring = parent / "keyring.json"
    keyring.write_text(json.dumps({"keys": [{
        "key_id": "test", "secret": base64.urlsafe_b64encode(KEY).decode().rstrip("=")}]}))
    keyring.chmod(0o600)
    assert load_keyring(keyring) == {"test": KEY}
    keyring.chmod(0o644)
    with pytest.raises(SubmissionError):
        load_keyring(keyring)

def test_unhashable_kind_and_boolean_schema_fail_cleanly_without_insert(queue):
    intake = SubmissionIntake(queue, {"test": KEY})
    records = [
        {"schema": True, "os": {"id": "debian", "version": "13"},
         "repositories": [{"type": "apt-list",
                           "url": "https://mirror.example.org/debian/"}]},
        {"schema": 1, "os": {"id": "debian", "version": "13"},
         "repositories": [{"type": ["apt-list"],
                           "url": "https://mirror.example.org/debian/"}]},
    ]
    for doc in records:
        raw = json.dumps(doc).encode()
        status, response, _ = intake.handle("POST", ENDPOINT, signed(raw),
                                            raw, now=NOW)
        assert status == 422, response
    with queue._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM proposals").fetchone()[0] == 0
