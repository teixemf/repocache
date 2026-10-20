"""Gate A negative tests for JSON recursion and persisted-state trust (#17)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest

from repocache import submissions
from repocache.intake import ENDPOINT, SubmissionIntake, canonical_request
from repocache.submissions import SubmissionError, SubmissionQueue, validate_payload

KEY = b"j" * 32
NOW = 1792496400
NONCE = base64.urlsafe_b64encode(b"\x02" * 16).decode("ascii").rstrip("=")


@pytest.fixture
def queue(tmp_path, monkeypatch):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    protected = tmp_path / "decisions"
    protected.mkdir(mode=0o700)
    protected.chmod(0o700)
    from repocache import submission_decisions as decisions
    # The test runner is non-root; bypass only the ownership assertion.
    # Security refusal of insecure owner/mode is tested separately.
    from os import O_RDONLY, O_NOFOLLOW, open as os_open
    monkeypatch.setattr(decisions, "_trusted_dir", lambda _path: None)
    monkeypatch.setattr(decisions, "_open_trusted", lambda path: os_open(
        path, O_RDONLY | O_NOFOLLOW))
    return SubmissionQueue(directory / "pending.sqlite3", journal_dir=protected)


def _deeply_nested_json() -> bytes:
    # Under 64 KiB but above the explicit 32-container protocol depth cap.
    return (b"[" * 1800) + b"0" + (b"]" * 1800)


def test_nested_remote_json_is_sanitized_without_queue_mutation(queue):
    raw = _deeply_nested_json()
    with pytest.raises(SubmissionError) as error:
        validate_payload(raw)
    assert error.value.code == "invalid_json"
    assert error.value.status == 400

    timestamp = str(NOW)
    headers = {
        "content-type": "application/json",
        "x-repocache-key-id": "known-client",
        "x-repocache-timestamp": timestamp,
        "x-repocache-nonce": NONCE,
        "x-repocache-signature": hmac.new(
            KEY, canonical_request(timestamp, NONCE, raw), hashlib.sha256
        ).hexdigest(),
    }
    status, body, _ = SubmissionIntake(queue, {"known-client": KEY}).handle(
        "POST", ENDPOINT, headers, raw, now=NOW)
    assert status == 400
    assert body == {"error": "invalid_json"}
    assert "Recursion" not in str(body)
    with queue._connect() as db:
        assert db.execute("SELECT COUNT(*) FROM proposals").fetchone()[0] == 0


def test_privileged_pending_reader_rejects_deep_stored_metadata(queue, monkeypatch):
    item = {
        "os": {"id": "debian", "version": "13"},
        "repositories": [{"type": "apt-list", "url": "https://mirror.example.org/debian/"}],
    }
    ident = queue.enqueue("digest", "nonce", "digest-body", item, now=NOW)
    with queue._connect() as db:
        db.execute("UPDATE proposals SET items=? WHERE id=?",
                   (_deeply_nested_json().decode("ascii"), ident))
    monkeypatch.setattr(submissions.os, "geteuid", lambda: 0)
    with pytest.raises(SubmissionError) as error:
        queue.pending()
    assert error.value.code == "invalid_stored_proposal"
    assert error.value.status == 503


@pytest.mark.parametrize("stored", ['{"a":', "[]", "1", '"not a repository array"'])
def test_privileged_pending_reader_rejects_invalid_stored_shapes(queue, monkeypatch, stored):
    item = {
        "os": {"id": "debian", "version": "13"},
        "repositories": [{"type": "apt-list", "url": "https://mirror.example.org/debian/"}],
    }
    ident = queue.enqueue("digest", "nonce", "digest-body", item, now=NOW)
    with queue._connect() as db:
        db.execute("UPDATE proposals SET items=? WHERE id=?", (stored, ident))
    monkeypatch.setattr(submissions.os, "geteuid", lambda: 0)
    with pytest.raises(SubmissionError) as error:
        queue.pending()
    assert error.value.code == "invalid_stored_proposal"


def test_brackets_inside_json_string_do_not_count_as_structure():
    url = "https://mirror.example.org/debian/" + ("[{}]" * 80)
    raw = json.dumps({
        "schema": 1,
        "os": {"id": "debian", "version": "13"},
        "repositories": [{"type": "apt-list", "url": url}],
    }).encode("utf-8")
    parsed = validate_payload(raw)
    assert parsed["repositories"][0]["url"] == url


def test_escaped_quotes_and_delimiters_do_not_defeat_depth_guard():
    raw = json.dumps({
        "schema": 1,
        "os": {"id": "debian", "version": "13"},
        "repositories": [{"type": "apt-list", "url": (
            "https://mirror.example.org/normal/[" + ("[]" * 20) + "]")}],
    }, separators=(",", ":")).encode("utf-8")
    assert validate_payload(raw)["os"]["id"] == "debian"
