"""Issue #51: durable activation journal and recovery regression tests."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from repocache import updater


@pytest.fixture
def prepared(monkeypatch, tmp_path):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    versions = root / "releases"
    versions.mkdir()
    old = versions / "0.3.0-old"
    new = versions / "0.4.0-new"
    for path in (old, new):
        (path / "bin").mkdir(parents=True)
        (path / "bin/repocache").write_text("fixture")
    current = root / "current"
    current.symlink_to(old)
    original = (json.dumps({"version": "0.3.0", "source_digest": "a" * 64}) + "\n").encode()
    manifest = root / "installed.json"
    manifest.write_bytes(original)
    for key, value in {
        "ROOT": root, "CURRENT": current, "MANIFEST": manifest,
        "EXECUTABLE": current / "bin/repocache",
    }.items():
        monkeypatch.setattr(updater, key, value)
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    return root, old, new, original


def _journal(root, old, new, original, phase, schema=1):
    path = root / ".update-journal.json"
    data = {
        "schema": schema, "phase": phase, "previous": str(old),
        "previous_manifest": base64.b64encode(original).decode("ascii"),
        "destination": str(new), "new_version": "0.4.0",
    }
    if schema == 2:
        data["transaction_id"] = "a" * 32
        data["new_manifest_sha256"] = hashlib.sha256(
            (root / "installed.json").read_bytes()).hexdigest()
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    return path


@pytest.mark.parametrize("phase", ["prepared", "activated"])
def test_recover_previous_generation_after_interruption(prepared, phase):
    root, old, new, original = prepared
    (root / "current").unlink()
    (root / "current").symlink_to(new)
    (root / "installed.json").write_text('{"version":"0.4.0"}')
    journal = _journal(root, old, new, original, phase)
    with updater.update_transaction():
        updater.recover_transaction()
        updater.recover_transaction()
    assert (root / "current").resolve() == old
    assert (root / "installed.json").read_bytes() == original
    assert not journal.exists()


def test_committed_state_retained_if_generation_matches(prepared):
    root, old, new, original = prepared
    (root / "current").unlink()
    (root / "current").symlink_to(new)
    manifest = root / "installed.json"
    manifest.write_text('{"version":"0.4.0","source_digest":"' + "b" * 64 + '"}')
    journal = _journal(root, old, new, original, "committed", schema=2)
    with updater.update_transaction():
        updater.recover_transaction()
    assert (root / "current").resolve() == new
    assert '"0.4.0"' in manifest.read_text()
    assert not journal.exists()


def test_invalid_journal_fails_closed_and_preserves_active_generation(prepared):
    root, old, new, original = prepared
    journal = root / ".update-journal.json"
    journal.write_text('{"schema":1,"phase":"activated","previous":"/etc"}')
    journal.chmod(0o600)
    with updater.update_transaction():
        with pytest.raises(updater.UpdateError, match="Corrupt transaction journal"):
            updater.recover_transaction()
    assert (root / "current").resolve() == old
    assert (root / "installed.json").read_bytes() == original
    assert journal.exists()


def test_recovery_never_follows_journal_symlinks(prepared):
    root, old, new, original = prepared
    outside = root.parent / "outside.json"
    outside.write_text("{}")
    (root / ".update-journal.json").symlink_to(outside)
    with updater.update_transaction():
        with pytest.raises(updater.UpdateError, match="Symlinked"):
            updater.recover_transaction()
    assert outside.read_text() == "{}"


def test_schema_one_committed_journal_rolls_back_not_assume_integrity(prepared):
    root, old, new, original = prepared
    (root / "current").unlink()
    (root / "current").symlink_to(new)
    (root / "installed.json").write_text('{"version":"0.4.0","source_digest":"' +
                                         "b" * 64 + '"}')
    _journal(root, old, new, original, "committed", schema=1)
    with updater.update_transaction():
        updater.recover_transaction()
    assert (root / "current").resolve() == old
    assert (root / "installed.json").read_bytes() == original


def test_committed_journal_changed_digest_is_rolled_back(prepared):
    root, old, new, original = prepared
    (root / "current").unlink()
    (root / "current").symlink_to(new)
    (root / "installed.json").write_text('{"version":"0.4.0","source_digest":"' +
                                         "b" * 64 + '"}')
    _journal(root, old, new, original, "committed", schema=2)
    (root / "installed.json").write_text('{"version":"0.4.0","source_digest":"' +
                                         "c" * 64 + '"}')
    with updater.update_transaction():
        updater.recover_transaction()
    assert (root / "current").resolve() == old
    assert (root / "installed.json").read_bytes() == original


def test_missing_previous_executable_fails_closed(prepared):
    root, old, new, original = prepared
    (old / "bin/repocache").unlink()
    _journal(root, old, new, original, "prepared", schema=2)
    with updater.update_transaction():
        with pytest.raises(updater.UpdateError, match="unavailable"):
            updater.recover_transaction()
    assert (root / ".update-journal.json").is_file()
    assert (root / "installed.json").read_bytes() == original
