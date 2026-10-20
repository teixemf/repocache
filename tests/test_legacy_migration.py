"""#55: root-owned legacy launcher migration state and malicious input tests."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("legacy_migration", ROOT / "scripts/migrate_v030.py")
assert SPEC and SPEC.loader
migration = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(migration)


@pytest.fixture
def historical(tmp_path, monkeypatch):
    root = tmp_path / "opt/repocache-cli"
    root.mkdir(parents=True)
    releases = root / "releases"
    first = releases / ("0.3.0-" + "a" * 12)
    (first / "bin").mkdir(parents=True)
    (first / "bin/repocache").write_text("verified v0.3.0")
    manifest = root / "installed.json"
    manifest.write_text(json.dumps({"version": "0.3.0", "source_digest": "a" * 64}) + "\n")
    (root / "current").symlink_to(first)
    links = (tmp_path / "usr/local/bin/repocache", tmp_path / "usr/bin/repocache")
    for link in links:
        link.parent.mkdir(parents=True)
        link.symlink_to(root / "current/bin/repocache")
    helper = tmp_path / "usr/local/libexec/repocache-recover.py"
    helper.parent.mkdir()
    monkeypatch.setattr(migration, "LEGACY_ROOT", root)
    monkeypatch.setattr(migration, "OLD_MANIFEST", manifest)
    monkeypatch.setattr(migration, "OLD_CURRENT", root / "current")
    monkeypatch.setattr(migration, "MANAGED", root / "managed")
    monkeypatch.setattr(migration, "LINKS", links)
    monkeypatch.setattr(migration, "HELPER", helper)
    monkeypatch.setattr(migration, "JOURNAL", root / ".migration-v030.json")
    monkeypatch.setattr(migration, "SAVED", root / ".migration-v030.saved.json")
    old = {
        "archive_sha256": migration.OLD_ARCHIVE_SHA256,
        "manifest_sha256": migration.digest(manifest.read_bytes()),
        "legacy_target": str(first),
        "links": {str(link): str(root / "current/bin/repocache") for link in links},
    }
    return old, links


def test_historical_migrator_is_disabled_before_accessing_host():
    with pytest.raises(migration.MigrationError, match="not supported"):
        migration.main()


def test_kill_after_first_launcher_swap_replays_to_exact_prior_legacy_state(historical):
    old, links = historical
    new_launcher = b"#!/bin/sh\n# signed new verified launcher\n"
    sha = hashlib.sha256(new_launcher).hexdigest()
    migration.save_record(migration.JOURNAL, old, sha)
    migration.install_launcher(links[0], new_launcher)
    assert links[0].is_file() and not links[0].is_symlink()
    assert migration.recover() is True
    assert migration.recover() is False
    for link in links:
        assert link.is_symlink()
        assert link.readlink() == Path(old["links"][str(link)])
    assert migration.OLD_MANIFEST.read_bytes().startswith(b'{"version":')
    assert not migration.JOURNAL.exists()


def test_cutover_then_explicit_rollback_preserves_old_manifest_and_launcher(historical):
    old, links = historical
    new_launcher = b"#!/bin/sh\n# signed root-owned launcher\n"
    sha = hashlib.sha256(new_launcher).hexdigest()
    files = {
        "scripts/repocache-launcher.sh": new_launcher,
        "src/repocache/recovery.py": b"print('trusted recovery')\n",
    }
    before = migration.OLD_MANIFEST.read_bytes()
    migration.cutover(files, old, sha)
    assert not links[0].is_symlink()
    assert links[1].readlink() == links[0]
    assert migration.SAVED.is_file()
    assert not migration.JOURNAL.exists()
    migration.rollback()
    assert migration.OLD_MANIFEST.read_bytes() == before
    for link in links:
        assert link.is_symlink()
        assert str(link.readlink()) == old["links"][str(link)]
    assert not migration.SAVED.exists()


def test_recovery_rejects_corrupt_baseline_or_forged_launcher(historical):
    old, links = historical
    new_launcher = b"trusted"
    sha = hashlib.sha256(new_launcher).hexdigest()
    migration.save_record(migration.JOURNAL, old, sha)
    migration.install_launcher(links[0], b"attacker")
    with pytest.raises(migration.MigrationError, match="Foreign"):
        migration.recover()
    assert migration.JOURNAL.exists()
    links[0].unlink()
    links[0].symlink_to(old["links"][str(links[0])])
    migration.OLD_MANIFEST.write_text('{"version":"forged"}')
    with pytest.raises(migration.MigrationError, match="checkpoint"):
        migration.recover()
    assert migration.JOURNAL.exists()


def test_migrator_fails_before_signature_verifier_for_wrong_transport_hash(tmp_path, monkeypatch):
    bundle = tmp_path / "repocache-v0.4.0.tar.gz"
    bundle.write_bytes(b"not the signed archive")
    checksum = tmp_path / "repocache-v0.4.0.tar.gz.sha256"
    checksum.write_text("0" * 64 + "  " + bundle.name + "\n")
    monkeypatch.setattr(migration, "trusted_anchor", lambda key: tmp_path / "approved.pem")
    def forbidden(*args, **kwargs):
        pytest.fail("No cryptographic or writable operation before checksum verification")
    monkeypatch.setattr(migration, "proc", forbidden)
    with pytest.raises(migration.MigrationError, match="checksum"):
        migration.authenticated_candidate(SimpleNamespace(
            key_id="test-owner", bundle=bundle, checksum=checksum,
            manifest=tmp_path / "manifest", signature=tmp_path / "signature",
            wheelhouse=tmp_path / "wheelhouse"))


def test_trust_root_rejects_untrusted_directory_and_symlink(historical):
    old, links = historical
    with pytest.raises(migration.MigrationError, match="authenticated input"):
        migration.load_record(migration.JOURNAL)
    migration.save_record(migration.JOURNAL, old, "a" * 64)
    forged = migration.JOURNAL
    forged.unlink()
    forged.symlink_to(migration.OLD_MANIFEST)
    with pytest.raises(migration.MigrationError):
        migration.load_record(forged)
