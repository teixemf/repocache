"""End-to-end publisher signing regressions for issue #47.

These tests create ephemeral Ed25519 keys; NO private key is committed.
A signature test only passes after OpenSSL has actually verified the bytes.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import subprocess
import tarfile
import time
from pathlib import Path

import pytest
from repocache import signatures, updater, upgrade, wheelhouse

@pytest.fixture(autouse=True)
def isolated_signature_api(monkeypatch):
    # The journal/lock has separate real interprocess regression tests.
    # These tests focus exclusively on signed archive trust boundaries.
    monkeypatch.setattr(updater, "update_transaction", contextlib.nullcontext)
    monkeypatch.setattr(updater, "recover_transaction", lambda: None)



def _openssl(*args: str) -> None:
    subprocess.run(["/usr/bin/openssl", *map(str, args)],
                   check=True, capture_output=True, timeout=20)


@pytest.fixture
def keys(tmp_path, monkeypatch):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    _openssl("genpkey", "-algorithm", "Ed25519", "-out", str(private))
    private.chmod(0o600)
    _openssl("pkey", "-in", str(private), "-pubout", "-out", str(public))
    public.chmod(0o644)
    monkeypatch.setattr(signatures, "_trusted_key", lambda key_id: public)
    return private, public


def _payload(archive: bytes, version: str = "0.3.0") -> bytes:
    now = int(time.time())
    data = {
        "schema": 1, "key_id": "publisher-2026",
        "repository": "teixemf/repocache", "channel": "stable",
        "version": version, "commit": "a" * 40,
        "archive": "repocache-v" + version + ".tar.gz",
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "policy_sha256": "b" * 64, "wheelhouse_sha256": None,
        "issued_at": now - 60, "expires_at": now + 3600,
    }
    return (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sign(raw: bytes, private: Path, tmp_path: Path) -> bytes:
    plain = tmp_path / "manifest-input"
    signature = tmp_path / "detached.sig"
    plain.write_bytes(raw)
    _openssl("pkeyutl", "-sign", "-inkey", str(private),
             "-rawin", "-in", str(plain), "-out", str(signature))
    return signature.read_bytes()


def test_verified_ed25519_archive_and_matching_identity(keys, tmp_path):
    private, _ = keys
    archive = b"synthetic binary test release"
    manifest = _payload(archive)
    signature = _sign(manifest, private, tmp_path)
    result = signatures.verify(archive, manifest, signature, "0.3.0")
    assert result["archive_sha256"] == hashlib.sha256(archive).hexdigest()
    assert result["key_id"] == "publisher-2026"


def test_attacker_created_matching_archive_and_checksum_cannot_bypass_signature(keys, tmp_path):
    private, _ = keys
    valid = b"approved"
    manifest = _payload(valid)
    signature = _sign(manifest, private, tmp_path)
    attacker_archive = b"malicious"
    attacker_checksum = hashlib.sha256(attacker_archive).hexdigest()
    assert attacker_checksum != hashlib.sha256(valid).hexdigest()
    with pytest.raises(signatures.SignatureError, match="archive SHA-256"):
        signatures.verify(attacker_archive, manifest, signature, "0.3.0")
    changed = _payload(attacker_archive)
    with pytest.raises(signatures.SignatureError, match="signature"):
        signatures.verify(attacker_archive, changed, signature, "0.3.0")


@pytest.mark.parametrize("field,value", [
    ("channel", "prerelease"), ("version", "0.4.0"),
    ("commit", "c" * 40), ("policy_sha256", "c" * 64),
    ("wheelhouse_sha256", "d" * 64), ("expires_at", 99999999999),
    ("key_id", "publisher-2027"),
])
def test_any_signed_metadata_mutation_requires_new_signature(keys, tmp_path, field, value):
    private, _ = keys
    archive = b"release"
    raw = _payload(archive)
    sig = _sign(raw, private, tmp_path)
    body = json.loads(raw)
    body[field] = value
    modified = (json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with pytest.raises(signatures.SignatureError):
        signatures.verify(archive, modified, sig, "0.3.0")


def test_expired_future_unknown_and_malformed_fail_closed(keys, tmp_path, monkeypatch):
    private, _ = keys
    archive = b"payload"
    raw = _payload(archive)
    sig = _sign(raw, private, tmp_path)
    monkeypatch.setattr(signatures.time, "time", lambda: 0)
    with pytest.raises(signatures.SignatureError, match="currently valid"):
        signatures.verify(archive, raw, sig, "0.3.0")
    monkeypatch.setattr(signatures.time, "time", lambda: 999999999999)
    with pytest.raises(signatures.SignatureError, match="currently valid"):
        signatures.verify(archive, raw, sig, "0.3.0")
    monkeypatch.undo()
    with pytest.raises(signatures.SignatureError):
        signatures.verify(archive, raw, b"short", "0.3.0")
    with pytest.raises(signatures.SignatureError, match="version"):
        signatures.verify(archive, raw, sig, "0.4.0")
    with pytest.raises(signatures.SignatureError, match="Duplicate"):
        signatures._parse(b'{"schema":1,"schema":1}')


def test_missing_wrong_and_revoked_trusted_public_keys(keys, tmp_path, monkeypatch):
    private, original = keys
    raw = _payload(b"release")
    sig = _sign(raw, private, tmp_path)
    second = tmp_path / "other-public.pem"
    other_key = tmp_path / "other-private.pem"
    _openssl("genpkey", "-algorithm", "Ed25519", "-out", str(other_key))
    _openssl("pkey", "-in", str(other_key), "-pubout", "-out", str(second))
    monkeypatch.setattr(signatures, "_trusted_key", lambda name: second)
    with pytest.raises(signatures.SignatureError, match="signature"):
        signatures.verify(b"release", raw, sig, "0.3.0")
    second.unlink()
    with pytest.raises(signatures.SignatureError, match="signature"):
        signatures.verify(b"release", raw, sig, "0.3.0")
    # Restoring an independently authorized key allows planned key rotation.
    monkeypatch.setattr(signatures, "_trusted_key", lambda name: original)
    assert signatures.verify(b"release", raw, sig, "0.3.0")["schema"] == 1


def test_trust_store_rejects_nonroot_owned_or_writable_key(tmp_path, monkeypatch):
    trust = tmp_path / "trust.d"
    trust.mkdir()
    key = trust / "publisher-2026.pem"
    key.write_text("fake")
    key.chmod(0o666)
    monkeypatch.setattr(signatures, "TRUST_DIR", trust)
    with pytest.raises(signatures.SignatureError, match="Unsafe"):
        signatures._trusted_key("publisher-2026")
    key.unlink()
    key.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(signatures.SignatureError):
        signatures._trusted_key("publisher-2026")


def test_unsigned_offline_bundle_cannot_execute_install_hook(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    monkeypatch.setattr(updater, "_installed", lambda: {"version": "0.0.0"})
    monkeypatch.setattr(updater, "install_source", lambda *a, **kw:
                        pytest.fail("Unsigned bundle reached Python install"))
    name = "repocache-v0.3.0.tar.gz"
    archive = tmp_path / name
    checksum = tmp_path / (name + ".sha256")
    archive.write_bytes(b"not an archive, must not be extracted")
    checksum.write_text(hashlib.sha256(archive.read_bytes()).hexdigest() +
                        "  " + name + "\n")
    with pytest.raises(upgrade.UpgradeError):
        upgrade.upgrade("0.3.0", archive, checksum)


def test_valid_signed_offline_bundle_verifies_before_source_install(tmp_path, keys, monkeypatch):
    private, _ = keys
    root = Path(__file__).resolve().parents[1]
    module = root / "scripts" / "build_release.py"
    spec = importlib.util.spec_from_file_location("build_signed_test", module)
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    archive, checksum = builder.build_release(tmp_path / "out", "v0.4.0")
    signer_module = root / "scripts" / "sign_release.py"
    spec2 = importlib.util.spec_from_file_location("offline_signer", signer_module)
    signer = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(signer)
    now = int(time.time())
    wheel_file = archive.with_name(archive.name + ".wheelhouse.tar.gz")
    wheel_file.write_bytes(b"test-only ephemeral signed dependency wheelhouse")
    manifest, detached = signer.sign(
        archive, private, "publisher-2026", "a" * 40,
        now - 5, now + 3600,
        wheelhouse_sha256=hashlib.sha256(wheel_file.read_bytes()).hexdigest())
    monkeypatch.setattr(wheelhouse, "verified_extract",
                        lambda archive, digest, destination: destination / "requirements.lock")
    monkeypatch.setattr(wheelhouse, "verify_application_wheel", lambda lock, version: None)
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    monkeypatch.setattr(updater, "_installed", lambda: {"version": "0.0.0"})
    called = []
    def install(source, **kw):
        called.append((source, kw))
        return {"version": "0.4.0", "status": "installed"}
    monkeypatch.setattr(updater, "install_source", install)
    result = upgrade.upgrade("0.4.0", archive, checksum,
                            system={"ID": "debian", "VERSION_ID": "13"})
    assert result["status"] == "installed"
    assert len(called) == 1
    assert called[0][1]["release_identity"]["archive_sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    # Changing only the signed compatibility hash must reject before install.
    changed = json.loads(manifest.read_bytes())
    changed["policy_sha256"] = "0" * 64
    wrong_policy = (json.dumps(changed, sort_keys=True, separators=(",", ":")) + "\n").encode()
    manifest.write_bytes(wrong_policy)
    detached.write_bytes(_sign(wrong_policy, private, tmp_path))
    with pytest.raises(upgrade.UpgradeError, match="policy digest mismatch"):
        upgrade.upgrade("0.4.0", archive, checksum,
                        system={"ID": "debian", "VERSION_ID": "13"})
    assert len(called) == 1
