"""Signed dependency-envelope negotiation for the v0.5.0 compatibility bridge (#82).

The schema-2 parser authenticates a *future* profile but this updater refuses
to install either schema-2 profile until #83/#84 deliver index, wheel lock,
asset inventory, native platform and recovery validation. Never use fixture
approval as evidence for an actual signed release candidate.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import subprocess
import time
from pathlib import Path

import pytest

from repocache import signatures, updater, upgrade


def _openssl(*args: str) -> None:
    subprocess.run(
        ["/usr/bin/openssl", *map(str, args)],
        capture_output=True, check=True, timeout=15,
    )


@pytest.fixture
def keypair(tmp_path, monkeypatch):
    private = tmp_path / "publisher-private.pem"
    public = tmp_path / "publisher-public.pem"
    _openssl("genpkey", "-algorithm", "Ed25519", "-out", str(private))
    _openssl("pkey", "-in", str(private), "-pubout", "-out", str(public))
    private.chmod(0o600)
    monkeypatch.setattr(signatures, "_trusted_key", lambda name: public)
    return private


def _manifest(archive: bytes, version: str, *, schema: int = 2,
              profile: str = "online-hash-locked-wheels") -> dict:
    now = int(time.time())
    document = {
        "schema": schema,
        "key_id": "publisher-2026",
        "repository": "teixemf/repocache",
        "channel": "stable",
        "version": version,
        "commit": "a" * 40,
        "archive": "repocache-v" + version + ".tar.gz",
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "policy_sha256": "b" * 64,
        "wheelhouse_sha256": None,
        "issued_at": now - 60,
        "expires_at": now + 3600,
    }
    if schema == 2:
        document.update({
            "dependency_profile": profile,
            "dependency_lock_sha256": "c" * 64,
            "asset_inventory_sha256": "d" * 64,
        })
        if profile == "legacy-offline-wheelhouse":
            document["wheelhouse_sha256"] = "e" * 64
            document["dependency_lock_sha256"] = None
    else:
        document["wheelhouse_sha256"] = "e" * 64
    return document


def _encoded(document: dict) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sign(tmp_path: Path, private: Path, raw: bytes) -> bytes:
    message = tmp_path / "message"
    detached = tmp_path / "message.sig"
    message.write_bytes(raw)
    _openssl("pkeyutl", "-sign", "-inkey", str(private),
             "-rawin", "-in", str(message), "-out", str(detached))
    return detached.read_bytes()


@pytest.mark.parametrize("schema,profile", [
    (1, "legacy-offline-wheelhouse"),
    (2, "legacy-offline-wheelhouse"),
    (2, "online-hash-locked-wheels"),
])
def test_ed25519_authenticates_exact_profile_bytes(keypair, tmp_path, schema, profile):
    archive = b"synthetic untrusted release archive"
    doc = _manifest(archive, "0.6.0", schema=schema, profile=profile)
    raw = _encoded(doc)
    sig = _sign(tmp_path, keypair, raw)
    verified = signatures.verify(archive, raw, sig, "0.6.0")
    assert verified["schema"] == schema
    if schema == 2:
        assert verified["dependency_profile"] == profile
    tampered = doc.copy()
    tampered["archive_sha256"] = "f" * 64
    with pytest.raises(signatures.SignatureError):
        signatures.verify(archive, _encoded(tampered), sig, "0.6.0")
    if schema == 2:
        changed = doc.copy()
        changed["asset_inventory_sha256"] = "f" * 64
        with pytest.raises(signatures.SignatureError, match="signature"):
            signatures.verify(archive, _encoded(changed), sig, "0.6.0")


@pytest.mark.parametrize("override", [
    {"schema": 3},
    {"schema": True},
    {"dependency_profile": "unrecognized-online"},
    {"dependency_profile": "legacy-offline-wheelhouse"},  # wrong wheel/lock pair
    {"dependency_lock_sha256": None},
    {"dependency_lock_sha256": "invalid"},
    {"wheelhouse_sha256": "f" * 64},
    {"asset_inventory_sha256": None},
    {"asset_inventory_sha256": "a"},
    {"index_url": "https://attacker.invalid/simple"},
    {"repository": "not-the-publisher/repo"},
])
def test_schema_two_rejects_unknown_or_inconsistent_fields(override):
    doc = _manifest(b"synthetic", "0.6.0")
    doc.update(override)
    with pytest.raises(signatures.SignatureError):
        signatures._parse(_encoded(doc))


@pytest.mark.parametrize("absent", [
    "dependency_profile", "dependency_lock_sha256", "asset_inventory_sha256",
])
def test_schema_two_rejects_missing_fields(absent):
    doc = _manifest(b"synthetic", "0.6.0")
    del doc[absent]
    with pytest.raises(signatures.SignatureError):
        signatures._parse(_encoded(doc))


def test_schema_one_never_accepts_additional_online_profile_fields():
    doc = _manifest(b"synthetic", "0.4.0", schema=1)
    doc["dependency_profile"] = "online-hash-locked-wheels"
    with pytest.raises(signatures.SignatureError, match="fields"):
        signatures._parse(_encoded(doc))


def test_duplicate_signed_profile_fields_are_refused():
    doc = _manifest(b"synthetic", "0.6.0")
    raw = _encoded(doc).decode()
    raw = raw.replace('"dependency_profile":', '"dependency_profile":"legacy-offline-wheelhouse","dependency_profile":')
    with pytest.raises(signatures.SignatureError, match="Duplicate"):
        signatures._parse(raw.encode())


@pytest.mark.parametrize("profile", [
    "online-hash-locked-wheels", "legacy-offline-wheelhouse",
])
@pytest.mark.parametrize("os_id,os_version", [("debian", "13"), ("almalinux", "10")])
def test_signed_future_profile_refused_before_archive_or_install(
        tmp_path, monkeypatch, keypair, profile, os_id, os_version):
    version = "0.6.0"
    basename = "repocache-v" + version + ".tar.gz"
    bundle = tmp_path / basename
    checksum = tmp_path / (basename + ".sha256")
    manifest = tmp_path / (basename + ".manifest.json")
    detached = tmp_path / (basename + ".manifest.json.sig")
    wheelhouse = tmp_path / (basename + ".wheelhouse.tar.gz")
    contents = b"not a TAR: the unsupported profile must stop before extraction"
    bundle.write_bytes(contents)
    checksum.write_text(hashlib.sha256(contents).hexdigest() + "  " + basename + "\n")
    raw = _encoded(_manifest(contents, version, profile=profile))
    manifest.write_bytes(raw)
    detached.write_bytes(_sign(tmp_path, keypair, raw))
    wheelhouse.write_bytes(b"not a valid wheelhouse")

    monkeypatch.setattr(updater, "update_transaction", contextlib.nullcontext)
    monkeypatch.setattr(updater, "recover_transaction", lambda: None)
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    monkeypatch.setattr(updater, "_installed", lambda: {"version": "0.4.0"})
    monkeypatch.setattr(updater, "install_source", lambda *args, **kwargs:
                        pytest.fail("Unimplemented profile reached installation"))
    monkeypatch.setattr(upgrade, "_extract_verified", lambda *args, **kwargs:
                        pytest.fail("Unsupported profile reached extraction"))
    with pytest.raises(upgrade.UpgradeError, match="not supported by this updater"):
        upgrade.upgrade(
            selected=version, bundle=bundle, checksum=checksum,
            system={"ID": os_id, "VERSION_ID": os_version},
        )
