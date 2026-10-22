"""Synthetic owner-candidate trust tests (#84); not publisher-key acceptance."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import subprocess
import tarfile
import time
from pathlib import Path

import pytest

from repocache import release_inventory, signatures


def _signer():
    path = Path(__file__).resolve().parents[1] / "scripts/sign_release.py"
    spec = importlib.util.spec_from_file_location("online_candidate_signer", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def signer_key(tmp_path, monkeypatch):
    private = tmp_path / "publisher-private.pem"
    public = tmp_path / "publisher-public.pem"
    subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "Ed25519",
                    "-out", str(private)], check=True, capture_output=True)
    subprocess.run(["/usr/bin/openssl", "pkey", "-in", str(private),
                    "-pubout", "-out", str(public)], check=True, capture_output=True)
    private.chmod(0o600)
    monkeypatch.setattr(signatures, "_trusted_key", lambda key_id: public)
    return private


def _archive(version="0.6.0", *, entry="src/repocache/cli.py",
             content=b"print('safe test fixture')\n"):
    sink = io.BytesIO()
    with tarfile.open(fileobj=sink, mode="w:gz") as tar:
        policy = json.dumps({"schema": 1, "version": version}).encode()
        for name, raw in (("release-policy.json", policy), (entry, content)):
            member = tarfile.TarInfo("repocache-v" + version + "/" + name)
            member.size = len(raw)
            member.mode = 0o644
            tar.addfile(member, io.BytesIO(raw))
    return sink.getvalue()


def _parts(archive=None, version="0.6.0"):
    archive = archive if archive is not None else _archive(version)
    basename = "repocache-v" + version + ".tar.gz"
    lock = {"schema": 1, "profiles": {
        "debian13-py313": [{"name": "rich", "version": "15.0.0"}],
        "almalinux10-py312": [{"name": "rich", "version": "15.0.0"}]}}
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "version": 1, "components": [{"name": "rich", "version": "15.0.0"}]}
    return {
        "archive": archive,
        "checksum": (hashlib.sha256(archive).hexdigest() + "  " + basename + "\n").encode(),
        "dependency_lock": (json.dumps(lock) + "\n").encode(),
        "sbom": (json.dumps(sbom) + "\n").encode(),
    }


def _candidate(tmp_path, parts):
    names = release_inventory.names("0.6.0")
    for role, raw in parts.items():
        (tmp_path / names[role]).write_bytes(raw)
    return (tmp_path / names["archive"], tmp_path / names["dependency_lock"],
            tmp_path / names["sbom"])


def _signed(tmp_path, signer_key, parts):
    source, lock, sbom = _candidate(tmp_path, parts)
    now = int(time.time())
    manifest, sig = _signer().sign(
        source, signer_key, "publisher-2026", "a" * 40, now - 10, now + 3600,
        online_lock=lock, online_sbom=sbom)
    inventory = (tmp_path / (source.name + ".assets.json")).read_bytes()
    return manifest.read_bytes(), sig.read_bytes(), inventory


def test_genuine_ephemeral_ed25519_binds_all_candidate_assets(
        tmp_path, signer_key):
    parts = _parts()
    manifest, detached, inventory = _signed(tmp_path, signer_key, parts)
    signed, lock = release_inventory.verify_signed_candidate(
        parts["archive"], manifest, detached, "0.6.0", inventory, parts)
    assert signed["schema"] == 2
    assert signed["wheelhouse_sha256"] is None
    assert signed["dependency_profile"] == "online-hash-locked-wheels"
    assert signed["asset_inventory_sha256"] == hashlib.sha256(inventory).hexdigest()
    assert signed["dependency_lock_sha256"] == hashlib.sha256(lock).hexdigest()
    assert set(json.loads(inventory)["assets"]) == set(release_inventory.ROLES)


@pytest.mark.parametrize("role", release_inventory.ROLES)
def test_substituted_signed_asset_refused_before_wheel_use(tmp_path, signer_key, role):
    parts = _parts()
    manifest, detached, inventory = _signed(tmp_path, signer_key, parts)
    altered = copy.deepcopy(parts)
    altered[role] += b"attacker content"
    with pytest.raises(release_inventory.InventoryError):
        release_inventory.verify_signed_candidate(
            parts["archive"], manifest, detached, "0.6.0", inventory, altered)


def test_owner_signature_and_inventory_are_both_required(tmp_path, signer_key):
    parts = _parts()
    manifest, detached, inventory = _signed(tmp_path, signer_key, parts)
    bad = json.loads(manifest)
    bad["asset_inventory_sha256"] = "0" * 64
    with pytest.raises(release_inventory.InventoryError, match="signature"):
        release_inventory.verify_signed_candidate(
            parts["archive"], (json.dumps(bad) + "\n").encode(),
            detached, "0.6.0", inventory, parts)
    with pytest.raises(release_inventory.InventoryError, match="inventory digest"):
        release_inventory.verify_signed_candidate(
            parts["archive"], manifest, detached, "0.6.0",
            inventory + b" ", parts)
    with pytest.raises(release_inventory.InventoryError):
        release_inventory.verify_signed_candidate(
            parts["archive"], manifest, b"x" * 64, "0.6.0", inventory, parts)


@pytest.mark.parametrize("variant", [
    "missing", "extra", "version", "duplicate", "bad-size", "unknown",
])
def test_inventory_structure_fails_closed(tmp_path, signer_key, variant):
    parts = _parts()
    manifest, detached, inventory = _signed(tmp_path, signer_key, parts)
    signed = signatures.verify(parts["archive"], manifest, detached, "0.6.0")
    metadata = json.loads(inventory)
    if variant == "missing":
        del metadata["assets"]["sbom"]
    elif variant == "extra":
        metadata["assets"]["wheelhouse"] = metadata["assets"]["archive"]
    elif variant == "version":
        metadata["version"] = "0.4.0"
    elif variant == "bad-size":
        metadata["assets"]["sbom"]["size"] = True
    elif variant == "unknown":
        metadata["schema"] = 2
    if variant == "duplicate":
        raw = b'{"schema":1,"schema":1}'
    else:
        raw = json.dumps(metadata).encode()
    # The independently signed digest must also match; no bypass is possible.
    with pytest.raises(release_inventory.InventoryError):
        release_inventory.verify_bound_assets(signed, raw, parts)


@pytest.mark.parametrize("entry,payload", [
    ("wheels/third_party-1.0-py3-none-any.whl", b"wheel"),
    ("src/vendor/module.so", b"\x7fELFmalware"),
    ("src/repocache/payload.py", b"PK\x03\x04zip code"),
    ("../outside.py", b"bad"),
])
def test_source_only_binary_and_traversal_rejected(entry, payload):
    with pytest.raises(release_inventory.InventoryError):
        release_inventory.build_inventory(
            "0.6.0", _parts(_archive(entry=entry, content=payload)))


def test_future_profile_requires_v06_and_two_target_lock():
    for version in ("0.4.0", "0.5.0", "0.6.0rc1"):
        with pytest.raises(release_inventory.InventoryError):
            release_inventory.names(version)
    parts = _parts()
    doc = json.loads(parts["dependency_lock"])
    del doc["profiles"]["almalinux10-py312"]
    parts["dependency_lock"] = json.dumps(doc).encode()
    with pytest.raises(release_inventory.InventoryError, match="closure"):
        release_inventory.build_inventory("0.6.0", parts)


def test_online_signer_refuses_legacy_wheelhouse_and_missing_sbom(
        tmp_path, signer_key):
    parts = _parts()
    src, lock, sbom = _candidate(tmp_path, parts)
    now = int(time.time())
    signer = _signer()
    with pytest.raises(ValueError, match="no wheelhouse"):
        signer.sign(src, signer_key, "publisher-2026", "a" * 40,
                    now - 10, now + 3600,
                    wheelhouse_sha256="a" * 64, online_lock=lock, online_sbom=sbom)
    with pytest.raises(ValueError, match="lock, SBOM"):
        signer.sign(src, signer_key, "publisher-2026", "a" * 40,
                    now - 10, now + 3600, online_lock=lock)
    assert not (tmp_path / (src.name + ".manifest.json")).exists()


def test_legacy_signing_schema1_path_remains_unchanged(tmp_path, signer_key):
    archive = _archive("0.4.0")
    src = tmp_path / "repocache-v0.4.0.tar.gz"
    src.write_bytes(archive)
    now = int(time.time())
    manifest, signature = _signer().sign(
        src, signer_key, "publisher-2026", "a" * 40, now - 10, now + 3600)
    assert json.loads(manifest.read_bytes())["schema"] == 1
    assert len(signature.read_bytes()) == 64
    assert not (tmp_path / (src.name + ".assets.json")).exists()
