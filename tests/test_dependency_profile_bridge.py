"""Signed dependency-profile compatibility bridge (issue #82).

Synthetic signed fixtures prove code-path behavior, not a real v0.5.0 release,
on-host migration, online package installation, or production recovery.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import subprocess
import tarfile
import time
from pathlib import Path

import pytest

from repocache import signatures, updater, upgrade, wheelhouse


PLATFORM = {"ID": "debian", "VERSION_ID": "13"}


def policy(version: str = "0.5.0", *, schema: int = 2,
           profile: str = "legacy-offline-wheelhouse") -> dict:
    result = {
        "schema": schema, "version": version,
        "python_min": "3.12", "python_max_exclusive": "3.14",
        "targets": [{"id": "debian", "major": "13"},
                    {"id": "almalinux", "major": "10"}],
        "compatible_from": ["0.4.0"] if version != "0.4.0" else [],
        "downgrade_from": [], "config_schema": 1, "api_schema": 1,
    }
    if schema == 2:
        result["dependency_profile"] = profile
    return result


def test_original_v04_policy_unchanged_and_rejects_additional_keys():
    original = policy(version="0.4.0", schema=1)
    assert upgrade._policy(original, "0.4.0", {"version": "0.0.0"}, PLATFORM) == original
    changed = dict(original, dependency_profile="legacy-offline-wheelhouse")
    with pytest.raises(upgrade.UpgradeError, match="compatibility policy"):
        upgrade._policy(changed, "0.4.0", {"version": "0.0.0"}, PLATFORM)


def test_signed_legacy_bridge_requires_explicit_previous_allowlist():
    previous = {"version": "0.4.0"}
    target = policy()
    assert upgrade._policy(target, "0.5.0", previous, PLATFORM) == target
    denied = dict(target, compatible_from=[])
    with pytest.raises(upgrade.UpgradeError, match="Compatibility"):
        upgrade._policy(denied, "0.5.0", previous, PLATFORM)


@pytest.mark.parametrize("bad", [
    "online-hash-locked-wheels", "unknown", "", None,
    True, 1, [], {"legacy-offline-wheelhouse": True},
])
def test_new_unimplemented_profiles_never_fall_back_to_legacy(bad):
    with pytest.raises(upgrade.UpgradeError, match="dependency profile"):
        upgrade._policy(policy(profile=bad), "0.5.0", {"version": "0.4.0"}, PLATFORM)


def test_schema_requires_exact_version_and_fields():
    with pytest.raises(upgrade.UpgradeError, match="schema"):
        upgrade._policy(policy("0.4.0"), "0.4.0", {"version": "0.0.0"}, PLATFORM)
    for schema in (True, 0, 3):
        bad = policy()
        bad["schema"] = schema
        with pytest.raises(upgrade.UpgradeError, match="policy|schema"):
            upgrade._policy(bad, "0.5.0", {"version": "0.4.0"}, PLATFORM)
    bad = dict(policy(), attacker_index="https://invalid.example/")
    with pytest.raises(upgrade.UpgradeError, match="schema"):
        upgrade._policy(bad, "0.5.0", {"version": "0.4.0"}, PLATFORM)


def test_runtime_profile_downgrade_cannot_use_old_version_allowlist():
    target = policy("0.5.0", schema=2)
    target["compatible_from"] = ["0.6.0"]
    previous = {
        "version": "0.6.0",
        "release_policy": dict(policy("0.6.0", schema=2,
                                      profile="online-hash-locked-wheels"),
                               downgrade_from=["0.5.0"]),
    }
    with pytest.raises(upgrade.UpgradeError, match="dependency profiles"):
        upgrade._policy(target, "0.5.0", previous, PLATFORM)


def _pack(version: str, selected: dict) -> bytes:
    raw = (json.dumps(selected, sort_keys=True) + "\n").encode()
    sink = io.BytesIO()
    with tarfile.open(fileobj=sink, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(upgrade.RELEASE_FILES):
            payload = (
                raw if name == "release-policy.json" else
                f'version = "{version}"\n'.encode() if name == "pyproject.toml" else
                b"synthetic accepted file for security testing\n"
            )
            info = tarfile.TarInfo(f"repocache-v{version}/{name}")
            info.size, info.mtime, info.mode = len(payload), 0, 0o644
            archive.addfile(info, io.BytesIO(payload))
    return sink.getvalue()


def _sign(raw: bytes, private: Path, directory: Path) -> bytes:
    source, target = directory / "signing-input", directory / "detached.sig"
    source.write_bytes(raw)
    subprocess.run(
        ["/usr/bin/openssl", "pkeyutl", "-sign", "-inkey", str(private),
         "-rawin", "-in", str(source), "-out", str(target)],
        capture_output=True, check=True, timeout=20)
    return target.read_bytes()


@pytest.fixture
def signing_key(tmp_path, monkeypatch):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    subprocess.run(
        ["/usr/bin/openssl", "genpkey", "-algorithm", "Ed25519",
         "-out", str(private)], capture_output=True, check=True, timeout=20)
    subprocess.run(
        ["/usr/bin/openssl", "pkey", "-in", str(private), "-pubout",
         "-out", str(public)], capture_output=True, check=True, timeout=20)
    private.chmod(0o600)
    monkeypatch.setattr(signatures, "_trusted_key", lambda key_id: public)
    return private


def _signed_local_fixture(tmp_path: Path, private: Path, selected: dict,
                          *, signed_policy: dict | None = None):
    version = selected["version"]
    prefix = f"repocache-v{version}.tar.gz"
    bundle = tmp_path / prefix
    checksum = tmp_path / (prefix + ".sha256")
    wheel = tmp_path / (prefix + ".wheelhouse.tar.gz")
    archive = _pack(version, selected)
    bundle.write_bytes(archive)
    checksum.write_text(hashlib.sha256(archive).hexdigest() + "  " + prefix + "\n")
    wheel.write_bytes(b"synthetic signed but not an installable real wheelhouse")
    now = int(time.time())
    policy_bytes = (json.dumps(signed_policy or selected, sort_keys=True) + "\n").encode()
    signed = {
        "schema": 1, "key_id": "fixture", "repository": "teixemf/repocache",
        "channel": "stable", "version": version,
        "commit": "a" * 40, "archive": prefix,
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
        "wheelhouse_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "issued_at": now - 60, "expires_at": now + 3600,
    }
    manifest = tmp_path / (prefix + ".manifest.json")
    sig = tmp_path / (prefix + ".manifest.json.sig")
    encoded = (json.dumps(signed, sort_keys=True, separators=(",", ":")) + "\n").encode()
    manifest.write_bytes(encoded)
    sig.write_bytes(_sign(encoded, private, tmp_path))
    return bundle, checksum


def _mock_install(monkeypatch):
    observed = []
    monkeypatch.setattr(updater, "update_transaction", contextlib.nullcontext)
    monkeypatch.setattr(updater, "recover_transaction", lambda: None)
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    monkeypatch.setattr(updater, "_installed", lambda: {"version": "0.4.0"})
    monkeypatch.setattr(
        wheelhouse, "verified_extract",
        lambda data, digest, dest: dest / "requirements.lock")
    monkeypatch.setattr(wheelhouse, "verify_application_wheel", lambda lock, v: None)
    def install(source, **kw):
        observed.append(kw)
        return {"status": "installed", "version": "0.5.0"}
    monkeypatch.setattr(updater, "install_source", install)
    return observed


def test_real_ed25519_signed_bridge_checks_policy_before_install(
        tmp_path, signing_key, monkeypatch):
    called = _mock_install(monkeypatch)
    selected = policy()
    bundle, checksum = _signed_local_fixture(tmp_path, signing_key, selected)
    result = upgrade.upgrade("0.5.0", bundle, checksum, system=PLATFORM)
    assert result["status"] == "installed"
    assert len(called) == 1
    assert called[0]["release_policy"]["dependency_profile"] == "legacy-offline-wheelhouse"
    assert called[0]["release_identity"]["wheelhouse_sha256"] == hashlib.sha256(
        (tmp_path / (bundle.name + ".wheelhouse.tar.gz")).read_bytes()).hexdigest()


def test_signed_policy_digest_disagreement_refused_before_install(
        tmp_path, signing_key, monkeypatch):
    called = _mock_install(monkeypatch)
    selected = policy()
    altered = dict(selected, compatible_from=[])
    bundle, checksum = _signed_local_fixture(
        tmp_path, signing_key, selected, signed_policy=altered)
    with pytest.raises(upgrade.UpgradeError, match="policy digest mismatch"):
        upgrade.upgrade("0.5.0", bundle, checksum, system=PLATFORM)
    assert not called


def test_authenticated_online_profile_not_activated_or_downloaded(
        tmp_path, signing_key, monkeypatch):
    called = _mock_install(monkeypatch)
    bundle, checksum = _signed_local_fixture(
        tmp_path, signing_key, policy(profile="online-hash-locked-wheels"))
    with pytest.raises(upgrade.UpgradeError, match="dependency profile"):
        upgrade.upgrade("0.5.0", bundle, checksum, system=PLATFORM)
    assert not called
