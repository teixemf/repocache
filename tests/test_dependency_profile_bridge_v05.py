"""Fail-closed dependency-profile compatibility bridge (issue #82).

These unit tests exercise the v0.5.0 legacy-safe seam; they do NOT prove an
owner-signed v0.5.0 release exists or that the future online installer works.
"""
from __future__ import annotations

import json

import pytest

from repocache import signatures, upgrade, updater


DEBIAN13 = {"ID": "debian", "VERSION_ID": "13"}
ALMA10 = {"ID": "almalinux", "VERSION_ID": "10.0"}
LEGACY = "legacy-offline-wheelhouse"


def bridge_policy():
    # Unchanged schema-1 policy is mandatory for a v0.4.0 -> v0.5.0
    # transition: the immutable v0.4.0 updater rejects unknown policy schemas.
    return {
        "schema": 1,
        "version": "0.5.0",
        "python_min": "3.12",
        "python_max_exclusive": "3.14",
        "targets": [
            {"id": "debian", "major": "13"},
            {"id": "almalinux", "major": "10"},
        ],
        "compatible_from": ["0.4.0"],
        "downgrade_from": [],
        "config_schema": 1,
        "api_schema": 1,
    }


def signed_legacy():
    # This is a signed-verifier OUTPUT fixture, never an independent
    # representation of genuine Ed25519 publisher acceptance.
    return {
        "schema": 1,
        "version": "0.5.0",
        "wheelhouse_sha256": "a" * 64,
    }


@pytest.mark.parametrize("platform", (DEBIAN13, ALMA10))
def test_legacy_v05_policy_allows_real_v04_version_transition(platform):
    policy = bridge_policy()
    prior = {"version": "0.4.0"}
    assert upgrade._policy(policy, "0.5.0", prior, platform) == policy
    assert upgrade._verified_dependency_profile(
        signed_legacy(), policy, "0.5.0") == LEGACY


@pytest.mark.parametrize("platform", (DEBIAN13, ALMA10))
def test_unknown_or_incompatible_previous_version_still_refused(platform):
    with pytest.raises(upgrade.UpgradeError, match="Compatibility"):
        upgrade._policy(bridge_policy(), "0.5.0", {"version": "0.3.0"}, platform)
    with pytest.raises(upgrade.UpgradeError, match="Downgrade"):
        downgrade = bridge_policy()
        downgrade["version"] = "0.5.0"
        downgrade["compatible_from"] = ["0.6.0"]
        upgrade._policy(downgrade, "0.5.0", {"version": "0.6.0"}, platform)


@pytest.mark.parametrize("change", (
    {"schema": 2},
    {"schema": True},
    {"version": "0.6.0"},
    {"wheelhouse_sha256": None},
    {"wheelhouse_sha256": "a" * 63},
    {"wheelhouse_sha256": "Z" * 64},
    {"wheelhouse_sha256": 17},
    {"distribution_profile": "online-hash-locked-wheels"},
))
def test_unrecognized_or_unpinned_authenticated_manifest_rejected(change):
    signed = signed_legacy()
    signed.update(change)
    # Extra fields cannot be passed through the real strict signature verifier.
    # Here ensure our application boundary still refuses invented profiles.
    if "distribution_profile" in change:
        with pytest.raises(signatures.SignatureError, match="Unsupported signed release manifest schema"):
            # Strict signed-manifest parsing must reject unknown schema-1 keys.
            payload = {
                "schema": 1, "key_id": "fixture", "repository": "teixemf/repocache",
                "channel": "stable", "version": "0.5.0",
                "commit": "a" * 40, "archive": "repocache-v0.5.0.tar.gz",
                "archive_sha256": "a" * 64, "policy_sha256": "a" * 64,
                "wheelhouse_sha256": "a" * 64,
                "issued_at": 1, "expires_at": 2,
                "distribution_profile": change["distribution_profile"],
            }
            signatures._parse(json.dumps(payload).encode("utf-8"))
        return
    with pytest.raises(upgrade.UpgradeError, match="profile|wheelhouse"):
        upgrade._verified_dependency_profile(signed, bridge_policy(), "0.5.0")


def test_schema2_or_unapproved_policy_extension_fails_closed():
    for mutation in ({"schema": 2}, {"dependency_profile": "online-hash-locked-wheels"}):
        policy = bridge_policy()
        policy.update(mutation)
        with pytest.raises(upgrade.UpgradeError, match="policy"):
            upgrade._policy(policy, "0.5.0", {"version": "0.4.0"}, DEBIAN13)
        with pytest.raises(upgrade.UpgradeError, match="profile"):
            upgrade._verified_dependency_profile(signed_legacy(), policy, "0.5.0")


def test_legacy_installed_manifest_without_profile_remains_compatible(tmp_path, monkeypatch):
    manifest = tmp_path / "installed.json"
    data = {"version": "0.4.0", "source_digest": "b" * 64}
    manifest.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(updater, "MANIFEST", manifest)
    assert updater._installed() == data


@pytest.mark.parametrize("bad", ("online-hash-locked-wheels", "", None, False))
def test_unknown_installed_manifest_profile_is_not_silently_reinterpreted(
        tmp_path, monkeypatch, bad):
    manifest = tmp_path / "installed.json"
    manifest.write_text(json.dumps({
        "version": "0.5.0", "source_digest": "b" * 64,
        "dependency_profile": bad,
    }), encoding="utf-8")
    monkeypatch.setattr(updater, "MANIFEST", manifest)
    with pytest.raises(updater.UpdateError, match="profile"):
        updater._installed()


def test_unimplemented_online_mode_refused_before_any_install_mutation(
        tmp_path, monkeypatch):
    src = tmp_path / "source"
    src.mkdir()
    (src / "pyproject.toml").write_text(
        '[project]\nversion = "0.6.0"\n', encoding="utf-8")
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    monkeypatch.setattr(
        updater, "_safe_links",
        lambda: pytest.fail("Must not inspect or mutate install paths"))
    monkeypatch.setattr(
        updater, "_run",
        lambda *a, **kw: pytest.fail("Must not create a virtualenv or run pip"))
    with pytest.raises(updater.UpdateError, match="online installation is disabled"):
        updater._install_source_locked(
            src, release_identity={"dependency_profile": "online-hash-locked-wheels"},
            wheel_lock=tmp_path / "fake.lock")
    assert not (tmp_path / "fake.lock").exists()
