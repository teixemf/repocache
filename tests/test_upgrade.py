import contextlib
"""Security and compatibility regression tests for verified release upgrades."""
import io
import hashlib
import json
import os
import tarfile
import urllib.error
from pathlib import Path

import pytest

from repocache import releases, updater, upgrade, signatures, wheelhouse


@pytest.fixture(autouse=True)
def fixture_wheels_only(monkeypatch):
    # Upgrade API contract fixtures isolate archive/policy flow. Real hash-
    # verified archive extraction and pip are exercised separately.
    monkeypatch.setattr(wheelhouse, "verified_extract",
                        lambda archive, digest, destination: destination / "requirements.lock")
    monkeypatch.setattr(wheelhouse, "verify_application_wheel", lambda lock, version: None)
    monkeypatch.setattr(updater, "update_transaction", contextlib.nullcontext)
    monkeypatch.setattr(updater, "recover_transaction", lambda: None)


VERSION = "0.4.0"
PREVIOUS = {"version": VERSION}
DEBIAN13 = {"ID": "debian", "VERSION_ID": "13"}
ALMA10 = {"ID": "almalinux", "VERSION_ID": "10.0"}


def policy():
    return {
        "schema": 1, "version": VERSION, "python_min": "3.12",
        "python_max_exclusive": "3.14",
        "targets": [{"id": "debian", "major": "13"},
                    {"id": "almalinux", "major": "10"}],
        "compatible_from": [], "downgrade_from": [],
        "config_schema": 1, "api_schema": 1
    }


def archive(tmp_path):
    import importlib.util
    module = Path(__file__).resolve().parents[1] / "scripts/build_release.py"
    spec = importlib.util.spec_from_file_location("upgrade_builder", module)
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    blob, sha = builder.build_release(tmp_path / "dist", "v" + VERSION)
    # Legacy behavior tests stub the signature gate; real cryptographic tests
    # run separately in test_signatures.py with fresh Ed25519 keys.
    blob.with_name(blob.name + ".manifest.json").write_text("test-only")
    blob.with_name(blob.name + ".manifest.json.sig").write_bytes(b"x" * 64)
    blob.with_name(blob.name + ".wheelhouse.tar.gz").write_bytes(b"ci-wheelhouse")
    return blob, sha, builder

def fake_signed_identity(archive_data, manifest_data, signature_data, version):
    with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:gz") as tar:
        member = tar.getmember("repocache-v" + version + "/release-policy.json")
        policy_digest = hashlib.sha256(tar.extractfile(member).read()).hexdigest()
    return {"archive_sha256": hashlib.sha256(archive_data).hexdigest(),
            "policy_sha256": policy_digest,
            "key_id": "fixture-only", "commit": "a" * 40,
            "wheelhouse_sha256": hashlib.sha256(b"ci-wheelhouse").hexdigest()}



def test_complete_archive_matches_manifest(tmp_path):
    blob, sha, builder = archive(tmp_path)
    assert set(builder.FILES) == set(upgrade.RELEASE_FILES)
    assert "scripts/migrate_v030.py" not in builder.FILES
    upgrade._verify_checksum(blob.read_bytes(), sha.read_bytes(), VERSION)
    src, verified = upgrade._extract_verified(
        blob.read_bytes(), VERSION, tmp_path / "extracted", PREVIOUS, DEBIAN13)
    assert verified == policy()
    assert src.joinpath("release-policy.json").is_file()
    assert not src.joinpath(".git").exists()


def test_selected_version_never_bypasses_integrity(tmp_path):
    blob, sha, _ = archive(tmp_path)
    with pytest.raises(upgrade.UpgradeError, match="SHA-256"):
        upgrade._verify_checksum(blob.read_bytes() + b"forgery", sha.read_bytes(), VERSION)
    with pytest.raises(upgrade.UpgradeError, match="SHA-256"):
        upgrade._verify_checksum(blob.read_bytes(), sha.read_bytes().replace(b"0", b"1"), VERSION)


def test_first_public_release_refuses_historical_upgrade():
    standalone = policy()
    assert standalone["compatible_from"] == []
    for system in (DEBIAN13, ALMA10):
        assert upgrade._policy(standalone, VERSION, {"version": "0.0.0"}, system) == standalone
        assert upgrade._policy(standalone, VERSION, {"version": VERSION}, system) == standalone
        with pytest.raises(upgrade.UpgradeError, match="Compatibility"):
            upgrade._policy(standalone, VERSION, {"version": "0.3.0"}, system)


def test_explicit_os_support_and_unknown_downgrades():
    for system in (DEBIAN13, ALMA10):
        assert upgrade._policy(policy(), VERSION, PREVIOUS, system)["schema"] == 1
    for system in ({"ID": "debian", "VERSION_ID": "12"},
                   {"ID": "almalinux", "VERSION_ID": "9"},
                   {"ID": "ubuntu", "VERSION_ID": "24.04"}):
        with pytest.raises(upgrade.UpgradeError, match="OS"):
            upgrade._policy(policy(), VERSION, PREVIOUS, system)
    target = policy()
    target["compatible_from"].append("0.5.0")
    with pytest.raises(upgrade.UpgradeError, match="Downgrade"):
        upgrade._policy(target, VERSION, {"version": "0.5.0"}, DEBIAN13)
    older = {"version": "0.5.0", "release_policy": {
        "downgrade_from": [VERSION], "config_schema": 1, "api_schema": 1}}
    assert upgrade._policy(target, VERSION, older, DEBIAN13)["version"] == VERSION


@pytest.mark.parametrize("bad", [
    {"version": "0.5.0"}, {"schema": 2}, {"compatible_from": "0.3.0"},
    {"targets": [{"id": "debian", "major": "12"}]}, {"config_schema": 999}
])
def test_invalid_policy_fails_closed(bad):
    target = policy()
    target.update(bad)
    with pytest.raises(upgrade.UpgradeError):
        upgrade._policy(target, VERSION, PREVIOUS, DEBIAN13)


def test_reject_symlink_and_path_traversal_archives(tmp_path):
    for member in ("repocache-v0.4.0/../../../escape", "repocache-v0.4.0/release-policy.json"):
        fileobj = io.BytesIO()
        with tarfile.open(fileobj=fileobj, mode="w:gz") as tar:
            entry = tarfile.TarInfo(member)
            entry.type = tarfile.SYMTYPE
            entry.linkname = "/etc/passwd"
            tar.addfile(entry)
        with pytest.raises(upgrade.UpgradeError):
            upgrade._extract_verified(fileobj.getvalue(), VERSION, tmp_path / (
                "out-" + str(len(list(tmp_path.iterdir())))), PREVIOUS, DEBIAN13)


def test_tampered_or_truncated_source_fails_before_install(tmp_path):
    fileobj = io.BytesIO()
    with tarfile.open(fileobj=fileobj, mode="w:gz") as tar:
        info = tarfile.TarInfo("repocache-v0.4.0/release-policy.json")
        data = json.dumps(policy()).encode()
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    with pytest.raises(upgrade.UpgradeError, match="Incomplete"):
        upgrade._extract_verified(fileobj.getvalue(), VERSION, tmp_path/"out", PREVIOUS, DEBIAN13)


def test_public_release_assets_refuse_legacy_credentials_before_network(monkeypatch):
    requests = []
    class UnexpectedNetwork:
        def open(self, request, timeout):
            requests.append(request.full_url)
            raise AssertionError("Request must be blocked without contacting GitHub")
    monkeypatch.setattr(upgrade.urllib.request, "build_opener", lambda *args: UnexpectedNetwork())
    with pytest.raises(upgrade.UpgradeError, match="credentials"):
        upgrade._request_bytes(
            "https://api.github.com/repos/teixemf/repocache/releases/assets/123",
            100, token="synthetic-old-private-token")
    assert not requests


def test_no_arbitrary_cdn_or_unofficial_mirrors():
    for address in ("https://evil.invalid/asset",
                    "http://release-assets.githubusercontent.com/asset",
                    "https://github.com.evil.invalid/asset"):
        with pytest.raises(upgrade.UpgradeError):
            upgrade._request_bytes(address, 100, token="secret")


def test_offline_verified_bundle_uses_only_local_files(monkeypatch, tmp_path):
    blob, sha, _ = archive(tmp_path)
    monkeypatch.setattr(signatures, "verify", fake_signed_identity)
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    monkeypatch.setattr(updater, "_installed", lambda: {"version": "0.0.0"})
    monkeypatch.setattr(releases, "discover", lambda *a, **kw:
                        pytest.fail("Offline upgrade must never query GitHub"))
    called = []
    monkeypatch.setattr(updater, "install_source", lambda source, **kw:
                        called.append((source, kw)) or
                        {"status": "installed", "version": VERSION})
    result = upgrade.upgrade(VERSION, blob, sha, system=DEBIAN13)
    assert result["status"] == "installed"
    assert len(called) == 1
    assert called[0][1]["release_policy"] == policy()


def test_invalid_local_bundle_does_not_install(monkeypatch, tmp_path):
    blob, sha, _ = archive(tmp_path)
    monkeypatch.setattr(signatures, "verify", fake_signed_identity)
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    monkeypatch.setattr(updater, "_installed", lambda: {"version": VERSION})
    monkeypatch.setattr(updater, "install_source", lambda *a, **kw:
                        pytest.fail("Invalid bundles cannot reach installation"))
    sha.write_text("bad")
    with pytest.raises(upgrade.UpgradeError):
        upgrade.upgrade(VERSION, blob, sha, system=DEBIAN13)


def test_remote_asset_metadata_requires_selected_release(monkeypatch):
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    monkeypatch.setattr(updater, "_installed", lambda: {"version": VERSION})
    monkeypatch.setattr(releases, "discover", lambda *a, **kw: [])
    with pytest.raises(upgrade.UpgradeError, match="No verified"):
        upgrade.upgrade()


def test_public_remote_release_upgrade_uses_only_verified_assets(monkeypatch, tmp_path):
    blob, sha, _ = archive(tmp_path)
    monkeypatch.setattr(signatures, "verify", fake_signed_identity)
    bytes_archive, bytes_checksum = blob.read_bytes(), sha.read_bytes()
    record = {"version": VERSION, "assets": {
        "archive": {"id": 301, "size": len(bytes_archive)},
        "checksum": {"id": 302, "size": len(bytes_checksum)},
        "manifest": {"id": 303, "size": 9},
        "signature": {"id": 304, "size": 64},
        "wheelhouse": {"id": 305, "size": len(b"ci-wheelhouse")},
    }}
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    monkeypatch.setattr(updater, "_installed", lambda: {"version": "0.0.0"})
    monkeypatch.setattr(releases, "discover", lambda *a, **kw: [record])
    seen = []
    def download(asset, token_file, max_bytes):
        seen.append(asset["id"])
        return {301: bytes_archive, 302: bytes_checksum,
                303: b"test-only", 304: b"x" * 64,
                305: b"ci-wheelhouse"}[asset["id"]]
    monkeypatch.setattr(upgrade, "_download_asset", download)
    monkeypatch.setattr(updater, "install_source", lambda source, **kw:
                        {"status": "installed", "version": VERSION,
                         "policy": kw["release_policy"]})
    result = upgrade.upgrade(system=DEBIAN13)
    assert result["version"] == VERSION
    assert result["policy"]["schema"] == 1
    assert seen == [303, 304, 301, 302, 305]


def test_unavailable_public_asset_never_falls_back_to_a_private_token(monkeypatch, tmp_path):
    token_file = tmp_path / "obsolete-private-token"
    token_file.write_text("synthetic-old-token")
    token_file.chmod(0o600)
    calls = []
    def unavailable(url, limit, token=None):
        calls.append(token)
        raise releases.DiscoveryError("authentication-required", "not available")
    monkeypatch.setattr(upgrade, "_request_bytes", unavailable)
    with pytest.raises(releases.DiscoveryError):
        upgrade._download_asset({"id": 55, "size": 4}, token_file, 100)
    assert calls == [None]


def test_bad_or_expired_asset_token_does_not_retry_untrusted_hosts(monkeypatch, tmp_path):
    credential = tmp_path / "protected-token"
    credential.write_text("ghp_expired")
    credential.chmod(0o600)
    seen = []
    def unavailable(url, limit, token=None):
        seen.append((url, token is not None))
        raise releases.DiscoveryError("authentication-required", "invalid credential")
    monkeypatch.setattr(upgrade, "_request_bytes", unavailable)
    with pytest.raises(releases.DiscoveryError):
        upgrade._download_asset({"id": 7, "size": 100}, credential, 200)
    assert len(seen) == 1
    assert all("api.github.com/repos/teixemf/repocache/releases/assets/" in u
               for u, _ in seen)


def test_same_version_requires_reauthenticated_bundle_identity(monkeypatch, tmp_path):
    blob, sha, _ = archive(tmp_path)
    monkeypatch.setattr(signatures, "verify", fake_signed_identity)
    digest = hashlib.sha256(blob.read_bytes()).hexdigest()
    marker = tmp_path / "repocache"
    marker.write_text("installed")
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    monkeypatch.setattr(updater, "EXECUTABLE", marker)
    monkeypatch.setattr(updater, "_installed", lambda: {
        "version": VERSION, "source_digest": "a" * 64,
        "archive_sha256": digest,
        "wheelhouse_sha256": hashlib.sha256(b"ci-wheelhouse").hexdigest()})
    record = {"version": VERSION, "assets": {
        "archive": {"id": 1, "size": len(blob.read_bytes())},
        "checksum": {"id": 2, "size": len(sha.read_bytes())},
        "manifest": {"id": 3, "size": 9},
        "signature": {"id": 4, "size": 64},
        "wheelhouse": {"id": 5, "size": len(b"ci-wheelhouse")},
    }}
    monkeypatch.setattr(releases, "discover", lambda *a, **kw: [record])
    data = {1: blob.read_bytes(), 2: sha.read_bytes(),
            3: b"test-only", 4: b"x" * 64,
            5: b"ci-wheelhouse"}
    seen = []
    monkeypatch.setattr(upgrade, "_download_asset", lambda asset, *args: (
        seen.append(asset["id"]) or data[asset["id"]]))
    result = upgrade.upgrade(system=DEBIAN13)
    assert result["status"] == "already-installed"
    assert seen == [3, 4, 1, 2, 5]
    monkeypatch.setattr(updater, "_installed", lambda: {
        "version": VERSION, "source_digest": "a" * 64})
    with pytest.raises(upgrade.UpgradeError, match="signed release identity"):
        upgrade.upgrade(system=DEBIAN13)


def test_unchanged_version_policy_can_be_revalidated_without_false_downgrade():
    current = {"version": VERSION, "source_digest": "a" * 64}
    assert upgrade._policy(policy(), VERSION, current, DEBIAN13)["version"] == VERSION


def test_clean_host_version_policy_requires_supported_os():
    assert upgrade._policy(policy(), VERSION, {"version": "0.0.0"}, DEBIAN13)["schema"] == 1
    with pytest.raises(upgrade.UpgradeError, match="OS"):
        upgrade._policy(policy(), VERSION, {"version": "0.0.0"},
                        {"ID": "debian", "VERSION_ID": "12"})
