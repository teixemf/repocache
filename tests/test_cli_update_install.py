"""CLI v1 explicit signed updater entrypoint regression gate (#107).

Mocks exercise only parser/adapter behavior. Native signed release, privileged
installation, recovery and rollback acceptance remain owned by #82-#85.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from repocache import cli, releases, updater


@pytest.mark.parametrize("argv", [
    ["--json", "update", "install", "0.5.0"],
    ["update", "install", "0.5.0", "--json"],
])
def test_explicit_install_routes_exact_version_to_existing_updater(monkeypatch, argv):
    calls = []

    def fake_apply(**kw):
        calls.append(kw)
        return {"ok": True, "status": "installed", "version": "0.5.0",
                "previous_version": "0.4.0"}

    monkeypatch.setattr(updater, "apply", fake_apply)
    result = CliRunner().invoke(cli.app, argv)
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["version"] == "0.5.0"
    assert calls == [{
        "version": "0.5.0", "bundle": None, "checksum": None,
        "manifest": None, "signature": None, "wheels": None,
    }]


@pytest.mark.parametrize("version", [
    "v0.5.0", "0.5", "0.5.0rc1", "01.5.0", "0.05.0", "0.5.0/../../tmp",
    "https://example.org/release", "0.5.0\n", "0.5.0+untrusted", "0.0.0", "9" * 70,
])
@pytest.mark.parametrize("prefix,suffix", [
    (["--json", "update", "install"], []),
    (["update", "install"], ["--json"]),
])
def test_malformed_version_refused_before_updater_invocation(
        monkeypatch, version, prefix, suffix):
    monkeypatch.setattr(updater, "apply", lambda **kw:
                        pytest.fail("Invalid release reached updater"))
    result = CliRunner().invoke(cli.app, [*prefix, version, *suffix])
    assert result.exit_code == 2, result.output
    response = json.loads(result.stdout)
    assert response == {
        "ok": False,
        "error": {"code": "INVALID_VERSION",
                  "message": "Expected a stable X.Y.Z version."},
    }
    assert not result.stderr


def test_missing_positional_version_never_calls_backend(monkeypatch):
    monkeypatch.setattr(updater, "apply", lambda **kw:
                        pytest.fail("Required version missing but updater called"))
    result = CliRunner().invoke(cli.app, ["update", "install"])
    assert result.exit_code != 0
    assert "VERSION" in result.output.upper()


@pytest.mark.parametrize("failure,status,code", [
    (updater.UpdateBusyError("Update already running"), 75, "busy"),
    (updater.UpdateError("Signed release rejected"), 2, "error"),
    (releases.DiscoveryError("offline", "GitHub is unreachable"), 2, "offline"),
    (releases.DiscoveryError("authentication-required", "Denied"), 2,
     "authentication-required"),
])
def test_signed_update_failure_preserves_legacy_exit_and_json(
        monkeypatch, failure, status, code):
    calls = []

    def rejected(**kwargs):
        calls.append(kwargs["version"])
        raise failure

    monkeypatch.setattr(updater, "apply", rejected)
    result = CliRunner().invoke(cli.app,
                                ["update", "install", "0.5.0", "--json"])
    assert result.exit_code == status, result.output
    doc = json.loads(result.stdout)
    assert doc["ok"] is False
    assert doc["status"] == code
    assert doc["performed"] is False
    assert doc["retryable"] is (code == "busy")
    assert calls == ["0.5.0"]
    assert not result.stderr


def test_offline_bundle_arguments_are_passed_unchanged_to_verified_backend(
        monkeypatch, tmp_path):
    calls = []

    def fake_apply(**kwargs):
        calls.append(kwargs)
        return {"ok": True, "status": "installed", "version": "0.5.0",
                "previous_version": "0.4.0"}

    monkeypatch.setattr(updater, "apply", fake_apply)
    named_paths = {
        "--bundle": tmp_path / "release.tar.gz",
        "--checksum": tmp_path / "release.sha256",
        "--manifest": tmp_path / "manifest.json",
        "--signature": tmp_path / "manifest.sig",
        "--wheelhouse": tmp_path / "wheels.tar.gz",
    }
    argv = ["update", "install", "0.5.0", "--json"]
    for key, value in named_paths.items():
        argv += [key, str(value)]
    result = CliRunner().invoke(cli.app, argv)
    assert result.exit_code == 0, result.output
    assert calls == [{
        "version": "0.5.0",
        "bundle": named_paths["--bundle"],
        "checksum": named_paths["--checksum"],
        "manifest": named_paths["--manifest"],
        "signature": named_paths["--signature"],
        "wheels": named_paths["--wheelhouse"],
    }]
    assert not list(tmp_path.iterdir())  # This adapter never writes the paths.


def test_legacy_bare_update_and_version_option_remain_explicitly_compatible(
        monkeypatch):
    calls = []

    def fake_apply(**kwargs):
        calls.append(kwargs)
        return {"ok": True, "status": "already-installed", "version": "0.5.0",
                "previous_version": "0.5.0"}

    monkeypatch.setattr(updater, "apply", fake_apply)
    runner = CliRunner()
    for argv in (["update"], ["update", "--version", "0.5.0"]):
        result = runner.invoke(cli.app, argv)
        assert result.exit_code == 0, (argv, result.output)
        assert "already-installed" in result.stdout
    assert [c["version"] for c in calls] == [None, "0.5.0"]
    assert all(set(c) == {
        "version", "bundle", "checksum", "manifest", "signature", "wheels",
    } for c in calls)


def test_install_help_does_not_run_update_or_prompt(monkeypatch):
    monkeypatch.setattr(updater, "apply", lambda **kw:
                        pytest.fail("Help must not install anything"))
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **kw:
                        pytest.fail("CLI must not prompt"))
    runner = CliRunner()
    result = runner.invoke(cli.app, ["update", "install", "--help"])
    assert result.exit_code == 0, result.output
    assert "VERSION" in result.output.upper()
    assert "install" not in result.stderr.lower()


def test_update_check_and_list_remain_unmodified(monkeypatch):
    monkeypatch.setattr(updater, "apply", lambda **kw:
                        pytest.fail("Read-only update commands called apply"))
    monkeypatch.setattr(updater, "check", lambda: {
        "status": "up-to-date", "performed": False,
        "installed_version": "0.4.0", "latest_version": "0.4.0",
        "message": "Up to date"})
    monkeypatch.setattr(updater, "list_versions", lambda: {
        "status": "up-to-date", "installed_version": "0.4.0",
        "message": "Up to date", "releases": []})
    for command in ("check", "list"):
        result = CliRunner().invoke(cli.app, ["update", command, "--json"])
        assert result.exit_code == 0, result.output
        assert isinstance(json.loads(result.stdout), dict)



def test_actual_signed_verifier_refuses_untrusted_offline_release_at_cli_boundary(
        monkeypatch, tmp_path):
    """Exercise CLI -> apply -> upgrade -> signatures.verify, not a fake apply.

    Only privileged lock/service-account preconditions are replaced, because
    this is an isolated test; the real signature verifier is never mocked.
    """
    import contextlib
    import hashlib
    from repocache import upgrade

    monkeypatch.setattr(updater, "update_transaction", contextlib.nullcontext)
    monkeypatch.setattr(updater, "recover_transaction", lambda: None)
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    monkeypatch.setattr(updater, "_installed", lambda: {"version": "0.4.0"})
    monkeypatch.setattr(releases, "discover", lambda *_a, **_kw:
                        pytest.fail("Offline assets must never trigger discovery"))
    monkeypatch.setattr(upgrade, "_download_asset", lambda *_a, **_kw:
                        pytest.fail("Offline assets must never trigger downloads"))
    monkeypatch.setattr(upgrade, "_extract_verified", lambda *_a, **_kw:
                        pytest.fail("Untrusted release must never be extracted"))
    monkeypatch.setattr(updater, "install_source", lambda *_a, **_kw:
                        pytest.fail("Untrusted release must never be installed"))

    archive = tmp_path / "repocache-v0.5.0.tar.gz"
    archive.write_bytes(b"untrusted inert bytes, not a tarball")
    checksum = tmp_path / (archive.name + ".sha256")
    checksum.write_text(
        hashlib.sha256(archive.read_bytes()).hexdigest() +
        "  " + archive.name + "\n", encoding="ascii")
    manifest = tmp_path / (archive.name + ".manifest.json")
    manifest.write_bytes(b"{}")  # Unsupported schema; not an owner manifest.
    signature = tmp_path / (manifest.name + ".sig")
    signature.write_bytes(b"x" * 64)  # Syntactically sized, not Ed25519.
    wheels = tmp_path / (archive.name + ".wheelhouse.tar.gz")
    wheels.write_bytes(b"untrusted inert wheelhouse bytes")
    original = {p.name: p.read_bytes()
                for p in (archive, checksum, manifest, signature, wheels)}
    result = CliRunner().invoke(cli.app, [
        "update", "install", "0.5.0", "--json",
        "--bundle", str(archive), "--checksum", str(checksum),
        "--manifest", str(manifest), "--signature", str(signature),
        "--wheelhouse", str(wheels),
    ])
    assert result.exit_code == 2, result.output
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["performed"] is False
    assert payload["status"] == "error"
    assert "signed release manifest schema" in payload["error"]
    assert not result.stderr
    assert {p.name: p.read_bytes()
            for p in (archive, checksum, manifest, signature, wheels)} == original


@pytest.mark.parametrize("missing", ["checksum", "bundle"])
def test_actual_backend_rejects_partial_local_bundle_before_any_network_or_install(
        monkeypatch, tmp_path, missing):
    import contextlib
    from repocache import upgrade

    monkeypatch.setattr(updater, "update_transaction", contextlib.nullcontext)
    monkeypatch.setattr(updater, "recover_transaction", lambda: None)
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    monkeypatch.setattr(releases, "discover", lambda *_a, **_kw:
                        pytest.fail("Invalid offline inputs must not contact GitHub"))
    monkeypatch.setattr(upgrade, "_download_asset", lambda *_a, **_kw:
                        pytest.fail("Invalid offline inputs must not download"))
    monkeypatch.setattr(updater, "install_source", lambda *_a, **_kw:
                        pytest.fail("Invalid offline inputs must not install"))
    argv = ["update", "install", "0.5.0", "--json"]
    if missing != "bundle":
        argv += ["--bundle", str(tmp_path / "repocache-v0.5.0.tar.gz")]
    if missing != "checksum":
        argv += ["--checksum", str(tmp_path / "repocache-v0.5.0.tar.gz.sha256")]
    result = CliRunner().invoke(cli.app, argv)
    assert result.exit_code == 2, result.output
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert "Both --bundle and --checksum" in payload["error"]
    assert list(tmp_path.iterdir()) == []




def test_cli_routes_ephemerally_signed_candidate_through_real_verifier(
        monkeypatch, tmp_path):
    """Prove CLI -> signed verifier -> policy parsing, with no activation.

    Signing keys exist only in tmp_path in disposable CI; this does NOT use
    the real publisher private key or test native privileged activation.
    """
    import contextlib
    import hashlib
    import importlib.util
    import subprocess
    import time

    from repocache import signatures, upgrade, wheelhouse

    root = Path(__file__).resolve().parents[1]

    def load_module(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def openssl(*args):
        subprocess.run(["/usr/bin/openssl", *map(str, args)],
                       check=True, capture_output=True, timeout=20)

    private = tmp_path / "ephemeral-private.pem"
    public = tmp_path / "ephemeral-public.pem"
    openssl("genpkey", "-algorithm", "Ed25519", "-out", private)
    private.chmod(0o600)
    openssl("pkey", "-in", private, "-pubout", "-out", public)
    public.chmod(0o644)
    monkeypatch.setattr(signatures, "_trusted_key", lambda key_id: public)

    builder = load_module("cli_v1_signed_builder", root / "scripts/build_release.py")
    signer = load_module("cli_v1_signed_signer", root / "scripts/sign_release.py")
    archive, checksum = builder.build_release(tmp_path / "output", "v0.4.0")
    wheel_file = archive.with_name(archive.name + ".wheelhouse.tar.gz")
    wheel_file.write_bytes(b"ephemeral wheelhouse placeholder, not executable")
    now = int(time.time())
    manifest, signature = signer.sign(
        archive, private, "ci-ephemeral", "a" * 40, now - 60, now + 3600,
        wheelhouse_sha256=hashlib.sha256(wheel_file.read_bytes()).hexdigest())

    monkeypatch.setattr(updater, "update_transaction", contextlib.nullcontext)
    monkeypatch.setattr(updater, "recover_transaction", lambda: None)
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    monkeypatch.setattr(updater, "_installed", lambda: {"version": "0.0.0"})
    monkeypatch.setattr(releases, "discover", lambda *_a, **_kw:
                        pytest.fail("Local signed candidate must not access GitHub"))
    monkeypatch.setattr(upgrade, "_download_asset", lambda *_a, **_kw:
                        pytest.fail("Local signed candidate must not download"))

    # The runner is Ubuntu, not an approved native host. Inject ONLY the
    # explicit Debian 13 test-host identity into the real policy validator.
    # Real archive extraction, manifest hash and Ed25519 checks remain live.
    real_extract = upgrade._extract_verified

    def simulated_host_extract(data, version, directory, previous,
                               system=None, signed_policy_sha256=None):
        assert system is None
        return real_extract(
            data, version, directory, previous,
            {"ID": "debian", "VERSION_ID": "13"},
            signed_policy_sha256=signed_policy_sha256)

    monkeypatch.setattr(upgrade, "_extract_verified", simulated_host_extract)
    monkeypatch.setattr(wheelhouse, "verified_extract",
                        lambda data, digest, destination:
                        destination / "requirements.lock")
    monkeypatch.setattr(wheelhouse, "verify_application_wheel",
                        lambda *_a, **_kw: None)
    installed = []

    def record_installer(source, **kwargs):
        installed.append(kwargs)
        assert (source / "pyproject.toml").is_file()
        return {"ok": True, "status": "installed", "version": "0.4.0",
                "previous_version": "0.0.0"}

    monkeypatch.setattr(updater, "install_source", record_installer)
    result = CliRunner().invoke(cli.app, [
        "update", "install", "0.4.0", "--json",
        "--bundle", str(archive), "--checksum", str(checksum),
        "--manifest", str(manifest), "--signature", str(signature),
        "--wheelhouse", str(wheel_file),
    ])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["version"] == "0.4.0"
    assert len(installed) == 1
    identity = installed[0]["release_identity"]
    assert identity["archive_sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert identity["publisher_key_id"] == "ci-ephemeral"
    assert installed[0]["release_policy"]["version"] == "0.4.0"



def test_updater_remains_single_source_for_signature_and_recovery():
    # An architectural guard: CLI must delegate, not bypass, signature
    # verification or implement a second updater pipeline.
    import inspect

    adapter_source = inspect.getsource(cli.update_install)
    assert "_perform_signed_update(" in adapter_source
    backend_source = inspect.getsource(cli._perform_signed_update)
    assert "from repocache.updater import apply" in backend_source
    assert "apply(version=version" in backend_source
    assert "subprocess" not in adapter_source
    assert "subprocess" not in backend_source
