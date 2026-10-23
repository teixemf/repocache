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
    "https://example.org/release", "0.5.0\n", "0.5.0+untrusted", "9" * 70,
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
