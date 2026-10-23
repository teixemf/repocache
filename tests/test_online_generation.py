"""Rootless transaction and fail-closed online venv rehearsal tests (issue #83).

All wheel staging and pip/venv execution are simulated here. The existing
Ed25519-first candidate fixtures in test_signed_dependency_staging.py prove
the independent pre-network signature/lock/SBOM verification path.
"""
from __future__ import annotations

import contextlib
import json
from pathlib import Path

import pytest

from repocache import application_wheel, online_deps, online_generation, signed_dependency_staging, updater


WHEEL = online_deps.Wheel(
    "rich", "15.0.0", "rich-15.0.0-py3-none-any.whl", "a" * 64,
    "https://files.pythonhosted.org/packages/ab/cdef/rich-15.0.0-py3-none-any.whl",
)


@pytest.fixture
def rootless_staging(tmp_path, monkeypatch):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(updater, "ROOT", root)
    monkeypatch.setattr(updater, "CURRENT", root / "current")
    monkeypatch.setattr(updater, "_installed", lambda: {"version": "0.0.0"})
    monkeypatch.setattr(online_generation, "_current_host_target", lambda: "debian13-py313")
    observations = []
    active = {"yes": False}
    monkeypatch.setattr(application_wheel, "verify", lambda *a: observations.append("owned-wheel-verified"))

    @contextlib.contextmanager
    def transaction():
        observations.append("lock-acquire")
        assert active["yes"] is False
        active["yes"] = True
        try:
            yield
        finally:
            active["yes"] = False
            observations.append("lock-release")

    def recovery():
        assert active["yes"]
        observations.append("recover")

    def verified(*args, **kwargs):
        assert active["yes"]
        assert observations[:2] == ["lock-acquire", "recover"]
        observations.append("signed-lock-verified")
        return (WHEEL,)

    def stage(*args, **kwargs):
        assert active["yes"]
        assert "signed-lock-verified" in observations
        observations.append("download")
        location = args[7]
        location.mkdir(mode=0o700)
        wheel_path = location / "requirements.lock"
        wheel_path.write_text("./wheels/rich-15.0.0-py3-none-any.whl --hash=sha256:" +
                              ("a" * 64) + "\n")
        wheel_path.chmod(0o600)
        return wheel_path

    def run(argv, **kwargs):
        assert active["yes"]
        if "venv" in argv:
            action = "venv"
        elif "install" in argv:
            action = "install-app" if kwargs.get("cwd", Path("/")).name == "owned-app" else "install-deps"
        elif "check" in argv:
            action = "check"
        elif "--format=json" in argv:
            action = "list"
        elif "--version" in argv:
            action = "cli-version"
        elif "--help" in argv:
            action = "cli-help"
        elif "-c" in argv:
            action = "tui-import"
        else:
            pytest.fail("Unexpected command in online venv rehearsal")
        observations.append("run-" + action)
        if "venv" in argv:
            new_venv = Path(argv[-1])
            (new_venv / "bin").mkdir(parents=True, mode=0o700)
            interpreter = new_venv / "bin" / "python"
            interpreter.write_text("# synthetic native Python executable\n")
            interpreter.chmod(0o700)
            return ""
        if "install" in argv:
            assert argv[:4] == [str(Path(argv[0])), "-I", "-m", "pip"]
            assert "--isolated" in argv
            for required in ("--no-index", "--no-deps", "--only-binary=:all:",
                             "--require-hashes", "--no-cache-dir", "--no-input"):
                assert required in argv
            assert "--extra-index-url" not in argv
            assert kwargs["cwd"].name in {"download", "owned-app"}
            if kwargs["cwd"].name == "owned-app":
                console = Path(argv[0]).parent / "repocache"
                console.write_text("# synthetic staged REPOCACHE executable\n")
                console.chmod(0o700)
                assert "--require-hashes" in argv
                assert (kwargs["cwd"] / "application.lock").is_file()
                assert (kwargs["cwd"] / application_wheel.filename("0.6.0")).is_file()
            return ""
        if "--version" in argv:
            return "REPOCACHE Control Center 0.6.0"
        if "--help" in argv:
            return "Usage: repocache [OPTIONS] COMMAND [ARGS]...\nupdate"
        if "-c" in argv:
            assert "RepoCacheApp" in argv[-1]
            assert "textual.app" in argv[-1]
            return ""
        if "check" in argv:
            return ""
        return json.dumps([
            {"name": "repocache-control", "version": "0.6.0"},
            {"name": "rich", "version": "15.0.0"},
            {"name": "pip", "version": "25.0"},
        ])

    monkeypatch.setattr(updater, "update_transaction", transaction)
    monkeypatch.setattr(updater, "recover_transaction", recovery)
    monkeypatch.setattr(signed_dependency_staging, "verified_candidate_wheels", verified)
    monkeypatch.setattr(signed_dependency_staging, "stage_signed_candidate", stage)
    monkeypatch.setattr(updater, "_run", run)
    return root, observations, active


def _rehearse():
    return online_generation.rehearse_signed_install(
        b"fake-source", b"signed-manifest", b"fake-signature",
        "0.6.0", b"asset-inventory",
        {"archive": b"fake-source", "application_wheel": b"synthetic-owner-wheel"},
        "debian13-py313", cafile=Path("/etc/ssl/certs/ca-certificates.crt"),
    )


def test_signed_stage_uses_exclusive_rootless_transaction_and_never_activates(
        rootless_staging):
    root, events, active = rootless_staging
    result = _rehearse()
    assert result == {
        "status": "application-and-dependencies-verified-only", "version": "0.6.0",
        "target": "debian13-py313", "dependency_count": 1,
        "cli_smoke": "passed", "tui_import_smoke": "passed",
        "activated": False,
    }
    assert events == ["lock-acquire", "recover", "signed-lock-verified",
                      "owned-wheel-verified", "download", "run-venv",
                      "run-install-deps", "owned-wheel-verified", "run-install-app",
                      "run-check", "run-list", "run-cli-version", "run-cli-help",
                      "run-tui-import", "lock-release"]
    assert not active["yes"]
    assert not (root / "current").exists()
    assert not (root / "installed.json").exists()
    assert not list((root / "online-preparations").iterdir())


@pytest.mark.parametrize("phase", ["signature", "download", "venv", "install",
                                    "check", "list"])
def test_every_failure_cleans_disposable_venv_and_keeps_active_generation(
        rootless_staging, monkeypatch, phase):
    root, events, _ = rootless_staging
    # This tests cleanup while the current symlink and installed state remain
    # untouched. The genuine signed stage path is independently tested in #100.
    if phase == "signature":
        def bad(*args, **kwargs):
            raise signed_dependency_staging.PreparationError("Unverified")
        monkeypatch.setattr(signed_dependency_staging, "verified_candidate_wheels", bad)
    elif phase == "download":
        def bad(*args, **kwargs):
            raise signed_dependency_staging.PreparationError("Unreachable")
        monkeypatch.setattr(signed_dependency_staging, "stage_signed_candidate", bad)
    else:
        original = updater._run
        def fail(argv, **kwargs):
            if phase in argv or (phase == "list" and "--format=json" in argv):
                raise updater.UpdateError("Synthetic rejected pip/venv invocation")
            return original(argv, **kwargs)
        monkeypatch.setattr(updater, "_run", fail)
    with pytest.raises(online_generation.PreparationInstallError):
        _rehearse()
    assert events[-1] == "lock-release"
    assert not (root / "current").exists()
    assert not (root / "installed.json").exists()
    parent = root / "online-preparations"
    assert not parent.exists() or list(parent.iterdir()) == []


@pytest.mark.parametrize("packages", [
    "not json",
    "{}", "[]",
    '[{"name":"rich","version":"15.0.0"}, {"name":"evil","version":"1.0.0"}]',
    '[{"name":"rich","version":"15.0.0"}, {"name":"RICH","version":"15.0.0"}]',
    '[{"name":"rich","version":"15.1.0"}]',
    '[{"name":true,"version":"15.0.0"}]',
])
def test_staged_pip_inventory_never_accepts_extra_or_incomplete_packages(packages):
    with pytest.raises(online_generation.PreparationInstallError):
        online_generation._check_installed(packages, (WHEEL,))


def test_pip_command_always_offline_wheel_only(tmp_path):
    lock = tmp_path / "requirements.lock"
    lock.write_text("./wheels/foo.whl --hash=sha256:" + "a" * 64 + "\n")
    commands = online_generation._install_commands(
        Path("/rootless/venv/bin/python"), lock)
    assert len(commands) == 3
    cmd, check, inventory = commands
    assert cmd[1:6] == ["-I", "-m", "pip", "--isolated", "install"]
    assert "--no-index" in cmd and "--only-binary=:all:" in cmd
    assert "--require-hashes" in cmd and "--no-deps" in cmd
    assert "--no-input" in cmd and "-r" in cmd
    assert check[-1] == "check" and inventory[-1] == "--format=json"


def test_online_rehearsal_refuses_downgrade_before_network(
        rootless_staging, monkeypatch):
    root, events, _ = rootless_staging
    monkeypatch.setattr(updater, "_installed", lambda: {"version": "0.6.0"})
    monkeypatch.setattr(updater, "_check_active_layout", lambda prior: None)
    with pytest.raises(online_generation.PreparationInstallError, match="cannot repair"):
        _rehearse()
    assert "signed-lock-verified" not in events
    assert not (root / "online-preparations").exists()


def test_online_rehearsal_refuses_symlinked_staging_parent_before_network(
        rootless_staging, tmp_path):
    root, events, _ = rootless_staging
    external = tmp_path / "external"
    external.mkdir()
    (root / "online-preparations").symlink_to(external, target_is_directory=True)
    with pytest.raises(online_generation.PreparationInstallError, match="Symlinked"):
        _rehearse()
    assert "download" not in events
    assert not list(external.iterdir())


def test_rootful_managed_working_directory_is_not_trusted(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(online_generation.updater, "ROOT", root)
    monkeypatch.setattr(online_generation.os, "geteuid", lambda: 0)
    with pytest.raises(online_generation.PreparationInstallError, match="root"):
        online_generation._managed_parent()
    assert not (root / "online-preparations").exists()


@pytest.mark.parametrize("contents,py,expect", [
    ('ID=debian\nVERSION_ID="13"\n', (3, 13), "debian13-py313"),
    ('ID=almalinux\nVERSION_ID="10.1"\n', (3, 12), "almalinux10-py312"),
])
def test_host_target_resolves_only_supported_native_python(contents, py, expect):
    assert online_generation._host_target(contents, py) == expect


@pytest.mark.parametrize("contents,py", [
    ("ID=ubuntu\nVERSION_ID=24.04\n", (3, 13)),
    ("ID=debian\nVERSION_ID=12\n", (3, 13)),
    ("ID=debian\nVERSION_ID=13\n", (3, 12)),
    ("ID=almalinux\nVERSION_ID=10\n", (3, 13)),
    ("ID=debian\nID=debian\nVERSION_ID=13\n", (3, 13)),
    ("ID=debian\nVERSION_ID=13x\n", (3, 13)),
])
def test_wrong_native_os_or_python_never_resolves_an_online_lock(contents, py):
    with pytest.raises(online_generation.PreparationInstallError):
        online_generation._host_target(contents, py)


def test_wrong_signed_target_is_refused_before_candidate_read_or_network(
        rootless_staging, monkeypatch):
    root, events, _ = rootless_staging
    monkeypatch.setattr(online_generation, "_current_host_target",
                        lambda: "almalinux10-py312")
    with pytest.raises(online_generation.PreparationInstallError, match="native OS"):
        _rehearse()
    assert "signed-lock-verified" not in events
    assert "download" not in events
    assert not (root / "online-preparations").exists()


def test_failed_online_stage_preserves_preexisting_signed_legacy_generation(
        rootless_staging, monkeypatch, tmp_path):
    root, events, _ = rootless_staging
    releases = root / "releases"
    releases.mkdir(mode=0o700)
    digest = "a" * 64
    old = releases / ("0.5.0-" + digest[:12] + "-trusted")
    (old / "bin").mkdir(parents=True, mode=0o700)
    executable = old / "bin" / "repocache"
    executable.write_text("# verified original application\n")
    executable.chmod(0o700)
    current = root / "current"
    current.symlink_to(old)
    manifest = root / "installed.json"
    original_manifest = b'{"version":"0.5.0","signed":true}\n'
    manifest.write_bytes(original_manifest)
    nginx = tmp_path / "nginx.conf"
    nginx.write_text("# existing operator configuration\n")
    monkeypatch.setattr(
        updater, "_installed",
        lambda: {"version": "0.5.0", "source_digest": digest})

    original_run = updater._run
    def fail_pip(argv, **kwargs):
        if "install" in argv:
            raise updater.UpdateError("Offline pip failed")
        return original_run(argv, **kwargs)
    monkeypatch.setattr(updater, "_run", fail_pip)

    with pytest.raises(online_generation.PreparationInstallError):
        _rehearse()
    assert current.is_symlink() and current.readlink() == old
    assert executable.read_text() == "# verified original application\n"
    assert manifest.read_bytes() == original_manifest
    assert nginx.read_text() == "# existing operator configuration\n"
    assert not list((root / "online-preparations").iterdir())
    assert events[-1] == "lock-release"
