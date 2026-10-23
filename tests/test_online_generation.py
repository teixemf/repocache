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

from repocache import online_deps, online_generation, signed_dependency_staging, updater


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
        observations.append("run-" + ("venv" if "venv" in argv else
                                     "install" if "install" in argv else
                                     "check" if "check" in argv else "list"))
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
            assert kwargs["cwd"].name == "download"
            return ""
        if "check" in argv:
            return ""
        return json.dumps([
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
        "0.6.0", b"asset-inventory", {"archive": b"fake-source"},
        "debian13-py313", cafile=Path("/etc/ssl/certs/ca-certificates.crt"),
    )


def test_signed_stage_uses_exclusive_rootless_transaction_and_never_activates(
        rootless_staging):
    root, events, active = rootless_staging
    result = _rehearse()
    assert result == {
        "status": "dependencies-verified-only", "version": "0.6.0",
        "target": "debian13-py313", "dependency_count": 1, "activated": False,
    }
    assert events == ["lock-acquire", "recover", "signed-lock-verified",
                      "download", "run-venv", "run-install", "run-check",
                      "run-list", "lock-release"]
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
