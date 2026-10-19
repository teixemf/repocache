"""Issue #50: deterministic full-transaction concurrency and restart tests.

Independent subprocesses use real fcntl.flock, atomic activation and
filesystem journals. Only venv/pip are stubbed to avoid downloading
dependencies; #49's separate CI covers signed offline pip and the real CLI.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest


# Each worker has an independent Python interpreter and kernel file descriptor.
# Barriers are files created only after a version has been ACTIVATED while
# A still holds the exclusive update lock.
WORKER = r"""
import json
import os
import sys
import time
from pathlib import Path
from repocache import updater

root, signals, source, mode = (Path(sys.argv[1]), Path(sys.argv[2]),
                               Path(sys.argv[3]), sys.argv[4])
updater.ROOT = root
updater.MANIFEST = root / "installed.json"
updater.CURRENT = root / "current"
updater.EXECUTABLE = root / "current/bin/repocache"
updater._require_service_account = lambda: None
updater._safe_links = lambda: None
version = source.name


def stub_command(args, **kwargs):
    if "-m" in args and args[args.index("-m") + 1] == "venv":
        destination = Path(args[-1])
        (destination / "bin").mkdir(parents=True, exist_ok=True)
        (destination / "bin/repocache").write_text("synthetic offline test\n")
        if mode == "kill_stage":
            (signals / "stage_ready").write_text(str(destination))
            while True:
                time.sleep(0.03)
        return ""
    if args[-1] == "--version":
        return "REPOCACHE " + version
    return ""


updater._run = stub_command
write_manifest = updater._write_manifest


def at_activation(manifest):
    (signals / "a_activated").write_text(str(updater.CURRENT.resolve()))
    deadline = time.monotonic() + 15
    while not (signals / "b_done").exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("Timed out at deterministic lock barrier")
        time.sleep(0.015)
    if mode == "a_fail":
        raise updater.UpdateError("injected activation failure")
    write_manifest(manifest)


if mode in ("a_fail", "a_pass"):
    updater._write_manifest = at_activation
if mode == "b_busy":
    (signals / "b_attempt").touch()

try:
    result = updater.install_source(source)
except updater.UpdateBusyError as error:
    if mode != "b_busy" or str(error) != "Another REPOCACHE update is running":
        raise
    (signals / "b_done").write_text("busy")
    print("BUSY", flush=True)
except updater.UpdateError as error:
    if mode != "a_fail" or str(error) != "injected activation failure":
        raise
    print("ROLLED_BACK", flush=True)
else:
    if mode == "b_busy":
        raise AssertionError("Second updater acquired the active transaction lock")
    print("SUCCESS:" + result["version"], flush=True)
"""


def source(directory: Path, version: str) -> Path:
    location = directory / version
    (location / "src/repocache").mkdir(parents=True)
    (location / "pyproject.toml").write_text(
        '[project]\nname = "repocache-control"\nversion = "' + version + '"\n')
    (location / "install.sh").write_text("#!/bin/sh\n")
    (location / "src/repocache/__init__.py").write_text(
        '__version__ = "' + version + '"\n')
    return location


@pytest.fixture
def scenario(tmp_path):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    release = root / "releases" / "0.2.0-baseline"
    (release / "bin").mkdir(parents=True)
    (release / "bin/repocache").write_text("baseline")
    (root / "current").symlink_to(release)
    (root / "installed.json").write_text(json.dumps({
        "version": "0.2.0", "source_digest": "a" * 64,
        "source": "trusted preexisting fixture",
    }) + "\n")
    protected = tmp_path / "unrelated-config"
    protected.write_text("must remain unchanged")
    signals = tmp_path / "barriers"
    signals.mkdir()
    sources = tmp_path / "sources"
    return root, signals, (source(sources, "0.2.1"), source(sources, "0.3.0")), protected


def worker(scenario, src, mode, *, wait=False):
    root, barriers, _, _ = scenario
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
    command = [sys.executable, "-c", WORKER, str(root), str(barriers), str(src), mode]
    if wait:
        return subprocess.run(command, text=True, capture_output=True, env=env, timeout=30)
    return subprocess.Popen(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env)


def barrier(path: Path, process: subprocess.Popen | None = None):
    deadline = time.monotonic() + 15
    while not path.exists() and time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            output, errors = process.communicate(timeout=3)
            pytest.fail("Worker died before barrier: " + output + " " + errors)
        time.sleep(0.02)
    assert path.exists(), "Timed out waiting for " + path.name


def assert_generation(root: Path, version: str):
    manifest = json.loads((root / "installed.json").read_text())
    assert manifest["version"] == version
    assert (root / "current").is_symlink()
    assert Path(os.readlink(root / "current")).is_dir()
    assert (root / "current/bin/repocache").is_file()
    assert not (root / ".update-journal.json").exists()
    assert (root / ".updater.lock").is_file()
    assert (root / ".updater.lock").stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("fail_first", [False, True], ids=["success-success", "fail-retry"])
def test_two_independent_installers_are_serialized_through_rollback(scenario, fail_first):
    root, signals, (first, second), protected = scenario
    a = worker(scenario, first, "a_fail" if fail_first else "a_pass")
    try:
        barrier(signals / "a_activated", a)
        # Process B starts AFTER A is activated but BEFORE A has committed.
        b = worker(scenario, second, "b_busy", wait=True)
        assert b.returncode == 0, b.stdout + "\n" + b.stderr
        assert "BUSY" in b.stdout
        assert (signals / "b_attempt").exists()
        barrier(signals / "b_done")
        stdout, stderr = a.communicate(timeout=25)
        assert a.returncode == 0, stdout + "\n" + stderr
        assert ("ROLLED_BACK" if fail_first else "SUCCESS:0.2.1") in stdout
        assert_generation(root, "0.2.0" if fail_first else "0.2.1")
        # B retries after A commits/rolls back, without seeing stale A state.
        retry = worker(scenario, second, "b_retry", wait=True)
        assert retry.returncode == 0, retry.stdout + "\n" + retry.stderr
        assert "SUCCESS:0.3.0" in retry.stdout
        assert_generation(root, "0.3.0")
        assert protected.read_text() == "must remain unchanged"
    finally:
        if a.poll() is None:
            a.kill()
            a.communicate(timeout=5)


def test_killed_stager_cannot_poison_reinstallation_of_same_release(scenario):
    root, signals, (first, _), protected = scenario
    a = worker(scenario, first, "kill_stage")
    try:
        barrier(signals / "stage_ready", a)
        incomplete = Path((signals / "stage_ready").read_text())
        assert incomplete.is_dir()
        assert incomplete.name.startswith("0.2.1-")
        a.kill()
        a.communicate(timeout=5)
        assert a.returncode != 0
        assert_generation(root, "0.2.0")
        retry = worker(scenario, first, "b_retry", wait=True)
        assert retry.returncode == 0, retry.stdout + "\n" + retry.stderr
        assert_generation(root, "0.2.1")
        # Every transaction has its own permanent venv path; a killed
        # incomplete environment is never reused as a trusted one.
        assert incomplete.is_dir()
        assert protected.read_text() == "must remain unchanged"
    finally:
        if a.poll() is None:
            a.kill()
            a.communicate(timeout=5)


def test_upgrade_api_enters_lock_before_preflight(monkeypatch, tmp_path):
    from repocache import upgrade, updater
    tmp_path.chmod(0o700)
    monkeypatch.setattr(updater, "ROOT", tmp_path)
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    observed = []
    monkeypatch.setattr(updater, "recover_transaction",
                        lambda: observed.append(("recovery", updater._TX_LOCAL.active)))
    monkeypatch.setattr(upgrade, "_upgrade_locked",
                        lambda **kwargs: observed.append(("upgrade", updater._TX_LOCAL.active)))
    upgrade.upgrade(selected="0.3.0")
    assert observed == [("recovery", True), ("upgrade", True)]


def test_busy_cli_reports_machine_readable_retry_status(monkeypatch):
    from typer.testing import CliRunner
    from repocache import updater
    from repocache.cli import app

    def busy(**kwargs):
        raise updater.UpdateBusyError("Another REPOCACHE update is running")

    monkeypatch.setattr(updater, "apply", busy)
    response = CliRunner().invoke(app, ["update", "--json"])
    assert response.exit_code == 75
    message = json.loads(response.output)
    assert message["status"] == "busy"
    assert message["retryable"] is True
    assert message["performed"] is False
