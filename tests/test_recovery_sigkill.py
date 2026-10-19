"""#51 crash-boundary matrix: actual SIGKILL, restart and interrupted rollback.

Each child process writes real filesystem state before being killed.
Recovery uses the same stdlib implementation as the root-owned launcher.
Actual physical power-loss durability is explicitly waived by maintainer.
"""
from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest
from repocache import recovery, updater


KILL_WORKER = r"""
import os, signal, sys
from pathlib import Path
from repocache import updater, recovery

root, source, injection = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
updater.ROOT = root
updater.CURRENT = root / "current"
updater.MANIFEST = root / "installed.json"
updater.EXECUTABLE = root / "current/bin/repocache"
updater._require_service_account = lambda: None
updater._safe_links = lambda: None

def stub(argv, **kwargs):
    if len(argv) > 2 and argv[1:3] == ["-m", "venv"]:
        dst = Path(argv[-1])
        (dst / "bin").mkdir(parents=True, exist_ok=True)
        (dst / "bin/repocache").write_text("fixture")
    elif argv[-1] == "--version":
        return "REPOCACHE 0.3.0"
    return ""

updater._run = stub

def kill():
    os.kill(os.getpid(), signal.SIGKILL)

# Every successful low-level replace/fsync boundary is independently killed
# in a fresh child, rather than mocking the result or inventing a power loss.
for operation in ("fsync", "replace"):
    if injection.startswith(operation + ":"):
        desired = int(injection.split(":", 1)[1])
        original = getattr(os, operation)
        count = [0]

        def wrap(*args, _original=original, _count=count, **kwargs):
            result = _original(*args, **kwargs)
            _count[0] += 1
            if _count[0] == desired:
                kill()
            return result

        setattr(os, operation, wrap)

counts = {"journal": 0}
original_journal = updater._write_journal

def journal(*args):
    original_journal(*args)
    counts["journal"] += 1
    if injection == "journal" + str(counts["journal"]):
        kill()

updater._write_journal = journal

original_activate = updater._replace_current

def activate(*args):
    original_activate(*args)
    if injection == "activate":
        kill()

updater._replace_current = activate

original_manifest = updater._write_manifest

def manifest(*args):
    original_manifest(*args)
    if injection == "manifest":
        kill()
    if injection in ("rollback", "rollback_manifest"):
        # Force a recoverable exception AFTER durable manifest replacement.
        raise updater.UpdateError("trigger interrupted rollback")

updater._write_manifest = manifest

if injection == "rollback":
    original_restore = recovery._activate
    def interrupted_restore(*args):
        original_restore(*args)
        kill()
    recovery._activate = interrupted_restore
elif injection == "rollback_manifest":
    original_restore_manifest = recovery._durable
    def interrupted_manifest_restore(*args):
        original_restore_manifest(*args)
        kill()
    recovery._durable = interrupted_manifest_restore

original_clear = updater._clear_journal

def clear():
    original_clear()
    if injection == "clear":
        kill()

updater._clear_journal = clear
updater.install_source(source)
raise SystemExit("Expected to be killed at a filesystem boundary")
"""


@pytest.fixture
def setup(tmp_path):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    old = root / "releases" / "0.2.0-initial"
    (old / "bin").mkdir(parents=True)
    (old / "bin/repocache").write_text("trusted old")
    (root / "current").symlink_to(old)
    previous = {
        "version": "0.2.0",
        "source_digest": "a" * 64,
        "source": "test-baseline",
    }
    raw = (json.dumps(previous) + "\n").encode()
    (root / "installed.json").write_bytes(raw)
    source = tmp_path / "fixture"
    (source / "src/repocache").mkdir(parents=True)
    (source / "pyproject.toml").write_text(
        '[project]\nname = "repocache-control"\nversion = "0.3.0"\n')
    (source / "install.sh").write_text("#!/bin/sh\n")
    (source / "src/repocache/__init__.py").write_text(
        '__version__ = "0.3.0"\n')
    untouched = tmp_path / "nginx-and-tls-fingerprint"
    untouched.write_text("immutable fixture")
    return root, old, source, raw, untouched


def assert_consistent(root, version, target=None):
    state = json.loads((root / "installed.json").read_bytes())
    assert state["version"] == version
    active = root / "current"
    assert active.is_symlink()
    current_path = Path(os.readlink(active))
    assert current_path.parent == root / "releases"
    assert current_path.is_dir()
    assert (current_path / "bin/repocache").is_file()
    assert current_path.name.startswith(state["version"] + "-")
    if target is not None:
        assert current_path == target
    if state["version"] == "0.3.0":
        assert current_path.name.split("-")[1] == state["source_digest"][:12]
    assert not (root / ".update-journal.json").exists()


@pytest.mark.parametrize(
    "boundary,committed", [
        ("journal1", False),
        ("activate", False),
        ("journal2", False),
        ("manifest", False),
        ("journal3", True),
        ("clear", True),
        ("rollback", False),
        ("rollback_manifest", False),
    ],
)
def test_sigkill_every_activation_commit_and_rollback_boundary(setup, boundary, committed, monkeypatch):
    root, old, source, old_bytes, untouched = setup
    rootdir = Path(__file__).resolve().parents[1]
    env = dict(os.environ, PYTHONPATH=str(rootdir / "src"))
    child = subprocess.run(
        [sys.executable, "-c", KILL_WORKER, str(root), str(source), boundary],
        text=True, capture_output=True, timeout=25, env=env,
    )
    assert child.returncode == -signal.SIGKILL, child.stderr
    monkeypatch.setattr(updater, "ROOT", root)
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    # Same recovery routine used by the independently pinned launcher helper;
    # run twice to prove a crash in the reconciler has an idempotent restart.
    with updater.update_transaction():
        recovery.reconcile(root)
        assert recovery.reconcile(root) == "consistent"
    assert_consistent(root, "0.3.0" if committed else "0.2.0",
                      None if committed else old)
    if not committed:
        assert (root / "installed.json").read_bytes() == old_bytes
    assert untouched.read_text() == "immutable fixture"



@pytest.mark.parametrize("boundary", [
    *(f"fsync:{i}" for i in range(1, 12)),
    *(f"replace:{i}" for i in range(1, 6)),
])
def test_sigkill_after_each_low_level_fsync_or_atomic_rename(setup, boundary, monkeypatch):
    root, old, source, before, untouched = setup
    env = dict(os.environ,
               PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
    result = subprocess.run(
        [sys.executable, "-c", KILL_WORKER,
         str(root), str(source), boundary],
        env=env, capture_output=True, text=True, timeout=25,
    )
    assert result.returncode == -signal.SIGKILL, (
        boundary + ": " + result.stdout + result.stderr)
    monkeypatch.setattr(updater, "ROOT", root)
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    with updater.update_transaction():
        recovery.reconcile(root)
        assert recovery.reconcile(root) == "consistent"
    manifest = json.loads((root / "installed.json").read_text())
    assert manifest["version"] in ("0.2.0", "0.3.0")
    assert_consistent(root, manifest["version"])
    if manifest["version"] == "0.2.0":
        assert (root / "current").resolve() == old
        assert (root / "installed.json").read_bytes() == before
    assert untouched.read_text() == "immutable fixture"


def test_no_journal_manifest_mismatch_fails_closed(setup):
    root, old, source, original, untouched = setup
    (root / "installed.json").write_text(
        '{"version":"0.4.0","source_digest":"' + "b" * 64 + '"}')
    with pytest.raises(recovery.RecoveryError, match="disagreement"):
        recovery.reconcile(root)
    assert (root / "current").resolve() == old
    assert untouched.read_text() == "immutable fixture"


def test_orphan_journal_and_unknown_fields_fail_closed(setup):
    root, old, source, original, untouched = setup
    file = root / ".update-journal.json"
    file.write_text('{"schema":2,"phase":"committed","unknown":"attacker"}')
    file.chmod(0o600)
    with pytest.raises(recovery.RecoveryError, match="Corrupt transaction journal"):
        recovery.reconcile(root)
    assert file.is_file()
    assert (root / "current").resolve() == old
