"""Sandbox-only atomic install, recovery and rollback negative/positive tests.

No real /etc or package source path may be used. A hidden marker inside a
temporary /tmp root is mandatory for any source replacement in this module.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys

import pytest


CLIENT = Path(__file__).resolve().parents[1] / "client"
sys.path.insert(0, str(CLIENT))
lab = importlib.import_module("transaction_atomic_lab")
stage = importlib.import_module("transaction_stage")

SOURCE = "etc/apt/sources.list.d/demo.sources"
BEFORE = b"Types: deb\nURIs: https://deb.debian.org/debian\nSuites: trixie\nComponents: main\n"
AFTER = b"Types: deb\nURIs: mirror+file:/etc/apt/mirrors/repocache.txt\nSuites: trixie\nComponents: main\n"


@pytest.fixture
def sandbox(tmp_path):
    tmp_path.chmod(0o700)
    (tmp_path / "etc/apt/sources.list.d").mkdir(parents=True)
    (tmp_path / "var/lib").mkdir(parents=True)
    (tmp_path / SOURCE).write_bytes(BEFORE)
    marker = tmp_path / lab.MARKER
    marker.write_bytes(lab.MAGIC)
    marker.chmod(0o600)
    return tmp_path


def prepared(sandbox):
    return stage.stage(sandbox, SOURCE, hashlib.sha256(BEFORE).hexdigest(), AFTER)["id"]


def test_atomic_apply_and_rollback_preserve_mode_and_private_snapshots(sandbox):
    ident = prepared(sandbox)
    path = sandbox / SOURCE
    original_stat = path.stat()
    result = lab.apply_sandbox(sandbox, ident)
    assert result["status"] == "installed"
    assert path.read_bytes() == AFTER
    assert path.stat().st_ino != original_stat.st_ino
    assert stat.S_IMODE(path.stat().st_mode) == stat.S_IMODE(original_stat.st_mode)
    assert lab.recover_sandbox(sandbox, ident)["status"] == "installed"
    with pytest.raises(stage.StageError, match="already modified"):
        lab.apply_sandbox(sandbox, ident)
    assert lab.rollback_sandbox(sandbox, ident)["status"] == "restored"
    assert path.read_bytes() == BEFORE
    assert lab.recover_sandbox(sandbox, ident)["status"] == "restored"
    assert (sandbox / "var/lib/repocache-client/staging" /
            ident / "original.bin").read_bytes() == BEFORE


def test_without_sandbox_marker_cannot_modify_sources(sandbox):
    ident = prepared(sandbox)
    (sandbox / lab.MARKER).unlink()
    with pytest.raises(stage.StageError):
        lab.apply_sandbox(sandbox, ident)
    assert (sandbox / SOURCE).read_bytes() == BEFORE


@pytest.mark.parametrize("mode", ["symlink", "writable", "incorrect-magic"])
def test_corrupted_marker_fails_closed(sandbox, mode):
    ident = prepared(sandbox)
    marker = sandbox / lab.MARKER
    if mode == "symlink":
        marker.unlink()
        marker.symlink_to(sandbox / SOURCE)
    elif mode == "writable":
        marker.chmod(0o644)
    else:
        marker.write_bytes(b"not an approved fixture\n")
    with pytest.raises(stage.StageError):
        lab.apply_sandbox(sandbox, ident)
    assert (sandbox / SOURCE).read_bytes() == BEFORE


def test_sandbox_gate_rejects_live_root():
    with pytest.raises(stage.StageError, match="restricted"):
        lab._sandbox(Path("/"))


def test_prepared_source_external_drift_never_overwritten(sandbox):
    ident = prepared(sandbox)
    path = sandbox / SOURCE
    path.write_bytes(b"external operator edit\n")
    with pytest.raises(stage.StageError, match="drift"):
        lab.apply_sandbox(sandbox, ident)
    assert path.read_bytes() == b"external operator edit\n"


def test_inode_replacement_even_with_same_bytes_is_drift(sandbox):
    ident = prepared(sandbox)
    path = sandbox / SOURCE
    alternate = path.with_suffix(".alt")
    alternate.write_bytes(BEFORE)
    os.replace(alternate, path)
    with pytest.raises(stage.StageError, match="drift"):
        lab.apply_sandbox(sandbox, ident)
    assert path.read_bytes() == BEFORE


def test_post_install_external_edit_prevents_rollback(sandbox):
    ident = prepared(sandbox)
    lab.apply_sandbox(sandbox, ident)
    source = sandbox / SOURCE
    source.write_bytes(b"external edit\n")
    with pytest.raises(stage.StageError, match="drift"):
        lab.rollback_sandbox(sandbox, ident)
    with pytest.raises(stage.StageError, match="externally"):
        lab.recover_sandbox(sandbox, ident)
    assert source.read_bytes() == b"external edit\n"


def test_external_chmod_after_apply_blocks_rollback_and_recovery(sandbox):
    ident = prepared(sandbox)
    lab.apply_sandbox(sandbox, ident)
    source = sandbox / SOURCE
    source.chmod(0o600)
    with pytest.raises(stage.StageError, match="metadata drift|External source drift"):
        lab.rollback_sandbox(sandbox, ident)
    with pytest.raises(stage.StageError, match="metadata drift"):
        lab.recover_sandbox(sandbox, ident)
    assert source.read_bytes() == AFTER


def test_xattr_source_fails_closed_without_dropping_metadata(sandbox):
    ident = prepared(sandbox)
    source = sandbox / SOURCE
    try:
        os.setxattr(source, "user.repocache-ci", b"owned")
    except OSError:
        pytest.skip("Filesystem does not support user xattrs")
    with pytest.raises(stage.StageError, match="extended attributes"):
        lab.apply_sandbox(sandbox, ident)
    assert source.read_bytes() == BEFORE
    assert os.getxattr(source, "user.repocache-ci") == b"owned"


def test_journal_integrity_and_unknown_state_are_not_accepted(sandbox):
    ident = prepared(sandbox)
    directory = sandbox / "var/lib/repocache-client/staging" / ident
    (directory / "unknown.data").write_bytes(b"unexpected")
    with pytest.raises(stage.StageError, match="Unknown transaction"):
        lab.apply_sandbox(sandbox, ident)
    assert (sandbox / SOURCE).read_bytes() == BEFORE


def _killed_worker(sandbox: Path, ident: str, injected: str):
    child = r"""
import os, signal, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import transaction_atomic_lab as lab
root, ident, fault = Path(sys.argv[2]), sys.argv[3], sys.argv[4]
if fault == "after-replace":
    original = lab._replace
    def kill_after(*args):
        original(*args)
        os.kill(os.getpid(), signal.SIGKILL)
    lab._replace = kill_after
elif fault in ("before-install-replace", "after-restore-replace"):
    original = lab._write_phase
    if fault == "before-install-replace":
        def kill_intent(directory, phase, identity, prior):
            original(directory, phase, identity, prior)
            if phase == "install-intent":
                os.kill(os.getpid(), signal.SIGKILL)
        lab._write_phase = kill_intent
    else:
        original_replace = lab._replace
        def kill_after_restore(*args):
            original_replace(*args)
            os.kill(os.getpid(), signal.SIGKILL)
        lab._replace = kill_after_restore
if fault == "after-restore-replace":
    lab.rollback_sandbox(root, ident)
else:
    lab.apply_sandbox(root, ident)
"""
    result = subprocess.run(
        [sys.executable, "-c", child, str(CLIENT), str(sandbox), ident, injected],
        text=True, capture_output=True, check=False, timeout=20,
    )
    assert result.returncode == -signal.SIGKILL, result.stderr


def test_sigkill_after_atomic_install_reverts_proven_own_write(sandbox):
    ident = prepared(sandbox)
    _killed_worker(sandbox, ident, "after-replace")
    assert (sandbox / SOURCE).read_bytes() == AFTER
    assert lab.recover_sandbox(sandbox, ident)["status"] == "restored"
    assert (sandbox / SOURCE).read_bytes() == BEFORE
    assert lab.recover_sandbox(sandbox, ident)["status"] == "restored"


def test_sigkill_after_intent_but_before_replace_keeps_original(sandbox):
    ident = prepared(sandbox)
    _killed_worker(sandbox, ident, "before-install-replace")
    assert (sandbox / SOURCE).read_bytes() == BEFORE
    assert lab.recover_sandbox(sandbox, ident)["status"] == "not-applied"
    assert (sandbox / SOURCE).read_bytes() == BEFORE


def test_sigkill_after_explicit_rollback_recognises_restored_file(sandbox):
    ident = prepared(sandbox)
    lab.apply_sandbox(sandbox, ident)
    _killed_worker(sandbox, ident, "after-restore-replace")
    assert (sandbox / SOURCE).read_bytes() == BEFORE
    assert lab.recover_sandbox(sandbox, ident)["status"] == "restored"
    assert (sandbox / SOURCE).read_bytes() == BEFORE


def test_crash_recovery_refuses_foreign_inode_even_with_expected_content(sandbox):
    ident = prepared(sandbox)
    _killed_worker(sandbox, ident, "after-replace")
    path = sandbox / SOURCE
    alter = path.with_suffix(".tmp-other")
    alter.write_bytes(AFTER)
    os.replace(alter, path)
    with pytest.raises(stage.StageError, match="External drift"):
        lab.recover_sandbox(sandbox, ident)
    assert path.read_bytes() == AFTER


def test_existing_client_sync_apply_remains_disabled(sandbox):
    script = (CLIENT / "repocache_client.py").read_text()
    assert 'raise ClientError("Applying changes is disabled until reviewed")' in script
    assert "transaction_atomic_lab" not in script
    assert "transaction_atomic_lab" not in (CLIENT / "install.sh").read_text()
