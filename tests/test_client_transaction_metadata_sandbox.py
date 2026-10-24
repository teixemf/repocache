"""Protected original metadata + sandbox atomic apply/rollback integration.

These tests are disposable /tmp fixtures. They NEVER authorize installed
REPOCACHE clients to edit real package-manager source files.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys

import pytest


CLIENT = Path(__file__).resolve().parents[1] / "client"
sys.path.insert(0, str(CLIENT))
stage = importlib.import_module("transaction_stage")
atomic = importlib.import_module("transaction_atomic_lab")
bridge = importlib.import_module("transaction_metadata_sandbox")
pre = importlib.import_module("source_preflight")
lab = importlib.import_module("source_metadata_lab")
SOURCE = "etc/apt/sources.list.d/metadata.sources"
ORIGINAL = b"Types: deb\nURIs: https://deb.debian.org/debian\nSuites: trixie\nComponents: main\n"
REPLACEMENT = b"Types: deb\nURIs: mirror+file:/etc/apt/mirrors/rc.txt\nSuites: trixie\nComponents: main\n"


@pytest.fixture
def sandbox(tmp_path):
    tmp_path.chmod(0o700)
    (tmp_path / "etc/apt/sources.list.d").mkdir(parents=True)
    (tmp_path / "var/lib").mkdir(parents=True)
    (tmp_path / SOURCE).write_bytes(ORIGINAL)
    marker = tmp_path / atomic.MARKER
    marker.write_bytes(atomic.MAGIC)
    marker.chmod(0o600)
    return tmp_path


def prepare(root, *, attrs=False, acl=False):
    source = root / SOURCE
    if attrs:
        os.setxattr(source, "user.repocache-test", b"fixture-secret-\x00\xff")
    if acl:
        executable = shutil.which("setfacl")
        if not executable:
            pytest.skip("setfacl is unavailable; native workflow requires it")
        subprocess.run([executable, "-m", "u:65534:r", str(source)],
                       check=True, capture_output=True, timeout=10)
    before_attrs = {name: os.getxattr(source, name) for name in os.listxattr(source)}
    old_mode = stat.S_IMODE(source.stat().st_mode)
    ident = stage.stage(root, SOURCE, hashlib.sha256(ORIGINAL).hexdigest(), REPLACEMENT)["id"]
    bridge.snapshot_sandbox(root, ident)
    return ident, before_attrs, old_mode


def test_supported_user_xattrs_survive_apply_recover_and_rollback(sandbox):
    ident, attrs, mode = prepare(sandbox, attrs=True)
    source = sandbox / SOURCE
    original = source.stat()
    assert atomic.apply_sandbox(sandbox, ident)["status"] == "installed"
    assert source.stat().st_ino != original.st_ino
    assert source.read_bytes() == REPLACEMENT
    assert {name: os.getxattr(source, name) for name in os.listxattr(source)} == attrs
    assert atomic.recover_sandbox(sandbox, ident)["status"] == "installed"
    assert atomic.rollback_sandbox(sandbox, ident)["status"] == "restored"
    assert source.read_bytes() == ORIGINAL
    assert stat.S_IMODE(source.stat().st_mode) == mode
    assert {name: os.getxattr(source, name) for name in os.listxattr(source)} == attrs
    protected = sandbox / "var/lib/repocache-client/staging" / ident / bridge.SNAPSHOT
    assert stat.S_IMODE(protected.stat().st_mode) == 0o600
    raw = protected.read_text()
    assert "fixture-secret" not in raw


def test_acl_and_xattr_combination_survives_transaction(sandbox):
    ident, attrs, mode = prepare(sandbox, attrs=True, acl=True)
    assert "system.posix_acl_access" in attrs
    source = sandbox / SOURCE
    assert atomic.apply_sandbox(sandbox, ident)["status"] == "installed"
    assert stat.S_IMODE(source.stat().st_mode) == mode
    assert {name: os.getxattr(source, name) for name in os.listxattr(source)} == attrs
    assert atomic.rollback_sandbox(sandbox, ident)["status"] == "restored"
    assert stat.S_IMODE(source.stat().st_mode) == mode
    assert {name: os.getxattr(source, name) for name in os.listxattr(source)} == attrs


def test_unsnapshotted_xattrs_still_block_existing_atomic_lab(sandbox):
    os.setxattr(sandbox / SOURCE, "user.private", b"secret")
    ident = stage.stage(sandbox, SOURCE, hashlib.sha256(ORIGINAL).hexdigest(), REPLACEMENT)["id"]
    with pytest.raises(stage.StageError, match="unhandled extended attributes"):
        atomic.apply_sandbox(sandbox, ident)
    assert (sandbox / SOURCE).read_bytes() == ORIGINAL


def test_external_metadata_change_after_snapshot_blocks_apply(sandbox):
    ident, _, _ = prepare(sandbox, attrs=True)
    os.setxattr(sandbox / SOURCE, "user.other", b"external")
    with pytest.raises(stage.StageError, match="attribute drift|metadata drift"):
        atomic.apply_sandbox(sandbox, ident)
    assert (sandbox / SOURCE).read_bytes() == ORIGINAL


def test_external_metadata_change_after_apply_blocks_rollback(sandbox):
    ident, _, _ = prepare(sandbox, attrs=True)
    atomic.apply_sandbox(sandbox, ident)
    os.setxattr(sandbox / SOURCE, "user.other", b"external")
    with pytest.raises(stage.StageError, match="attribute drift"):
        atomic.rollback_sandbox(sandbox, ident)
    with pytest.raises(stage.StageError, match="attribute drift"):
        atomic.recover_sandbox(sandbox, ident)
    assert (sandbox / SOURCE).read_bytes() == REPLACEMENT


def test_corrupt_private_snapshot_fails_before_source_replacement(sandbox):
    ident, _, _ = prepare(sandbox, attrs=True)
    snapshot = sandbox / "var/lib/repocache-client/staging" / ident / bridge.SNAPSHOT
    data = json.loads(snapshot.read_text())
    data["original_inode"] += 1
    snapshot.write_text(json.dumps(data))
    with pytest.raises(stage.StageError, match="Invalid protected original metadata snapshot"):
        atomic.apply_sandbox(sandbox, ident)
    assert (sandbox / SOURCE).read_bytes() == ORIGINAL


def test_duplicate_or_bad_snapshot_is_refused(sandbox):
    ident, _, _ = prepare(sandbox, attrs=True)
    with pytest.raises(stage.StageError, match="already exists"):
        bridge.snapshot_sandbox(sandbox, ident)
    snapshot = sandbox / "var/lib/repocache-client/staging" / ident / bridge.SNAPSHOT
    data = json.loads(snapshot.read_text())
    data["attributes"].append(data["attributes"][0])
    snapshot.write_text(json.dumps(data))
    with pytest.raises(stage.StageError, match="Invalid protected original metadata snapshot"):
        atomic.apply_sandbox(sandbox, ident)


def test_incomplete_snapshot_blocks_transaction(sandbox):
    ident = stage.stage(sandbox, SOURCE, hashlib.sha256(ORIGINAL).hexdigest(), REPLACEMENT)["id"]
    stage_dir = sandbox / "var/lib/repocache-client/staging" / ident
    (stage_dir / ".original-attributes.partial").write_bytes(b"incomplete")
    with pytest.raises(stage.StageError, match="Unknown transaction"):
        atomic.apply_sandbox(sandbox, ident)
    assert (sandbox / SOURCE).read_bytes() == ORIGINAL


def test_sigkill_after_atomic_replace_recovery_preserves_xattrs(sandbox):
    ident, attrs, _ = prepare(sandbox, attrs=True)
    child = r"""
import os, signal, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import transaction_atomic_lab as lab
old = lab._replace
def interrupt(*args):
    old(*args)
    os.kill(os.getpid(), signal.SIGKILL)
lab._replace = interrupt
lab.apply_sandbox(Path(sys.argv[2]), sys.argv[3])
"""
    result = subprocess.run(
        [sys.executable, "-c", child, str(CLIENT), str(sandbox), ident],
        capture_output=True, check=False, timeout=20,
    )
    assert result.returncode == -signal.SIGKILL
    source = sandbox / SOURCE
    assert source.read_bytes() == REPLACEMENT
    assert {name: os.getxattr(source, name) for name in os.listxattr(source)} == attrs
    assert atomic.recover_sandbox(sandbox, ident)["status"] == "restored"
    assert source.read_bytes() == ORIGINAL
    assert {name: os.getxattr(source, name) for name in os.listxattr(source)} == attrs


def test_security_selinux_attribute_is_refused_before_snapshot(sandbox, monkeypatch):
    original = lab.os.listxattr
    monkeypatch.setattr(lab.os, "listxattr",
                        lambda fd: original(fd) + ["security.selinux"])
    ident = stage.stage(sandbox, SOURCE, hashlib.sha256(ORIGINAL).hexdigest(), REPLACEMENT)["id"]
    with pytest.raises(pre.PreflightError, match="Security label"):
        bridge.snapshot_sandbox(sandbox, ident)
    assert (sandbox / SOURCE).read_bytes() == ORIGINAL
