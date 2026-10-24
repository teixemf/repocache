"""Safety regressions for journalled source-temp recovery, sandbox ONLY.

No test accesses real package-manager source files.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

import pytest


CLIENT = Path(__file__).resolve().parents[1] / "client"
sys.path.insert(0, str(CLIENT))
import transaction_stage as stage  # noqa: E402
import transaction_atomic_lab as lab  # noqa: E402

SOURCE = "etc/apt/sources.list.d/recovery.list"
BEFORE = b"deb https://upstream.invalid/repo stable main\n"
AFTER = b"deb mirror+file:/etc/apt/mirrors/cache stable main\n"


@pytest.fixture
def root(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / SOURCE
    path.parent.mkdir(parents=True)
    (tmp_path / "var/lib").mkdir(parents=True)
    path.write_bytes(BEFORE)
    marker = tmp_path / lab.MARKER
    marker.write_bytes(lab.MAGIC)
    marker.chmod(0o600)
    return tmp_path


def prepared(root):
    ident = stage.stage(root, SOURCE, hashlib.sha256(BEFORE).hexdigest(), AFTER)["id"]
    return ident, root / SOURCE


def terminate_before_replace(root, ident, action):
    child = r"""
import os, signal, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import transaction_atomic_lab as lab
def crash_before_replace(*args):
    os.kill(os.getpid(), signal.SIGKILL)
lab._replace = crash_before_replace
root, ident, action = Path(sys.argv[2]), sys.argv[3], sys.argv[4]
if action == "apply":
    lab.apply_sandbox(root, ident)
elif action == "rollback":
    lab.rollback_sandbox(root, ident)
else:
    raise RuntimeError("unknown action")
"""
    proc = subprocess.run(
        [sys.executable, "-c", child, str(CLIENT), str(root), ident, action],
        check=False, capture_output=True, timeout=20,
    )
    assert proc.returncode == -signal.SIGKILL, proc.stderr.decode(errors="replace")


def test_interrupted_rollback_resumes_verified_intent(root):
    ident, source = prepared(root)
    assert lab.apply_sandbox(root, ident)["status"] == "installed"
    terminate_before_replace(root, ident, "rollback")
    journal = json.loads((root / "var/lib/repocache-client/staging" / ident /
                          lab.JOURNAL).read_text())
    assert journal["phase"] == "restore-intent"
    pending = source.parent / (".repocache-atomic-" + ident)
    assert pending.read_bytes() == BEFORE
    assert source.read_bytes() == AFTER
    assert lab.recover_sandbox(root, ident)["status"] == "restored"
    assert source.read_bytes() == BEFORE
    assert not pending.exists()
    assert lab.recover_sandbox(root, ident)["status"] == "restored"


def test_interrupted_install_discards_only_verified_own_temp(root):
    ident, source = prepared(root)
    terminate_before_replace(root, ident, "apply")
    pending = source.parent / (".repocache-atomic-" + ident)
    assert pending.read_bytes() == AFTER
    assert source.read_bytes() == BEFORE
    assert lab.recover_sandbox(root, ident)["status"] == "not-applied"
    assert not pending.exists()
    assert source.read_bytes() == BEFORE


@pytest.mark.parametrize("mutation", ["bytes", "foreign-inode", "symlink"])
def test_interrupted_rollback_never_uses_tampered_temporary(root, mutation):
    ident, source = prepared(root)
    lab.apply_sandbox(root, ident)
    terminate_before_replace(root, ident, "rollback")
    pending = source.parent / (".repocache-atomic-" + ident)
    if mutation == "bytes":
        pending.write_bytes(b"untrusted\n")
    elif mutation == "foreign-inode":
        replacement = pending.with_suffix(".foreign")
        replacement.write_bytes(BEFORE)
        os.replace(replacement, pending)
    else:
        pending.unlink()
        pending.symlink_to(source)
    with pytest.raises(stage.StageError):
        lab.recover_sandbox(root, ident)
    assert source.read_bytes() == AFTER


def test_missing_journalled_rollback_temp_fails_closed(root):
    ident, source = prepared(root)
    lab.apply_sandbox(root, ident)
    terminate_before_replace(root, ident, "rollback")
    pending = source.parent / (".repocache-atomic-" + ident)
    pending.unlink()
    with pytest.raises(stage.StageError, match="Missing journalled rollback"):
        lab.recover_sandbox(root, ident)
    assert source.read_bytes() == AFTER


def test_unjournalled_orphan_is_not_removed_or_accepted(root):
    ident, source = prepared(root)
    pending = source.parent / (".repocache-atomic-" + ident)
    pending.write_bytes(b"foreign")
    with pytest.raises(stage.StageError, match="Unjournalled"):
        lab.recover_sandbox(root, ident)
    assert pending.read_bytes() == b"foreign"
    assert source.read_bytes() == BEFORE


def test_completed_stage_with_unexpected_temporary_fails_closed(root):
    ident, source = prepared(root)
    lab.apply_sandbox(root, ident)
    pending = source.parent / (".repocache-atomic-" + ident)
    pending.write_bytes(b"foreign")
    with pytest.raises(stage.StageError, match="Unjournalled"):
        lab.recover_sandbox(root, ident)
    assert pending.read_bytes() == b"foreign"
    assert source.read_bytes() == AFTER


def test_unexpected_temp_inode_blocks_install_recovery(root):
    ident, source = prepared(root)
    terminate_before_replace(root, ident, "apply")
    pending = source.parent / (".repocache-atomic-" + ident)
    impostor = pending.with_suffix(".impostor")
    impostor.write_bytes(AFTER)
    os.replace(impostor, pending)
    with pytest.raises(stage.StageError, match="Foreign or modified"):
        lab.recover_sandbox(root, ident)
    assert source.read_bytes() == BEFORE
    assert pending.exists()
