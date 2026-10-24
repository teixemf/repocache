#!/usr/bin/env python3
"""Real #131/#132 atomic shared-file source regression, disposable /tmp ONLY.

Uses pinned integrated transaction sources from _transaction_dependency.
Executes full-root positive path and actual non-root negative path inside
disposable native Debian 13 / AlmaLinux 10 containers.
"""
from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "client"
# Integration tests MUST import the local reconciled transaction engine,
# not an older checked-out dependency that would bypass ACL/xattr changes.
if not (CLIENT / "transaction_atomic_lab.py").is_file():
    raise RuntimeError("Reconciled sandbox transaction engine unavailable")
sys.path.insert(0, str(CLIENT))

import source_preflight as pre  # noqa: E402
import source_entry_boundaries as boundaries  # noqa: E402
import entry_candidate_sandbox as candidates  # noqa: E402
import entry_approval_plan_sandbox as approvals  # noqa: E402
import entry_transaction_stage_sandbox as bridge  # noqa: E402
import entry_atomic_sandbox as wrapper  # noqa: E402
import transaction_stage as stage  # noqa: E402
import transaction_atomic_lab as atomic  # noqa: E402


FILES = {
    "etc/apt/sources.list.d/mixture.list": (
        b"# Ansible owns the file\n"
        b"deb [signed-by=/etc/apt/keyrings/internal.gpg] https://one.invalid/repo trixie main\n"
        b"# preserved comment\n"
        b"deb https://operator.invalid/repo trixie main\n"
    ),
    "etc/apt/sources.list.d/mixture.sources": (
        b"Types: deb\nURIs: https://one.invalid/deb\n"
        b"Suites: trixie\nComponents: main\n"
        b"Signed-By: /etc/apt/keyrings/internal.gpg\n\n"
        b"Types: deb\nURIs: https://operator.invalid/deb\n"
        b"Suites: trixie\nComponents: main\n"
    ),
    "etc/yum.repos.d/mixture.repo": (
        b"# managed by operator\n"
        b"[baseos]\nname=BaseOS\nbaseurl=https://one.invalid/repo\n"
        b"enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n\n"
        b"[extras]\nbaseurl=https://operator.invalid/repo\n"
        b"enabled=0\ngpgcheck=1\n"
    ),
}
URL = "https://cache.invalid/packages/"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fixture(root, relative, body):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    chosen = boundaries.boundaries(relative, body)[0]
    ident = candidates.register_entry_candidate_sandbox(
        root, relative, sha(body), chosen["sha256"])["id"]
    approvals.approve_entry_plan_sandbox(root, ident, sha(body), chosen["sha256"])
    stage_info = bridge.stage_entry_change_sandbox(root, ident, URL)
    return path, ident, stage_info["stage_id"], chosen


def assert_siblings(relative, before, after):
    old = boundaries.boundaries(relative, before)
    new = boundaries.boundaries(relative, after)
    assert len(old) == len(new) == 2
    assert old[1]["sha256"] == new[1]["sha256"]
    # With different-length URLs the second entry's offsets may shift, but
    # its complete original bytes and all trailing comments remain identical.
    assert before[old[1]["start"]:old[1]["end"]] == after[
        new[1]["start"]:new[1]["end"]]


def real_unprivileged_refusal(root, ident, stage_id):
    worker = r"""
import os, sys
os.setgroups([])
os.setgid(65534)
os.setuid(65534)
sys.path.insert(0, sys.argv[1])
import entry_atomic_sandbox as tool
import entry_approval_plan_sandbox as appr
try:
    tool.apply_entry_sandbox(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
except appr.ApprovalRefused:
    sys.exit(0)
sys.exit(4)
"""
    proc = subprocess.run([sys.executable, "-c", worker, str(CLIENT),
                           str(root), ident, stage_id, URL],
                          capture_output=True, timeout=15, check=False)
    assert proc.returncode == 0, proc.stderr


def interrupted_install(root, ident, stage_id):
    worker = r"""
import os, signal, sys
sys.path.insert(0, sys.argv[1])
import transaction_atomic_lab as atomic
import entry_atomic_sandbox as tool
original = atomic._replace
def kill_after_replace(*args):
    original(*args)
    os.kill(os.getpid(), signal.SIGKILL)
atomic._replace = kill_after_replace
tool.apply_entry_sandbox(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
"""
    proc = subprocess.run([sys.executable, "-c", worker, str(CLIENT),
                           str(root), ident, stage_id, URL],
                          capture_output=True, timeout=20, check=False)
    assert proc.returncode == -signal.SIGKILL, proc.stderr


def main():
    assert os.geteuid() == 0, "Native positive sandbox scenario requires UID 0"
    with tempfile.TemporaryDirectory(prefix="rc-shared-atomic-") as private:
        root = Path(private)
        root.chmod(0o700)
        (root / "var/lib").mkdir(parents=True)
        marker = root / pre.MARKER
        marker.write_bytes(pre.TEST_MAGIC)
        marker.chmod(0o600)
        writer_marker = root / atomic.MARKER
        writer_marker.write_bytes(atomic.MAGIC)
        writer_marker.chmod(0o600)

        for relative, original in FILES.items():
            source, cid, sid, first = fixture(root, relative, original)
            initial = source.stat()
            real_unprivileged_refusal(root, cid, sid)
            assert source.read_bytes() == original

            # A valid approval + source digest may never substitute for an
            # unrelated or corrupted protected stage. No source modification.
            try:
                wrapper.apply_entry_sandbox(root, cid, "f" * 32, URL)
            except (approvals.ApprovalRefused, stage.StageError):
                pass
            else:
                raise AssertionError("Unknown stage was accepted")
            assert source.read_bytes() == original

            applied = wrapper.apply_entry_sandbox(root, cid, sid, URL)
            assert applied["state"] == "installed"
            assert applied["production_write_eligible"] is False
            changed = source.read_bytes()
            assert changed != original and source.stat().st_ino != initial.st_ino
            assert_siblings(relative, original, changed)
            assert b"operator.invalid" in changed
            assert atomic.recover_sandbox(root, sid)["status"] == "installed"

            restored = wrapper.rollback_entry_sandbox(root, cid, sid, URL)
            assert restored["state"] == "restored"
            assert source.read_bytes() == original
            assert_siblings(relative, original, changed)

        # Sibling changed after planning => stale stage must never apply.
        other = "etc/apt/sources.list.d/conflict.list"
        before = FILES["etc/apt/sources.list.d/mixture.list"]
        path, cid, sid, _ = fixture(root, other, before)
        path.write_bytes(before + b"# operator new note\n")
        try:
            wrapper.apply_entry_sandbox(root, cid, sid, URL)
        except (approvals.ApprovalRefused, stage.StageError):
            pass
        else:
            raise AssertionError("Stale whole-file stage was applied")
        assert path.read_bytes().endswith(b"# operator new note\n")

        # Operator changes sibling while planned update is active: rollback
        # must fail, preserving the operator's edit instead of clobbering it.
        other = "etc/yum.repos.d/rollback-conflict.repo"
        before = FILES["etc/yum.repos.d/mixture.repo"]
        path, cid, sid, _ = fixture(root, other, before)
        wrapper.apply_entry_sandbox(root, cid, sid, URL)
        current = path.read_bytes() + b"# operator post-install edit\n"
        path.write_bytes(current)
        try:
            wrapper.rollback_entry_sandbox(root, cid, sid, URL)
        except (approvals.ApprovalRefused, stage.StageError):
            pass
        else:
            raise AssertionError("Rollback clobbered external operator edit")
        assert path.read_bytes() == current

        # Kill after rename but before completion journal: the bounded
        # existing #132 recovery must restore the exact original file.
        other = "etc/apt/sources.list.d/interrupted.sources"
        before = FILES["etc/apt/sources.list.d/mixture.sources"]
        path, cid, sid, _ = fixture(root, other, before)
        interrupted_install(root, cid, sid)
        assert path.read_bytes() != before
        outcome = wrapper.recover_entry_sandbox(root, cid, sid, URL)
        assert outcome["state"] == "restored"
        assert path.read_bytes() == before

        # Metadata is deliberately fail-closed until #135/#137 and SELinux
        # are reconciled into the complete, reviewed production writer.
        other = "etc/apt/sources.list.d/attr-refusal.list"
        before = FILES["etc/apt/sources.list.d/mixture.list"]
        path, cid, sid, _ = fixture(root, other, before)
        os.setxattr(path, "user.synthetic", b"nonsecret")
        try:
            wrapper.apply_entry_sandbox(root, cid, sid, URL)
        except (approvals.ApprovalRefused, stage.StageError):
            pass
        else:
            raise AssertionError("Unsupported source xattrs were overwritten")
        assert path.read_bytes() == before

    print("PASS: mixed-file atomic apply/rollback, preserved siblings, drift and SIGKILL recovery")


if __name__ == "__main__":
    main()
