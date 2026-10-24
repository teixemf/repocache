#!/usr/bin/env python3
"""Native distro-container smoke for the sandbox-only transaction experiment.

No writes to installed /etc and no APT/DNF source configuration. This script
only uses disposable roots beneath /tmp and the OS-provided Python 3.
"""
from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))
import transaction_stage as stage  # noqa: E402
import transaction_atomic_lab as lab  # noqa: E402


def fixture(root: Path, relative: str, original: bytes):
    root.chmod(0o700)
    path = root / relative
    path.parent.mkdir(parents=True)
    (root / "var/lib").mkdir(parents=True)
    marker = root / lab.MARKER
    marker.write_bytes(lab.MAGIC)
    marker.chmod(0o600)
    path.write_bytes(original)
    return path


def case(relative: str, before: bytes, after: bytes):
    with tempfile.TemporaryDirectory(prefix="rc-atomic-distro-") as temp:
        root = Path(temp)
        source = fixture(root, relative, before)
        ident = stage.stage(root, relative, hashlib.sha256(before).hexdigest(), after)["id"]
        assert source.read_bytes() == before
        assert lab.apply_sandbox(root, ident)["status"] == "installed"
        assert source.read_bytes() == after
        assert lab.recover_sandbox(root, ident)["status"] == "installed"
        assert lab.rollback_sandbox(root, ident)["status"] == "restored"
        assert source.read_bytes() == before

        marker = root / lab.MARKER
        marker.unlink()
        try:
            lab.apply_sandbox(root, ident)
        except stage.StageError:
            pass
        else:
            raise AssertionError("Missing sandbox marker was not refused")


def sigkill_case():
    relative = "etc/apt/sources.list.d/ci.list"
    before = b"deb https://deb.debian.org/debian trixie main\n"
    after = b"deb mirror+file:/etc/apt/mirrors/ci.txt trixie main\n"
    with tempfile.TemporaryDirectory(prefix="rc-atomic-sigkill-") as temp:
        root = Path(temp)
        source = fixture(root, relative, before)
        ident = stage.stage(root, relative, hashlib.sha256(before).hexdigest(), after)["id"]
        worker = r"""
import os, signal, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import transaction_atomic_lab as lab
orig = lab._replace
def interrupt(*args):
    orig(*args)
    os.kill(os.getpid(), signal.SIGKILL)
lab._replace = interrupt
lab.apply_sandbox(Path(sys.argv[2]), sys.argv[3])
"""
        result = subprocess.run(
            [sys.executable, "-c", worker, str(ROOT / "client"), str(root), ident],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=20,
        )
        assert result.returncode == -signal.SIGKILL, result.stderr.decode(errors="replace")
        assert source.read_bytes() == after
        assert lab.recover_sandbox(root, ident)["status"] == "restored"
        assert source.read_bytes() == before


if __name__ == "__main__":
    case("etc/apt/sources.list.d/ci.sources",
         b"Types: deb\nURIs: https://deb.debian.org/debian\nSuites: trixie\nComponents: main\n",
         b"Types: deb\nURIs: mirror+file:/etc/apt/mirrors/ci.txt\nSuites: trixie\nComponents: main\n")
    case("etc/yum.repos.d/ci.repo",
         b"[ci]\nbaseurl=https://upstream.invalid/repo\ngpgcheck=1\n",
         b"[ci]\nbaseurl=https://cache.invalid/repo\ngpgcheck=1\n")
    sigkill_case()
    print("PASS: atomic sandbox APT/DNF fixtures + SIGKILL recovery")
