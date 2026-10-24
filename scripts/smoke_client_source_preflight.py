#!/usr/bin/env python3
"""Run read-only source metadata preflight on isolated native distro fixtures.

The script never inspects or edits live /etc/apt or /etc/yum.repos.d paths.
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))
import source_preflight as pre  # noqa: E402

REPOS = {
    "etc/apt/sources.list.d/example.sources":
        b"Types: deb\nURIs: https://deb.debian.org/debian\nSuites: trixie\n"
        b"Components: main\n",
    "etc/yum.repos.d/example.repo":
        b"[example]\nbaseurl=https://rpm.example.org/linux/\ngpgcheck=1\n",
}


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="repocache-preflight-native-") as temporary:
        base = Path(temporary)
        base.chmod(0o700)
        marker = base / pre.MARKER
        marker.write_bytes(pre.TEST_MAGIC)
        marker.chmod(0o600)
        for relative, data in REPOS.items():
            path = base / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            before = path.stat()
            result = pre.inspect_source(relative, root=base)
            assert result["sha256"] == hashlib.sha256(data).hexdigest()
            assert result["inode"] == before.st_ino
            assert result["write_eligible"] is False
            assert path.read_bytes() == data
            assert path.stat().st_ino == before.st_ino

        apt = base / "etc/apt/sources.list.d/example.sources"
        apt.chmod(0o666)
        try:
            pre.inspect_source("etc/apt/sources.list.d/example.sources", root=base)
        except pre.PreflightError:
            pass
        else:
            raise AssertionError("World-writable source incorrectly accepted")

        apt.chmod(0o644)
        apt.unlink()
        apt.symlink_to(base / "etc/yum.repos.d/example.repo")
        try:
            pre.inspect_source("etc/apt/sources.list.d/example.sources", root=base)
        except pre.PreflightError:
            pass
        else:
            raise AssertionError("Source symlink incorrectly accepted")

    if os.geteuid() == 0 and hasattr(os, "fork"):
        # Real UID transition: child cannot inspect the fixed native root.
        pid = os.fork()
        if pid == 0:
            try:
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)
                try:
                    pre.inspect_source("etc/apt/sources.list", root=Path("/"))
                except pre.PreflightError as exc:
                    os._exit(0 if "Root authorization" in str(exc) else 2)
                os._exit(3)
            except BaseException:
                os._exit(4)
        _, status = os.waitpid(pid, 0)
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, (
            "Unprivileged inspection was not denied")
        print("PASS: real non-root UID denied for native root inspection")

    print("PASS: native Python read-only source trust preflight (APT/DNF fixtures)")


if __name__ == "__main__":
    main()
