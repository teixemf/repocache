#!/usr/bin/env python3
"""Native Debian 13 / AlmaLinux 10 sandbox-only file metadata regression.

Uses OS Python and setfacl, never writes real APT/DNF configuration paths.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))
import source_preflight as pre  # noqa: E402
import source_metadata_lab as lab  # noqa: E402


def main():
    with tempfile.TemporaryDirectory(prefix="repocache-acl-xattr-") as private:
        sandbox = Path(private)
        sandbox.chmod(0o700)
        marker = sandbox / pre.MARKER
        marker.write_bytes(pre.TEST_MAGIC)
        marker.chmod(0o600)
        for relative in ("etc/apt/sources.list.d/ci.sources",
                         "etc/yum.repos.d/ci.repo"):
            source = sandbox / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            original = b"synthetic APT or DNF metadata fixture\n"
            source.write_bytes(original)
            os.setxattr(source, "user.repocache-probe", b"non-secret-value")
            subprocess.run(["setfacl", "-m", "u:65534:r", str(source)],
                           check=True, capture_output=True, timeout=20)
            attrs = {name: os.getxattr(source, name) for name in os.listxattr(source)}
            assert "system.posix_acl_access" in attrs
            before = source.stat()
            result = lab.clone_sandbox_source(sandbox, relative)
            copy = source.parent / result["clone_name"]
            assert copy.read_bytes() == original
            assert result["contains_posix_access_acl"]
            assert not result["production_apply_eligible"]
            assert {name: os.getxattr(copy, name) for name in os.listxattr(copy)} == attrs
            assert source.read_bytes() == original
            assert source.stat().st_ino == before.st_ino
            copy.unlink()
        print("PASS: OS-native POSIX ACL + user-xattr sandbox round trip")


if __name__ == "__main__":
    main()
