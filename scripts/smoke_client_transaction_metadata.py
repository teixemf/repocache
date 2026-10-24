#!/usr/bin/env python3
"""Linux distro container smoke: protected ACL/xattr snapshot + atomic rollback.

Synthetic, disposable /tmp sources only. No privileged REPOCACHE operation.
"""
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "client"))
import transaction_stage as stage  # noqa: E402
import transaction_atomic_lab as atomic  # noqa: E402
import transaction_metadata_sandbox as bridge  # noqa: E402

BEFORE = b"Types: deb\nURIs: https://deb.debian.org/debian\nSuites: trixie\nComponents: main\n"
AFTER = b"Types: deb\nURIs: mirror+file:/etc/apt/mirrors/ci.txt\nSuites: trixie\nComponents: main\n"
SOURCE = "etc/apt/sources.list.d/ci.sources"


def main():
    with tempfile.TemporaryDirectory(prefix="repocache-metadata-txn-") as root_string:
        root = Path(root_string)
        root.chmod(0o700)
        source = root / SOURCE
        source.parent.mkdir(parents=True)
        (root / "var/lib").mkdir(parents=True)
        marker = root / atomic.MARKER
        marker.write_bytes(atomic.MAGIC)
        marker.chmod(0o600)
        source.write_bytes(BEFORE)
        os.setxattr(source, "user.repocache", b"\x00native\xff")
        subprocess.run(["setfacl", "-m", "u:65534:r", str(source)],
                       check=True, capture_output=True, timeout=10)
        attrs = {key: os.getxattr(source, key) for key in os.listxattr(source)}
        assert "system.posix_acl_access" in attrs
        original_mode = source.stat().st_mode & 0o777
        ident = stage.stage(root, SOURCE, hashlib.sha256(BEFORE).hexdigest(), AFTER)["id"]
        bridge.snapshot_sandbox(root, ident)
        assert atomic.apply_sandbox(root, ident)["status"] == "installed"
        assert source.read_bytes() == AFTER
        assert {key: os.getxattr(source, key) for key in os.listxattr(source)} == attrs
        assert (source.stat().st_mode & 0o777) == original_mode
        assert atomic.rollback_sandbox(root, ident)["status"] == "restored"
        assert source.read_bytes() == BEFORE
        assert {key: os.getxattr(source, key) for key in os.listxattr(source)} == attrs
        print("PASS: native OS Python ACL/xattr transactional sandbox roundtrip")


if __name__ == "__main__":
    main()
