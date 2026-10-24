#!/usr/bin/env python3
"""Native distro smoke: private candidate IDs and source drift, no real /etc.

The only modified paths are marked, disposable /tmp fixtures. Registry
candidates never grant authorization to edit host package sources.
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path

CLIENT = Path(__file__).resolve().parents[1] / "client"
sys.path.insert(0, str(CLIENT))
import source_preflight as pre  # noqa: E402
import managed_registry_sandbox as reg  # noqa: E402

CASES = (
    ("etc/apt/sources.list.d/fixture.list",
     b"deb https://deb.debian.org/debian trixie main\n"),
    ("etc/apt/sources.list.d/fixture.sources",
     b"Types: deb\nURIs: https://deb.debian.org/debian\nSuites: trixie\nComponents: main\n"),
    ("etc/yum.repos.d/fixture.repo",
     b"[fixture]\nbaseurl=https://repo.almalinux.org/almalinux/10/BaseOS/x86_64/os/\n"
     b"enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n"),
)


def main():
    with tempfile.TemporaryDirectory(prefix="repocache-managed-id-") as name:
        root = Path(name)
        root.chmod(0o700)
        marker = root / pre.MARKER
        marker.write_bytes(pre.TEST_MAGIC)
        marker.chmod(0o600)
        ids = []
        for rel, contents in CASES:
            source = root / rel
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(contents)
            old = source.stat()
            ident = reg.register_candidate_sandbox(
                root, rel, hashlib.sha256(contents).hexdigest())["id"]
            ids.append(ident)
            inspected = reg.inspect_candidate_sandbox(root, ident)
            assert inspected["state"] == "intact"
            assert inspected["ownership_granted"] is False
            assert inspected["write_eligible"] is False
            assert source.stat().st_ino == old.st_ino
            assert source.read_bytes() == contents
        assert len(set(ids)) == len(CASES)

        source = root / CASES[0][0]
        replacement = source.with_suffix(".tmp")
        replacement.write_bytes(CASES[0][1])
        os.replace(replacement, source)
        assert reg.inspect_candidate_sandbox(root, ids[0])["state"] == "drift"
        assert reg.inspect_candidate_sandbox(root, ids[1])["state"] == "intact"
        assert reg.inspect_candidate_sandbox(root, ids[2])["state"] == "intact"
        print("PASS: protected candidate IDs, source drift and no package-source writes")


if __name__ == "__main__":
    main()
