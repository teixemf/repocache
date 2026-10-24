#!/usr/bin/env python3
"""Native OS Python smoke: non-authoritative APT/DNF per-entry candidate IDs.

Only disposable /tmp fixtures are modified. Shared source-file bytes are
never rewritten by the candidate registry.
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
import source_entry_boundaries as bounds  # noqa: E402
import entry_candidate_sandbox as entries  # noqa: E402

SOURCES = {
    "etc/apt/sources.list.d/mixed.list": (
        b"# operator maintained\n"
        b"deb https://deb.debian.org/debian trixie main\n"
        b"deb https://security.debian.org/debian-security trixie-security main\n"
    ),
    "etc/apt/sources.list.d/mixed.sources": (
        b"Types: deb\nURIs: https://deb.debian.org/debian\nSuites: trixie\n"
        b"Components: main\n\n"
        b"Types: deb\nURIs: https://security.debian.org/debian-security\n"
        b"Suites: trixie-security\nComponents: main\n"
    ),
    "etc/yum.repos.d/mixed.repo": (
        b"[baseos]\nbaseurl=https://repo.almalinux.org/almalinux/10/BaseOS/x86_64/os/\n"
        b"gpgcheck=1\nenabled=1\n"
        b"[unmanaged]\nbaseurl=https://upstream.example.invalid/extras\n"
        b"gpgcheck=1\nenabled=0\n"
    ),
}


def main():
    with tempfile.TemporaryDirectory(prefix="repocache-entry-owner-") as tmp:
        root = Path(tmp)
        root.chmod(0o700)
        marker = root / pre.MARKER
        marker.write_bytes(pre.TEST_MAGIC)
        marker.chmod(0o600)
        for rel, body in SOURCES.items():
            source = root / rel
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(body)
            chunks = bounds.boundaries(rel, body)
            assert len(chunks) == 2
            assert chunks[0]["structure_subset_pass"]
            inode = source.stat().st_ino
            item = entries.register_entry_candidate_sandbox(
                root, rel, hashlib.sha256(body).hexdigest(), chunks[0]["sha256"])
            assert not item["ownership_granted"] and not item["write_eligible"]
            assert entries.inspect_entry_candidate_sandbox(root, item["id"])["state"] == "intact"
            assert source.read_bytes() == body
            assert source.stat().st_ino == inode
            # Ansible/operator changes a sibling in the same file:
            # selected entry still matches, but any whole-file commit is unsafe.
            if rel.endswith(".repo"):
                changed = body.replace(b"enabled=0", b"enabled=1")
            elif rel.endswith(".sources"):
                changed = body.replace(b"trixie-security", b"bookworm-security")
            else:
                changed = body + b"# operator note added\n"
            source.write_bytes(changed)
            verdict = entries.inspect_entry_candidate_sandbox(root, item["id"])
            assert verdict["state"] == "file-drift" and verdict["entry_intact"]
            assert not verdict["file_intact"] and not verdict["write_eligible"]
            assert source.read_bytes() == changed
        print("PASS: native isolated per-entry candidates and sibling drift refusal")


if __name__ == "__main__":
    main()
