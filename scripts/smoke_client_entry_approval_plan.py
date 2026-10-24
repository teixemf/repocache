#!/usr/bin/env python3
"""Root-only explicit sandbox approval and read-only source edit planning.

Runs exclusively in disposable Debian 13 / AlmaLinux 10 Docker fixtures.
Does not edit installed APT/DNF source files, install privileged helpers,
or expose a public CLI approval capability.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

CLIENT = Path(__file__).resolve().parents[1] / "client"
sys.path.insert(0, str(CLIENT))
import source_preflight as pre  # noqa: E402
import source_entry_boundaries as bounds  # noqa: E402
import entry_candidate_sandbox as entry  # noqa: E402
import entry_approval_plan_sandbox as plan  # noqa: E402

CASES = {
    "etc/apt/sources.list.d/mixed.list": (
        b"# operator's file; preserve comments\n"
        b"deb https://one.invalid/deb trixie main\n"
        b"deb https://two.invalid/deb trixie main\n"
    ),
    "etc/apt/sources.list.d/mixed.sources": (
        b"Types: deb\nURIs: https://one.invalid/deb\n"
        b"Suites: trixie\nComponents: main\n\n"
        b"Types: deb\nURIs: https://two.invalid/deb\n"
        b"Suites: trixie\nComponents: main\n"
    ),
    "etc/yum.repos.d/mixed.repo": (
        b"[first]\nbaseurl=https://one.invalid/repo\n"
        b"gpgcheck=1\nenabled=1\n"
        b"[other]\nbaseurl=https://two.invalid/repo\n"
        b"gpgcheck=1\nenabled=1\n"
    ),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    if os.geteuid() != 0:
        raise RuntimeError("Dedicated native container approval smoke requires UID 0")
    with tempfile.TemporaryDirectory(prefix="rc-entry-approval-") as tmp:
        root = Path(tmp)
        root.chmod(0o700)
        marker = root / pre.MARKER
        marker.write_bytes(pre.TEST_MAGIC)
        marker.chmod(0o600)
        for rel, before in CASES.items():
            source = root / rel
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(before)
            first, sibling = bounds.boundaries(rel, before)
            ident = entry.register_entry_candidate_sandbox(
                root, rel, sha(before), first["sha256"])["id"]
            old_inode = source.stat().st_ino
            # Real UID/GID transition in a new process must deny approval.
            worker = r"""
import os, sys
os.setgroups([])
os.setgid(65534)
os.setuid(65534)
sys.path.insert(0, sys.argv[1])
import entry_approval_plan_sandbox as ap
try:
    ap.approve_entry_plan_sandbox(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
except ap.ApprovalRefused:
    raise SystemExit(0)
raise SystemExit(3)
"""
            denied = subprocess.run([
                sys.executable, "-c", worker, str(CLIENT), str(root),
                ident, sha(before), first["sha256"],
            ], check=False, capture_output=True, text=True, timeout=15)
            assert denied.returncode == 0, denied.stderr
            approved = plan.approve_entry_plan_sandbox(
                root, ident, sha(before), first["sha256"])
            assert approved["decision"] == "approve-entry-plan"
            assert not approved["production_write_eligible"]
            report = plan.preview_entry_change_sandbox(
                root, ident, "https://cache.invalid/repo/")
            assert report["state"] == "planned"
            assert report["other_entries_preserved"] == 1
            assert not report["signature_trust_verified"]
            built = plan._build_plan(root, ident, "https://cache.invalid/repo/")
            assert built["original"] == before
            assert built["proposed"] != before
            changed = bounds.boundaries(rel, built["proposed"])
            assert changed[1]["sha256"] == sibling["sha256"]
            assert source.read_bytes() == before
            assert source.stat().st_ino == old_inode
            assert "cache.invalid" not in json.dumps(report)
            # External source change after approval must forbid stale plan.
            source.write_bytes(before + b"# operator changed the shared file\n"
                               if rel.endswith((".list", ".repo"))
                               else before.replace(b"two.invalid", b"three.invalid"))
            try:
                plan.preview_entry_change_sandbox(
                    root, ident, "https://cache.invalid/repo/")
            except plan.ApprovalRefused:
                pass
            else:
                raise AssertionError("Stale approved plan was incorrectly accepted")
        print("PASS: root-only sandbox approval + exact-byte sibling preservation")


if __name__ == "__main__":
    main()
