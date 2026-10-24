#!/usr/bin/env python3
"""Real #131 staging integration of an approved one-entry shared-file plan.

This runs only in disposable, explicitly marked native distro /tmp roots,
with the exact unmerged #131 revision checked out by a separate CI step.
No source replacement, no privilege delegation, no production apply.
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
CLIENT = PROJECT / "client"
STAGING = PROJECT / "client"
if not (STAGING / "transaction_stage.py").is_file():
    raise RuntimeError("Integrated transaction staging dependency is unavailable")
sys.path.insert(0, str(STAGING))
sys.path.insert(0, str(CLIENT))

import source_preflight as pre  # noqa: E402
import source_entry_boundaries as bounds  # noqa: E402
import entry_candidate_sandbox as candidate  # noqa: E402
import entry_approval_plan_sandbox as approval  # noqa: E402
import entry_transaction_stage_sandbox as bridge  # noqa: E402
import transaction_stage as stage  # noqa: E402

CASES = {
    "etc/apt/sources.list.d/mixed.sources": (
        b"Types: deb\nURIs: https://one.invalid/deb\n"
        b"Suites: trixie\nComponents: main\n\n"
        b"Types: deb\nURIs: https://two.invalid/deb\n"
        b"Suites: trixie\nComponents: main\n"
    ),
    "etc/yum.repos.d/mixed.repo": (
        b"[first]\nbaseurl=https://one.invalid/repo\n"
        b"gpgcheck=1\nenabled=1\n"
        b"[operator]\nbaseurl=https://two.invalid/repo\n"
        b"gpgcheck=1\nenabled=1\n"
    ),
}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main():
    assert os.geteuid() == 0, "Native stage integration smoke requires container root"
    with tempfile.TemporaryDirectory(prefix="rc-approved-stage-") as temp:
        root = Path(temp)
        root.chmod(0o700)
        (root / "var/lib").mkdir(parents=True)
        marker = root / pre.MARKER
        marker.write_bytes(pre.TEST_MAGIC)
        marker.chmod(0o600)
        for relative, original in CASES.items():
            source = root / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(original)
            first, sibling = bounds.boundaries(relative, original)
            id = candidate.register_entry_candidate_sandbox(
                root, relative, sha(original), first["sha256"])["id"]
            approval.approve_entry_plan_sandbox(root, id,
                                                sha(original), first["sha256"])
            response = bridge.stage_entry_change_sandbox(
                root, id, "https://cache.invalid/packages/")
            assert response["state"] == "prepared"
            assert response["siblings_byte_preserved"] == 1
            assert response["production_write_eligible"] is False
            # Verify protected state through the authentic #131 inspector,
            # not a stub and not a copy of its implementation.
            state = stage.inspect(root, response["stage_id"])
            assert state["status"] == "prepared"
            assert source.read_bytes() == original
            assert sha(source.read_bytes()) == response["shared_source_sha256"]
            # Refuse a second conflicting protected stage.
            try:
                bridge.stage_entry_change_sandbox(
                    root, id, "https://cache.invalid/packages/")
            except stage.StageError:
                pass
            else:
                raise AssertionError("Duplicate source transaction was accepted")
        print("PASS: current protected staging preserves live sources and siblings")


if __name__ == "__main__":
    main()
