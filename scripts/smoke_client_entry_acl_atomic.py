#!/usr/bin/env python3
"""Native mixed-entry ACL/xattr sandbox roundtrip (Debian 13 and AlmaLinux 10).

No installed APT/DNF paths. The root of every mutation is an ephemeral
marked private /tmp tree. This is NOT a SELinux enforcing environment.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

CLIENT = Path(__file__).resolve().parents[1] / "client"
sys.path.insert(0, str(CLIENT))

import source_preflight as pre  # noqa: E402
import source_entry_boundaries as spans  # noqa: E402
import entry_candidate_sandbox as registry  # noqa: E402
import entry_approval_plan_sandbox as approval  # noqa: E402
import entry_transaction_stage_sandbox as staging  # noqa: E402
import entry_atomic_sandbox as writer  # noqa: E402
import transaction_atomic_lab as atomic  # noqa: E402

URL = "https://cache.invalid/repo"
SOURCES = {
    "etc/apt/sources.list.d/mixed.list": (
        b"# operator's repository file\n"
        b"deb https://one.invalid/repo trixie main\n"
        b"# untouched sibling\n"
        b"deb https://two.invalid/repo trixie main\n"
    ),
    "etc/apt/sources.list.d/mixed.sources": (
        b"Types: deb\nURIs: https://one.invalid/repo\nSuites: trixie\n"
        b"Components: main\n\n"
        b"Types: deb\nURIs: https://two.invalid/repo\n"
        b"Suites: trixie\nComponents: main\n"
    ),
    "etc/yum.repos.d/mixed.repo": (
        b"[first]\nbaseurl=https://one.invalid/repo\n"
        b"enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n\n"
        b"[other]\nbaseurl=https://two.invalid/repo\n"
        b"enabled=1\ngpgcheck=1\n"
    ),
}


def digest(x: bytes) -> str:
    return hashlib.sha256(x).hexdigest()


def attributes(path: Path) -> dict[str, bytes]:
    return {name: os.getxattr(path, name) for name in os.listxattr(path)}


def approve_and_stage(root: Path, relative: str, body: bytes):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    os.setxattr(path, "user.rc_test", b"\0ACL-secret-byte\xff")
    subprocess.run(["setfacl", "-m", "u:65534:r", str(path)],
                   check=True, capture_output=True, timeout=10)
    baseline = attributes(path)
    assert "system.posix_acl_access" in baseline
    mode = path.stat().st_mode & 0o777
    first = spans.boundaries(relative, body)[0]
    identity = registry.register_entry_candidate_sandbox(
        root, relative, digest(body), first["sha256"])["id"]
    approved = approval.approve_entry_plan_sandbox(
        root, identity, digest(body), first["sha256"])
    assert approved["scope"] == "sandbox-only"
    prepared = staging.stage_entry_change_sandbox(root, identity, URL)
    assert prepared["state"] == "prepared"
    assert not prepared["production_write_eligible"]
    protected = root / "var/lib/repocache-client/staging" / prepared["stage_id"] / (
        "original-attributes.json")
    assert protected.is_file() and protected.stat().st_mode & 0o777 == 0o600
    return path, identity, prepared["stage_id"], baseline, mode


def main():
    assert os.geteuid() == 0, "The native lab smoke requires root inside disposable container"
    with tempfile.TemporaryDirectory(prefix="rc-acl-mixed-source-") as private:
        root = Path(private)
        root.chmod(0o700)
        (root / "var/lib").mkdir(parents=True)
        marker = root / pre.MARKER
        marker.write_bytes(pre.TEST_MAGIC)
        marker.chmod(0o600)
        atomic_marker = root / atomic.MARKER
        atomic_marker.write_bytes(atomic.MAGIC)
        atomic_marker.chmod(0o600)
        for rel, body in SOURCES.items():
            path, candidate, sid, before_attrs, mode = approve_and_stage(root, rel, body)
            before_entries = spans.boundaries(rel, body)
            original_inode = path.stat().st_ino
            assert writer.apply_entry_sandbox(root, candidate, sid, URL)["state"] == "installed"
            after = path.read_bytes()
            assert after != body and path.stat().st_ino != original_inode
            assert spans.boundaries(rel, after)[1]["sha256"] == before_entries[1]["sha256"]
            assert attributes(path) == before_attrs, "Metadata changed on atomic install"
            assert (path.stat().st_mode & 0o777) == mode
            assert writer.rollback_entry_sandbox(root, candidate, sid, URL)["state"] == "restored"
            assert path.read_bytes() == body
            assert attributes(path) == before_attrs, "Metadata changed on rollback"
            assert (path.stat().st_mode & 0o777) == mode

        # External xattr change after stage MUST block application.
        rel = "etc/apt/sources.list.d/metadata-drift.list"
        body = SOURCES["etc/apt/sources.list.d/mixed.list"]
        path, candidate, sid, _, _ = approve_and_stage(root, rel, body)
        os.setxattr(path, "user.rc_external", b"operator-update")
        try:
            writer.apply_entry_sandbox(root, candidate, sid, URL)
        except Exception:
            pass
        else:
            raise AssertionError("External metadata drift allowed source replacement")
        assert path.read_bytes() == body

        # External attribute change after applying MUST block rollback.
        rel = "etc/yum.repos.d/rollback-drift.repo"
        body = SOURCES["etc/yum.repos.d/mixed.repo"]
        path, candidate, sid, _, _ = approve_and_stage(root, rel, body)
        writer.apply_entry_sandbox(root, candidate, sid, URL)
        after = path.read_bytes()
        os.setxattr(path, "user.rc_external", b"operator-update")
        try:
            writer.rollback_entry_sandbox(root, candidate, sid, URL)
        except Exception:
            pass
        else:
            raise AssertionError("Rollback clobbered an external metadata change")
        assert path.read_bytes() == after

    print("PASS: native mixed-entry exact siblings + ACL/xattr atomic install/rollback")


if __name__ == "__main__":
    main()
