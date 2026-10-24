#!/usr/bin/env python3
"""Offline owner-signature preflight and optional non-activating v0.6 rehearsal.

The eight candidate artifacts MUST have been signed offline by the actual
release publisher. This command never generates signing keys or publishes
assets. A local digest, GitHub checksum or CI-generated test key is NOT trust.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from repocache import (candidate_sandbox, online_deps, online_generation,
                       release_inventory, signed_dependency_staging, signatures,
                       updater)

_MAX_BYTES = {
    "archive": release_inventory.MAX_ARCHIVE,
    "checksum": 200,
    "dependency_lock": release_inventory.MAX_LOCK,
    "sbom": release_inventory.MAX_SBOM,
    "application_wheel": release_inventory.application_wheel.MAX_APP_WHEEL,
    "inventory": release_inventory.MAX_INVENTORY,
    "manifest": signatures.MAX_MANIFEST,
    "signature": signatures.MAX_SIGNATURE,
}


class CandidateInputError(RuntimeError):
    """Invalid candidate input. No package download or candidate execution."""


def _filenames(version: str) -> dict[str, str]:
    base = release_inventory.names(version)
    archive = base["archive"]
    return {**base, "inventory": archive + ".assets.json",
            "manifest": archive + ".manifest.json",
            "signature": archive + ".manifest.json.sig"}


def read_exact_candidate(directory: Path, version: str) -> dict[str, bytes]:
    """Read eight exact regular files through one pinned, no-follow dirfd.

    A TOCTOU-resistant local read is not a substitute for a publisher signature.
    No candidate bytes are executed or interpreted before signature validation.
    """
    names = _filenames(version)
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise CandidateInputError("Untrusted candidate directory") from exc
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISDIR(meta.st_mode)
                or meta.st_uid not in (0, os.geteuid())
                or stat.S_IMODE(meta.st_mode) & 0o022):
            raise CandidateInputError("Unsafe candidate directory ownership or mode")
        try:
            actual = set(os.listdir(fd))
        except OSError as exc:
            raise CandidateInputError("Cannot enumerate candidate directory") from exc
        if actual != set(names.values()):
            raise CandidateInputError("Expected exactly eight signed candidate assets")
        result: dict[str, bytes] = {}
        for role, name in names.items():
            try:
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                                os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
            except OSError as exc:
                raise CandidateInputError("Unsafe candidate asset") from exc
            try:
                before = os.fstat(child)
                limit = _MAX_BYTES[role]
                if (not stat.S_ISREG(before.st_mode)
                        or before.st_nlink != 1
                        or before.st_uid not in (0, meta.st_uid)
                        or stat.S_IMODE(before.st_mode) & 0o022
                        or not 0 < before.st_size <= limit):
                    raise CandidateInputError("Untrusted candidate file or size")
                with os.fdopen(os.dup(child), "rb", closefd=True) as stream:
                    raw = stream.read(limit + 1)
                after = os.fstat(child)
                if (len(raw) != before.st_size
                        or before.st_size != after.st_size
                        or before.st_mtime_ns != after.st_mtime_ns
                        or before.st_ino != after.st_ino
                        or before.st_dev != after.st_dev):
                    raise CandidateInputError("Candidate changed during read")
                result[role] = raw
            finally:
                os.close(child)
        return result
    finally:
        os.close(fd)


def verify_candidate(directory: Path, version: str
                     ) -> tuple[dict[str, bytes], dict[str, Any]]:
    """Authenticate owner Ed25519 manifest, all bytes, both dependency graphs."""
    data = read_exact_candidate(directory, version)
    assets = {role: data[role] for role in release_inventory.ROLES}
    plans = {}
    for target in online_deps.TARGETS:
        wheels = signed_dependency_staging.verified_candidate_wheels(
            data["archive"], data["manifest"], data["signature"],
            version, data["inventory"], assets, target)
        plans[target] = len(wheels)
    return data, {
        "status": "owner-signature-and-locks-verified-only",
        "version": version,
        "targets": plans,
        "publisher_authenticated": True,
        "activation": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--rehearse", action="store_true",
                        help="Run the existing fail-closed non-activating updater rehearsal")
    parser.add_argument("--ca-file", type=Path,
                        help="Native system CA bundle; required with --rehearse")
    opts = parser.parse_args(argv)
    if opts.rehearse != (opts.ca_file is not None):
        parser.error("--rehearse requires --ca-file (and vice versa)")
    try:
        data, result = verify_candidate(opts.assets_dir, opts.version)
        if opts.rehearse:
            # Existing rehearsal checks the native OS/Python, service UID,
            # installed predecessor, exclusive update lock, patched bwrap,
            # verified network wheels, and no-activation invariant itself.
            assets = {role: data[role] for role in release_inventory.ROLES}
            executed = online_generation.rehearse_signed_install(
                data["archive"], data["manifest"], data["signature"],
                opts.version, data["inventory"], assets,
                online_generation._current_host_target(), cafile=opts.ca_file)
            if executed.get("activated") is not False:
                raise CandidateInputError("Unsafe rehearsal activation result")
            result["rehearsal"] = executed
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (CandidateInputError, release_inventory.InventoryError,
            signed_dependency_staging.PreparationError, signatures.SignatureError,
            online_generation.PreparationInstallError, online_deps.DependencyError,
            candidate_sandbox.SandboxError, updater.UpdateError,
            OSError, ValueError) as exc:
        # Avoid printing asset content, URLs, credentials or paths from errors.
        print("Candidate refused: " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
