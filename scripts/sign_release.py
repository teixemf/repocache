#!/usr/bin/env python3
"""Offline Ed25519 signing of reproducible RELEASE artifacts.

Requires a protected external signing key. Never generate or publish a private
key as part of the release build. Signing is a separate gated publisher step.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
import sys

# Only locally reviewed checkout code participates in offline signing.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from repocache import release_inventory

def sign(bundle: Path, key: Path, key_id: str, commit: str,
         issued_at: int, expires_at: int, wheelhouse_sha256: str | None = None,
         *, passphrase: bytes | None = None,
         online_lock: Path | None = None, online_sbom: Path | None = None):
    if not re.fullmatch(r"repocache-v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\.tar\.gz", bundle.name):
        raise ValueError("Invalid release archive name")
    version = bundle.name.removeprefix("repocache-v").removesuffix(".tar.gz")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,47}", key_id):
        raise ValueError("Invalid signer key id")
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("Invalid release commit")
    if expires_at <= issued_at or issued_at <= 0:
        raise ValueError("Invalid release validity interval")
    # Reject conflicting signed dependency profiles before reading any
    # legacy wheelhouse bytes or computing release authority.
    if ((online_lock is not None or online_sbom is not None)
            and wheelhouse_sha256 is not None):
        raise ValueError("Online signing requires no wheelhouse")
    if wheelhouse_sha256 is not None:
        if not re.fullmatch(r"[a-f0-9]{64}", wheelhouse_sha256):
            raise ValueError("Invalid wheelhouse digest")
        wheelpath = bundle.with_name(bundle.name + ".wheelhouse.tar.gz")
        if (not wheelpath.is_file() or wheelpath.is_symlink()
                or hashlib.sha256(wheelpath.read_bytes()).hexdigest() != wheelhouse_sha256):
            raise ValueError("Signed wheelhouse artifact is absent or mismatched")
    online = online_lock is not None or online_sbom is not None
    if online:
        if online_lock is None or online_sbom is None or wheelhouse_sha256 is not None:
            raise ValueError("Online signing requires lock, SBOM and no wheelhouse")
        expected = release_inventory.names(version)
        if online_lock.name != expected["dependency_lock"] or online_sbom.name != expected["sbom"]:
            raise ValueError("Online candidate filename mismatch")
        for candidate in (bundle, online_lock, online_sbom):
            if candidate.is_symlink() or not candidate.is_file():
                raise ValueError("Online candidate inputs must be regular files")
        checksum = bundle.with_name(expected["checksum"])
        if checksum.is_symlink() or not checksum.is_file():
            raise ValueError("Candidate checksum is missing or unsafe")
        assets = {"archive": bundle.read_bytes(), "checksum": checksum.read_bytes(),
                  "dependency_lock": online_lock.read_bytes(), "sbom": online_sbom.read_bytes()}
        try:
            inventory_bytes = release_inventory.build_inventory(version, assets)
        except release_inventory.InventoryError as exc:
            raise ValueError("Invalid candidate source-only inventory") from exc
        inventory_path = bundle.with_name(bundle.name + ".assets.json")
        if inventory_path.exists() or inventory_path.is_symlink():
            raise ValueError("Refusing to replace existing inventory")
    if key.is_symlink() or not key.is_file() or key.stat().st_mode & 0o077:
        raise ValueError("Signing key must be a protected non-symlinked file (mode 0600)")
    with tarfile.open(bundle, "r:gz") as archive:
        try:
            policy_member = archive.getmember(f"repocache-v{version}/release-policy.json")
        except KeyError as exc:
            raise ValueError("Release archive lacks compatibility policy") from exc
        if not policy_member.isfile() or policy_member.size > 16384:
            raise ValueError("Invalid release policy entry")
        content = archive.extractfile(policy_member)
        if content is None:
            raise ValueError("Cannot read release policy")
        policy_digest = hashlib.sha256(content.read(policy_member.size + 1)).hexdigest()
    document = {
        "schema": 1, "key_id": key_id, "repository": "teixemf/repocache",
        "channel": "stable", "version": version, "commit": commit,
        "archive": bundle.name,
        "archive_sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
        "policy_sha256": policy_digest,
        "wheelhouse_sha256": wheelhouse_sha256,
        "issued_at": issued_at, "expires_at": expires_at,
    }
    if online:
        document.update({
            "schema": 2, "dependency_profile": "online-hash-locked-wheels",
            "dependency_lock_sha256": release_inventory.digest(assets["dependency_lock"]),
            "asset_inventory_sha256": release_inventory.digest(inventory_bytes),
        })
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    manifest = bundle.with_name(bundle.name + ".manifest.json")
    signature = bundle.with_name(bundle.name + ".manifest.json.sig")
    with tempfile.TemporaryDirectory(prefix="repocache-sign-") as temp:
        raw = Path(temp) / "manifest"
        output = Path(temp) / "signature"
        raw.write_bytes(payload)
        result = subprocess.run(
            ["/usr/bin/openssl", "pkeyutl", "-sign", "-inkey",
             str(key), *(["-passin", "fd:0"] if passphrase is not None else []),
             "-rawin", "-in", str(raw), "-out", str(output)],
            input=(passphrase + b"\n") if passphrase is not None else None,
            capture_output=True, timeout=15, check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"})
        if result.returncode != 0 or not output.is_file() or output.stat().st_size != 64:
            raise RuntimeError("Ed25519 signing failed")
        signed = output.read_bytes()
    if online:
        # Write only after successful signature creation; never publish here.
        inventory_path.write_bytes(inventory_bytes)
        inventory_path.chmod(0o644)
    manifest.write_bytes(payload)
    signature.write_bytes(signed)
    manifest.chmod(0o644)
    signature.chmod(0o644)
    return manifest, signature


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--bundle", type=Path, required=True)
    p.add_argument("--private-key", type=Path, required=True)
    p.add_argument("--key-id", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--issued-at", type=int, default=int(time.time()))
    p.add_argument("--expires-at", type=int, required=True)
    p.add_argument("--wheelhouse-sha256", default=None)
    p.add_argument("--online-lock", type=Path)
    p.add_argument("--online-sbom", type=Path)
    args = p.parse_args()
    for path in sign(args.bundle, args.private_key, args.key_id, args.commit,
                     args.issued_at, args.expires_at, args.wheelhouse_sha256,
                     online_lock=args.online_lock, online_sbom=args.online_sbom):
        print(path)
