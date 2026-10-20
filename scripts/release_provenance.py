#!/usr/bin/env python3
"""Sign and verify REPOCACHE release-build provenance.

The detached Ed25519 signature covers the complete artifact inventory,
reviewed dependency lock digests, workflow hash, tag and workflow run identity.
A signed CI statement proves possession of the configured publisher key; it
does NOT independently establish branch review or private-key custody.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

REPO = "teixemf/repocache"
TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA = re.compile(r"^[a-f0-9]{64}$")
COMMIT = re.compile(r"^[a-f0-9]{40}$")
KEY_ID = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
ASSET_SUFFIXES = (
    "",
    ".sha256",
    ".manifest.json",
    ".manifest.json.sig",
    ".wheelhouse.tar.gz",
    ".wheelhouse.tar.gz.sha256",
)


class ProvenanceError(ValueError):
    """Untrusted or inconsistent release-build provenance."""


def digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ProvenanceError("Missing or symlinked release input: " + path.name)
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(131072), b""):
            h.update(block)
    return h.hexdigest()


def strict_dict(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ProvenanceError("Duplicate field in provenance")
        result[key] = value
    return result


def canonical(document: dict) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def expected_assets(bundle: Path) -> dict[str, str]:
    if not TAG.fullmatch(bundle.name.removeprefix("repocache-").removesuffix(".tar.gz")):
        raise ProvenanceError("Invalid release bundle name")
    return {bundle.name + suffix: digest(bundle.with_name(bundle.name + suffix))
            for suffix in ASSET_SUFFIXES}


def make_document(bundle: Path, key_id: str, commit: str, tag: str,
                  workflow_ref: str, run_id: str, run_attempt: str,
                  root: Path) -> dict:
    if (not TAG.fullmatch(tag) or bundle.name != "repocache-" + tag + ".tar.gz"
            or not KEY_ID.fullmatch(key_id) or not COMMIT.fullmatch(commit)
            or not run_id.isdecimal() or int(run_id) < 1
            or not run_attempt.isdecimal() or int(run_attempt) < 1
            or workflow_ref != REPO + "/.github/workflows/release.yml@refs/tags/" + tag):
        raise ProvenanceError("Invalid, unreviewed or mismatched release provenance identity")
    locks = {
        name: digest(root / name) for name in
        ("deps/runtime-wheels.lock", "deps/build-wheels.lock")
    }
    return {
        "schema": 1, "repository": REPO, "tag": tag, "commit": commit,
        "publisher_key_id": key_id,
        "build": {
            "workflow_ref": workflow_ref,
            "workflow_sha256": digest(root / ".github/workflows/release.yml"),
            "run_id": int(run_id), "run_attempt": int(run_attempt),
        },
        "dependency_locks": locks,
        "artifacts": expected_assets(bundle),
    }


def sign(document: dict, private_key: Path, bundle: Path,
         *, passphrase: bytes | None = None) -> tuple[Path, Path]:
    if (private_key.is_symlink() or not private_key.is_file()
            or private_key.stat().st_mode & 0o077):
        raise ProvenanceError("Signing key must be a non-symlinked private file, mode 0600")
    payload = canonical(document)
    out = bundle.with_name(bundle.name + ".provenance.json")
    sig = out.with_name(out.name + ".sig")
    with tempfile.TemporaryDirectory(prefix="repocache-provenance-") as tmp:
        root = Path(tmp)
        message, detached = root / "message", root / "signature"
        message.write_bytes(payload)
        result = subprocess.run(
            ["/usr/bin/openssl", "pkeyutl", "-sign", "-inkey",
             str(private_key),
             *(["-passin", "fd:0"] if passphrase is not None else []),
             "-rawin", "-in", str(message), "-out", str(detached)],
            input=(passphrase + b"\n") if passphrase is not None else None,
            capture_output=True, timeout=20,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"})
        if result.returncode or not detached.is_file() or detached.stat().st_size != 64:
            raise ProvenanceError("Could not sign release provenance")
        signature = detached.read_bytes()
    # Only write provenance after complete artifact/lock checks and signature.
    out.write_bytes(payload)
    sig.write_bytes(signature)
    out.chmod(0o644)
    sig.chmod(0o644)
    return out, sig


def verify(bundle: Path, provenance: Path, signature: Path, public_key: Path,
           root: Path, *, commit: str, tag: str, workflow_ref: str,
           run_id: str, run_attempt: str) -> dict:
    if provenance.is_symlink() or signature.is_symlink():
        raise ProvenanceError("Symlinked provenance inputs refused")
    raw = provenance.read_bytes()
    signature_bytes = signature.read_bytes()
    if not raw or len(raw) > 16384 or len(signature_bytes) != 64:
        raise ProvenanceError("Missing, oversized or invalid signed provenance")
    try:
        statement = json.loads(raw, object_pairs_hook=strict_dict)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ProvenanceError("Malformed release provenance") from exc
    if (not isinstance(statement, dict) or set(statement) != {
            "schema", "repository", "tag", "commit", "publisher_key_id",
            "build", "dependency_locks", "artifacts"}
            or statement.get("schema") != 1
            or canonical(statement) != raw):
        raise ProvenanceError("Noncanonical or unrecognized release provenance")
    expected = make_document(bundle, statement["publisher_key_id"], commit,
                             tag, workflow_ref, run_id, run_attempt, root)
    if statement != expected:
        raise ProvenanceError("Release provenance does not match actual inputs or run identity")
    if public_key.is_symlink() or not public_key.is_file():
        raise ProvenanceError("Publisher verification key is unavailable")
    with tempfile.TemporaryDirectory(prefix="repocache-provenance-verify-") as tmp:
        signed = Path(tmp) / "statement"
        detached = Path(tmp) / "signature"
        signed.write_bytes(raw)
        detached.write_bytes(signature_bytes)
        result = subprocess.run(
            ["/usr/bin/openssl", "pkeyutl", "-verify", "-pubin", "-inkey",
             str(public_key), "-rawin", "-in", str(signed), "-sigfile", str(detached)],
            capture_output=True, text=True, timeout=20,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"})
        if result.returncode:
            raise ProvenanceError("Publisher provenance signature is invalid")
    return statement


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("sign", "verify"))
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--key-id", default="")
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    args = parser.parse_args()
    if args.mode == "sign":
        if args.private_key is None:
            raise ProvenanceError("Publisher private key is mandatory for signing")
        document = make_document(args.bundle, args.key_id, args.commit,
                                 args.tag, args.workflow_ref, args.run_id,
                                 args.run_attempt, args.root)
        for path in sign(document, args.private_key, args.bundle):
            print(path)
    else:
        if args.public_key is None:
            raise ProvenanceError("Independent publisher public key required")
        base = args.bundle.with_name(args.bundle.name + ".provenance.json")
        doc = verify(args.bundle, base, base.with_name(base.name + ".sig"),
                     args.public_key, args.root, commit=args.commit, tag=args.tag,
                     workflow_ref=args.workflow_ref, run_id=args.run_id,
                     run_attempt=args.run_attempt)
        print("PASS: signed release provenance verified for " + doc["tag"])


if __name__ == "__main__":
    main()
