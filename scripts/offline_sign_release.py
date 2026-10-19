#!/usr/bin/env python3
"""Review-gated, offline owner signing of an authenticated release candidate.

Never creates a tag or release. The operator holds the encrypted signing key
outside GitHub, and all input verification precedes unlocking that key.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from release_provenance import make_document, sign as sign_provenance, verify as verify_provenance
from sign_release import sign as sign_manifest
from verify_release_candidate import verify as verify_candidate

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "keys/repocache-2026-10.pem"
PUBLIC_DER_SHA256 = "7bbf4b840f762a610da648869564a5b77669f24191d0c5c7af04c14c043dc0fb"
KEY_ID = "repocache-2026-10"
REPOSITORY = "teixemf/repocache"


class OfflineSigningError(ValueError):
    pass


def _read_only_command(argv: list[str], secret: bytes | None = None) -> bytes:
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C"}
    if argv[0] == "gh":
        env["HOME"] = str(Path.home())
        for key in ("GH_TOKEN", "GH_HOST", "XDG_CONFIG_HOME"):
            if key in os.environ:
                env[key] = os.environ[key]
    try:
        result = subprocess.run(argv, input=(secret + b"\n") if secret is not None else None,
                                capture_output=True, timeout=30, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OfflineSigningError("Signing prerequisite unavailable") from exc
    if result.returncode:
        raise OfflineSigningError("Signing prerequisite failed")
    return result.stdout


def validate_public_key(private_key: Path, password: bytes) -> str:
    """Check that a protected owner key matches the independently pinned anchor."""
    if (private_key.is_symlink() or not private_key.is_file()
            or private_key.stat().st_mode & 0o077):
        raise OfflineSigningError("Owner signing key must be a private 0600 regular file")
    if PUBLIC.is_symlink() or not PUBLIC.is_file():
        raise OfflineSigningError("Trusted public anchor is unavailable")
    expected = _read_only_command(["/usr/bin/openssl", "pkey", "-pubin",
                                   "-in", str(PUBLIC), "-outform", "DER"])
    digest = hashlib.sha256(expected).hexdigest()
    if digest != PUBLIC_DER_SHA256:
        raise OfflineSigningError("Publisher trust anchor differs from reviewed fingerprint")
    actual = _read_only_command(["/usr/bin/openssl", "pkey", "-in",
                                 str(private_key), "-passin", "fd:0",
                                 "-pubout", "-outform", "DER"], password)
    if actual != expected:
        raise OfflineSigningError("Owner private key does not match the trusted publisher")
    return digest


def validate_candidate_identity(bundle: Path, commit: str, run_id: str,
                                attempt: str) -> tuple[str, str]:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise OfflineSigningError("Reviewed commit must be an exact full Git SHA")
    if not run_id.isdecimal() or int(run_id) < 1 or not attempt.isdecimal() or int(attempt) < 1:
        raise OfflineSigningError("Invalid workflow execution identifier")
    checkout = _read_only_command(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).decode().strip()
    if checkout != commit:
        raise OfflineSigningError("Checked-out source does not match reviewed commit")
    if _read_only_command(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=no"]):
        raise OfflineSigningError("Unreviewed source modifications detected")
    matched = re.fullmatch(r"repocache-(v[0-9]+\.[0-9]+\.[0-9]+)\.tar\.gz", bundle.name)
    if not matched:
        raise OfflineSigningError("Malformed candidate asset filename")
    tag = matched.group(1)
    try:
        run = json.loads(_read_only_command(
            ["gh", "api", f"repos/{REPOSITORY}/actions/runs/{run_id}"]))
        ancestry = json.loads(_read_only_command(
            ["gh", "api", f"repos/{REPOSITORY}/compare/{commit}...main"]))
        tag_commit = json.loads(_read_only_command(
            ["gh", "api", f"repos/{REPOSITORY}/commits/{tag}"]))
        tag_ref = json.loads(_read_only_command(
            ["gh", "api", f"repos/{REPOSITORY}/git/ref/tags/{tag}"]))
    except (ValueError, UnicodeError) as exc:
        raise OfflineSigningError("Cannot validate the upstream CI and Git identity") from exc
    if (run.get("head_sha") != commit or run.get("head_branch") != tag
            or run.get("event") != "workflow_dispatch"
            or run.get("status") != "completed" or run.get("conclusion") != "success"
            or run.get("run_attempt") != int(attempt)
            or run.get("actor", {}).get("login") != "teixemf"
            or ancestry.get("status") not in ("ahead", "identical")
            or tag_commit.get("sha") != commit
            or tag_ref.get("ref") != "refs/tags/" + tag):
        raise OfflineSigningError("Release candidate identity or approval cannot be proven")
    identity = REPOSITORY + "/.github/workflows/release.yml@refs/tags/" + tag
    return tag, identity


def sign_candidate(bundle: Path, private_key: Path, *, commit: str,
                   run_id: str, attempt: str, password: bytes,
                   check_github: bool = True) -> tuple[Path, Path, Path, Path]:
    if not isinstance(password, bytes) or not password or b"\n" in password:
        raise OfflineSigningError("A protected-key passphrase is required")
    bundle = bundle.absolute()
    if bundle.is_symlink() or not bundle.is_file():
        raise OfflineSigningError("Candidate must be an existing regular release archive")
    if check_github:
        tag, workflow_ref = validate_candidate_identity(bundle, commit, run_id, attempt)
    else:
        matched = re.fullmatch(r"repocache-(v[0-9]+\.[0-9]+\.[0-9]+)\.tar\.gz", bundle.name)
        if not matched:
            raise OfflineSigningError("Malformed candidate filename")
        tag = matched.group(1)
        workflow_ref = REPOSITORY + "/.github/workflows/release.yml@refs/tags/" + tag

    # Verify package, wheelchain, manifest and source first; never unlock for
    # an unvalidated candidate. No signature key is present on GitHub runners.
    verify_candidate(bundle.parent)
    validate_public_key(private_key, password)
    wheels = bundle.with_name(bundle.name + ".wheelhouse.tar.gz")
    digest = hashlib.sha256(wheels.read_bytes()).hexdigest()
    now = int(time.time()) - 30
    manifest, detached = sign_manifest(
        bundle, private_key, KEY_ID, commit, now, now + 365 * 86400,
        digest, passphrase=password)
    document = make_document(bundle, KEY_ID, commit, tag, workflow_ref,
                             run_id, attempt, ROOT)
    provenance, proof = sign_provenance(
        document, private_key, bundle, passphrase=password)
    _read_only_command(["/usr/bin/openssl", "pkeyutl", "-verify", "-pubin",
                        "-inkey", str(PUBLIC), "-rawin", "-in", str(manifest),
                        "-sigfile", str(detached)])
    verify_provenance(bundle, provenance, proof, PUBLIC, ROOT,
                      commit=commit, tag=tag, workflow_ref=workflow_ref,
                      run_id=run_id, run_attempt=attempt)
    return manifest, detached, provenance, proof


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", default="1")
    args = parser.parse_args()
    password = getpass.getpass("Offline signing key passphrase: ").encode("utf-8")
    for output in sign_candidate(args.bundle, args.private_key, commit=args.commit,
                                 run_id=args.run_id, attempt=args.run_attempt,
                                 password=password):
        print("SIGNED: " + str(output))


if __name__ == "__main__":
    try:
        main()
    except (OfflineSigningError, OSError, ValueError) as exc:
        print("REFUSED: " + type(exc).__name__, file=sys.stderr)
        raise SystemExit(2)
