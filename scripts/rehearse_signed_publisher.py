#!/usr/bin/env python3
"""Offline publisher-side integration rehearsal with ephemeral Ed25519 keys.

CI-only verification of signed archive, pinned wheelhouse, SBOM and key path.
Never commits a key, writes /etc or publishes a GitHub release.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from repocache import signatures, wheelhouse


def run(*args: str) -> None:
    subprocess.run(list(map(str, args)), check=True, capture_output=True, timeout=30)


def main(output: Path) -> None:
    import tomllib
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    archive = output / ("repocache-v" + version + ".tar.gz")
    wheels = output / (archive.name + ".wheelhouse.tar.gz")
    if not archive.is_file() or not wheels.is_file():
        raise RuntimeError("Incomplete publisher rehearsal artifacts")
    # Ensure compromised build artifacts cannot be signed if they differ
    # from the actual reviewed source and exact committed dependency locks.
    from verify_release_candidate import verify as verify_release_candidate
    verify_release_candidate(output)
    script = ROOT / "scripts/sign_release.py"
    spec = importlib.util.spec_from_file_location("publisher_signing", script)
    if spec is None or spec.loader is None:
        raise RuntimeError("Signer module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix="repocache-publisher-") as temp:
        work = Path(temp)
        private = work / "ci-private.pem"
        public = work / "ci-public.pem"
        run("/usr/bin/openssl", "genpkey", "-algorithm", "Ed25519", "-out", private)
        private.chmod(0o600)
        run("/usr/bin/openssl", "pkey", "-in", private, "-pubout", "-out", public)
        digest = hashlib.sha256(wheels.read_bytes()).hexdigest()
        signed, detached = module.sign(
            archive, private, "ci-ephemeral-publisher", "a" * 40,
            int(time.time()) - 10, int(time.time()) + 3600, digest)
        original_key = signatures._trusted_key
        try:
            signatures._trusted_key = lambda key_id: public
            verified = signatures.verify(
                archive.read_bytes(), signed.read_bytes(), detached.read_bytes(), version)
        finally:
            signatures._trusted_key = original_key
        if verified["wheelhouse_sha256"] != digest:
            raise RuntimeError("Publisher signature did not bind wheelhouse")
        lock = wheelhouse.verified_extract(wheels.read_bytes(), digest, work / "staged")
        wheelhouse.verify_application_wheel(lock, version)
        sbom = json.loads((lock.parent / "sbom.json").read_text())
        if sbom["metadata"]["component"]["version"] != version:
            raise RuntimeError("Publisher-signed SBOM application version mismatch")
        poisoned = b"tampered wheelhouse"
        try:
            wheelhouse.verified_extract(poisoned, digest, work / "tampered")
        except wheelhouse.WheelhouseError:
            pass
        else:
            raise RuntimeError("Tampered wheelhouse passed verification")
        # Exercise the actual built release rather than only a mocked file
        # fixture, using an ephemeral key which is NEVER a production signer.
        provenance_path = ROOT / "scripts/release_provenance.py"
        p_spec = importlib.util.spec_from_file_location("ci_publisher_provenance", provenance_path)
        if p_spec is None or p_spec.loader is None:
            raise RuntimeError("Signed provenance checker is unavailable")
        provenance = importlib.util.module_from_spec(p_spec)
        p_spec.loader.exec_module(provenance)
        tag = "v" + version
        workflow_ref = (
            "teixemf/repocache/.github/workflows/release.yml@refs/tags/" + tag)
        doc = provenance.make_document(
            archive, "ci-ephemeral-publisher", "a" * 40, tag,
            workflow_ref, "12345", "1", ROOT)
        statement, signature = provenance.sign(doc, private, archive)
        verified_statement = provenance.verify(
            archive, statement, signature, public, ROOT, commit="a" * 40,
            tag=tag, workflow_ref=workflow_ref, run_id="12345", run_attempt="1")
        if verified_statement["artifacts"][archive.name] != hashlib.sha256(
                archive.read_bytes()).hexdigest():
            raise RuntimeError("Signed provenance did not bind the built archive")
        try:
            provenance.verify(
                archive, statement, signature, public, ROOT, commit="b" * 40,
                tag=tag, workflow_ref=workflow_ref, run_id="12345", run_attempt="1")
        except provenance.ProvenanceError:
            pass
        else:
            raise RuntimeError("Provenance accepted changed release commit")
        print("PASS: ephemeral Ed25519-signed provenance binds real source, "
              "wheelhouse, SBOM, pinned locks and workflow identity", flush=True)

        # Rehearse the EXACT owner-facing offline signer (not just its parts)
        # using a disposable passphrase-encrypted key. No production key,
        # Github token or publisher permission is available to this CI job.
        import offline_sign_release as owner_signer
        encrypted = work / "ci-encrypted-only.pem"
        encrypted_public = work / "ci-encrypted-public.pem"
        ephemeral_password = b"ci-disposable-ed25519-only"
        subprocess.run(
            ["/usr/bin/openssl", "genpkey", "-algorithm", "Ed25519",
             "-aes-256-cbc", "-pass", "fd:0", "-out", str(encrypted)],
            input=ephemeral_password + b"\n", capture_output=True, check=True)
        encrypted.chmod(0o600)
        subprocess.run(
            ["/usr/bin/openssl", "pkey", "-in", str(encrypted),
             "-passin", "fd:0", "-pubout", "-out", str(encrypted_public)],
            input=ephemeral_password + b"\n", capture_output=True, check=True)
        encoded = subprocess.run(
            ["/usr/bin/openssl", "pkey", "-pubin", "-in",
             str(encrypted_public), "-outform", "DER"],
            capture_output=True, check=True).stdout
        original_pub = owner_signer.PUBLIC
        original_fingerprint = owner_signer.PUBLIC_DER_SHA256
        try:
            owner_signer.PUBLIC = encrypted_public
            owner_signer.PUBLIC_DER_SHA256 = hashlib.sha256(encoded).hexdigest()
            try:
                owner_signer.validate_public_key(encrypted, b"incorrect-passphrase")
            except owner_signer.OfflineSigningError:
                pass
            else:
                raise RuntimeError("Encrypted signer accepted wrong passphrase")
            outputs = owner_signer.sign_candidate(
                archive, encrypted, commit="a" * 40, run_id="12345",
                attempt="1", password=ephemeral_password, check_github=False)
            if len(outputs) != 4 or not all(item.is_file() for item in outputs):
                raise RuntimeError("Owner offline signer did not produce all signed assets")
        finally:
            owner_signer.PUBLIC = original_pub
            owner_signer.PUBLIC_DER_SHA256 = original_fingerprint
        print("PASS: complete passphrase-protected owner offline signing "
              "rejects wrong passwords and verifies real unsigned candidate", flush=True)
    print("PASS: verified signed release + wheelhouse + SBOM + offline source identity")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) == 2 else ROOT / "dist")
