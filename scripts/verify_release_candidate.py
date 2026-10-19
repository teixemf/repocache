#!/usr/bin/env python3
"""Fail-closed release candidate verification BEFORE accessing publisher keys.

Rebuild release archive from checked-out reviewed sources, verify exact pinned
runtime wheel identities/digests and build-tool SBOM records. Does not sign,
execute release code, install packages, download dependencies or publish.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from repocache import wheelhouse
from build_release import build_release


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_lock(name: str) -> dict[str, tuple[str, str]]:
    approved: dict[str, tuple[str, str]] = {}
    for line in (ROOT / "deps" / name).read_text().splitlines():
        parts = line.split(" ")
        if (len(parts) != 3
                or re.fullmatch(r"[a-z][a-z0-9_]*", parts[0]) is None
                or re.fullmatch(r"[0-9][a-zA-Z0-9.]*", parts[1]) is None
                or re.fullmatch(r"[a-f0-9]{64}", parts[2]) is None
                or parts[0] in approved):
            raise ValueError("Invalid, duplicate or non-immutable dependency lock pin")
        approved[parts[0]] = (parts[1], parts[2])
    if not approved:
        raise ValueError("Empty approved dependency lock")
    return approved


def verify(output: Path) -> None:
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    bundle = output / ("repocache-v" + version + ".tar.gz")
    wheel_bundle = output / (bundle.name + ".wheelhouse.tar.gz")
    for path in (bundle, wheel_bundle):
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing or symlinked candidate release asset")
    with tempfile.TemporaryDirectory(prefix="repocache-candidate-") as path:
        clean = Path(path)
        expected_bundle, _ = build_release(clean)
        if sha(expected_bundle.read_bytes()) != sha(bundle.read_bytes()):
            raise ValueError("Candidate source differs from reviewed checkout")
        from_zip = wheel_bundle.read_bytes()
        contents = wheelhouse.verified_extract(
            from_zip, sha(from_zip), clean / "wheels")
        wheelhouse.verify_application_wheel(contents, version)
        artifacts: dict[str, tuple[str, str]] = {}
        for filename in (contents.parent / "wheels").glob("*.whl"):
            parts = filename.name.split("-")
            if len(parts) < 5:
                raise ValueError("Unexpected wheel identity")
            key, wheel_version = parts[0], parts[1]
            if key in artifacts:
                raise ValueError("Duplicate wheel distribution")
            artifacts[key] = (wheel_version, sha(filename.read_bytes()))
        application = artifacts.pop("repocache_control", None)
        if application is None or application[0] != version:
            raise ValueError("Missing or mismatched REPOCACHE application")
        if artifacts != read_lock("runtime-wheels.lock"):
            raise ValueError("Candidate runtime wheels differ from approved lock")
        sbom = json.loads((contents.parent / "sbom.json").read_text())
        if (sbom["metadata"]["component"]["version"] != version):
            raise ValueError("Candidate CycloneDX version differs from release")
        tools = {
            entry["name"]: (
                entry["version"],
                entry.get("hashes", [{}])[0].get("content"))
            for entry in sbom["metadata"]["tools"]["components"]
        }
        for name, expected in read_lock("build-wheels.lock").items():
            if tools.get(name) != expected:
                raise ValueError("Candidate build backend inventory differs from approved lock")
    print("PASS: rebuilt release and pinned runtime/build wheelhouse match reviewed source")


if __name__ == "__main__":
    verify(Path(sys.argv[1]) if len(sys.argv) == 2 else ROOT / "dist")
