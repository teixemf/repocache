#!/usr/bin/env python3
"""Build a reproducible tar.gz archive and SHA-256 checksum for releases."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import tarfile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "README.md", "CHANGELOG.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "pyproject.toml", "install.sh", "platform_check.py", "release-policy.json",
    "docs/PRODUCTION_EXISTING_NGINX.md",
    "src/repocache/__init__.py", "src/repocache/cli.py",
    "src/repocache/core.py", "src/repocache/catalog.py", "src/repocache/rendering.py",
    "src/repocache/tui.py", "src/repocache/updater.py",
    "src/repocache/releases.py", "src/repocache/upgrade.py",
    "src/repocache/signatures.py", "src/repocache/recovery.py", "src/repocache/wheelhouse.py",
    "client/repocache_client.py", "client/install.sh",
    "scripts/bootstrap-rootless.sh", "scripts/repocache-launcher.sh",
)

# Explicitly owned source additions required for v0.6+; never vendor wheels.
ONLINE_FILES = (
    "src/repocache/release_inventory.py",
    "src/repocache/online_deps.py",
    "src/repocache/signed_dependency_staging.py",
    "src/repocache/online_generation.py",
    "src/repocache/application_wheel.py",
    "src/repocache/candidate_sandbox.py",
)


def build_release(output: Path, tag: str = "", *,
                  online_lock: Path | None = None,
                  online_sbom: Path | None = None) -> tuple[Path, Path]:
    text = (ROOT / "pyproject.toml").read_text()
    match = re.search(r'^version\s*=\s*"(\d+\.\d+\.\d+)"\s*$', text, re.MULTILINE)
    if not match:
        raise ValueError("Invalid project version in pyproject.toml")
    version = match.group(1)
    if tag and tag != "v" + version:
        raise ValueError("Tag does not match the project version")
    init = (ROOT / "src/repocache/__init__.py").read_text()
    if f'__version__ = "{version}"' not in init:
        raise ValueError("Project and package versions do not match")
    try:
        policy = json.loads((ROOT / "release-policy.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError("Incomplete release bundle: release-policy.json") from error
    if (policy.get("version") != version or type(policy.get("schema")) is not int
            or policy["schema"] != 1):
        raise ValueError("Release compatibility policy version does not match the project")
    online = online_lock is not None or online_sbom is not None
    if online:
        # Immutable v0.4.0 supports only signed schema 1 + offline wheelhouse;
        # the first v0.5.0 must retain that bootstrapping contract.
        if tuple(map(int, version.split("."))) < (0, 6, 0):
            raise ValueError("Source-only candidate requires v0.6.0 or later")
        if online_lock is None or online_sbom is None:
            raise ValueError("Online candidate requires BOTH lock and SBOM")
        if (policy.get("compatible_from") != ["0.5.0"]
                or policy.get("targets") != [
                    {"id": "debian", "major": "13"},
                    {"id": "almalinux", "major": "10"}]
                or policy.get("python_min") != "3.12"
                or policy.get("python_max_exclusive") != "3.14"):
            raise ValueError("Online candidate has unapproved compatibility policy")
        for artifact in (online_lock, online_sbom):
            if artifact.is_symlink() or not artifact.is_file():
                raise ValueError("Missing or symlinked candidate metadata")
        if online_lock.stat().st_size > 131072 or online_sbom.stat().st_size > 262144:
            raise ValueError("Online candidate metadata exceeds size limit")
        lock_data, sbom_data = online_lock.read_bytes(), online_sbom.read_bytes()
    package = output / f"repocache-v{version}.tar.gz"
    checksum = package.with_name(package.name + ".sha256")

    def _write_archive(handle) -> None:
        with gzip.GzipFile(filename="", mode="wb", fileobj=handle, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for name in (FILES + ONLINE_FILES if online else FILES):
                    source = ROOT / name
                    if not source.is_file() or source.is_symlink():
                        raise ValueError(f"Incomplete release bundle: {name}")
                    data = source.read_bytes()
                    item = tarfile.TarInfo(f"repocache-v{version}/{name}")
                    item.size, item.mtime = len(data), 0
                    item.uid = item.gid = 0
                    item.uname = item.gname = "root"
                    item.mode = (0o755 if name in (
                        "install.sh", "client/install.sh", "client/repocache_client.py",
                        "scripts/bootstrap-rootless.sh", "scripts/repocache-launcher.sh")
                        else 0o644)
                    tar.addfile(item, io.BytesIO(data))

    if not online:
        # Historical schema-1 path: preserve existing output and artifact layout.
        output.mkdir(parents=True, exist_ok=True)
        with package.open("wb") as handle:
            _write_archive(handle)
        checksum.write_text(
            f"{hashlib.sha256(package.read_bytes()).hexdigest()}  {package.name}\n")
        return package, checksum

    # Source-only candidates are prepared and validated IN MEMORY first.
    # No incomplete or conflicting files are left in a publication directory.
    buffer = io.BytesIO()
    _write_archive(buffer)
    archive_bytes = buffer.getvalue()
    checksum_bytes = (
        f"{hashlib.sha256(archive_bytes).hexdigest()}  {package.name}\n").encode()
    sys.path.insert(0, str(ROOT / "src"))
    from repocache import application_wheel, release_inventory
    try:
        original_wheel = application_wheel.build(archive_bytes, version)
    except application_wheel.ApplicationWheelError as exc:
        raise ValueError("Cannot generate first-party application wheel") from exc
    assets = {"archive": archive_bytes, "checksum": checksum_bytes,
              "dependency_lock": lock_data, "sbom": sbom_data,
              "application_wheel": original_wheel}
    try:
        release_inventory.build_inventory(version, assets)
    except release_inventory.InventoryError as exc:
        raise ValueError("Online candidate fails source-only inventory checks") from exc
    names = release_inventory.names(version)
    desired = {
        package: archive_bytes,
        checksum: checksum_bytes,
        output / names["dependency_lock"]: lock_data,
        output / names["sbom"]: sbom_data,
        output / names["application_wheel"]: original_wheel,
    }
    # Reject old wheelhouses, signatures, unknown binaries and partial mixes
    # BEFORE any writes. Exact identical repeat builds are idempotent.
    if output.is_symlink() or (output.exists() and not output.is_dir()):
        raise ValueError("Unsafe source-only candidate output directory")
    if output.exists():
        for child in output.iterdir():
            if child not in desired or child.is_symlink() or not child.is_file():
                raise ValueError("Mixed or unexpected source-only candidate output")
        for child, expected_bytes in desired.items():
            if child.exists() and child.read_bytes() != expected_bytes:
                raise ValueError("Source-only candidate bytes changed at the same version")
    output.mkdir(parents=True, exist_ok=True)
    for child, expected_bytes in desired.items():
        if not child.exists():
            child.write_bytes(expected_bytes)
    return package, checksum


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--tag", default="")
    parser.add_argument("--online-lock", type=Path)
    parser.add_argument("--online-sbom", type=Path)
    args = parser.parse_args()
    print("\n".join(map(str, build_release(args.output, args.tag,
              online_lock=args.online_lock, online_sbom=args.online_sbom))))
