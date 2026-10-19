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
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "README.md", "CHANGELOG.md", "LICENSE", "pyproject.toml", "install.sh", "platform_check.py", "release-policy.json",
    "src/repocache/__init__.py", "src/repocache/cli.py",
    "src/repocache/core.py", "src/repocache/catalog.py", "src/repocache/rendering.py",
    "src/repocache/tui.py", "src/repocache/updater.py",
    "src/repocache/releases.py", "src/repocache/upgrade.py",
    "src/repocache/signatures.py", "src/repocache/recovery.py", "src/repocache/wheelhouse.py",
    "client/repocache_client.py", "client/install.sh",
    "scripts/bootstrap-rootless.sh", "scripts/repocache-launcher.sh",
    "scripts/migrate_v030.py",
)


def build_release(output: Path, tag: str = "") -> tuple[Path, Path]:
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
    if policy.get("version") != version or policy.get("schema") != 1:
        raise ValueError("Release compatibility policy version does not match the project")
    output.mkdir(parents=True, exist_ok=True)
    package = output / f"repocache-v{version}.tar.gz"
    with package.open("wb") as handle:
        with gzip.GzipFile(filename="", mode="wb", fileobj=handle, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for name in FILES:
                    source = ROOT / name
                    if not source.is_file() or source.is_symlink():
                        raise ValueError(f"Incomplete release bundle: {name}")
                    data = source.read_bytes()
                    item = tarfile.TarInfo(f"repocache-v{version}/{name}")
                    item.size, item.mtime = len(data), 0
                    item.uid = item.gid = 0
                    item.uname = item.gname = "root"
                    item.mode = 0o755 if name in ("install.sh", "client/install.sh", "client/repocache_client.py",
                                                       "scripts/bootstrap-rootless.sh", "scripts/repocache-launcher.sh",
                                                       "scripts/migrate_v030.py") else 0o644
                    tar.addfile(item, io.BytesIO(data))
    checksum = package.with_name(package.name + ".sha256")
    checksum.write_text(f"{hashlib.sha256(package.read_bytes()).hexdigest()}  {package.name}\n")
    return package, checksum


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--tag", default="")
    args = parser.parse_args()
    print("\n".join(map(str, build_release(args.output, args.tag))))
