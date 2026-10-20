"""Public release archive reproducibility, license and integrity contract."""
from __future__ import annotations

import hashlib
import importlib.util
import re
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_build", ROOT / "scripts/build_release.py")
builder = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(builder)
version = re.search(r'^version\s*=\s*"(\d+\.\d+\.\d+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)
tag = "v" + version


def test_archive_is_reproducible_contains_license_and_every_expected_file(tmp_path):
    archive, checksum = builder.build_release(tmp_path / "a", tag)
    second, _ = builder.build_release(tmp_path / "b", tag)
    assert archive.read_bytes() == second.read_bytes()
    assert checksum.read_text() == f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n"
    with tarfile.open(archive, "r:gz") as tf:
        assert set(tf.getnames()) == {f"repocache-{tag}/{name}" for name in builder.FILES}
        assert all(m.isfile() and m.uid == m.gid == 0 and m.mtime == 0 for m in tf)
        assert tf.extractfile(f"repocache-{tag}/LICENSE").read() == (ROOT / "LICENSE").read_bytes()
        guide = "docs/PRODUCTION_EXISTING_NGINX.md"
        assert tf.extractfile(f"repocache-{tag}/{guide}").read() == (ROOT / guide).read_bytes()
        assert all(".git" not in name.split("/") for name in tf.getnames())
        assert all("tests" not in name.split("/") for name in tf.getnames())


def test_version_license_and_policy_identical():
    import tomllib
    import json
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())
    policy = json.loads((ROOT / "release-policy.json").read_text())
    assert metadata["project"]["version"] == policy["version"] == version
    assert metadata["project"]["license"] == "Apache-2.0"
    assert metadata["project"]["license-files"] == ["LICENSE"]
    assert (ROOT / "src/repocache/__init__.py").read_text().find(f'__version__ = "{version}"') >= 0
    assert (ROOT / "LICENSE").read_text().lstrip().startswith("Apache License")


def test_unmatched_tag_fails_closed(tmp_path):
    with pytest.raises(ValueError, match="Tag"):
        builder.build_release(tmp_path, "v99.9.9")


def test_missing_file_causes_no_silent_truncation(tmp_path, monkeypatch):
    source = tmp_path / "empty"
    source.mkdir()
    (source / "pyproject.toml").write_text('[project]\nversion = "' + version + '"\n')
    pkg = source / "src/repocache"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text('__version__ = "' + version + '"\n')
    (source / "release-policy.json").write_text((ROOT / "release-policy.json").read_text())
    monkeypatch.setattr(builder, "ROOT", source)
    with pytest.raises(ValueError, match="Incomplete release bundle"):
        builder.build_release(tmp_path / "dist", tag)
