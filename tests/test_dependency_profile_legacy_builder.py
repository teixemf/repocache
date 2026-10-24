"""Release-builder bootstrap contract: old v0.4.0 can only install schema 1.

Preserves the critical compatibility finding in PR #90 without prematurely
publishing a policy-schema 2 format that the reconciled updater cannot install.
"""
from __future__ import annotations

import importlib.util
import json
import tarfile
from pathlib import Path

import pytest


def _builder():
    path = Path(__file__).resolve().parents[1] / "scripts/build_release.py"
    spec = importlib.util.spec_from_file_location("legacy_transition_builder_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _files(root: Path, builder, version: str, schema: int = 1):
    for name in builder.FILES:
        output = root / name
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("test fixture only\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(f'version = "{version}"\n')
    (root / "src/repocache/__init__.py").write_text(
        f'__version__ = "{version}"\n')
    policy = {
        "schema": schema, "version": version,
        "python_min": "3.12", "python_max_exclusive": "3.14",
        "targets": [{"id": "debian", "major": "13"},
                    {"id": "almalinux", "major": "10"}],
        "compatible_from": ["0.4.0"],
        "downgrade_from": [], "config_schema": 1, "api_schema": 1,
    }
    if schema == 2:
        policy["dependency_profile"] = "legacy-offline-wheelhouse"
    (root / "release-policy.json").write_text(json.dumps(policy) + "\n")
    return policy


def test_v05_schema1_bundle_remains_buildable_for_immutable_v04(tmp_path, monkeypatch):
    builder = _builder()
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    expected = _files(tmp_path, builder, "0.5.0")
    archive, checksum = builder.build_release(tmp_path / "dist", "v0.5.0")
    assert archive.is_file() and checksum.is_file()
    with tarfile.open(archive, "r:gz") as tar:
        member = tar.extractfile("repocache-v0.5.0/release-policy.json")
        assert member is not None
        actual = json.loads(member.read())
    assert actual == expected
    assert "dependency_profile" not in actual


@pytest.mark.parametrize("version", ["0.5.0", "0.6.0"])
def test_no_schema2_bundle_while_updater_disables_schema2(tmp_path, monkeypatch, version):
    builder = _builder()
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    _files(tmp_path, builder, version, schema=2)
    with pytest.raises(ValueError, match="Release compatibility policy version"):
        builder.build_release(tmp_path / "dist", "v" + version)
    assert not (tmp_path / "dist" / f"repocache-v{version}.tar.gz").exists()
