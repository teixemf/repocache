"""Candidate build and untrusted GitHub asset discovery regressions (#84).

No source-only candidate is signed with the actual publisher key here.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tarfile
from pathlib import Path

import pytest

from repocache import release_inventory, releases


def _builder():
    script = Path(__file__).resolve().parents[1] / "scripts/build_release.py"
    spec = importlib.util.spec_from_file_location("future_bundle_builder", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _prepare_tree(tmp_path: Path, builder, version: str):
    for name in builder.FILES + builder.ONLINE_FILES:
        entry = tmp_path / name
        entry.parent.mkdir(parents=True, exist_ok=True)
        entry.write_text("# source controlled by synthetic test\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "repocache-control"\nversion = "' + version +
        '"\nrequires-python = ">=3.12"\nlicense = "Apache-2.0"\n'
        'dependencies = ["typer>=0.12,<1", "rich>=13,<16", "textual>=0.80,<10"]\n'
        '[project.scripts]\nrepocache = "repocache.cli:app"\n')

    (tmp_path / "src/repocache/__init__.py").write_text(
        f'__version__ = "{version}"\n')
    policy = {
        "schema": 1, "version": version,
        "python_min": "3.12", "python_max_exclusive": "3.14",
        "targets": [{"id": "debian", "major": "13"},
                    {"id": "almalinux", "major": "10"}],
        "compatible_from": ["0.5.0"], "downgrade_from": [],
        "config_schema": 1, "api_schema": 1,
    }
    (tmp_path / "release-policy.json").write_text(json.dumps(policy) + "\n")


def _metadata(tmp_path: Path, version: str = "0.6.0"):
    filename = "rich-15.0.0-py3-none-any.whl"
    wheel = {
        "name": "rich", "version": "15.0.0",
        "filename": filename, "sha256": "a" * 64,
        "url": "https://files.pythonhosted.org/packages/ab/cdef/" + filename,
    }
    requirements = {"schema": 1, "profiles": {
        "debian13-py313": [wheel], "almalinux10-py312": [wheel],
    }}
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5",
           "version": 1, "components": [{"name": "rich", "version": "15.0.0"}]}
    lock = tmp_path / "approved-lock.json"
    sbom = tmp_path / "approved-sbom.json"
    lock.write_text(json.dumps(requirements) + "\n")
    sbom.write_text(json.dumps(bom) + "\n")
    return lock, sbom


def test_source_only_candidate_bundle_contains_owned_runtime_and_no_vendor_wheels(
        tmp_path, monkeypatch):
    builder = _builder()
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    _prepare_tree(tmp_path, builder, "0.6.0")
    lock, sbom = _metadata(tmp_path)
    output = tmp_path / "dist"
    archive, checksum = builder.build_release(
        output, "v0.6.0", online_lock=lock, online_sbom=sbom)
    expected = release_inventory.names("0.6.0")
    assert archive.name == expected["archive"]
    assert checksum.name == expected["checksum"]
    assert (output / expected["dependency_lock"]).read_bytes() == lock.read_bytes()
    assert (output / expected["sbom"]).read_bytes() == sbom.read_bytes()
    assert (output / expected["application_wheel"]).is_file()
    assert not (output / (archive.name + ".wheelhouse.tar.gz")).exists()
    assert not (output / (archive.name + ".manifest.json")).exists()
    assert not (output / (archive.name + ".assets.json")).exists()
    with tarfile.open(archive, "r:gz") as tar:
        members = {m.name.removeprefix("repocache-v0.6.0/") for m in tar}
    assert members == set(builder.FILES + builder.ONLINE_FILES)
    assert not any(path.endswith(".whl") or path.startswith("vendor/")
                   for path in members)
    assets = {"archive": archive.read_bytes(),
              "checksum": checksum.read_bytes(),
              "dependency_lock": lock.read_bytes(),
              "sbom": sbom.read_bytes(),
              "application_wheel": (output / expected["application_wheel"]).read_bytes()}
    raw = release_inventory.build_inventory("0.6.0", assets)
    assert set(json.loads(raw)["assets"]) == set(release_inventory.ROLES)


def test_reproducible_source_only_build(tmp_path, monkeypatch):
    builder = _builder()
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    _prepare_tree(tmp_path, builder, "0.6.0")
    lock, sbom = _metadata(tmp_path)
    a, _ = builder.build_release(tmp_path / "a", "v0.6.0",
                                 online_lock=lock, online_sbom=sbom)
    b, _ = builder.build_release(tmp_path / "b", "v0.6.0",
                                 online_lock=lock, online_sbom=sbom)
    assert a.read_bytes() == b.read_bytes()


def test_identical_candidate_rebuild_is_idempotent(tmp_path, monkeypatch):
    builder = _builder()
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    _prepare_tree(tmp_path, builder, "0.6.0")
    lock, sbom = _metadata(tmp_path)
    out = tmp_path / "dist"
    archive, checksum = builder.build_release(
        out, "v0.6.0", online_lock=lock, online_sbom=sbom)
    original = {p.name: (p.read_bytes(), p.stat().st_mtime_ns)
                for p in out.iterdir()}
    same_archive, same_checksum = builder.build_release(
        out, "v0.6.0", online_lock=lock, online_sbom=sbom)
    assert same_archive == archive and same_checksum == checksum
    assert {p.name: (p.read_bytes(), p.stat().st_mtime_ns)
            for p in out.iterdir()} == original


def test_mixed_legacy_wheelhouse_rejected_before_candidate_write(tmp_path, monkeypatch):
    builder = _builder()
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    _prepare_tree(tmp_path, builder, "0.6.0")
    lock, sbom = _metadata(tmp_path)
    out = tmp_path / "dist"
    out.mkdir()
    wheelhouse = out / "repocache-v0.6.0.tar.gz.wheelhouse.tar.gz"
    wheelhouse.write_bytes(b"unapproved third-party wheelhouse")
    with pytest.raises(ValueError, match="Mixed or unexpected"):
        builder.build_release(out, "v0.6.0", online_lock=lock, online_sbom=sbom)
    assert set(out.iterdir()) == {wheelhouse}
    assert wheelhouse.read_bytes() == b"unapproved third-party wheelhouse"


def test_source_change_same_release_version_does_not_replace_candidate(
        tmp_path, monkeypatch):
    builder = _builder()
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    _prepare_tree(tmp_path, builder, "0.6.0")
    lock, sbom = _metadata(tmp_path)
    out = tmp_path / "dist"
    builder.build_release(out, "v0.6.0", online_lock=lock, online_sbom=sbom)
    previous = {p.name: p.read_bytes() for p in out.iterdir()}
    (tmp_path / "README.md").write_text("tampered source at same version\n")
    with pytest.raises(ValueError, match="changed at the same version"):
        builder.build_release(out, "v0.6.0", online_lock=lock, online_sbom=sbom)
    assert {p.name: p.read_bytes() for p in out.iterdir()} == previous


@pytest.mark.parametrize("version", ["0.4.0", "0.5.0"])
def test_online_bundle_before_v06_never_emitted(tmp_path, monkeypatch, version):
    builder = _builder()
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    _prepare_tree(tmp_path, builder, version)
    lock, sbom = _metadata(tmp_path)
    with pytest.raises(ValueError, match="v0.6.0"):
        builder.build_release(tmp_path / "dist", "v" + version,
                              online_lock=lock, online_sbom=sbom)
    assert not (tmp_path / "dist").exists()


def test_legacy_default_keeps_old_files_and_does_not_need_lock(
        tmp_path, monkeypatch):
    builder = _builder()
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    _prepare_tree(tmp_path, builder, "0.5.0")
    archive, checksum = builder.build_release(tmp_path / "dist", "v0.5.0")
    with tarfile.open(archive, "r:gz") as tar:
        members = {m.name.removeprefix("repocache-v0.5.0/") for m in tar}
    assert members == set(builder.FILES)
    assert checksum.is_file()


@pytest.mark.parametrize("case", ["missing-sbom", "tampered-sbom", "invalid-policy", "symlinked-lock"])
def test_builder_denies_incomplete_candidate_without_claiming_signed_release(
        tmp_path, monkeypatch, case):
    builder = _builder()
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    _prepare_tree(tmp_path, builder, "0.6.0")
    lock, sbom = _metadata(tmp_path)
    if case == "missing-sbom":
        sbom = None
    elif case == "tampered-sbom":
        sbom.write_text('{"bomFormat":"not-CycloneDX"}')
    elif case == "invalid-policy":
        body = json.loads((tmp_path / "release-policy.json").read_text())
        body["compatible_from"] = ["0.4.0"]
        (tmp_path / "release-policy.json").write_text(json.dumps(body))
    elif case == "symlinked-lock":
        link = tmp_path / "link.json"
        link.symlink_to(lock)
        lock = link
    with pytest.raises(ValueError):
        builder.build_release(tmp_path / "out", "v0.6.0",
                              online_lock=lock, online_sbom=sbom)


def _public_record(version: str = "0.6.0"):
    names = release_inventory.names(version)
    names.update({
        "inventory": names["archive"] + ".assets.json",
        "manifest": names["archive"] + ".manifest.json",
        "signature": names["archive"] + ".manifest.json.sig",
    })
    assets = [
        {"name": filename, "id": i + 200, "size": 100 + i}
        for i, filename in enumerate(names.values())
    ]
    return {
        "tag_name": "v" + version,
        "draft": False, "prerelease": False, "immutable": True,
        "html_url": "https://github.com/teixemf/repocache/releases/tag/v" + version,
        "assets": assets,
    }


def test_public_source_only_eight_assets_discoverable_but_not_installable(
        monkeypatch):
    candidate = _public_record()
    monkeypatch.setattr(
        releases, "_request_public_first",
        lambda *a, **kw: [candidate])
    result = releases.report("0.5.0", list_all=True)
    assert result["latest_version"] == "0.6.0"
    item = result["releases"][0]
    assert len(item["assets"]) == 8
    assert item["dependency_profile_hint"] == "online-hash-locked-wheels"
    assert item["eligible"] is False
    assert item["compatibility"] == "unknown"
    assert "not installable" in item["compatibility_reason"]
    assert not any("wheelhouse" in x for x in item["assets"])


@pytest.mark.parametrize("case", [
    "unsigned-metadata", "missing-inventory", "missing-lock", "missing-sbom",
    "duplicate-id", "duplicate-name", "missing-own-wheel",
    "extra-wheelhouse", "unexpected-extra",
    "zero-size", "wrong-tag", "draft",
])
def test_untrusted_public_online_metadata_fails_closed(case):
    candidate = _public_record()
    assets = candidate["assets"]
    if case == "unsigned-metadata":
        candidate["immutable"] = False
    elif case == "missing-inventory":
        assets[:] = [a for a in assets if not a["name"].endswith(".assets.json")]
    elif case == "missing-lock":
        assets[:] = [a for a in assets if not a["name"].endswith(".dependency-lock.json")]
    elif case == "missing-sbom":
        assets[:] = [a for a in assets if not a["name"].endswith(".sbom.json")]
    elif case == "missing-own-wheel":
        assets[:] = [a for a in assets if not a["name"].endswith("-py3-none-any.whl")]
    elif case == "duplicate-id":
        assets[1]["id"] = assets[0]["id"]
    elif case == "duplicate-name":
        assets[1]["name"] = assets[0]["name"]
    elif case == "extra-wheelhouse":
        assets.append({"name": "repocache-v0.6.0.tar.gz.wheelhouse.tar.gz",
                       "id": 555, "size": 120})
    elif case == "unexpected-extra":
        assets.append({"name": "attacker.bin", "id": 556, "size": 1})
    elif case == "zero-size":
        assets[0]["size"] = 0
    elif case == "wrong-tag":
        candidate["tag_name"] = "v0.5.0"
    elif case == "draft":
        candidate["draft"] = True
    assert releases._release(candidate) is None


def test_old_profile_metadata_retained_even_after_v06():
    legacy = {"tag_name": "v0.7.0", "draft": False, "prerelease": False,
              "html_url": "https://github.com/teixemf/repocache/releases/tag/v0.7.0"}
    source = "repocache-v0.7.0.tar.gz"
    assets = [source, source + ".sha256", source + ".manifest.json",
              source + ".manifest.json.sig", source + ".wheelhouse.tar.gz"]
    legacy["assets"] = [
        {"name": n, "id": i + 10, "size": i + 100}
        for i, n in enumerate(assets)]
    item = releases._release(legacy)
    assert item is not None
    assert "wheelhouse" in item["assets"]


def test_same_name_cannot_redeclare_two_profiles():
    r = _public_record()
    r["assets"].append({"id": 99,
                       "name": "repocache-v0.6.0.tar.gz.wheelhouse.tar.gz",
                       "size": 200})
    assert releases._release(r) is None
