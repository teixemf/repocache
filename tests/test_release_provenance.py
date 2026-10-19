"""Release provenance binds exact build inputs and rejects unreviewed identity."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "release_provenance_public", ROOT / "scripts/release_provenance.py")
provenance = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(provenance)


def _fixture(tmp_path):
    bundle = tmp_path / "repocache-v0.4.0.tar.gz"
    for suffix in provenance.ASSET_SUFFIXES:
        (tmp_path / (bundle.name + suffix)).write_bytes(
            ("ephemeral-test-input-" + suffix).encode())
    return bundle


def _build(bundle, **override):
    params = {
        "key_id": "ci-fixture",
        "commit": "a" * 40,
        "tag": "v0.4.0",
        "workflow_ref": "teixemf/repocache/.github/workflows/release.yml@refs/tags/v0.4.0",
        "run_id": "123",
        "run_attempt": "1",
        "root": ROOT
    }
    params.update(override)
    return provenance.make_document(bundle, **params)


def test_release_statement_binds_wheels_signatures_and_lockfiles(tmp_path):
    bundle = _fixture(tmp_path)
    statement = _build(bundle)
    assert statement["repository"] == "teixemf/repocache"
    assert statement["tag"] == "v0.4.0"
    assert len(statement["artifacts"]) == len(provenance.ASSET_SUFFIXES)
    assert len(statement["dependency_locks"]) == 2
    first_digest = statement["artifacts"][bundle.name]
    bundle.write_bytes(b"altered")
    assert provenance.expected_assets(bundle)[bundle.name] != first_digest


@pytest.mark.parametrize("bad", [
    {"run_attempt": "0"}, {"run_id": "0"}, {"commit": "bad"},
    {"tag": "v0.3.0"}, {"workflow_ref": "different/workflow"},
    {"key_id": "UNSAFE KEY ID"}
])
def test_release_identity_rejects_unapproved_input(tmp_path, bad):
    with pytest.raises(provenance.ProvenanceError):
        _build(_fixture(tmp_path), **bad)


def test_duplicate_fields_and_symlink_assets_are_rejected(tmp_path):
    with pytest.raises(provenance.ProvenanceError):
        provenance.strict_dict([("schema", 1), ("schema", 2)])
    bundle = _fixture(tmp_path)
    target = tmp_path / "not-an-asset"
    target.write_bytes(b"untrusted")
    bundle.unlink()
    bundle.symlink_to(target)
    with pytest.raises(provenance.ProvenanceError):
        provenance.expected_assets(bundle)
