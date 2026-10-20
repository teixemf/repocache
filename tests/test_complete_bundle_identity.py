"""Exhaustive distributed-member identity regression for first-public v0.4.0.

A source_digest based on selected installed files must never substitute for the
SHA-256 of the complete signed archive. All approved distribution members are
mutated one at a time in a disposable, deterministic tar fixture.
"""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile

import pytest

from repocache import upgrade

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "release_builder_bundle_identity", ROOT / "scripts/build_release.py")
builder = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(builder)

VERSION = "0.4.0"
TAG = "v" + VERSION
MEMBERS = tuple(builder.FILES)


@pytest.fixture(scope="module")
def verified_original(tmp_path_factory):
    output = tmp_path_factory.mktemp("full-archive-digest")
    archive, checksum = builder.build_release(output, TAG)
    contents = archive.read_bytes()
    listed = checksum.read_bytes()
    assert len(MEMBERS) == len(set(MEMBERS))
    assert set(MEMBERS) == set(upgrade.RELEASE_FILES)
    assert len(MEMBERS) > 15
    upgrade._verify_checksum(contents, listed, VERSION)
    return contents, listed


def mutate_exactly_one_member(original: bytes, relative_name: str) -> bytes:
    output = io.BytesIO()
    modified = 0
    with tarfile.open(fileobj=io.BytesIO(original), mode="r:gz") as source:
        with gzip.GzipFile(fileobj=output, filename="", mode="wb", mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w",
                              format=tarfile.PAX_FORMAT) as dest:
                for member in source:
                    assert member.isfile()
                    content = source.extractfile(member).read()
                    if member.name == f"repocache-{TAG}/{relative_name}":
                        assert content, "An empty member needs a distinct mutation fixture"
                        content = bytes([content[0] ^ 0x01]) + content[1:]
                        modified += 1
                    member.size = len(content)
                    dest.addfile(member, io.BytesIO(content))
    assert modified == 1, f"Distribution member absent or duplicated: {relative_name}"
    return output.getvalue()


@pytest.mark.parametrize("relative_path", MEMBERS)
def test_mutation_of_each_distributed_member_changes_full_archive_identity(
        verified_original, relative_path):
    original, original_checksum = verified_original
    altered = mutate_exactly_one_member(original, relative_path)
    assert altered != original
    assert hashlib.sha256(altered).digest() != hashlib.sha256(original).digest()

    # Even if an attacker modifies an otherwise non-executable README, client
    # installer, operational guide or TLS-neutral file, the original release
    # identity is no longer valid. A matching *attacker* checksum is not
    # authenticity and is independently rejected by signature tests.
    with pytest.raises(upgrade.UpgradeError, match="SHA-256"):
        upgrade._verify_checksum(altered, original_checksum, VERSION)


def test_client_docs_policy_and_nonpython_members_are_part_of_signed_inventory(
        verified_original):
    expected = {
        "README.md", "LICENSE", "release-policy.json", "client/install.sh",
        "client/repocache_client.py", "docs/PRODUCTION_EXISTING_NGINX.md",
        "scripts/bootstrap-rootless.sh", "scripts/repocache-launcher.sh",
    }
    assert expected <= set(MEMBERS)
    original, checksum = verified_original
    with tarfile.open(fileobj=io.BytesIO(original), mode="r:gz") as tar:
        assert {member.name.removeprefix(f"repocache-{TAG}/")
                for member in tar} == set(MEMBERS)
    assert hashlib.sha256(original).hexdigest().encode("ascii") in checksum


def test_runtime_records_authenticated_bundle_separately_from_partial_source_hash():
    source = (ROOT / "src/repocache/upgrade.py").read_text(encoding="utf-8")
    installed = (ROOT / "src/repocache/updater.py").read_text(encoding="utf-8")
    assert '"archive_sha256": archive_digest' in source
    assert '"signed_manifest_sha256": hashlib.sha256(manifest_data).hexdigest()' in source
    assert '"publisher_key_id": signed["key_id"]' in source
    assert '"release_commit": signed["commit"]' in source
    assert '"wheelhouse_sha256": wheel_digest' in source
    assert 'previous.get("archive_sha256") != archive_digest' in source
    assert 'previous.get("signed_manifest_sha256") != hashlib.sha256(' in source
    assert 'release_identity' in installed and 'source_digest' in installed
