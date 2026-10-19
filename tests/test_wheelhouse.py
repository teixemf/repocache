"""Strict offline-wheel lock, SBOM and archive layout regression suite."""
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest
from repocache import wheelhouse


def _fixture():
    name = "example-1.0-py3-none-any.whl"
    wheel = b"an isolated, intentionally non-executable test wheel"
    digest = hashlib.sha256(wheel).hexdigest()
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "components": [{
            "type": "library", "name": "example", "version": "1.0",
            "hashes": [{"alg": "SHA-256", "content": digest}],
            "properties": [{"name": "repocache:wheel-file", "value": name}]
        }]
    }
    return {
        "requirements.lock": "./wheels/" + name + " --hash=sha256:" + digest + "\n",
        "wheels/" + name: wheel,
        "sbom.json": json.dumps(sbom),
    }


def _archive(entries):
    blob = io.BytesIO()
    with tarfile.open(fileobj=blob, mode="w:gz") as output:
        for name, data in entries.items():
            raw = data if isinstance(data, bytes) else data.encode("utf-8")
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            output.addfile(member, io.BytesIO(raw))
    return blob.getvalue()


def _check(entries, destination):
    payload = _archive(entries)
    return wheelhouse.verified_extract(
        payload, hashlib.sha256(payload).hexdigest(), destination)


def test_valid_dependency_graph_never_uses_index(tmp_path):
    lock = _check(_fixture(), tmp_path / "verified")
    assert lock.is_file()
    argv = wheelhouse.install_argv(Path("/tmp/venv/bin/python"), lock)
    assert {"--no-index", "--require-hashes", "--no-deps", "--no-cache-dir"} <= set(argv)


def test_transport_hash_cannot_substitute_for_authenticated_digest(tmp_path):
    with pytest.raises(wheelhouse.WheelhouseError):
        wheelhouse.verified_extract(_archive(_fixture()),
                                    hashlib.sha256(b"different signed asset").hexdigest(),
                                    tmp_path / "bad")


@pytest.mark.parametrize("mutation", ["modified-wheel", "extra-wheel", "missing-wheel", "unsafe-index"])
def test_invalid_dependency_graph_fails_closed(tmp_path, mutation):
    files = _fixture()
    name = next(n for n in files if n.endswith(".whl"))
    if mutation == "modified-wheel":
        files[name] = b"changed"
    elif mutation == "extra-wheel":
        files["wheels/unapproved-1.0-py3-none-any.whl"] = b"unexpected"
    elif mutation == "missing-wheel":
        files.pop(name)
    else:
        files["requirements.lock"] = "--extra-index-url https://example.invalid\n"
    with pytest.raises(wheelhouse.WheelhouseError):
        _check(files, tmp_path / "target")


@pytest.mark.parametrize("unsafe", [
    "../traversal", "/absolute/entry", "wheels/../bad.whl",
    "tmp/executable.sh", "wheels/extra.txt",
])
def test_archive_traversal_or_nonwheel_entry_is_rejected(tmp_path, unsafe):
    files = _fixture()
    files[unsafe] = b"not approved"
    with pytest.raises(wheelhouse.WheelhouseError):
        _check(files, tmp_path / "target")
    assert not (tmp_path / "traversal").exists()


@pytest.mark.parametrize("mutation", ["missing", "bad-hash", "duplicate"])
def test_cyclonedx_inventory_matches_pinned_wheels(tmp_path, mutation):
    files = _fixture()
    if mutation == "missing":
        del files["sbom.json"]
    else:
        sbom = json.loads(files["sbom.json"])
        if mutation == "bad-hash":
            sbom["components"][0]["hashes"][0]["content"] = "f" * 64
        else:
            sbom["components"].append(dict(sbom["components"][0]))
        files["sbom.json"] = json.dumps(sbom)
    with pytest.raises(wheelhouse.WheelhouseError):
        _check(files, tmp_path / "target")
