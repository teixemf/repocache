"""Publisher Ed25519 -> signed asset inventory -> locked wheels -> staging.

Uses ephemeral keys and in-memory candidate bytes. No real PyPI/privileged
installation and no claim of actual publisher-key release acceptance.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import subprocess
import tarfile
import time
from pathlib import Path

import pytest

from repocache import online_deps, release_inventory, signatures, signed_dependency_staging

VERSION = "0.6.0"
TARGET = "debian13-py313"
NAME = "rich-15.0.0-py3-none-any.whl"
URL = "https://files.pythonhosted.org/packages/ab/cdef/" + NAME


def _signer():
    path = Path(__file__).resolve().parents[1] / "scripts/sign_release.py"
    spec = importlib.util.spec_from_file_location("candidate_bridge_signer", path)
    assert spec is not None and spec.loader is not None
    signer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(signer)
    return signer


@pytest.fixture
def publisher(tmp_path, monkeypatch):
    secret = tmp_path / "secret.pem"
    public = tmp_path / "public.pem"
    subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "Ed25519",
                    "-out", str(secret)], check=True, capture_output=True, timeout=20)
    secret.chmod(0o600)
    subprocess.run(["/usr/bin/openssl", "pkey", "-in", str(secret),
                    "-pubout", "-out", str(public)],
                   check=True, capture_output=True, timeout=20)
    monkeypatch.setattr(signatures, "_trusted_key", lambda key_id: public)
    return secret


def _policy():
    return {
        "schema": 1, "version": VERSION,
        "python_min": "3.12", "python_max_exclusive": "3.14",
        "targets": [{"id": "debian", "major": "13"},
                    {"id": "almalinux", "major": "10"}],
        "compatible_from": ["0.5.0"], "downgrade_from": [],
        "config_schema": 1, "api_schema": 1,
    }


def _archive(policy=None):
    data = (json.dumps(_policy() if policy is None else policy) + "\n").encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
        for path, payload in [
            ("release-policy.json", data),
            ("src/repocache/cli.py", b"# original synthetic test source\n"),
        ]:
            item = tarfile.TarInfo("repocache-v" + VERSION + "/" + path)
            item.mode, item.size = 0o644, len(payload)
            tf.addfile(item, io.BytesIO(payload))
    return buffer.getvalue()


def _parts(policy=None, *, upstream=URL, duplicate=False):
    record = {"name": "rich", "version": "15.0.0", "filename": NAME,
              "sha256": "a" * 64, "url": upstream}
    lock = {"schema": 1, "profiles": {
        "debian13-py313": [record],
        "almalinux10-py312": [copy.deepcopy(record)],
    }}
    if duplicate:
        lock["profiles"]["debian13-py313"].append(copy.deepcopy(record))
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "version": 1, "components": [{"name": "rich", "version": "15.0.0"}]}
    source = _archive(policy)
    base = "repocache-v" + VERSION + ".tar.gz"
    return {
        "archive": source,
        "checksum": (hashlib.sha256(source).hexdigest() + "  " + base + "\n").encode(),
        "dependency_lock": (json.dumps(lock) + "\n").encode(),
        "sbom": (json.dumps(sbom) + "\n").encode(),
    }


def _signed(tmp_path, secret, parts):
    names = release_inventory.names(VERSION)
    for role, body in parts.items():
        (tmp_path / names[role]).write_bytes(body)
    source = tmp_path / names["archive"]
    now = int(time.time())
    manifest, sig = _signer().sign(
        source, secret, "publisher-2026", "a" * 40,
        now - 5, now + 3600, online_lock=tmp_path / names["dependency_lock"],
        online_sbom=tmp_path / names["sbom"])
    inventory = (tmp_path / (source.name + ".assets.json")).read_bytes()
    return manifest.read_bytes(), sig.read_bytes(), inventory


def test_signed_complete_candidate_traces_exact_wheels_on_both_targets(
        tmp_path, publisher):
    parts = _parts()
    manifest, signature, inventory = _signed(tmp_path, publisher, parts)
    for target in online_deps.TARGETS:
        wheels = signed_dependency_staging.verified_candidate_wheels(
            parts["archive"], manifest, signature, VERSION, inventory,
            parts, target)
        assert len(wheels) == 1
        assert wheels[0].filename == NAME
        assert wheels[0].url == URL


def test_publisher_authenticated_handoff_is_only_path_to_network_staging(
        tmp_path, publisher, monkeypatch):
    parts = _parts()
    manifest, signature, inventory = _signed(tmp_path, publisher, parts)
    observed = []
    def staged(wheels, destination, *, cafile):
        observed.append((tuple(wheels), destination, cafile))
        return destination / "requirements.lock"
    monkeypatch.setattr(online_deps, "stage_wheels", staged)
    dest = tmp_path / "staged"
    cafile = tmp_path / "ca.pem"
    lock_path = signed_dependency_staging.stage_signed_candidate(
        parts["archive"], manifest, signature, VERSION, inventory,
        parts, TARGET, dest, cafile=cafile)
    assert lock_path == dest / "requirements.lock"
    assert len(observed) == 1
    assert observed[0][0][0].sha256 == "a" * 64


@pytest.mark.parametrize("kind", [
    "invalid-signature", "mutated-lock", "mutated-inventory", "unsupported-target",
    "mutated-archive", "missing-sbom",
])
def test_invalid_candidate_never_reaches_upstream_or_staging(
        tmp_path, publisher, monkeypatch, kind):
    parts = _parts()
    manifest, signature, inventory = _signed(tmp_path, publisher, parts)
    target = TARGET
    if kind == "invalid-signature":
        signature = b"z" * 64
    elif kind == "mutated-lock":
        parts["dependency_lock"] += b" "
    elif kind == "mutated-inventory":
        inventory += b" "
    elif kind == "unsupported-target":
        target = "ubuntu24-py313"
    elif kind == "mutated-archive":
        parts["archive"] += b" "
    elif kind == "missing-sbom":
        del parts["sbom"]
    monkeypatch.setattr(
        online_deps, "stage_wheels",
        lambda *a, **kw: pytest.fail("Unverified candidate reached staging"))
    monkeypatch.setattr(
        online_deps, "_open",
        lambda *a, **kw: pytest.fail("Unverified candidate reached network"))
    with pytest.raises(signed_dependency_staging.PreparationError):
        signed_dependency_staging.stage_signed_candidate(
            parts.get("archive", b""), manifest, signature, VERSION,
            inventory, parts, target, tmp_path / "staged",
            cafile=tmp_path / "ca.pem")


@pytest.mark.parametrize("change", [
    {"compatible_from": []},
    {"version": "0.5.0"},
    {"schema": 2},
    {"targets": [{"id": "debian", "major": "13"}]},
])
def test_even_re_signed_unsupported_compatibility_refused(
        tmp_path, publisher, change):
    selected = {**_policy(), **change}
    parts = _parts(selected)
    manifest, signature, inventory = _signed(tmp_path, publisher, parts)
    with pytest.raises(signed_dependency_staging.PreparationError, match="policy"):
        signed_dependency_staging.verified_candidate_wheels(
            parts["archive"], manifest, signature, VERSION, inventory,
            parts, TARGET)


@pytest.mark.parametrize("case", ["extra", "missing", "duplicate", "wrong-version"])
def test_authenticated_sbom_must_match_both_locked_platforms(
        tmp_path, publisher, case):
    parts = _parts()
    document = json.loads(parts["sbom"])
    if case == "extra":
        document["components"].append({"name": "untracked", "version": "1.0.0"})
    elif case == "missing":
        document["components"] = []
    elif case == "duplicate":
        document["components"].append(copy.deepcopy(document["components"][0]))
    else:
        document["components"][0]["version"] = "14.0.0"
    parts["sbom"] = (json.dumps(document) + "\n").encode()
    if case == "missing":
        # The offline publisher already refuses a completely empty SBOM;
        # acceptance cannot proceed to installation with this candidate.
        with pytest.raises(ValueError, match="source-only inventory"):
            _signed(tmp_path, publisher, parts)
        return
    manifest, signature, inventory = _signed(tmp_path, publisher, parts)
    with pytest.raises(signed_dependency_staging.PreparationError, match="SBOM"):
        signed_dependency_staging.verified_candidate_wheels(
            parts["archive"], manifest, signature, VERSION, inventory,
            parts, TARGET)


@pytest.mark.parametrize("upstream", [
    "https://evil.example/packages/ab/cdef/" + NAME,
    "http://files.pythonhosted.org/packages/ab/cdef/" + NAME,
    URL + "?unreviewed=1",
])
def test_owner_signed_but_unapproved_origin_never_stages(
        tmp_path, publisher, upstream, monkeypatch):
    parts = _parts(upstream=upstream)
    manifest, signature, inventory = _signed(tmp_path, publisher, parts)
    monkeypatch.setattr(
        online_deps, "_open",
        lambda *a, **kw: pytest.fail("Unsafe upstream was contacted"))
    with pytest.raises(signed_dependency_staging.PreparationError):
        signed_dependency_staging.stage_signed_candidate(
            parts["archive"], manifest, signature, VERSION, inventory,
            parts, TARGET, tmp_path / "staged", cafile=tmp_path / "ca.pem")


def test_signed_duplicate_full_lock_closure_refused(tmp_path, publisher):
    parts = _parts(duplicate=True)
    manifest, signature, inventory = _signed(tmp_path, publisher, parts)
    with pytest.raises(signed_dependency_staging.PreparationError):
        signed_dependency_staging.verified_candidate_wheels(
            parts["archive"], manifest, signature, VERSION, inventory,
            parts, TARGET)
