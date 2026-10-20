"""Deterministic hostile TAR corpus and bounded extraction regression (#38).

All artifacts are tiny or highly compressible synthetic fixtures. No privileged
process, production filesystem, real user data, or private signing key is used.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tarfile
import tempfile
import time

import pytest

from repocache import upgrade, wheelhouse

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.4.0"
PREFIX = "repocache-v0.4.0/"
CLEAN = {"version": "0.0.0"}
DEBIAN = {"ID": "debian", "VERSION_ID": "13"}


def archive(entries, *, format=tarfile.PAX_FORMAT):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", format=format) as tar:
        for name, kind, payload in entries:
            entry = tarfile.TarInfo(name)
            if kind == "regular":
                entry.size = len(payload)
                tar.addfile(entry, io.BytesIO(payload))
            else:
                entry.type = kind
                entry.linkname = "fixture"
                tar.addfile(entry)
    return stream.getvalue()


def extract(payload, location):
    return upgrade._extract_verified(payload, VERSION, location, CLEAN, DEBIAN)


@pytest.mark.parametrize("bad", [
    "/absolute", "../../escape", "docs/../escape", "./manifest",
    "docs//nested", "unexpected-file", "docs/CHANGELOG.md/child",
    "client/../../outside", "client/%2e%2e/surprise",
    "docs/PRODUCTION_EXISTING_NGINX.md/child",
])
def test_unapproved_tar_member_paths_never_write_outside_staging(tmp_path, bad):
    blob = archive([(PREFIX + bad, "regular", b"sanitized")])
    with pytest.raises(upgrade.UpgradeError):
        extract(blob, tmp_path / "staging")
    assert not (tmp_path / "outside").exists()
    assert not (tmp_path / "escape").exists()


@pytest.mark.parametrize("kind", [
    tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE,
    tarfile.BLKTYPE, tarfile.FIFOTYPE, tarfile.DIRTYPE,
])
def test_tar_links_devices_pipes_and_directories_are_rejected(tmp_path, kind):
    target = tmp_path / "outside"
    target.write_text("protected")
    blob = archive([(PREFIX + "release-policy.json", kind, b"")])
    with pytest.raises(upgrade.UpgradeError):
        extract(blob, tmp_path / "staging")
    assert target.read_text() == "protected"


def test_duplicate_member_cannot_replace_release_policy(tmp_path):
    name = PREFIX + "release-policy.json"
    blob = archive([(name, "regular", b"a"), (name, "regular", b"b")])
    with pytest.raises(upgrade.UpgradeError, match="layout"):
        extract(blob, tmp_path / "staging")


@pytest.mark.parametrize("format", [tarfile.GNU_FORMAT, tarfile.PAX_FORMAT])
def test_gnu_and_pax_extended_names_must_still_match_allowlist(tmp_path, format):
    name = PREFIX + "unexpected/" + "x" * 200
    blob = archive([(name, "regular", b"not-allowed")], format=format)
    with pytest.raises(upgrade.UpgradeError):
        extract(blob, tmp_path / "staging")


@pytest.mark.parametrize("raw", [
    b"not gzip",
    gzip.compress(b"not a tar"),
    b"\x1f\x8b\x08\x00",
    gzip.compress(b"\x00" * 513),
])
def test_invalid_or_truncated_stream_fails_without_external_writes(tmp_path, raw):
    with pytest.raises((upgrade.UpgradeError, OSError, EOFError, ValueError)):
        extract(raw, tmp_path / "staging")
    assert not (tmp_path / "escape").exists()


def test_exact_maximum_compressed_archive_limit(tmp_path):
    # No decompression or staging attempted for input beyond the hard cap.
    with pytest.raises(upgrade.UpgradeError, match="compressed size limit"):
        extract(b"x" * (upgrade.MAX_ARCHIVE + 1), tmp_path / "staging")
    assert not (tmp_path / "staging").exists()


def test_precreated_destination_and_symlink_refused(tmp_path):
    bad = tmp_path / "stage"
    bad.mkdir()
    (bad / ("repocache-v" + VERSION)).symlink_to(tmp_path, target_is_directory=True)
    blob = archive([(PREFIX + "release-policy.json", "regular", b"{}")])
    with pytest.raises(upgrade.UpgradeError, match="staging"):
        extract(blob, bad)
    assert not (tmp_path / "release-policy.json").exists()


@pytest.mark.parametrize("attack", ["leaf", "directory"])
def test_staging_symlink_substitution_refused_without_outside_write(tmp_path, monkeypatch, attack):
    where = tmp_path / "stage"
    external = tmp_path / "outside"
    external.mkdir()
    original = upgrade._write_staged_member

    def inject(root, relative, data, mode):
        # Simulate a hostile preexisting entry in an otherwise disposable
        # staging directory. O_EXCL/O_NOFOLLOW must prevent following it.
        if attack == "leaf":
            (root / "release-policy.json").symlink_to(external / "sensitive")
        else:
            (root / "client").symlink_to(external, target_is_directory=True)
        return original(root, relative, data, mode)

    monkeypatch.setattr(upgrade, "_write_staged_member", inject)
    name = "release-policy.json" if attack == "leaf" else "client/install.sh"
    blob = archive([(PREFIX + name, "regular", b"synthetic")])
    with pytest.raises(upgrade.UpgradeError):
        extract(blob, where)
    assert list(external.iterdir()) == []


def test_wheelhouse_unsafe_members_cannot_escape(tmp_path):
    names = ["../escape", "/absolute", "wheels/../../escape",
             "wheels/invalid.txt", "foo"]
    for idx, bad in enumerate(names):
        blob = archive([(bad, "regular", b"synthetic")])
        with pytest.raises(wheelhouse.WheelhouseError):
            wheelhouse.verified_extract(blob, hashlib.sha256(blob).hexdigest(),
                                        tmp_path / ("wheelhouse" + str(idx)))
    assert not (tmp_path / "escape").exists()


def test_signed_manifest_can_authenticate_rejected_tar_layout(tmp_path, monkeypatch):
    # This deliberately signs a *test-only* archive containing an invalid
    # member. Authenticity is not permission to bypass the source file allowlist.
    from repocache import signatures
    private = tmp_path / "ephemeral-signing-key"
    public = tmp_path / "ephemeral-public-key"
    subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "Ed25519",
                    "-out", str(private)], check=True, capture_output=True, timeout=15)
    subprocess.run(["/usr/bin/openssl", "pkey", "-in", str(private), "-pubout",
                    "-out", str(public)], check=True, capture_output=True, timeout=15)
    monkeypatch.setattr(signatures, "_trusted_key", lambda key_id: public)
    payload = archive([(PREFIX + "unexpected", "regular", b"unsigned-content-not-executed")])
    now = int(time.time())
    doc = {"schema": 1, "key_id": "publisher-2026",
           "repository": "teixemf/repocache", "channel": "stable",
           "version": VERSION, "commit": "a" * 40,
           "archive": "repocache-v" + VERSION + ".tar.gz",
           "archive_sha256": hashlib.sha256(payload).hexdigest(),
           "policy_sha256": "b" * 64, "wheelhouse_sha256": None,
           "issued_at": now - 60, "expires_at": now + 3600}
    raw = (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode()
    manifest = tmp_path / "manifest"
    manifest.write_bytes(raw)
    sig = tmp_path / "signature"
    subprocess.run(["/usr/bin/openssl", "pkeyutl", "-sign", "-inkey",
                    str(private), "-rawin", "-in", str(manifest), "-out", str(sig)],
                   check=True, capture_output=True, timeout=15)
    assert signatures.verify(payload, raw, sig.read_bytes(), VERSION)["archive_sha256"] == doc["archive_sha256"]
    with pytest.raises(upgrade.UpgradeError):
        extract(payload, tmp_path / "stage")


def test_compressed_resource_bomb_is_refused_in_bounded_subprocess(tmp_path):
    oversized = upgrade.MAX_UNPACKED + 1
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as out:
        item = tarfile.TarInfo(PREFIX + "release-policy.json")
        item.size = oversized
        out.addfile(item, io.BytesIO(b"A" * oversized))
    blob = stream.getvalue()
    assert len(blob) < upgrade.MAX_ARCHIVE

    script = """
import sys, tempfile
sys.path.insert(0, 'src')
from pathlib import Path
from repocache import upgrade
with tempfile.TemporaryDirectory() as folder:
    try:
        upgrade._extract_verified(sys.stdin.buffer.read(), '0.4.0',
                                  Path(folder), {'version':'0.0.0'},
                                  {'ID':'debian','VERSION_ID':'13'})
    except upgrade.UpgradeError:
        print('PASS: bounded hostile archive refused')
    else:
        raise SystemExit('unexpected archive acceptance')
"""
    def restrict():
        resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    result = subprocess.run([sys.executable, "-c", script], input=blob,
                            cwd=ROOT, capture_output=True, timeout=10,
                            preexec_fn=restrict)
    assert result.returncode == 0, result.stderr.decode(errors="replace")[-600:]
    assert b"PASS: bounded hostile archive refused" in result.stdout


def test_pax_extended_member_metadata_is_not_an_implicit_allowlist(tmp_path):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.PAX_FORMAT) as out:
        entry = tarfile.TarInfo(PREFIX + "release-policy.json")
        entry.pax_headers = {"comment": "untrusted supplemental metadata"}
        entry.size = 2
        out.addfile(entry, io.BytesIO(b"{}"))
    with pytest.raises(upgrade.UpgradeError, match="layout"):
        extract(stream.getvalue(), tmp_path / "source")


def test_pax_wheelhouse_member_is_not_implicitly_approved(tmp_path):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.PAX_FORMAT) as out:
        entry = tarfile.TarInfo("requirements.lock")
        entry.pax_headers = {"comment": "untrusted supplemental metadata"}
        entry.size = 1
        out.addfile(entry, io.BytesIO(b"x"))
    blob = stream.getvalue()
    with pytest.raises(wheelhouse.WheelhouseError, match="entry"):
        wheelhouse.verified_extract(
            blob, hashlib.sha256(blob).hexdigest(), tmp_path / "deps")


def test_bounded_gzip_reader_cannot_overdecode_highly_compressible_metadata():
    # Deliberately small cap: hard limit must be enforced on decoded, not
    # solely compressed, bytes before TAR or filesystem handling.
    bomb = gzip.compress(b"A" * 1_000_000)
    assert len(bomb) < 2_000
    with gzip.GzipFile(fileobj=io.BytesIO(bomb), mode="rb") as compressed:
        limited = wheelhouse._BoundedGzipReader(compressed, 1_024)
        with pytest.raises(OSError, match="resource limit"):
            limited.read(1_000_000)
