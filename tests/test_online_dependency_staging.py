"""Adversarial, network-free tests for #83's unsigned-runtime prevention.

These unit fixtures do not prove publisher signing, native PyPI availability,
complete transitive resolution or production installation (#84/#85).
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import zipfile
from pathlib import Path

import pytest

from repocache import online_deps


WHEEL_NAME = "rich-15.0.0-py3-none-any.whl"
WHEEL_URL = "https://files.pythonhosted.org/packages/ab/cdef/" + WHEEL_NAME


def _wheel(*, name: str = "rich", version: str = "15.0.0",
           hostile_path: str | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as z:
        base = name.replace("-", "_") + "-" + version + ".dist-info/"
        z.writestr(base + "METADATA",
                   f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n")
        z.writestr(base + "WHEEL", "Wheel-Version: 1.0\nGenerator: test\n")
        z.writestr(hostile_path or (name.replace("-", "_") + "/__init__.py"),
                   "value = 1\n")
    return buffer.getvalue()


def _record(data: bytes | None = None) -> dict[str, str]:
    data = _wheel() if data is None else data
    return {"name": "rich", "version": "15.0.0", "filename": WHEEL_NAME,
            "sha256": hashlib.sha256(data).hexdigest(), "url": WHEEL_URL}


def _payload(record: dict | None = None) -> dict:
    entry = record if record is not None else _record()
    return {"schema": 1, "profiles": {
        "debian13-py313": [entry],
        "almalinux10-py312": [copy.deepcopy(entry)],
    }}


def _lock(payload: dict) -> tuple[bytes, str]:
    raw = (json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n").encode()
    return raw, hashlib.sha256(raw).hexdigest()


def _parse(payload: dict, *, target: str = "debian13-py313"):
    raw, expected = _lock(payload)
    return online_deps.parse_verified_lock(raw, expected, target)


def test_complete_two_platform_lock_and_no_dynamic_resolution():
    entries = _parse(_payload())
    assert len(entries) == 1
    assert entries[0].name == "rich"
    assert entries[0].version == "15.0.0"
    assert _parse(_payload(), target="almalinux10-py312") == entries
    with pytest.raises(online_deps.DependencyError, match="target"):
        _parse(_payload(), target="debian12-py313")


def test_signed_digest_must_match_before_parsing_any_lock_fields():
    raw, digest = _lock(_payload())
    with pytest.raises(online_deps.DependencyError, match="digest"):
        online_deps.parse_verified_lock(raw, "0" * 64, "debian13-py313")
    with pytest.raises(online_deps.DependencyError, match="digest"):
        online_deps.parse_verified_lock(raw + b" ", digest, "debian13-py313")
    with pytest.raises(online_deps.DependencyError, match="digest"):
        online_deps.parse_verified_lock(b"{" * (online_deps.MAX_LOCK + 1),
                                        hashlib.sha256(raw).hexdigest(),
                                        "debian13-py313")


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(schema=True),
    lambda d: d.update(schema=2),
    lambda d: d.update(untrusted=True),
    lambda d: d["profiles"].pop("almalinux10-py312"),
    lambda d: d["profiles"].update({"other": []}),
    lambda d: d["profiles"].update({"debian13-py313": []}),
    lambda d: d["profiles"].update({"debian13-py313": [None]}),
    lambda d: d["profiles"]["debian13-py313"][0].update(allow_unsafe=True),
    lambda d: d["profiles"]["debian13-py313"][0].update(version="15.1.0rc1"),
    lambda d: d["profiles"]["debian13-py313"][0].update(name="Rich"),
    lambda d: d["profiles"]["debian13-py313"][0].update(sha256="nope"),
    lambda d: d["profiles"]["debian13-py313"].append(
        copy.deepcopy(d["profiles"]["debian13-py313"][0])),
])
def test_unknown_schema_names_versions_and_duplicate_wheels_fail_closed(mutation):
    payload = _payload()
    mutation(payload)
    with pytest.raises(online_deps.DependencyError):
        _parse(payload)


@pytest.mark.parametrize("url", [
    "http://files.pythonhosted.org/packages/ab/cdef/" + WHEEL_NAME,
    "https://evil.example/packages/ab/cdef/" + WHEEL_NAME,
    "https://files.pythonhosted.org.evil.example/packages/ab/cdef/" + WHEEL_NAME,
    "https://user:secret@files.pythonhosted.org/packages/ab/cdef/" + WHEEL_NAME,
    "https://files.pythonhosted.org:443/packages/ab/cdef/" + WHEEL_NAME,
    "https://files.pythonhosted.org/packages/ab/cdef/" + WHEEL_NAME + "?token=x",
    "https://files.pythonhosted.org/packages/ab/cdef/" + WHEEL_NAME + "#fragment",
    "https://files.pythonhosted.org/packages/ab/%2e%2e/" + WHEEL_NAME,
    "https://files.pythonhosted.org/packages/ab/../" + WHEEL_NAME,
    "https://files.pythonhosted.org/packages/ab/cdef/not-" + WHEEL_NAME,
    "https://127.0.0.1/packages/ab/cdef/" + WHEEL_NAME,
])
def test_unapproved_urls_refused(url):
    entry = _record()
    entry["url"] = url
    with pytest.raises(online_deps.DependencyError, match="metadata"):
        _parse(_payload(entry))


def test_duplicate_json_fields_and_deep_json_refused():
    raw = b'{"schema":1,"schema":1,"profiles":{}}'
    with pytest.raises(online_deps.DependencyError, match="Duplicate"):
        online_deps.parse_verified_lock(
            raw, hashlib.sha256(raw).hexdigest(), "debian13-py313")
    raw = (b'[' * 1300) + b'0' + (b']' * 1300)
    with pytest.raises(online_deps.DependencyError, match="Invalid"):
        online_deps.parse_verified_lock(
            raw, hashlib.sha256(raw).hexdigest(), "debian13-py313")


class FakeResponse:
    def __init__(self, data: bytes, url: str = WHEEL_URL,
                 status: int = 200, length: str | None = None):
        self.stream = io.BytesIO(data)
        self.url = url
        self.status = status
        self.headers = {} if length is None else {"Content-Length": length}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stream.close()

    def geturl(self):
        return self.url

    def read(self, size: int):
        return self.stream.read(size)


def _stage(monkeypatch, tmp_path: Path, data: bytes, *,
           response_url: str = WHEEL_URL,
           status: int = 200, length: str | None = None):
    monkeypatch.setattr(
        online_deps, "_open",
        lambda url, cafile: FakeResponse(data, response_url, status, length))
    bundle = _record(data)
    entries = _parse(_payload(bundle))
    ca = tmp_path / "trusted-ca.pem"
    ca.write_text("synthetic certificate source; no actual TLS call")
    dest = tmp_path / "prepared"
    lock = online_deps.stage_wheels(entries, dest, cafile=ca)
    return lock, dest, bundle


def test_hash_verified_wheel_staging_and_offline_only_install_argv(tmp_path, monkeypatch):
    if os.geteuid() == 0:
        monkeypatch.setattr(online_deps.os, "geteuid", lambda: tmp_path.stat().st_uid)
    data = _wheel()
    lock, directory, record = _stage(monkeypatch, tmp_path, data)
    assert (directory / "wheels" / WHEEL_NAME).read_bytes() == data
    assert lock.read_text() == (
        "./wheels/" + WHEEL_NAME + " --hash=sha256:" + record["sha256"] + "\n")
    argv = online_deps.offline_install_argv(Path("/venv/bin/python"), lock)
    assert "--no-index" in argv and "--no-deps" in argv
    assert "--require-hashes" in argv and "--no-input" in argv
    assert str(lock) in argv and "--extra-index-url" not in argv


@pytest.mark.parametrize("scenario", ["hash", "redirect", "status", "oversize", "archive"])
def test_transport_hash_archive_failures_clean_staging(tmp_path, monkeypatch, scenario):
    if os.geteuid() == 0:
        monkeypatch.setattr(online_deps.os, "geteuid", lambda: tmp_path.stat().st_uid)
    good = _wheel()
    content = (b"poison" if scenario == "hash" else
               _wheel(hostile_path="../escape.py") if scenario == "archive" else good)
    entry = _record(good if scenario in ("hash", "redirect", "status", "oversize") else content)
    remote_url = "https://evil.example/leak" if scenario == "redirect" else WHEEL_URL
    remote_status = 301 if scenario == "status" else 200
    length = str(online_deps.MAX_WHEEL + 1) if scenario == "oversize" else None
    monkeypatch.setattr(
        online_deps, "_open",
        lambda url, cafile: FakeResponse(content, remote_url, remote_status, length))
    ca = tmp_path / "ca.pem"
    ca.write_text("synthetic")
    dest = tmp_path / "prepared"
    with pytest.raises(online_deps.DependencyError):
        online_deps.stage_wheels(_parse(_payload(entry)), dest, cafile=ca)
    assert not dest.exists()


def test_root_execution_refused_before_transport(monkeypatch, tmp_path):
    monkeypatch.setattr(online_deps.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        online_deps, "_open",
        lambda *a: pytest.fail("Root execution reached upstream download"))
    ca = tmp_path / "ca.pem"
    ca.write_text("synthetic")
    with pytest.raises(online_deps.DependencyError, match="root"):
        online_deps.stage_wheels(_parse(_payload()), tmp_path / "prepared",
                                  cafile=ca)
    assert not (tmp_path / "prepared").exists()
