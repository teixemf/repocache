"""Negative-path tests for the read-only server install v1 parser (#18/#25/#26).

No test here starts services, changes packages, accesses the network or grants
authorization to install. Real native preflight is a separate acceptance gate.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from repocache.server_install_v1 import (
    InstallInputError, parse_install_bytes, validate_install_document,
    validate_os_identity,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "docs" / "examples" / "server-install-v1.json"


def fixture() -> dict:
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def as_bytes(document: dict) -> bytes:
    return json.dumps(document, ensure_ascii=False).encode("utf-8")


def refuse(document: dict, *, for_apply: bool = False) -> None:
    with pytest.raises(InstallInputError):
        parse_install_bytes(as_bytes(document), for_apply=for_apply)


def test_real_inert_example_parses_as_validate_and_apply_intent():
    doc = fixture()
    assert parse_install_bytes(EXAMPLE.read_bytes()) == doc
    assert parse_install_bytes(EXAMPLE.read_bytes(), for_apply=True) == doc
    assert doc["deployment"]["listen"]["bind_address"] == "127.0.0.1"
    assert doc["deployment"]["firewall"]["modify"] is False
    assert [r["kind"] for r in doc["repositories"]] == ["apt", "dnf"]
    assert all(r["desired_state"] == "disabled" for r in doc["repositories"])


def test_missing_generation_only_allowed_for_read_only_validation():
    doc = fixture()
    del doc["expected_state_generation"]
    assert validate_install_document(doc) == doc
    refuse(doc, for_apply=True)


@pytest.mark.parametrize("path,value", [
    (("schema_version",), True),
    (("schema_version",), 1.0),
    (("schema_version",), "1"),
    (("schema_version",), 2),
    (("expected_state_generation",), -1),
    (("expected_state_generation",), 2**63),
    (("deployment", "listen", "https_port"), False),
    (("deployment", "listen", "https_port"), 65536),
    (("deployment", "listen", "https_port"), 0),
    (("deployment", "logging", "retention_days"), 3651),
    (("deployment", "logging", "metrics_opt_in"), 1),
    (("deployment", "cache_policy", "global", "inactive_seconds"), True),
    (("deployment", "cache_policy", "global", "max_size_bytes"), 0),
    (("deployment", "cache_policy", "disk_pressure", "warning_free_bytes"), 0),
    (("deployment", "native_packages", "policy"), "auto"),
    (("deployment", "nginx", "ownership"), "adopt"),
    (("deployment", "tls", "mode"), "self-signed"),
    (("deployment", "firewall", "modify"), "false"),
])
def test_reject_wrong_types_ranges_and_unsafe_enums(path, value):
    doc = fixture()
    cursor = doc
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    refuse(doc)


@pytest.mark.parametrize("path,value", [
    (("deployment", "listen", "hostname"), "bad..example"),
    (("deployment", "listen", "hostname"), "a" * 64 + ".invalid"),
    (("deployment", "listen", "bind_address"), "0.0.0.0/0"),
    (("deployment", "listen", "bind_address"), "127.000.0.1"),
    (("deployment", "paths", "cache_root"), "/tmp/../cache"),
    (("deployment", "paths", "cache_root"), "/tmp//cache"),
    (("deployment", "paths", "cache_root"), "/tmp/cache\nbad"),
    (("deployment", "paths", "cache_root"), "/tmp/cache/"),
    (("deployment", "tls", "private_key_file"), "file:///etc/tls/key"),
])
def test_reject_noncanonical_ips_hosts_paths(path, value):
    doc = fixture()
    cursor = doc
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    refuse(doc)


@pytest.mark.parametrize("url", [
    "http://mirror.example.invalid/debian/",
    "https://user:secret@mirror.example.invalid/debian/",
    "https://127.0.0.1/debian/",
    "https://127.000.0.1/debian/",
    "https://0x7f.1/debian/",
    "https://mirror.example.invalid:/debian/",
    "https://mirror.example.invalid/deb ian/",
    "https://mirror.example.invalid/debian",
    "https://mirror.example.invalid/a/../b/",
    "https://mirror.example.invalid/a//b/",
    "https://mirror.example.invalid/a/%2e%2e/",
    "https://mirror.example.invalid/debian/?private=1",
    "https://mirror.example.invalid/debian/#marker",
    "https://mirror.example.invalid:99999/debian/",
])
def test_reject_untrusted_or_ambiguous_upstreams(url):
    doc = fixture()
    doc["repositories"][0]["upstream"]["base_url"] = url
    refuse(doc)


def test_reject_base_url_host_missing_from_allowlist():
    doc = fixture()
    doc["repositories"][0]["upstream"]["allowed_hosts"] = ["other.example.invalid"]
    refuse(doc)


def test_reject_normalized_duplicate_upstream_host():
    doc = fixture()
    doc["repositories"][0]["upstream"]["allowed_hosts"] = [
        "mirror.example.invalid", "MIRROR.example.invalid"]
    refuse(doc)


def test_reject_duplicate_repo_id_and_upstream_layout_identity():
    doc = fixture()
    same = copy.deepcopy(doc["repositories"][0])
    doc["repositories"].append(same)
    refuse(doc)
    same["id"] = "another-id"
    refuse(doc)


def test_reject_unknown_fields_at_every_depth():
    for key in ("root", "deployment", "repository", "layout", "override"):
        doc = fixture()
        loc = {
            "root": doc,
            "deployment": doc["deployment"],
            "repository": doc["repositories"][0],
            "layout": doc["repositories"][0]["layout"],
            "override": doc["repositories"][0]["cache_overrides"],
        }[key]
        loc["authorized"] = True
        refuse(doc)


def test_reject_apt_dnf_layout_cross_contamination():
    doc = fixture()
    doc["repositories"][0]["layout"]["metadata_path"] = "repodata/repomd.xml"
    refuse(doc)
    doc = fixture()
    doc["repositories"][1]["layout"]["suites"] = ["trixie"]
    refuse(doc)


def test_reject_duplicate_keys_in_nested_json_objects():
    payload = EXAMPLE.read_bytes().replace(
        b'"max_size_bytes": 10737418240',
        b'"max_size_bytes": 10737418240, "max_size_bytes": 10737418240')
    with pytest.raises(InstallInputError, match="Duplicate JSON"):
        parse_install_bytes(payload)


@pytest.mark.parametrize("payload", [
    b"\xef\xbb\xbf{}",
    b"{}\n{}",
    b"NaN",
    b'{"kind":"\\ud800"}',
    b'{"bad": Infinity}',
    b" " * (1024 * 1024 + 1),
    b"\xff",
    b"[" * 30 + b"0" + b"]" * 30,
    b'{"schema_version":' + b"9" * 6000 + b"}",
])
def test_reject_malformed_oversized_or_deep_documents(payload):
    with pytest.raises(InstallInputError):
        parse_install_bytes(payload)


def test_reject_missing_required_and_forbidden_null():
    doc = fixture()
    del doc["deployment"]["nginx"]
    refuse(doc)
    doc = fixture()
    doc["deployment"]["tls"] = None
    refuse(doc)
    doc = fixture()
    doc["repositories"] = None
    refuse(doc)


def test_validate_optional_fields_do_not_patch_existing_overrides():
    doc = fixture()
    doc["deployment"].pop("firewall")
    doc["deployment"]["logging"].pop("metrics_opt_in")
    doc["repositories"][0].pop("cache_overrides")
    assert parse_install_bytes(as_bytes(doc)) == doc
    doc["repositories"][0]["cache_overrides"] = {"inactive_seconds": 100}
    assert parse_install_bytes(as_bytes(doc)) == doc
    doc["repositories"][0]["cache_overrides"]["max_size_bytes"] = True
    refuse(doc)


def test_relative_metadata_path_requires_tokens():
    doc = fixture()
    doc["repositories"][1]["layout"]["metadata_path"] = "../repodata/repomd.xml"
    refuse(doc)
    doc["repositories"][1]["layout"]["metadata_path"] = "repodata//repomd.xml"
    refuse(doc)


@pytest.mark.parametrize("release,python_version,expected", [
    ('ID=debian\nVERSION_ID="13"\n', (3, 13), "debian"),
    ("ID=debian\nVERSION_ID=13.1\n", (3, 13), "debian"),
    ("ID=almalinux\nVERSION_ID=10.0\n", (3, 12), "almalinux"),
    ("ID=almalinux\nVERSION_ID=10.1\n", (3, 12), "almalinux"),
])
def test_supported_os_identity_read_only(release, python_version, expected):
    assert validate_os_identity(release, python_version) == expected


@pytest.mark.parametrize("release,python_version", [
    ("ID=debian\nVERSION_ID=12\n", (3, 13)),
    ("ID=almalinux\nVERSION_ID=9.5\n", (3, 12)),
    ("ID=ubuntu\nVERSION_ID=24.04\n", (3, 12)),
    ("ID=debian\nID=debian\nVERSION_ID=13\n", (3, 13)),
    ("ID=debian\nVERSION_ID=13\n", (3, 12)),
    ("ID=almalinux\nVERSION_ID=10\n", (3, 13)),
    ("ID=debian\nVERSION_ID=13beta\n", (3, 13)),
    ("VERSION_ID=13\n", (3, 13)),
])
def test_unsupported_os_or_python_rejected(release, python_version):
    with pytest.raises(InstallInputError):
        validate_os_identity(release, python_version)


def test_no_subprocess_network_or_filesystem_side_effects(monkeypatch):
    # Input validation is pure. Neither a path probe nor a network request
    # is necessary to recognize an inert fixture and reject foreign input.
    import os
    import subprocess
    import socket

    def blocked(*args, **kwargs):
        raise AssertionError("validator attempted a host or network operation")

    monkeypatch.setattr(os, "system", blocked)
    monkeypatch.setattr(subprocess, "run", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    doc = fixture()
    assert validate_install_document(doc) == doc
    doc["deployment"]["nginx"]["ownership"] = "adopt"
    refuse(doc)
