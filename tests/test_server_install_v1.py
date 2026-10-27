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


# Independent security review (RC-192-01 through RC-192-09) regressions.


def _with_second_apt(doc: dict, url: str) -> dict:
    other = copy.deepcopy(doc["repositories"][0])
    other["id"] = "second-apt"
    other["upstream"]["base_url"] = url
    doc["repositories"].append(other)
    return doc


def test_review_duplicate_effective_https_origin_default_port():
    doc = _with_second_apt(
        fixture(), "https://mirror.example.invalid:443/debian/")
    refuse(doc)


def test_review_reordered_apt_component_set_is_same_identity():
    doc = fixture()
    doc["repositories"][0]["layout"]["components"] = ["main", "contrib"]
    second = copy.deepcopy(doc["repositories"][0])
    second["id"] = "apt-duplicate-set"
    second["layout"]["components"] = ["contrib", "main"]
    doc["repositories"].append(second)
    refuse(doc)


def test_review_case_sensitive_url_paths_are_distinct():
    doc = _with_second_apt(
        fixture(), "https://mirror.example.invalid/Debian/")
    assert parse_install_bytes(as_bytes(doc)) == doc


def test_review_effective_port_normalization_and_canonical_root_path():
    doc = fixture()
    doc["repositories"][0]["upstream"]["base_url"] = (
        "https://mirror.example.invalid/")
    assert parse_install_bytes(as_bytes(doc)) == doc
    doc["repositories"][0]["upstream"]["base_url"] = (
        "https://mirror.example.invalid:000443/")
    assert parse_install_bytes(as_bytes(doc)) == doc


@pytest.mark.parametrize("control", ["\u0085", "\u202e", "\u200b", "\u0001"])
def test_review_control_or_format_unicode_rejected(control):
    doc = fixture()
    doc["deployment"]["paths"]["cache_root"] = (
        "/var/cache/repocache/x" + control + "y")
    refuse(doc)


@pytest.mark.parametrize("suffix", ["a[0]/", "$arg_target/", "a;b/",
                                      "a?token/", "a b/", "a%20b/"])
def test_review_unsafe_unescaped_upstream_paths_rejected(suffix):
    doc = fixture()
    doc["repositories"][0]["upstream"]["base_url"] = (
        "https://mirror.example.invalid/" + suffix)
    refuse(doc)


def test_review_oversize_predecoded_document_rejected():
    doc = fixture()
    doc["repositories"] = []
    for i in range(500):
        entry = copy.deepcopy(fixture()["repositories"][0])
        entry["id"] = f"apt{i}"
        entry["upstream"]["base_url"] = (
            f"https://mirror.example.invalid/debian{i}/")
        entry["layout"]["release_key_refs"] = [
            "file:/etc/repocache/keys/" + "a" * 1870]
        doc["repositories"].append(entry)
    payload = as_bytes(doc)
    assert len(payload) > 1024 * 1024
    refuse(doc)
    with pytest.raises(InstallInputError):
        validate_install_document(doc)


def test_review_python_version_elements_must_be_real_ints():
    with pytest.raises(InstallInputError):
        validate_os_identity(
            "ID=debian\nVERSION_ID=13\n", (3.0, 13.0))


def test_review_private_tls_key_cannot_overlap_generated_include():
    doc = fixture()
    doc["deployment"]["tls"]["private_key_file"] = (
        doc["deployment"]["paths"]["generated_include"])
    refuse(doc)


def test_review_public_trust_reference_cannot_reference_private_tls_key():
    doc = fixture()
    doc["repositories"][0]["layout"]["release_key_refs"] = [
        "file:" + doc["deployment"]["tls"]["private_key_file"]]
    refuse(doc)


def test_review_managed_directory_and_key_path_overlap_rejected():
    doc = fixture()
    doc["deployment"]["tls"]["private_key_file"] = (
        doc["deployment"]["paths"]["cache_root"] + "/key.pem")
    refuse(doc)
    doc = fixture()
    doc["deployment"]["paths"]["log_root"] = (
        doc["deployment"]["paths"]["state_root"] + "/logs")
    refuse(doc)


def test_review_public_ref_inside_managed_cache_directory_rejected():
    doc = fixture()
    doc["repositories"][1]["layout"]["gpg_key_refs"] = [
        "file:" + doc["deployment"]["paths"]["cache_root"] + "/key.gpg"]
    refuse(doc)


def test_review_validated_return_is_an_independent_deep_snapshot():
    doc = fixture()
    checked = validate_install_document(doc)
    doc["repositories"][0]["upstream"]["base_url"] = "http://127.0.0.1/"
    doc["deployment"]["tls"]["private_key_file"] = "/unsafe/key"
    assert checked["repositories"][0]["upstream"]["base_url"] == (
        "https://mirror.example.invalid/debian/")
    assert checked["deployment"]["tls"]["private_key_file"] == (
        "/etc/repocache/tls/example-key.pem")


def test_review_oversize_integer_token_rejected_without_global_int_limit():
    import sys

    get_limit = getattr(sys, "get_int_max_str_digits", None)
    set_limit = getattr(sys, "set_int_max_str_digits", None)
    old = get_limit() if get_limit else None
    try:
        if set_limit:
            set_limit(0)
        payload = b'{"schema_version":' + b"9" * 100000 + b"}"
        with pytest.raises(InstallInputError):
            parse_install_bytes(payload)
    finally:
        if set_limit and old is not None:
            set_limit(old)


def test_review_invalid_predecoded_json_values_rejected():
    doc = fixture()
    doc["deployment"]["listen"]["https_port"] = float("nan")
    with pytest.raises(InstallInputError):
        validate_install_document(doc)


def test_review_false_for_apply_argument_rejected():
    with pytest.raises(InstallInputError):
        validate_install_document(fixture(), for_apply="false")


# RC-192-04 follow-up: inverse ancestry and prefix-boundary regression tests.


def _reject_both_document_apis(document: dict) -> None:
    with pytest.raises(InstallInputError):
        parse_install_bytes(as_bytes(document))
    with pytest.raises(InstallInputError):
        validate_install_document(document)


@pytest.mark.parametrize("file_path", [
    "/var/cache/nginx",
    "/var/log/nginx",
])
def test_review_inverse_file_ancestor_of_managed_directory(file_path):
    document = fixture()
    document["deployment"]["paths"]["generated_include"] = file_path
    _reject_both_document_apis(document)


@pytest.mark.parametrize("reference", [
    "file:/var/cache/nginx",
    "file:/var/log/nginx",
    "file:/var/lib/repocache",
])
def test_review_inverse_trust_ref_ancestor_of_managed_directory(reference):
    document = fixture()
    document["repositories"][0]["layout"]["release_key_refs"] = [reference]
    _reject_both_document_apis(document)


def test_review_tls_certificate_file_ancestor_of_private_key():
    document = fixture()
    document["deployment"]["tls"]["certificate_file"] = "/etc/repocache/tls"
    _reject_both_document_apis(document)


def test_review_public_trust_ref_file_ancestor_of_tls_private_key():
    document = fixture()
    document["repositories"][0]["layout"]["release_key_refs"] = [
        "file:/etc/repocache/tls"]
    _reject_both_document_apis(document)


def test_review_public_trust_ref_cannot_overlap_tls_certificate():
    document = fixture()
    document["repositories"][0]["layout"]["release_key_refs"] = [
        "file:" + document["deployment"]["tls"]["certificate_file"]]
    _reject_both_document_apis(document)


def test_review_valid_similar_prefix_paths_remain_distinct():
    document = fixture()
    # These names look similar but end at different path segment boundaries.
    document["deployment"]["paths"]["generated_include"] = (
        "/var/cache/nginx-cache.conf")
    document["deployment"]["tls"]["certificate_file"] = (
        "/etc/repocache/tls-archive/cert.pem")
    document["repositories"][0]["layout"]["release_key_refs"] = [
        "file:/var/cache/nginx-archive/pub.gpg"]
    assert parse_install_bytes(as_bytes(document)) == document
    assert validate_install_document(document) == document


def test_review_separate_file_paths_inside_same_parent_are_allowed():
    document = fixture()
    document["deployment"]["tls"]["certificate_file"] = (
        "/etc/repocache/tls/cert.pem")
    document["deployment"]["tls"]["private_key_file"] = (
        "/etc/repocache/tls/key.pem")
    assert parse_install_bytes(as_bytes(document)) == document


# RC-192-09: mutation-resistant proof that json.loads uses our bounded
# pre-conversion integer callback, not a later post-conversion range check.


def test_review_integer_token_guard_rejects_before_conversion():
    token = b"9" * 1000  # Small bounded fixture, well below the 1 MiB input cap.
    payload = b'{"schema_version":' + token + b"}"
    # If parse_int=_parse_int is replaced by parse_int=int, _depth() still
    # rejects the huge integer but with a different, post-conversion error.
    with pytest.raises(InstallInputError,
                       match="integer token exceeds signed 64-bit range"):
        parse_install_bytes(payload)


def test_review_parser_calls_preconversion_integer_callback(monkeypatch):
    from repocache import server_install_v1 as validator

    tokens = []
    callback = validator._parse_int

    def observe_before_conversion(token: str) -> int:
        tokens.append(len(token))
        return callback(token)

    monkeypatch.setattr(validator, "_parse_int", observe_before_conversion)
    payload = b'{"schema_version":' + b"8" * 1000 + b"}"
    with pytest.raises(InstallInputError,
                       match="integer token exceeds signed 64-bit range"):
        validator.parse_install_bytes(payload)
    assert tokens == [1000]  # Must fail if json.loads silently switches to int.
