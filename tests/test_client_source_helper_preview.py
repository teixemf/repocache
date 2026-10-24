"""Non-installed client helper prototype CLI and privilege boundary tests.

No tests edit real /etc. This is neither a release CLI contract nor a root
helper; _test_root is internal test injection guarded by source_preflight.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import stat
import sys
from pathlib import Path

import pytest


CLIENT = Path(__file__).resolve().parents[1] / "client"
sys.path.insert(0, str(CLIENT))
helper = importlib.import_module("source_helper_preview")
pre = importlib.import_module("source_preflight")
SOURCE = "etc/apt/sources.list.d/ci.sources"
CONTENTS = b"Types: deb\nURIs: https://deb.debian.org/debian\nSuites: trixie\nComponents: main\n"


@pytest.fixture
def host(tmp_path):
    tmp_path.chmod(0o700)
    marker = tmp_path / pre.MARKER
    marker.write_bytes(pre.TEST_MAGIC)
    marker.chmod(0o600)
    file = tmp_path / SOURCE
    file.parent.mkdir(parents=True)
    file.write_bytes(CONTENTS)
    return tmp_path


def invoke(capsys, argv, *, root=None):
    result = helper.main(argv, _test_root=root)
    output = capsys.readouterr()
    assert output.err == ""
    doc = json.loads(output.out)
    assert doc["schema_version"] == 1
    assert doc["read_only"] is True
    assert doc["write_eligible"] is False
    return result, doc


@pytest.mark.parametrize("args", (["--json", "status"], ["status", "--json"]))
def test_status_is_rootless_and_not_installed(capsys, monkeypatch, args):
    monkeypatch.setattr(pre, "inspect_source", lambda *a, **kw:
                        pytest.fail("status must not touch /etc or any source"))
    code, doc = invoke(capsys, args)
    assert code == 0 and doc["ok"]
    assert doc["installed"] is False
    assert doc["source_writes_supported"] is False
    assert doc["semantic_repository_validation_supported"] is False
    assert doc["capabilities"] == ["status", "inspect-source"]
    assert "commit" not in doc["capabilities"]


@pytest.mark.parametrize("args", (
    ["--json", "inspect-source", "--source", SOURCE],
    ["inspect-source", "--source", SOURCE, "--json"],
))
def test_scoped_inspection_passes_without_disclosing_config(capsys, host, args):
    before = (host / SOURCE).stat()
    code, doc = invoke(capsys, args, root=host)
    assert code == 0 and doc["ok"]
    assert doc["operation"] == "inspect-source"
    assert doc["filesystem_preflight"] == "pass"
    assert doc["source_contents_returned"] is False
    assert doc["source_path_returned"] is False
    for key in ("repository_syntax_verified", "package_signatures_verified",
                "upstream_fallback_verified", "managed_ownership_verified"):
        assert doc[key] is False
    assert SOURCE not in json.dumps(doc)
    assert "deb.debian.org" not in json.dumps(doc)
    assert hashlib.sha256(CONTENTS).hexdigest() not in json.dumps(doc)
    assert (host / SOURCE).read_bytes() == CONTENTS
    after = (host / SOURCE).stat()
    assert (after.st_dev, after.st_ino, after.st_mtime_ns) == (
        before.st_dev, before.st_ino, before.st_mtime_ns)


@pytest.mark.parametrize("source", (
    "../../etc/shadow",
    "/etc/apt/sources.list",
    "etc/apt/sources.list.d/../../shadow",
    "etc/yum.repos.d/../passwd",
    "https://user:very-secret@example.org/",
    "etc/apt/sources.list.d/\u202e-malicious.sources",
))
def test_bad_source_path_is_redacted_and_fails(capsys, host, source):
    status, doc = invoke(capsys, ["inspect-source", "--source", source, "--json"],
                         root=host)
    assert status != 0 and not doc["ok"]
    assert doc["error"]["code"] == "SOURCE_PREFLIGHT_REFUSED"
    assert source not in json.dumps(doc)
    assert "very-secret" not in json.dumps(doc)
    assert (host / SOURCE).read_bytes() == CONTENTS


@pytest.mark.parametrize("args", (
    ["--json", "commit", "--source", SOURCE],
    ["--json", "recover"],
    ["--json", "restore"],
    ["--json", "validate", "--source", SOURCE],
    ["--json", "inspect-source", "--source", SOURCE, "--root", "/"],
    ["--json", "inspect-source", "--source", "secret", "--arbitrary", "token-abc"],
    ["--json", "inspect-source"],
    ["--json"],
))
def test_unapproved_commands_and_options_fail_closed_without_echo(
        capsys, host, args):
    code, doc = invoke(capsys, args, root=host)
    assert code == 2 and not doc["ok"]
    assert doc["error"]["code"] == "INVALID_ARGUMENTS"
    assert "token-abc" not in json.dumps(doc)
    assert (host / SOURCE).read_bytes() == CONTENTS


def test_unprivileged_inspection_cannot_target_native_root(capsys, monkeypatch):
    monkeypatch.setattr(helper.os, "geteuid", lambda: 65534)
    code, doc = invoke(capsys, ["--json", "inspect-source", "--source", SOURCE])
    assert code != 0
    assert doc["error"]["code"] == "ROOT_REQUIRED"
    assert doc["write_eligible"] is False


def test_missing_fixture_marker_does_not_enable_root_override(capsys, host):
    (host / pre.MARKER).unlink()
    code, doc = invoke(capsys, ["--json", "inspect-source", "--source", SOURCE],
                       root=host)
    assert code != 0 and not doc["ok"]
    assert doc["error"]["code"] == "SOURCE_PREFLIGHT_REFUSED"


@pytest.mark.parametrize("mutation", ("symlink", "world-writable", "hardlink"))
def test_unsafe_sources_fail_without_mutation(capsys, host, mutation):
    path = host / SOURCE
    if mutation == "symlink":
        path.unlink()
        path.symlink_to(host / pre.MARKER)
    elif mutation == "world-writable":
        path.chmod(0o666)
    else:
        os.link(path, path.parent / "copy.sources")
    code, doc = invoke(capsys, ["--json", "inspect-source", "--source", SOURCE],
                       root=host)
    assert code == 3 and doc["error"]["code"] == "SOURCE_PREFLIGHT_REFUSED"


def test_xattrs_are_reported_only_as_presence(capsys, host):
    path = host / SOURCE
    try:
        os.setxattr(path, "user.repocache", b"sensitive-secret-value")
    except OSError:
        pytest.skip("xattrs unavailable on the sandbox filesystem")
    code, doc = invoke(capsys, ["--json", "inspect-source", "--source", SOURCE],
                       root=host)
    assert code == 0 and doc["ok"]
    assert doc["extended_attributes_present"] is True
    assert doc["write_eligible"] is False
    assert "sensitive-secret-value" not in json.dumps(doc)
    assert "user.repocache" not in json.dumps(doc)


def test_human_status_and_failure_output_are_noninteractive(capsys, host):
    assert helper.main(["status"]) == 0
    plain = capsys.readouterr().out
    assert "read-only" in plain.lower()
    assert "privileges" in plain.lower()
    assert helper.main(["inspect-source", "--source", "../../secret"],
                       _test_root=host) == 3
    plain = capsys.readouterr().out
    assert "SOURCE_PREFLIGHT_REFUSED" in plain
    assert "../../secret" not in plain


def test_installer_and_approved_client_cli_do_not_reference_preview():
    assert "source_helper_preview" not in (CLIENT / "repocache_client.py").read_text()
    assert "source_helper_preview" not in (CLIENT / "install.sh").read_text()
    assert "Applying changes is disabled until reviewed" in (
        CLIENT / "repocache_client.py").read_text()
