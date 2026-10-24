"""Versioned JSON / exit code v1 contract across all three executables (#107).

This is a parser and output test, not native signed-release acceptance.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from repocache import cli

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))
sys.path.insert(0, str(ROOT / "workstation/src"))

import repocache_client as client  # noqa: E402
from repocache_release import cli as release  # noqa: E402


def assert_error_document(raw: str, code: str) -> dict:
    doc = json.loads(raw)  # Also rejects ANSI, concatenated documents and prose.
    assert doc["schema_version"] == 1
    assert doc["ok"] is False
    assert doc["error"]["code"] == code
    assert isinstance(doc["error"]["message"], str)
    assert doc["error"]["message"]
    return doc


@pytest.mark.parametrize("args", [
    ["--json", "repos", "show"],
    ["repos", "show", "--json"],
    ["--json", "repos", "nonexistent-action"],
    ["--json", "repos", "show", "debian", "--unknown-option"],
])
def test_server_json_syntax_failure_does_not_reach_nginx(monkeypatch, args):
    monkeypatch.setattr(cli, "nginx_config", lambda *_a, **_kw:
                        pytest.fail("Parser must fail before NGINX"))
    monkeypatch.setattr(cli, "discover_repos", lambda *_a, **_kw:
                        pytest.fail("Parser must fail before repository read"))
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 2, (args, result.output, repr(result.exception))
    assert_error_document(result.stdout, "INVALID_ARGUMENT")
    assert not result.stderr


def test_server_error_normalization_adds_version_and_keeps_retryability(capsys):
    cli.emit_json({"ok": False, "status": "busy", "performed": False,
                   "retryable": True, "error": "Update already running"})
    result = assert_error_document(capsys.readouterr().out, "BUSY")
    assert result["status"] == "busy"
    assert result["retryable"] is True
    assert result["performed"] is False


def test_server_success_json_additive_fields_only(monkeypatch):
    original = {"ok": True, "validated": True, "partial": False, "stdout": "",
                "source": "fixture", "warnings": [], "stderr": ""}
    repo = {"name": "debian", "path": "/debian/", "upstream": "https://example.org"}
    monkeypatch.setattr(cli, "nginx_config", lambda *_: original)
    monkeypatch.setattr(cli, "discover_repos", lambda *_: [repo])
    result = CliRunner().invoke(cli.app, ["--json", "repos", "list"])
    assert result.exit_code == 0, result.output
    doc = json.loads(result.stdout)
    assert doc["schema_version"] == 1
    assert doc["ok"] is True
    assert doc["repos"] == [repo]


@pytest.mark.parametrize("argv", [
    ["--json", "repos", "unknown"],
    ["repos", "list", "--json", "--unknown-option"],
    ["--json", "repos", "submit"],  # Missing --output is an operation refusal.
])
def test_client_error_contract_with_no_source_mutation(monkeypatch, tmp_path, capsys, argv):
    if argv[-1] == "submit":
        monkeypatch.setattr(client, "discover", lambda *_a: [])
        monkeypatch.setattr(client, "_distro", lambda *_a: {"ID": "debian"})
    else:
        monkeypatch.setattr(client, "discover", lambda *_a:
                            pytest.fail("Parse errors must not read sources"))
    result = client.run(argv, root=tmp_path)
    assert result == 2
    output = capsys.readouterr()
    doc = assert_error_document(output.out, "OPERATION_FAILED" if
                                argv[-1] == "submit" else "INVALID_ARGUMENT")
    assert doc["ok"] is False
    assert not output.err
    assert not list(tmp_path.iterdir())


def test_client_invalid_repository_check_preserves_exit_three(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(client, "discover", lambda *_a: [{
        "name": "bad", "enabled": True, "route": "direct",
        "urls": ["invalid"], "support": "unknown",
    }])
    monkeypatch.setattr(client, "_classify_repository", lambda *_: "invalid")
    monkeypatch.setattr(client, "_connectivity", lambda *_: [
        {"name": "dns", "ok": True, "detail": "fixture"},
    ])
    monkeypatch.setattr(client, "_catalog", lambda *_: {"schema": 1, "repositories": []})
    monkeypatch.setattr(client, "_distro", lambda *_: {"ID": "debian", "VERSION_ID": "13"})
    assert client.run(["check", "--json"], root=tmp_path) == 3
    doc = assert_error_document(capsys.readouterr().out, "REPOSITORY_INVALID")
    assert doc["exit_code"] == 3
    assert doc["compatibility_summary"]["invalid"] == 1
    assert not list(tmp_path.iterdir())


def test_client_required_check_failure_preserves_exit_one(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(client, "discover", lambda *_: [])
    monkeypatch.setattr(client, "_connectivity", lambda *_: [
        {"name": "dns", "ok": False, "detail": "offline"},
    ])
    monkeypatch.setattr(client, "_distro", lambda *_: {"ID": "debian"})
    assert client.run(["--json", "check"], root=tmp_path) == 1
    doc = assert_error_document(capsys.readouterr().out, "REQUIRED_CHECK_FAILED")
    assert doc["exit_code"] == 1
    assert not list(tmp_path.iterdir())


def test_client_json_success_is_versioned_but_preserves_list_fields(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(client, "discover", lambda *_: [])
    monkeypatch.setattr(client, "_distro", lambda *_: {"ID": "debian"})
    assert client.run(["--json", "repos", "list"], root=tmp_path) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["schema_version"] == 1
    assert doc["ok"] is True
    assert doc["repositories"] == []


@pytest.mark.parametrize("argv", [
    ["--json", "candidate", "unknown"],
    ["candidate", "status", "latest", "--json"],
])
def test_workstation_exit_and_structured_errors_preserved(capsys, argv):
    result = release.main(argv)
    assert result == (1 if "latest" in argv else 2)
    document = assert_error_document(
        capsys.readouterr().out,
        "INVALID_RELEASE" if "latest" in argv else "INVALID_ARGUMENT",
    )
    assert "result" not in document


def test_contract_specifies_legacy_numeric_exceptions_explicitly():
    contract = (ROOT / "docs/architecture/CLI_ERROR_CONTRACT_V1.md").read_text()
    for code in ("0", "1", "2", "3", "75"):
        assert f"`{code}`" in contract
    assert "NOT" in contract or "compatibility" in contract
