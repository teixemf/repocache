"""CLI v1 conformance gate for registered *current* server/client commands (#107).

This intentionally enumerates the transient public parser surface, including
legacy commands. A future parser edit must update this inventory, its behavior
tests and docs together. Planned CLI verbs are NOT represented as implemented.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

from typer.main import get_command
from typer.testing import CliRunner

from repocache import cli


ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "client" / "repocache_client.py"
INVENTORY = ROOT / "tests" / "cli_surface_inventory.json"

spec = importlib.util.spec_from_file_location("client_cli_contract_v1", CLIENT)
client = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(client)


def _server_paths():
    def walk(command, prefix=()):
        paths = set()
        if hasattr(command, "commands"):
            for name, child in command.commands.items():
                path = (*prefix, name)
                paths.add(" ".join(path))
                paths.update(walk(child, path))
        return paths
    return walk(get_command(cli.app))


def _client_paths():
    def walk(parser, prefix=()):
        paths = set()
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, child in action.choices.items():
                    path = (*prefix, name)
                    paths.add(" ".join(path))
                    paths.update(walk(child, path))
        return paths
    return walk(client.build_parser())


def test_entire_registered_command_surface_has_an_explicit_reviewed_inventory():
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    assert inventory["architecture"] == "docs/architecture/CLI_ARCHITECTURE.md"
    assert inventory["release_operator"]["status"] == "planned-not-installed"
    assert _server_paths() == set(inventory["server"])
    assert _client_paths() == set(inventory["client"])
    assert len(inventory["server"]) == len(set(inventory["server"]))
    assert len(inventory["client"]) == len(set(inventory["client"]))


def test_canonical_server_repos_aliases_and_json_equivalence(monkeypatch):
    calls = []
    data = {"ok": True, "validated": True, "source": "fixture",
            "partial": False, "warnings": [], "stderr": "", "stdout": ""}
    repo = {"name": "debian", "path": "/debian/", "upstream": "https://example.org"}
    monkeypatch.setattr(cli, "nginx_config", lambda *_: calls.append("read") or data)
    monkeypatch.setattr(cli, "discover_repos", lambda _: [repo])
    runner = CliRunner()
    invocations = [
        ["--json", "repos", "list"],
        ["repos", "list", "--json"],
        ["--json", "repo", "ls"],
        ["repo", "ls", "--json"],
    ]
    for args in invocations:
        result = runner.invoke(cli.app, args)
        assert result.exit_code == 0, (args, result.output)
        assert json.loads(result.stdout)["repos"] == [repo]
    for args in (
        ["repo", "show", "debian", "--json"],
        ["--json", "repos", "info", "debian"],
    ):
        result = runner.invoke(cli.app, args)
        assert result.exit_code == 0, (args, result.output)
        assert json.loads(result.stdout)["repo"] == repo
    assert calls == ["read"] * 6


def test_unknown_repo_returns_one_json_error_document_without_upstream_probe(monkeypatch):
    data = {"ok": True, "stdout": ""}
    monkeypatch.setattr(cli, "nginx_config", lambda *_: data)
    monkeypatch.setattr(cli, "discover_repos", lambda _: [])
    monkeypatch.setattr(cli, "check_upstream", lambda *_: 1 / 0)
    result = CliRunner().invoke(cli.app, ["--json", "repo", "test", "missing"])
    assert result.exit_code == 1, result.output
    assert json.loads(result.stdout)["error"]["code"] == "REPOSITORY_NOT_FOUND"
    assert not result.stderr



def test_failed_discovery_is_not_misreported_as_an_absent_repository(monkeypatch):
    monkeypatch.setattr(cli, "nginx_config", lambda *_: {
        "ok": False, "partial": True, "stdout": ""})
    monkeypatch.setattr(cli, "discover_repos", lambda *_: [])
    result = CliRunner().invoke(cli.app, ["--json", "repos", "show", "debian"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["error"]["code"] == "REPOSITORY_LOOKUP_UNAVAILABLE"


def test_server_object_help_and_stream_json_refusal_are_read_only(monkeypatch):
    monkeypatch.setattr(cli, "nginx_config", lambda *_: 1 / 0)
    monkeypatch.setattr(cli, "command", lambda *_a, **_k: 1 / 0)
    runner = CliRunner()
    help_result = runner.invoke(cli.app, ["repos"])
    assert help_result.exit_code in (0, 2)
    assert "list" in help_result.output
    for args in (["--json", "logs", "follow"], ["--json", "service", "reload", "--yes"]):
        refused = runner.invoke(cli.app, args)
        assert refused.exit_code == 2, (args, refused.output)
        assert json.loads(refused.stdout)["error"]["code"] == "UNSUPPORTED_OUTPUT_MODE"


def test_client_aliases_and_global_option_placement_do_not_mutate(monkeypatch, tmp_path, capsys):
    calls = []
    monkeypatch.setattr(client, "discover", lambda *_: calls.append("discover") or [])
    monkeypatch.setattr(client, "_distro", lambda *_: "debian")
    for argv in (
        ["--json", "repos", "list"],
        ["repos", "list", "--json"],
        ["repo", "ls", "--json"],
        ["repo", "--json", "list"],
        ["check", "--json", "--server", "https://cache.example.org"],
    ):
        if argv[0] == "check":
            monkeypatch.setattr(client, "_connectivity", lambda *_: [
                {"name": "dns", "ok": True, "detail": "ok"}])
            monkeypatch.setattr(client, "_catalog", lambda *_: {"schema": 1, "repositories": []})
        assert client.run(argv, root=tmp_path) == 0
        assert isinstance(json.loads(capsys.readouterr().out), dict)
    assert len(calls) == 5
    assert list(tmp_path.iterdir()) == []


def test_client_object_only_help_never_loads_repository_sources(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(client, "discover", lambda *_: 1 / 0)
    for noun in ("repos", "repo"):
        assert client.run([noun], root=tmp_path) == 0
        assert "list" in capsys.readouterr().out
    assert list(tmp_path.iterdir()) == []


def test_client_sync_write_opt_in_still_refuses_unsafe_work(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(client, "discover", lambda *_: [])
    monkeypatch.setattr(client, "_distro", lambda *_: "debian")
    monkeypatch.setattr(client, "_catalog", lambda *_: 1 / 0)
    assert client.run(["repos", "sync", "--apply"], root=tmp_path) == 2
    assert "disabled until reviewed" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


def test_preserved_existing_cli_contract_anchors():
    assert {"check", "repos list", "repos submit", "repos sync"} <= _client_paths()
    assert {"update list", "repos list", "repos show"} <= _server_paths()
