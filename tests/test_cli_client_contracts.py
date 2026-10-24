"""Non-interactive REPOCACHE server/client CLI contracts (#85).

No network, no local host APT/DNF writes; client filesystem is a temp root.
These are in-tree regressions, NOT signed native online-install acceptance.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from repocache import cli, updater


def _client():
    path = Path(__file__).resolve().parents[1] / "client/repocache_client.py"
    spec = importlib.util.spec_from_file_location("repocache_client_cli_fixture", path)
    assert spec is not None and spec.loader is not None
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


@pytest.fixture
def test_client_root(tmp_path):
    (tmp_path / "etc/apt").mkdir(parents=True)
    (tmp_path / "etc/os-release").write_text('ID=debian\nVERSION_ID="13"\n')
    (tmp_path / "etc/apt/sources.list").write_text(
        "deb https://deb.debian.org/debian trixie main\n")
    return tmp_path


def test_client_approved_help_verbs_are_noninteractive(capsys):
    client = _client()
    for argv, expected in (
        (["--help"], "repos"),
        (["repos", "--help"], "submit"),
        (["repos", "submit", "--help"], "--output"),
        (["repos", "sync", "--help"], "--apply"),
        (["check", "--help"], "--help"),
    ):
        with pytest.raises(SystemExit) as exited:
            client.run(argv)
        assert exited.value.code == 0
        output = capsys.readouterr().out
        assert expected in output
        assert "Continue?" not in output


def test_client_list_and_export_from_disposable_source_tree(
        test_client_root, capsys):
    client = _client()
    args = ["--server", "https://cache.example.org", "--json"]
    assert client.run(args + ["repos", "list"], root=test_client_root) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["os"] == {"ID": "debian", "VERSION_ID": "13"}
    assert len(document["repositories"]) == 1
    assert document["repositories"][0]["urls"] == [
        "https://deb.debian.org/debian"]
    output = test_client_root / "submission.json"
    assert client.run(args + ["repos", "submit", "--output", str(output)],
                      root=test_client_root) == 0
    capsys.readouterr()
    report = json.loads(output.read_text())
    assert report["os"] == {"id": "debian", "version": "13"}
    assert report["repositories"][0]["url"] == "https://deb.debian.org/debian"
    assert os.stat(output).st_mode & 0o777 == 0o600
    assert (test_client_root / "etc/apt/sources.list").read_text() == (
        "deb https://deb.debian.org/debian trixie main\n")


def test_client_sync_apply_denied_and_dry_run_has_no_side_effect(
        test_client_root, monkeypatch, capsys):
    client = _client()
    prior = (test_client_root / "etc/apt/sources.list").read_bytes()
    monkeypatch.setattr(client, "_catalog", lambda server: {
        "schema": 1,
        "repositories": [{"upstream": "https://deb.debian.org/debian/",
                          "cache": "https://cache.example.org/debian/"}],
    })
    args = ["--server", "https://cache.example.org", "--json", "repos", "sync"]
    assert client.run(args, root=test_client_root) == 0
    response = json.loads(capsys.readouterr().out)
    assert "DRY RUN" in response["note"]
    assert len(response["repositories"]) == 1
    assert client.run(args + ["--apply"], root=test_client_root) == 2
    rejected = json.loads(capsys.readouterr().out)
    assert rejected["ok"] is False
    assert (test_client_root / "etc/apt/sources.list").read_bytes() == prior


def test_client_check_noninteractive_offline_returns_structured_code(
        test_client_root, capsys, monkeypatch):
    client = _client()
    monkeypatch.setattr(
        client, "_connectivity", lambda server: [
            {"name": "dns", "ok": False, "detail": "Synthetic offline"}])
    monkeypatch.setattr(client, "_catalog", lambda server:
                        pytest.fail("Offline check must not request catalog"))
    assert client.run(["--server", "https://cache.example.org",
                       "--json", "check"], root=test_client_root) == 1
    response = json.loads(capsys.readouterr().out)
    assert response["exit_code"] == 1
    assert response["ok"] is False
    assert (test_client_root / "etc/apt/sources.list").is_file()


@pytest.mark.parametrize("command,stub,code", [
    (["update", "check", "--json"], "check", 3),
    (["update", "list", "--json"], "list_versions", 3),
])
def test_server_update_json_offline_exit_is_script_friendly(
        command, stub, code, monkeypatch):
    payload = {"status": "offline", "message": "Synthetic offline",
               "installed_version": "0.5.0", "latest_version": None,
               "releases": []}
    monkeypatch.setattr(updater, stub, lambda: payload)
    result = CliRunner().invoke(cli.app, command)
    assert result.exit_code == code
    response = json.loads(result.output)
    assert response["status"] == "offline"
    assert response["installed_version"] == "0.5.0"


def test_server_failed_update_never_prompts_or_reports_success(monkeypatch):
    def reject(*args, **kwargs):
        raise updater.UpdateError("Synthetic unauthenticated candidate")
    monkeypatch.setattr(updater, "apply", reject)
    result = CliRunner().invoke(cli.app, ["update", "--json"])
    assert result.exit_code == 2
    document = json.loads(result.output)
    assert document["performed"] is False
    assert document["ok"] is False
    assert "Synthetic unauthenticated" in document["error"]
    assert "Proceed?" not in result.output


@pytest.fixture
def test_almalinux10_root(tmp_path):
    """Disposable AlmaLinux 10 DNF tree; never inspect the runner's /etc."""
    (tmp_path / "etc/yum.repos.d").mkdir(parents=True)
    (tmp_path / "etc/os-release").write_text(
        'ID=almalinux\nVERSION_ID="10.1"\n', encoding="utf-8")
    (tmp_path / "etc/yum.repos.d/official.repo").write_text(
        "[baseos]\n"
        "name=AlmaLinux BaseOS\n"
        "baseurl=https://repo.almalinux.org/almalinux/10/BaseOS/x86_64/os/\n"
        "enabled=1\n"
        "\n[disabled-third-party]\n"
        "name=Disabled third-party\n"
        "baseurl=https://packages.example.org/private/\n"
        "enabled=0\n", encoding="utf-8")
    return tmp_path


def test_almalinux10_dnf_cli_inventory_export_and_sync_are_read_only(
        test_almalinux10_root, monkeypatch, capsys):
    """Exercise approved client commands against actual DNF parser, offline."""
    client = _client()
    root = test_almalinux10_root
    repo_file = root / "etc/yum.repos.d/official.repo"
    before = repo_file.read_bytes()
    args = ["--server", "https://cache.example.org", "--json"]

    assert client.run(args + ["repos", "list"], root=root) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["os"]["ID"] == "almalinux"
    assert listed["os"]["VERSION_ID"] == "10.1"
    assert [(repo["name"], repo["type"], repo["enabled"])
            for repo in listed["repositories"]] == [
                ("baseos", "dnf", True),
                ("disabled-third-party", "dnf", False)]
    upstream = "https://repo.almalinux.org/almalinux/10/BaseOS/x86_64/os/"
    assert listed["repositories"][0]["urls"] == [upstream]

    exported = root / "request.json"
    assert client.run(
        args + ["repos", "submit", "--output", str(exported)], root=root) == 0
    capsys.readouterr()
    request = json.loads(exported.read_text(encoding="utf-8"))
    assert request["os"] == {"id": "almalinux", "version": "10.1"}
    assert request["repositories"] == [{"type": "dnf", "url": upstream}]
    assert exported.stat().st_mode & 0o777 == 0o600

    monkeypatch.setattr(client, "_catalog", lambda server: {
        "schema": 1,
        "repositories": [{
            "upstream": upstream,
            "cache": "https://cache.example.org/almalinux/baseos/",
        }],
    })
    assert client.run(args + ["repos", "sync"], root=root) == 0
    preview = json.loads(capsys.readouterr().out)
    assert "DRY RUN" in preview["note"]
    assert [repo["supported"] for repo in preview["repositories"]] == [True, False]
    assert client.run(args + ["repos", "sync", "--apply"], root=root) == 2
    rejected = json.loads(capsys.readouterr().out)
    assert rejected["ok"] is False
    assert repo_file.read_bytes() == before

    monkeypatch.setattr(client, "_connectivity", lambda server: [
        {"name": "dns", "ok": False, "detail": "Synthetic offline"}])
    monkeypatch.setattr(client, "_catalog", lambda server:
                        pytest.fail("Offline check must not fetch a catalog"))
    assert client.run(args + ["check"], root=root) == 1
    checked = json.loads(capsys.readouterr().out)
    assert checked["ok"] is False
    assert checked["exit_code"] == 1
    assert checked["repositories"][0]["type"] == "dnf"
    assert repo_file.read_bytes() == before
