"""Stable, non-mutating client check classifications and exit codes."""
import importlib.util
import json
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "client" / "repocache_client.py"
spec = importlib.util.spec_from_file_location("client_compatibility_under_test", MODULE)
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)

APPROVED = {"schema": 1, "repositories": [
    {"upstream": "https://deb.debian.org/debian/",
     "cache": "https://cache.example.org/debian/"},
]}


def ready(monkeypatch):
    monkeypatch.setattr(client, "_connectivity", lambda server: [
        {"name": "dns", "ok": True, "detail": "Resolved"},
        {"name": "https", "ok": True, "detail": "Certificate valid"},
    ])
    monkeypatch.setattr(client, "_catalog", lambda server: APPROVED)


def root_with_repos(tmp_path):
    etc = tmp_path / "etc"
    (etc / "apt/mirrors").mkdir(parents=True)
    (etc / "apt/sources.list.d").mkdir(parents=True)
    (etc / "yum.repos.d").mkdir(parents=True)
    (etc / "os-release").write_text('ID=debian\nVERSION_ID="13"\n')
    (etc / "apt/mirrors/debian.txt").write_text(
        "https://cache.example.org/debian/\nhttps://deb.debian.org/debian/\n")
    (etc / "apt/sources.list").write_text(
        "deb mirror+file:/etc/apt/mirrors/debian.txt trixie main\n")
    (etc / "apt/sources.list.d/extra.sources").write_text(
        "Types: deb\nURIs: https://other.example.org/packages/\n"
        "Suites: trixie\nComponents: main\n")
    (etc / "yum.repos.d/alma.repo").write_text(
        "[alma]\nbaseurl=https://unapproved.example.org/repo/\nenabled=1\n")
    return tmp_path


def test_catalog_classification_covers_mirrors_deb822_and_dnf(monkeypatch, tmp_path, capsys):
    root = root_with_repos(tmp_path)
    ready(monkeypatch)
    before = {str(p): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    assert client.run(["--json", "check"], root=root) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["exit_code"] == 0
    assert result["compatibility_summary"] == {
        "supported": 1, "unknown": 2, "unavailable": 0, "invalid": 0
    }
    assert {x["name"]: x["compatibility"] for x in result["repositories"]} == {
        "sources.list:1": "supported", "extra.sources:1": "unknown",
        "alma": "unknown"
    }
    assert before == {str(p): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_missing_catalog_preserves_inventory(monkeypatch, tmp_path, capsys):
    root = root_with_repos(tmp_path)
    ready(monkeypatch)
    def unavailable(server):
        raise client.ClientError("Catalog is unavailable")
    monkeypatch.setattr(client, "_catalog", unavailable)
    assert client.run(["--json", "check"], root=root) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["compatibility_summary"]["unavailable"] == 3
    assert result["compatibility_summary"]["invalid"] == 0
    assert len(result["repositories"]) == 3


def test_invalid_repository_is_actionable_nonzero(monkeypatch, tmp_path, capsys):
    root = root_with_repos(tmp_path)
    (root / "etc/apt/sources.list").write_text("deb file:/srv/local trixie main\n")
    ready(monkeypatch)
    assert client.run(["--json", "check"], root=root) == 3
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert result["compatibility_summary"]["invalid"] == 1


def test_server_failure_returns_one_but_keeps_repositories(monkeypatch, tmp_path, capsys):
    root = root_with_repos(tmp_path)
    monkeypatch.setattr(client, "_connectivity", lambda server: [
        {"name": "dns", "ok": False, "detail": "Could not resolve"}
    ])
    monkeypatch.setattr(client, "_catalog", lambda server: 1/0)
    assert client.run(["--json", "check"], root=root) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["compatibility_summary"]["unavailable"] == 3
    assert len(result["repositories"]) == 3
