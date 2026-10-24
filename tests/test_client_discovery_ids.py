"""Read-only repository discovery IDs and targeted sync plans (#24, UC-27).

Synthetic fixtures validate stability only while the source file and semantic
identity remain unchanged. Managed persistent IDs require separate transaction
state and must not be inferred from these discovery IDs.
"""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest


MODULE = Path(__file__).resolve().parents[1] / "client" / "repocache_client.py"
spec = importlib.util.spec_from_file_location("client_identity_test", MODULE)
client = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(client)

SERVER = "https://cache.example.org"
CATALOG = {"schema": 1, "repositories": [
    {"upstream": "https://deb.debian.org/debian/",
     "cache": "https://cache.example.org/debian/"},
    {"upstream": "https://rpm.example.org/linux/",
     "cache": "https://cache.example.org/linux/"},
]}


@pytest.fixture()
def host(tmp_path):
    apt = tmp_path / "etc/apt"
    (apt / "sources.list.d").mkdir(parents=True)
    dnf = tmp_path / "etc/yum.repos.d"
    dnf.mkdir(parents=True)
    (tmp_path / "etc/os-release").write_text('ID=debian\nVERSION_ID=13\n')
    (apt / "sources.list").write_text(
        "deb https://deb.debian.org/debian trixie main\n"
        "deb-src https://deb.debian.org/debian trixie main\n"
        "deb https://deb.debian.org/debian trixie-updates main\n"
    )
    (apt / "sources.list.d/multiple.sources").write_text(
        "Types: deb\nURIs: https://deb.debian.org/debian/\n"
        "Suites: trixie\nComponents: main\n\n"
        "Types: deb\nURIs: https://deb.debian.org/debian/\n"
        "Suites: trixie-updates\nComponents: main\n"
    )
    (dnf / "repositories.repo").write_text(
        "[core]\nbaseurl=https://rpm.example.org/linux/\nenabled=1\n\n"
        "[extras]\nbaseurl=https://rpm.example.org/linux/\nenabled=0\n"
    )
    return tmp_path


def _snapshot(root):
    return {str(path): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def test_discovery_ids_are_unique_opaque_and_repeatable(host):
    a = client.discover(host, SERVER)
    b = client.discover(host, SERVER)
    assert len(a) == 7
    assert [repo["id"] for repo in a] == [repo["id"] for repo in b]
    assert len({repo["id"] for repo in a}) == len(a)
    assert all(re.fullmatch(r"(?:apt|dnf)-[0-9a-f]{24}", repo["id"]) for repo in a)
    assert all(not repo["identity_conflict"] for repo in a)
    assert "deb.debian.org" not in json.dumps([r["id"] for r in a])


def test_apt_semantic_identity_survives_line_order_and_comments(host):
    before = {repo["id"] for repo in client.discover(host, SERVER)
              if repo["type"] == "apt-list"}
    source = host / "etc/apt/sources.list"
    source.write_text(
        "# inserted unrelated comment\n"
        "deb https://deb.debian.org/debian trixie-updates main\n"
        "\n"
        "deb-src https://deb.debian.org/debian trixie main # comment\n"
        "deb https://deb.debian.org/debian trixie main\n"
    )
    after = {repo["id"] for repo in client.discover(host, SERVER)
             if repo["type"] == "apt-list"}
    assert before == after


def test_deb822_stanza_reorder_does_not_change_discovery_ids(host):
    source = host / "etc/apt/sources.list.d/multiple.sources"
    first, second = source.read_text().strip().split("\n\n")
    before = {r["id"] for r in client.discover(host, SERVER)
              if r["type"] == "apt-deb822"}
    source.write_text(second + "\n\n" + first + "\n")
    after = {r["id"] for r in client.discover(host, SERVER)
             if r["type"] == "apt-deb822"}
    assert before == after


def test_dnf_identity_is_section_based_not_order_or_current_mirror(host):
    before = {r["name"]: r["id"] for r in client.discover(host, SERVER)
              if r["type"] == "dnf"}
    source = host / "etc/yum.repos.d/repositories.repo"
    source.write_text(
        "[extras]\nbaseurl=https://changed.example.org/linux/\nenabled=0\n"
        "[core]\nbaseurl=https://rpm.example.org/linux/\nenabled=1\n"
    )
    after = {r["name"]: r["id"] for r in client.discover(host, SERVER)
             if r["type"] == "dnf"}
    assert before == after


def test_targeted_sync_filters_multiple_repositories_without_mutation(
        monkeypatch, host, capsys):
    monkeypatch.setattr(client, "_catalog", lambda _: CATALOG)
    ids = [r["id"] for r in client.discover(host, SERVER)]
    before = _snapshot(host)
    selected = ids[0], ids[-1]
    assert client.run(["--server", SERVER, "--json", "repos", "sync",
                       "--repo", selected[0], "--repo", selected[1]],
                      root=host) == 0
    doc = json.loads(capsys.readouterr().out)
    assert {r["id"] for r in doc["repositories"]} == set(selected)
    assert doc["dry_run"] is True
    assert doc["planned_changes"] == 0
    assert all(not r["plan"]["apply_eligible"] for r in doc["repositories"])
    assert _snapshot(host) == before


@pytest.mark.parametrize("selected", (
    "",
    "bad/../../path",
    "apt-" + "0" * 24,
    "https://user:secret@example.org/",
))
def test_unknown_or_invalid_id_fails_before_catalog(monkeypatch, host, capsys, selected):
    monkeypatch.setattr(client, "_catalog", lambda *_: pytest.fail(
        "untrusted or unknown selection must fail before network access"))
    before = _snapshot(host)
    result = client.run(["--server", SERVER, "--json", "repos", "sync",
                         "--repo", selected], root=host)
    assert result == 2
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is False
    assert "secret" not in json.dumps(data)
    assert _snapshot(host) == before


def test_duplicate_equivalent_sources_are_explicitly_ambiguous(
        monkeypatch, host, capsys):
    source = host / "etc/apt/sources.list"
    original = "deb https://deb.debian.org/debian trixie main\n"
    source.write_text(original + original)
    repos = client.discover(host, SERVER)
    duplicates = [repo for repo in repos if repo["type"] == "apt-list"]
    assert len(duplicates) == 2
    assert duplicates[0]["id"] == duplicates[1]["id"]
    assert all(repo["identity_conflict"] for repo in duplicates)
    assert all(repo["plan"]["reason"] == "ambiguous-discovery-identity"
               for repo in client._sync_plan(duplicates, CATALOG)["repositories"])
    monkeypatch.setattr(client, "_catalog", lambda *_: pytest.fail(
        "ambiguous targeted ID must fail before catalog fetch"))
    assert client.run(["--server", SERVER, "repos", "sync",
                       "--repo", duplicates[0]["id"]], root=host) == 2


def test_apply_still_refuses_with_target_before_catalog(monkeypatch, host):
    before = _snapshot(host)
    monkeypatch.setattr(client, "_catalog", lambda *_: pytest.fail(
        "apply must be refused before network"))
    selected = client.discover(host, SERVER)[0]["id"]
    assert client.run(["--server", SERVER, "repos", "sync",
                       "--repo", selected, "--apply"], root=host) == 2
    assert _snapshot(host) == before


def test_private_urls_never_enter_discovery_id(host):
    path = host / "etc/apt/sources.list"
    path.write_text(
        "deb https://alice:token123@deb.debian.org/debian trixie main\n"
    )
    one = client.discover(host, SERVER)[0]
    path.write_text(
        "deb https://bob:token456@deb.debian.org/debian trixie main\n"
    )
    two = client.discover(host, SERVER)[0]
    assert one["id"] == two["id"]
    assert "alice" not in one["id"] and "token123" not in one["id"]
    assert one["requires_auth_review"] and two["requires_auth_review"]
