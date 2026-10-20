"""Client diagnostics are noninteractive, privacy-preserving and read-only."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "public_client", Path(__file__).resolve().parents[1] / "client/repocache_client.py")
client = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(client)


@pytest.fixture
def host(tmp_path):
    apt = tmp_path / "etc/apt"
    (apt / "sources.list.d").mkdir(parents=True)
    (tmp_path / "etc/yum.repos.d").mkdir(parents=True)
    (tmp_path / "etc/os-release").write_text('ID=debian\nVERSION_ID="13"\n')
    (apt / "sources.list").write_text(
        "deb [arch=amd64] https://deb.debian.org/debian trixie main\n")
    (apt / "sources.list.d/disabled.sources").write_text(
        "Types: deb\nURIs: https://example.org/repo/\nEnabled: no\n")
    (tmp_path / "etc/yum.repos.d/cache.repo").write_text(
        "[cache]\nbaseurl=https://cache.example.org/linux/\nenabled=1\n"
        "[disabled]\nbaseurl=https://other.example.org/pkg/\nenabled=0\n")
    return tmp_path


def test_apt_and_dnf_read_only_inventory(host):
    repos = client.discover(host, client.DEFAULT_SERVER)
    assert len(repos) == 4
    assert {r["name"]: r["route"] for r in repos}["cache"] == "repocache"
    assert not next(r for r in repos if r["name"].startswith("disabled.sources"))["enabled"]


@pytest.mark.parametrize("origin", [
    "http://cache.example.org", "https://account:pass@cache.example.org",
    "https://cache.example.org/path", "https://cache.example.org?x=y",
    "https://cache.example.org#part", "https://cache.example.org:0",
])
def test_server_is_https_origin_without_credentials(origin):
    with pytest.raises(client.ClientError):
        client._server(origin)


def test_export_never_includes_url_credentials_or_internal_hosts(host):
    (host / "etc/apt/sources.list").write_text(
        "deb https://guest:synthetic@example.org/repo?session=untrusted stable main\n")
    payload = client._payload(client._distro(host),
                              client.discover(host, client.DEFAULT_SERVER),
                              client.DEFAULT_SERVER)
    serialized = json.dumps(payload)
    assert all(word not in serialized for word in ["synthetic", "session=", "guest", "hostname"])
    assert any(x["url"] == "https://example.org/repo" for x in payload["repositories"])


def test_export_requires_exclusive_new_file_with_private_permissions(host, tmp_path):
    output = tmp_path / "inventory.json"
    assert client.run(["repos", "submit", "--output", str(output)], root=host) == 0
    assert output.stat().st_mode & 0o077 == 0
    assert json.loads(output.read_text())["schema"] == 1
    assert client.run(["repos", "submit", "--output", str(output)], root=host) == 2


def test_remote_submission_is_not_implicitly_authorized(host):
    assert client.run(["repos", "submit"], root=host) == 2
    assert client.run(["repos", "submit", "--token-file", "/nonexistent"], root=host) == 2


def test_check_preserves_configuration_even_with_catalog(monkeypatch, host, capsys):
    monkeypatch.setattr(client, "_connectivity", lambda _: [
        {"name": "dns", "ok": True, "detail": "ok"},
        {"name": "https", "ok": True, "detail": "ok"}])
    monkeypatch.setattr(client, "_catalog", lambda _: {"schema": 1, "repositories": [
        {"upstream": "https://deb.debian.org/debian/",
         "cache": "https://cache.example.org/debian/"}]})
    before = {str(p): p.read_bytes() for p in host.rglob("*") if p.is_file()}
    assert client.run(["--json", "check"], root=host) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is True
    assert {str(p): p.read_bytes() for p in host.rglob("*") if p.is_file()} == before


def test_missing_catalog_is_only_a_warning(monkeypatch, host, capsys):
    monkeypatch.setattr(client, "_connectivity", lambda _: [
        {"name": "dns", "ok": True, "detail": "ok"},
        {"name": "https", "ok": True, "detail": "ok"}])
    def unavailable(_):
        raise client.ClientError("No validated catalog")
    monkeypatch.setattr(client, "_catalog", unavailable)
    assert client.run(["--json", "check"], root=host) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["compatibility_summary"]["unavailable"] >= 1


def test_mirror_list_is_local_and_fallback_is_preserved(host):
    mirror = host / "etc/apt/mirrors"
    mirror.mkdir()
    (mirror / "safe.txt").write_text(
        "https://cache.example.org/debian/\nhttps://deb.debian.org/debian/\n")
    (host / "etc/apt/sources.list").write_text(
        "deb mirror+file:/etc/apt/mirrors/safe.txt trixie main\n")
    repo = client.discover(host, client.DEFAULT_SERVER)[0]
    assert repo["route"] == "mixed" and len(repo["urls"]) == 2
    payload = client._payload(client._distro(host), [repo], client.DEFAULT_SERVER)
    assert len(payload["repositories"]) == 1
    assert "cache.example.org" not in payload["repositories"][0]["url"]


def test_repository_sources_are_never_followed_through_file_symlinks(host, tmp_path):
    secret = tmp_path / "outside"
    secret.write_text("deb https://outside.example.org/repo stable main\n")
    (host / "etc/apt/sources.list.d/foreign.list").symlink_to(secret)
    assert not any("outside.example" in json.dumps(x)
                   for x in client.discover(host, client.DEFAULT_SERVER))


def test_sync_apply_refused_before_contacting_catalog(monkeypatch, host):
    def should_not_call(_):
        raise AssertionError("Unsafe apply should have failed before network access")
    monkeypatch.setattr(client, "_catalog", should_not_call)
    assert client.run(["repos", "sync", "--apply"], root=host) == 2
