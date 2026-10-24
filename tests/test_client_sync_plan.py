"""Read-only REPOCACHE Client sync plans; no APT/DNF write opt-in (#24).

The plan is advisory until native trust/fallback tests prove safe rewrites on
Debian 13 and AlmaLinux 10. Synthetic fixtures do not constitute that proof.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


MODULE = Path(__file__).resolve().parents[1] / "client/repocache_client.py"
spec = importlib.util.spec_from_file_location("client_sync_plan_under_test", MODULE)
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


@pytest.fixture
def host(tmp_path):
    apt = tmp_path / "etc/apt"
    apt.mkdir(parents=True)
    (apt / "sources.list.d").mkdir()
    dnf = tmp_path / "etc/yum.repos.d"
    dnf.mkdir(parents=True)
    (tmp_path / "etc/os-release").write_text('ID=debian\nVERSION_ID="13"\n')
    (apt / "sources.list").write_text(
        "deb https://deb.debian.org/debian trixie main\n"
        "deb [trusted=yes] https://deb.debian.org/debian trixie-security main\n"
        "deb https://user:password@deb.debian.org/debian trixie-updates main\n"
    )
    (apt / "sources.list.d/multi.sources").write_text(
        "Types: deb\nURIs: https://deb.debian.org/debian\n"
        "Suites: trixie\nComponents: main\nEnabled: no\n\n"
        "Types: deb\nURIs: https://deb.debian.org/debian\n"
        "Suites: trixie-updates\nComponents: main\n"
        "Trusted: yes\n"
    )
    (dnf / "samples.repo").write_text(
        "[rpm]\nbaseurl=https://rpm.example.org/linux/\nenabled=1\n"
        "[restricted]\nbaseurl=https://rpm.example.org/linux/\n"
        "username=account\npassword=do-not-emit\nenabled=1\n"
        "[unsafe]\nbaseurl=https://rpm.example.org/linux/\n"
        "gpgcheck=0\nenabled=1\n"
        "[mirror]\nmirrorlist=https://rpm.example.org/linux/mirrors\nenabled=1\n"
        "[metalink]\nmetalink=https://rpm.example.org/linux/metadata\nenabled=1\n"
    )
    return tmp_path


def _snapshot(root):
    return {str(path): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def test_advisory_plan_handles_apts_dnf_weak_signatures_and_private_urls(host):
    repos = client.discover(host, SERVER)
    plan = client._sync_plan(repos, CATALOG)
    by_name = {item["name"]: item for item in plan["repositories"]}

    assert plan["dry_run"] is True
    assert plan["planned_changes"] == 0
    assert by_name["sources.list:1"]["plan"]["status"] == "candidate"
    assert by_name["sources.list:1"]["plan"]["apply_eligible"] is False
    assert by_name["sources.list:2"]["plan"]["reason"] == "weak-package-or-transport-verification"
    assert by_name["sources.list:3"]["plan"]["reason"] == "credentials-or-parameterized-url"
    assert by_name["multi.sources:1"]["plan"]["reason"] == "disabled-locally"
    assert by_name["multi.sources:2"]["plan"]["status"] == "blocked"
    assert by_name["rpm"]["plan"]["status"] == "candidate"
    assert by_name["restricted"]["plan"]["reason"] == "credentials-or-parameterized-url"
    assert by_name["unsafe"]["plan"]["reason"] == "weak-package-or-transport-verification"
    assert by_name["mirror"]["plan"]["reason"] == "native-mirror-indirection-not-verified"
    assert by_name["metalink"]["plan"]["reason"] == "native-mirror-indirection-not-verified"
    assert all(x["plan"]["action"] == "none" for x in plan["repositories"])
    assert "password" not in json.dumps(plan)
    assert "do-not-emit" not in json.dumps(plan)


def test_mixed_route_is_not_proof_of_native_failover(tmp_path):
    mirror = tmp_path / "sources.list"
    mixed = client._repo("mixed", "apt-list", [
        "https://cache.example.org/debian/",
        "https://deb.debian.org/debian/",
    ], mirror, SERVER)
    cached_only = client._repo("cached", "apt-list", [
        "https://cache.example.org/debian/",
    ], mirror, SERVER)
    result = client._sync_plan([mixed, cached_only], CATALOG)
    assert result["repositories"][0]["plan"]["reason"] == "existing-cache-fallback-not-verified"
    assert result["repositories"][1]["plan"]["reason"] == "cache-only-no-fallback-evidence"
    assert all(not x["plan"]["apply_eligible"] for x in result["repositories"])


def test_catalog_unknown_or_invalid_repository_is_never_actionable(tmp_path):
    path = tmp_path / "sources.list"
    unknown = client._repo("unknown", "apt-list",
                           ["https://unrelated.example.org/repo"], path, SERVER)
    invalid = client._repo("local", "apt-list", ["file:/media/repo"], path, SERVER)
    result = client._sync_plan([unknown, invalid], CATALOG)
    assert [entry["plan"]["reason"] for entry in result["repositories"]] == [
        "not-in-active-catalog", "invalid-or-unsupported-source"
    ]


def test_sync_json_is_read_only_idempotent_and_discloses_no_credentials(
        host, monkeypatch, capsys):
    monkeypatch.setattr(client, "_catalog", lambda server: CATALOG)
    before = _snapshot(host)
    for _ in range(2):
        assert client.run(["--server", SERVER, "--json", "repos", "sync"],
                          root=host) == 0
        response = json.loads(capsys.readouterr().out)
        assert response["dry_run"] is True
        assert response["planned_changes"] == 0
        assert response["plan_summary"]["candidate"] == 2
        assert "password" not in json.dumps(response)
        assert "do-not-emit" not in json.dumps(response)
        assert _snapshot(host) == before


def test_apply_still_refused_before_any_network_or_local_write(host, monkeypatch):
    before = _snapshot(host)
    def no_catalog(_):
        pytest.fail("apply must refuse before catalog requests")
    monkeypatch.setattr(client, "_catalog", no_catalog)
    assert client.run(["--server", SERVER, "repos", "sync", "--apply"],
                      root=host) == 2
    assert _snapshot(host) == before


def test_explicitly_disabled_sources_precede_other_plan_checks(tmp_path):
    repo = client._repo("disabled", "dnf", [
        "https://user:secret@rpm.example.org/linux/"],
        tmp_path / "r.repo", SERVER, enabled=False,
        auth_hint=True, weak_integrity=True)
    entry = client._sync_plan([repo], CATALOG)["repositories"][0]
    assert entry["plan"]["reason"] == "disabled-locally"
    assert not entry["plan"]["apply_eligible"]



@pytest.mark.parametrize("url, expected", (
    ("https://cache.example.org/debian/", True),
    ("https://cache.example.org:443/debian/", True),
    ("http://cache.example.org/debian/", False),
    ("https://cache.example.org:8443/debian/", False),
    ("https://cache.example.org:0/debian/", False),
    ("https://user:pass@cache.example.org/debian/", False),
    ("https://other.example.org/debian/", False),
    ("https://cache.example.org:65536/debian/", False),
))
def test_cache_origin_includes_scheme_port_and_rejects_credentials(url, expected):
    assert client._same_https_origin(url, SERVER) is expected


def test_catalog_rejects_cache_route_on_different_port(monkeypatch):
    def redirect_port(_url, *, max_bytes):
        return {"schema": 1, "repositories": [{
            "upstream": "https://deb.debian.org/debian/",
            "cache": "https://cache.example.org:8443/debian/",
        }]}
    monkeypatch.setattr(client, "_fetch_json", redirect_port)
    with pytest.raises(client.ClientError, match="Invalid catalog URL"):
        client._catalog(SERVER)


def test_http_same_host_is_not_treated_as_current_cache(tmp_path):
    repo = client._repo("http", "apt-list",
                        ["http://cache.example.org/debian/"],
                        tmp_path / "repo.list", SERVER)
    assert repo["route"] == "direct"
    result = client._sync_plan([repo], CATALOG)
    assert result["repositories"][0]["plan"]["reason"] == "not-in-active-catalog"



def test_one_approved_url_does_not_authorize_other_upstreams(tmp_path):
    repo = client._repo("multi", "apt-deb822", [
        "https://deb.debian.org/debian/",
        "https://unapproved.example.org/private/",
    ], tmp_path / "sources.sources", SERVER)
    planned = client._sync_plan([repo], CATALOG)["repositories"][0]
    assert planned["supported"] is True
    assert planned["plan"]["status"] == "blocked"
    assert planned["plan"]["reason"] == "unapproved-additional-upstreams"
    assert planned["plan"]["apply_eligible"] is False


def test_unsupported_repository_type_is_not_a_candidate(tmp_path):
    repo = client._repo("future", "unrecognized", [
        "https://deb.debian.org/debian/",
    ], tmp_path / "future.sources", SERVER)
    planned = client._sync_plan([repo], CATALOG)["repositories"][0]
    assert planned["plan"]["reason"] == "unsupported-repository-format"
    assert planned["plan"]["apply_eligible"] is False
