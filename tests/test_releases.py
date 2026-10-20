"""Public GitHub Releases discovery must be anonymous, read-only and fail closed."""
import json
import urllib.error

import pytest

from repocache import releases


def item(v, *, draft=False, prerelease=False, assets=True):
    tag = "v" + v
    name = "repocache-" + tag + ".tar.gz"
    return {"tag_name": tag, "draft": draft, "prerelease": prerelease,
            "html_url": "https://github.com/teixemf/repocache/releases/tag/" + tag,
            "assets": ([{"id": 7, "name": name, "size": 200},
                        {"id": 8, "name": name + ".sha256", "size": 98},
                        {"id": 9, "name": name + ".manifest.json", "size": 900},
                        {"id": 10, "name": name + ".manifest.json.sig", "size": 64},
                        {"id": 11, "name": name + ".wheelhouse.tar.gz", "size": 4000}]
                       if assets else [])}


def test_version_sorted_not_lexical_and_installed_absent(monkeypatch):
    monkeypatch.setattr(releases, "_request_public_first", lambda *a, **kw:
                        [item("0.9.0"), item("0.10.0"), item("0.3.0")])
    result = releases.report("0.2.0", list_all=True)
    assert result["status"] == "update-available"
    assert [x["version"] for x in result["releases"]] == ["0.10.0", "0.9.0", "0.3.0"]
    assert not any(x["installed"] for x in result["releases"])
    assert all(x["compatibility"] == "unknown" and not x["eligible"]
               for x in result["releases"])


def test_prerelease_draft_and_missing_assets_excluded(monkeypatch):
    monkeypatch.setattr(releases, "_request_public_first", lambda *a, **kw:
                        [item("2.0.0", draft=True),
                         item("1.9.0", prerelease=True),
                         item("1.8.0", assets=False), item("1.0.0")])
    result = releases.report("1.0.0", list_all=True)
    assert result["status"] == "up-to-date"
    assert len(result["releases"]) == 1
    assert result["releases"][0]["installed"]
    assert result["update_available"] is False


def test_reject_redirect_without_forwarding_authorization():
    handler = releases.NoRedirect()
    assert handler.redirect_request(None, None, 302, "redirect", None,
                                    "https://attacker.invalid") is None
    with pytest.raises(releases.DiscoveryError):
        releases._request("https://evil.example/repos/teixemf/repocache/releases", token="never")


@pytest.mark.parametrize("bad", [
    {"tag_name": "v1.0.0rc1"}, {"tag_name": "v01.0.0"},
    {"html_url": "https://evil.example/releases/tag/v1.0.0"},
    {"assets": []}, {"assets": [{"id": 1, "name": "evil", "size": 40}]},
])
def test_reject_invalid_release_metadata(bad):
    record = item("1.0.0")
    record.update(bad)
    assert releases._release(record) is None


def test_token_file_protected(tmp_path):
    p = tmp_path / "token"
    p.write_text("ghp_example")
    p.chmod(0o644)
    with pytest.raises(releases.DiscoveryError) as err:
        releases._token(p)
    assert err.value.status == "authentication-required"
    p.chmod(0o600)
    assert releases._token(p) == "ghp_example"
    link = tmp_path / "symlink"
    link.symlink_to(p)
    with pytest.raises(releases.DiscoveryError):
        releases._token(link)


def test_public_first_does_not_send_existing_token(monkeypatch, tmp_path):
    calls = []
    def public(url, token=None):
        calls.append(token)
        return [item("0.4.0")]
    monkeypatch.setattr(releases, "_request", public)
    p = tmp_path / "token"
    p.write_text("ghp_not_sent")
    p.chmod(0o600)
    assert releases._request_public_first("https://api.github.com/repos/teixemf/repocache/releases", p)
    assert calls == [None]


def test_private_404_must_not_retry_with_an_old_token(monkeypatch, tmp_path):
    calls = []
    def unavailable(url, token=None):
        calls.append(token)
        raise releases.DiscoveryError("authentication-required", "not found")
    monkeypatch.setattr(releases, "_request", unavailable)
    old_token = tmp_path / "old-token"
    old_token.write_text("synthetic-disabled-token")
    old_token.chmod(0o600)
    with pytest.raises(releases.DiscoveryError, match="not found"):
        releases._request_public_first(
            "https://api.github.com/repos/teixemf/repocache/releases", old_token)
    assert calls == [None]


def test_public_discovery_does_not_reauthenticate(monkeypatch, tmp_path):
    token = tmp_path / "old-token"
    token.write_text("synthetic-disabled-token")
    token.chmod(0o600)
    calls = []
    def anonymous(url, token=None):
        calls.append(token)
        raise releases.DiscoveryError("authentication-required", "not public")
    monkeypatch.setattr(releases, "_request", anonymous)
    assert releases.report("0.3.0", token_file=token)["status"] == "authentication-required"
    assert calls == [None]


@pytest.mark.parametrize("status", ["authentication-required", "offline", "invalid-release", "error"])
def test_all_failures_report_installed_without_lying(monkeypatch, status):
    monkeypatch.setattr(releases, "discover", lambda *a:
                        (_ for _ in ()).throw(releases.DiscoveryError(status, "unavailable")))
    result = releases.report("0.3.0")
    assert result["installed_version"] == "0.3.0"
    assert result["update_available"] is None
    assert result["status"] == status


def test_ambiguous_404_is_not_marked_private(monkeypatch, tmp_path):
    monkeypatch.setattr(releases, "_request", lambda *a, **kw:
                        (_ for _ in ()).throw(releases.DiscoveryError(
                            "authentication-required", "not found or authentication required")))
    outcome = releases.report("0.3.0", token_file=tmp_path/"missing")
    assert outcome["status"] == "authentication-required"
    assert "private" not in outcome["message"].lower()


def test_pagination_and_unknown_releases(monkeypatch):
    calls = []
    def pages(url, token_file=None):
        calls.append(url)
        if "&page=1" in url:
            return [item("0.4.0") for _ in range(100)]
        return [item("0.3.0")]
    monkeypatch.setattr(releases, "_request_public_first", pages)
    assert [r["version"] for r in releases.discover()] == ["0.4.0", "0.3.0"]
    assert len(calls) == 2


def test_existing_per_user_credentials_are_never_loaded_for_public_discovery(monkeypatch, tmp_path):
    old_credential = tmp_path / ".config/repocache/github-token"
    old_credential.parent.mkdir(parents=True)
    old_credential.write_text("synthetic-disallowed-token")
    old_credential.chmod(0o600)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("REPOCACHE_GITHUB_TOKEN_FILE", raising=False)
    calls = []
    def anonymous(url, token=None):
        calls.append(token)
        raise releases.DiscoveryError("authentication-required", "not available")
    monkeypatch.setattr(releases, "_request", anonymous)
    assert releases.report("0.3.0")["status"] == "authentication-required"
    assert calls == [None]


def test_invalid_explicit_path_does_not_prevent_anonymous_public_release(monkeypatch):
    monkeypatch.setenv("REPOCACHE_GITHUB_TOKEN_FILE", "relative/token")
    monkeypatch.setattr(releases, "_request", lambda url, token=None: [item("0.4.0")])
    assert releases.report("0.3.0")["status"] == "update-available"
    monkeypatch.setattr(releases, "_request", lambda url, token=None:
                        (_ for _ in ()).throw(releases.DiscoveryError(
                            "authentication-required", "private or unavailable")))
    assert releases.report("0.3.0")["status"] == "authentication-required"
