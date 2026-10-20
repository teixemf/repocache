"""Anonymous public release transport: bounded one-hop redirects (#37).

Disposable, in-process HTTP fixtures only. No production credentials or
external HTTP requests are used. Redirect locations are deliberately synthetic.
"""
from __future__ import annotations

from email.message import Message
import io
import json
import urllib.error

import pytest

from repocache import releases, upgrade

API = "https://api.github.com/repos/teixemf/repocache/releases/assets/123"
METADATA = "https://api.github.com/repos/teixemf/repocache/releases"
CDN = "https://release-assets.githubusercontent.com/fixture?sig=synthetic-expiring-value"


class Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, max_bytes):
        return self.payload[:max_bytes]


class FakeOpener:
    def __init__(self, events):
        self.events = list(events)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request.full_url, dict(request.header_items()), timeout))
        if not self.events:
            pytest.fail("An unexpected redirect or network request escaped fixture")
        event = self.events.pop(0)
        if isinstance(event, BaseException):
            raise event
        return Response(event)


def redirect(location, status=302):
    headers = Message()
    headers["Location"] = location
    return urllib.error.HTTPError(API, status, "disposable redirect", headers, None)


def opener(monkeypatch, module, events):
    fixture = FakeOpener(events)
    monkeypatch.setattr(module.urllib.request, "build_opener", lambda *args: fixture)
    return fixture


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_anonymous_official_asset_redirect_uses_one_approved_cdn_hop(monkeypatch, status):
    fixture = opener(monkeypatch, upgrade, [redirect(CDN, status), b"verified"])
    assert upgrade._request_bytes(API, 16) == b"verified"
    assert [request[0] for request in fixture.requests] == [API, CDN]
    assert all(not any("authorization" in k.lower() for k in headers)
               for _, headers, _ in fixture.requests)
    assert all(timeout == 12 for _, _, timeout in fixture.requests)


@pytest.mark.parametrize("invalid", [
    "http://release-assets.githubusercontent.com/resource",
    "https://unrelated.invalid/resource",
    "https://release-assets.githubusercontent.com.invalid/resource",
    "https://release-assets.githubusercontent.com:9443/resource",
    "https://member:pass@release-assets.githubusercontent.com/resource",
    "https://api.github.com/repos/teixemf/repocache/releases/assets/123",
    "//release-assets.githubusercontent.com/resource",
    "https://release-assets.githubusercontent.com/resource#fragment",
])
def test_untrusted_redirects_rejected_without_followup(monkeypatch, invalid):
    fixture = opener(monkeypatch, upgrade, [redirect(invalid)])
    with pytest.raises(upgrade.UpgradeError, match="redirect") as err:
        upgrade._request_bytes(API, 64)
    assert len(fixture.requests) == 1
    assert invalid not in str(err.value)


def test_cdn_redirect_chain_is_rejected_before_next_hop(monkeypatch):
    fixture = opener(monkeypatch, upgrade, [redirect(CDN), redirect(CDN)])
    with pytest.raises(upgrade.UpgradeError, match="redirect"):
        upgrade._request_bytes(API, 64)
    assert [u for u, _, _ in fixture.requests] == [API, CDN]


@pytest.mark.parametrize("invalid", [
    "https://api.github.com:8443/repos/teixemf/repocache/releases/assets/123",
    "https://api.github.com/repos/teixemf/repocache/releases/assets/1234extra",
    "https://api.github.com/repos/teixemf/repocache/releases/assets/0",
    "https://objects.githubusercontent.com:444/fixture",
    "https://objects.githubusercontent.com/fixture#x",
    "http://api.github.com/repos/teixemf/repocache/releases/assets/123",
])
def test_unsafe_direct_asset_origin_rejected_without_http(monkeypatch, invalid):
    fixture = opener(monkeypatch, upgrade, [])
    with pytest.raises(upgrade.UpgradeError):
        upgrade._request_bytes(invalid, 64)
    assert not fixture.requests


@pytest.mark.parametrize("status", [401, 403, 404, 410, 429, 500])
def test_expired_or_unavailable_signed_url_never_leaks_query(monkeypatch, status):
    fixture = opener(monkeypatch, upgrade, [redirect(CDN),
                                            redirect(CDN + "&expired", status)])
    with pytest.raises((upgrade.UpgradeError, releases.DiscoveryError)) as err:
        upgrade._request_bytes(API, 64)
    assert len(fixture.requests) == 2
    assert "synthetic-expiring-value" not in str(err.value)
    assert CDN not in str(err.value)


@pytest.mark.parametrize("content,maxbytes", [(b"abcde", 4), (b"a" * 400, 40)])
def test_asset_response_is_bounded_and_sanitized(monkeypatch, content, maxbytes):
    fixture = opener(monkeypatch, upgrade, [content])
    with pytest.raises(upgrade.UpgradeError, match="maximum allowed size"):
        upgrade._request_bytes(API, maxbytes)
    assert len(fixture.requests) == 1


def test_incomplete_asset_and_existing_credential_are_not_retried(monkeypatch, tmp_path):
    fixture = opener(monkeypatch, upgrade, [b"short"])
    stale = tmp_path / "old-private-token"
    stale.write_text("synthetic-disallowed-token")
    stale.chmod(0o600)
    with pytest.raises(upgrade.UpgradeError, match="reported size"):
        upgrade._download_asset({"id": 123, "size": 20}, stale, 40)
    assert len(fixture.requests) == 1
    assert not any("authorization" in k.lower() for k in fixture.requests[0][1])


@pytest.mark.parametrize("error", [TimeoutError("redacted"), OSError("redacted"),
                                    urllib.error.URLError("redacted")])
def test_timeout_and_connection_failures_have_stable_nonsensitive_errors(monkeypatch, error):
    fixture = opener(monkeypatch, upgrade, [error])
    with pytest.raises(upgrade.UpgradeError, match="Could not download") as ex:
        upgrade._request_bytes(API, 64)
    assert "redacted" not in str(ex.value)
    assert len(fixture.requests) == 1


def test_anonymous_discovery_metadata_bound_and_stale_token_nonuse(monkeypatch, tmp_path):
    fixture = opener(monkeypatch, releases, [b"[]" * (releases.MAX_RESPONSE // 2 + 2)])
    token = tmp_path / "historical-token"
    token.write_text("synthetic-disallowed-token")
    token.chmod(0o600)
    monkeypatch.setattr(releases, "_token", lambda *args:
                        pytest.fail("Deprecated token must never be loaded"))
    with pytest.raises(releases.DiscoveryError, match="size limit") as err:
        releases._request_public_first(METADATA, token)
    assert "synthetic-disallowed-token" not in str(err.value)
    assert len(fixture.requests) == 1
    assert not any("authorization" in k.lower() for k in fixture.requests[0][1])


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_api_metadata_redirect_refused_even_if_official(monkeypatch, status):
    fixture = opener(monkeypatch, releases, [redirect(METADATA, status)])
    with pytest.raises(releases.DiscoveryError, match="redirect"):
        releases._request(METADATA)
    assert len(fixture.requests) == 1
