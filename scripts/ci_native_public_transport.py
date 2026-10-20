#!/usr/bin/env python3
"""Native public-release transport checks using the packaged source code.

Runs in disposable Debian 13 and AlmaLinux 10 release-bundle smoke images.
All HTTP access is intercepted by a deterministic fake opener, including
network failures. This does not access a real repository, token or URL.
"""
from __future__ import annotations

from email.message import Message
import io
from pathlib import Path
import urllib.error
import urllib.request

from repocache import releases, upgrade

API = "https://api.github.com/repos/teixemf/repocache/releases/assets/123"
META = "https://api.github.com/repos/teixemf/repocache/releases"
CDN = "https://release-assets.githubusercontent.com/disposable?sig=synthetic"


class Reply:
    def __init__(self, content):
        self.content = content

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, maximum):
        return self.content[:maximum]


class FakeOpener:
    def __init__(self, events):
        self.events = list(events)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request.full_url, dict(request.header_items()), timeout))
        if not self.events:
            raise AssertionError("Test attempted an unsanctioned network request")
        item = self.events.pop(0)
        if isinstance(item, Exception):
            raise item
        return Reply(item)


def redir(where):
    headers = Message()
    headers["Location"] = where
    return urllib.error.HTTPError(API, 302, "Synthetic redirect", headers, None)


def intercept(events):
    f = FakeOpener(events)
    urllib.request.build_opener = lambda *_: f
    return f


def must_reject(run, error, message):
    try:
        run()
    except error as exc:
        if "synthetic" in str(exc).lower():
            raise AssertionError("Sensitive synthetic redirect exposed") from exc
    else:
        raise AssertionError(message)


def main():
    # Verify both anonymous discovery and asset API transport on real OS Python.
    fake = intercept([b"[]"])
    assert releases._request_public_first(META, Path("/tmp/never-read-token")) == []
    assert [r[0] for r in fake.requests] == [META]
    assert not any("authorization" in key.lower() for key in fake.requests[0][1])

    fake = intercept([redir(CDN), b"archive"])
    assert upgrade._request_bytes(API, 40) == b"archive"
    assert [r[0] for r in fake.requests] == [API, CDN]
    assert all(not any("authorization" in key.lower() for key in headers)
               for _, headers, _ in fake.requests)
    assert all(timeout == 12 for _, _, timeout in fake.requests)

    for rejected in (
        "https://untrusted.invalid/resource",
        "http://release-assets.githubusercontent.com/resource",
        "https://release-assets.githubusercontent.com:8080/resource",
        "https://api.github.com/repos/teixemf/repocache/releases/assets/124",
    ):
        fake = intercept([redir(rejected)])
        must_reject(lambda: upgrade._request_bytes(API, 40),
                    upgrade.UpgradeError, "Untrusted redirect accepted")
        assert len(fake.requests) == 1

    fake = intercept([redir(CDN), redir(CDN + "&again")])
    must_reject(lambda: upgrade._request_bytes(API, 40),
                upgrade.UpgradeError, "Chained CDN redirect accepted")
    assert len(fake.requests) == 2

    fake = intercept([b"x" * 21])
    must_reject(lambda: upgrade._request_bytes(API, 20),
                upgrade.UpgradeError, "Oversized asset accepted")

    fake = intercept([redir(CDN), urllib.error.HTTPError(
        CDN, 403, "synthetic-secret", Message(), None)])
    must_reject(lambda: upgrade._request_bytes(API, 40),
                upgrade.UpgradeError, "Expired synthetic asset accepted")

    fake = intercept([redir(CDN)])
    must_reject(lambda: releases._request(META),
                releases.DiscoveryError, "Metadata redirect accepted")
    assert len(fake.requests) == 1

    must_reject(lambda: upgrade._request_bytes(API, 40, token="synthetic"),
                upgrade.UpgradeError, "Legacy asset token accepted")
    must_reject(lambda: releases._request(META, token="synthetic"),
                releases.DiscoveryError, "Legacy metadata token accepted")
    print("PASS: native public GitHub transport refuses unsafe redirects and credentials")


if __name__ == "__main__":
    main()
