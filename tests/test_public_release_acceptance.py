"""Defensive unit checks for the public release acceptance harness (#71).

These mocks test parser/identity rejection only. Real-public download, signature,
rootless installation and rollback evidence come solely from the Actions jobs.
"""
import json
import sys
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import public_release_acceptance as accept  # noqa: E402


def test_v040_pinned_inventory_is_complete():
    item = accept.target("v0.4.0")
    assert len(item["assets"]) == 8
    assert item["release_id"] == 419296178
    assert item["commit"] == "063c86c9a138bffca6f76f7407e8f1c86bfe4390"
    assert len({a["id"] for a in item["assets"].values()}) == 8


@pytest.mark.parametrize("tag", (
    "v0.4.1", "v0.4.0/../../bad", "main", "v0.4.0\nother", "v0.4.0-rc1",
))
def test_unreviewed_target_rejected(tag):
    with pytest.raises(accept.AcceptanceError):
        accept.target(tag)


@pytest.mark.parametrize("url", (
    "http://api.github.com/repos/teixemf/repocache/releases",
    "https://evil.example.com/file",
    "https://github.com.evil.example.com/file",
    "https://user:pass@github.com/file",
    "https://github.com:444/file",
))
def test_non_github_network_target_rejected(url):
    with pytest.raises(accept.AcceptanceError):
        accept.download(url, 100)


def test_off_origin_redirect_refused():
    handler = accept.StrictRedirect()
    request = urllib.request.Request("https://github.com/teixemf/repocache")
    for url in ("https://evil.example.com/target", "http://github.com/unsafe",
                "https://user:password@github.com/file"):
        with pytest.raises(accept.AcceptanceError):
            handler.redirect_request(request, None, 302, "Found", {}, url)


def test_duplicate_json_field_refused():
    with pytest.raises(accept.AcceptanceError, match="Duplicate"):
        accept.decode(b'{"tag":"v0.4.0","tag":"v0.4.1"}')


def test_missing_local_asset_fails_before_public_signature(tmp_path):
    with pytest.raises(accept.AcceptanceError, match="Local published asset mismatch"):
        accept.verify_files("v0.4.0", accept.target("v0.4.0"), tmp_path)


def release_fixture():
    p = accept.target("v0.4.0")
    assets = [
        {"id": obj["id"], "name": name, "size": obj["size"],
         "digest": "sha256:" + obj["sha256"], "state": "uploaded",
         "browser_download_url": accept.DOWNLOAD + "v0.4.0/" + name}
        for name, obj in p["assets"].items()
    ]
    return {
        "id": p["release_id"], "tag_name": "v0.4.0", "draft": False,
        "prerelease": False, "immutable": True,
        "published_at": "2026-10-21T08:11:22Z",
        "html_url": "https://github.com/teixemf/repocache/releases/tag/v0.4.0",
        "assets": assets,
    }


@pytest.mark.parametrize("change", (
    ("draft", True), ("immutable", False), ("published_at", None),
    ("tag_name", "v0.4.1"), ("id", 99),
))
def test_publication_metadata_fail_closed(monkeypatch, change):
    document = release_fixture()
    document[change[0]] = change[1]

    def get(url, limit):
        return json.dumps(document).encode()

    monkeypatch.setattr(accept, "download", get)
    with pytest.raises(accept.AcceptanceError):
        accept.assert_public_release("v0.4.0", accept.target("v0.4.0"))


def test_extra_public_asset_rejected(monkeypatch):
    document = release_fixture()
    document["assets"].append({**document["assets"][0], "name": "unexpected.bin"})
    monkeypatch.setattr(accept, "download",
                        lambda url, lim: json.dumps(document).encode())
    with pytest.raises(accept.AcceptanceError, match="Unexpected published asset"):
        accept.assert_public_release("v0.4.0", accept.target("v0.4.0"))


def test_ref_movement_rejected(monkeypatch):
    document = release_fixture()
    pinned = accept.target("v0.4.0")

    def fake(url, limit):
        if "/git/ref/tags/" in url:
            return json.dumps({"ref": "refs/tags/v0.4.0",
                               "object": {"sha": "0" * 40, "type": "commit"}}).encode()
        return json.dumps(document).encode()

    monkeypatch.setattr(accept, "download", fake)
    with pytest.raises(accept.AcceptanceError, match="Version tag moved"):
        accept.assert_public_release("v0.4.0", pinned)


def test_matching_release_identity_fixture(monkeypatch):
    pinned = accept.target("v0.4.0")
    def fake(url, limit):
        if "/git/ref/tags/" in url:
            value = {"ref": "refs/tags/v0.4.0",
                     "object": {"sha": pinned["commit"], "type": "commit"}}
        elif "/actions/runs/" in url:
            value = {"head_sha": pinned["commit"], "head_branch": "v0.4.0",
                     "run_attempt": pinned["run_attempt"], "actor": {"login": "teixemf"},
                     "event": "workflow_dispatch", "status": "completed",
                     "conclusion": "success"}
        else:
            value = release_fixture()
        return json.dumps(value).encode()
    monkeypatch.setattr(accept, "download", fake)
    accept.assert_public_release("v0.4.0", pinned)
