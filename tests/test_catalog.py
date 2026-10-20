"""Catalog exports require validation and explicit route approval."""
import json

import pytest

from repocache.catalog import (
    CatalogError, build_catalog, load_approvals, publish_catalog,
)


def nginx(*, validated=True, config=None):
    if config is None:
        config = """
server {
  location /debian/ {
    proxy_pass https://deb.debian.org/debian/;
  }
  location /security/ {
    proxy_pass https://security.debian.org/debian-security/;
  }
}
"""
    return {"ok": True, "validated": validated, "partial": False, "stdout": config}


def approved():
    return [{"path": "/debian/", "upstream": "https://deb.debian.org/debian/"}]


def test_approved_catalog_is_exact_and_sorted():
    data = build_catalog(nginx(), [
        {"path": "/security/", "upstream": "https://security.debian.org/debian-security/"},
        *approved()
    ], "https://cache.example.org")
    assert data["schema"] == 1
    assert data["repositories"] == [
        {"upstream": "https://deb.debian.org/debian/",
         "cache": "https://cache.example.org/debian/"},
        {"upstream": "https://security.debian.org/debian-security/",
         "cache": "https://cache.example.org/security/"},
    ]


@pytest.mark.parametrize("change", [
    {"validated": False}, {"ok": False}, {"partial": True},
])
def test_unvalidated_nginx_is_rejected(change):
    cfg = nginx()
    cfg.update(change)
    with pytest.raises(CatalogError):
        build_catalog(cfg, approved(), "https://cache.example.org")


@pytest.mark.parametrize("items", [
    [{"path": "/debian/", "upstream": "https://wrong.example.net/debian/"}],
    [{"path": "/unknown/", "upstream": "https://deb.debian.org/debian/"}],
    [{"path": "/../", "upstream": "https://deb.debian.org/debian/"}],
    [{"path": "/debian/", "upstream": "http://deb.debian.org/debian/"}],
    [{"path": "/debian/", "upstream": "https://user:token@deb.debian.org/debian/"}],
    approved() + approved(),
])
def test_invalid_or_unapproved_mappings_are_rejected(items):
    with pytest.raises(CatalogError):
        build_catalog(nginx(), items, "https://cache.example.org")


def test_approval_file_requires_explicit_allowlist(tmp_path):
    p = tmp_path / "allowlist.json"
    p.write_text(json.dumps({"schema": 1, "approved_routes": approved()}))
    assert load_approvals(p) == approved()
    link = tmp_path / "link.json"
    link.symlink_to(p)
    with pytest.raises(CatalogError):
        load_approvals(link)


def test_untrusted_submission_cannot_be_used_as_approval(tmp_path):
    p = tmp_path / "request.json"
    p.write_text(json.dumps({"schema": 1, "repositories": approved()}))
    with pytest.raises(CatalogError):
        load_approvals(p)


def test_atomic_publish_and_symlink_protection(tmp_path):
    target = tmp_path / "catalog.json"
    target.write_text("old")
    data = build_catalog(nginx(), approved(), "https://cache.example.org")
    publish_catalog(data, target)
    assert json.loads(target.read_text()) == data
    assert target.stat().st_mode & 0o777 == 0o644
    assert sorted(x.name for x in tmp_path.iterdir()) == ["catalog.json"]
    link = tmp_path / "linked.json"
    link.symlink_to(target)
    with pytest.raises(CatalogError):
        publish_catalog(data, link)
    assert json.loads(target.read_text()) == data
