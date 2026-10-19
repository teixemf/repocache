"""Contract between server-generated catalogs and the standalone client."""
import importlib.util
from pathlib import Path

from repocache.catalog import build_catalog

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("standalone_client_contract",
                                               ROOT / "client/repocache_client.py")
client = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(client)


def test_server_catalog_is_interoperable_with_client(monkeypatch):
    nginx = {
        "ok": True, "validated": True, "partial": False,
        "stdout": (
            "server {\n"
            "  location /debian/ {\n"
            "    proxy_pass https://deb.debian.org/debian/;\n"
            "  }\n"
            "}"
        )
    }
    approved = build_catalog(
        nginx, [{"path": "/debian/", "upstream": "https://deb.debian.org/debian/"}],
        "https://cache.example.org")
    monkeypatch.setattr(client, "_fetch_json", lambda *a, **kw: approved)
    fetched = client._catalog("https://cache.example.org")
    assert fetched == approved
    mirrors = {"urls": ["https://cache.example.org/debian/",
                        "https://deb.debian.org/debian/"],
               "route": "mixed", "enabled": True}
    assert client._classify_repository(mirrors, fetched) == "supported"
    mirrors["urls"].append("https://unapproved.example.org/packages")
    assert client._classify_repository(mirrors, fetched) == "unknown"
