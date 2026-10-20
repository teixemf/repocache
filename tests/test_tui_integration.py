"""Exercise the real TUI when Textual is installed.

Other tests run without Textual; a full environment should run this test.
"""
from __future__ import annotations

import asyncio

import pytest


def test_textual_mount_refresh_and_repos(monkeypatch, tmp_path):
    pytest.importorskip("textual")
    from textual.widgets import DataTable, TabbedContent
    from repocache import tui
    from repocache.core import Settings

    sample = {
        "service": "active",
        "nginx_config_readable": True,
        "nginx_config_validated": False,
        "nginx_config_source": "NGINX files (direct read)",
        "nginx_config_partial": False,
        "repos": [{"name": "debian", "path": "/debian/", "upstream": "https://deb.debian.org/debian/"}],
        "disk": {"ok": True, "used": 100, "total": 1000, "percent": 10},
        "metrics": {"hit_rate": None, "available": False, "requests": 0, "hit": 0, "miss": 0,
                    "errors_5xx": None, "series": [], "series_unit": "hour", "cache_observed": 0,
                    "bytes_sent": None, "avg_request_ms": None, "first_seen": None, "last_seen": None,
                    "detail": "no samples", "truncated": False},
    }
    monkeypatch.setattr(tui, "snapshot", lambda *a, **kw: sample)
    monkeypatch.setattr(tui, "health", lambda *a, **kw: {"checks": [{"name": "NGINX", "result": "OK", "detail": "active"}]})
    monkeypatch.setattr(tui, "service_status", lambda: "active")
    monkeypatch.setattr(tui, "disk_status", lambda *a: sample["disk"])
    monkeypatch.setattr(tui, "metrics", lambda *a, **kw: sample["metrics"])
    monkeypatch.setattr(tui, "Settings", lambda: Settings(metrics_log=tmp_path / "no-log"))

    async def exercise():
        app = tui.RepoCacheApp(auto_refresh=True, refresh_interval=5)
        async with app.run_test(size=(130, 44)) as pilot:
            await pilot.pause(0.3)
            assert app.query_one("#repo-table", DataTable).row_count == 1
            await pilot.press("2")
            assert app.query_one(TabbedContent).active == "repos"
            await pilot.press("a")
            assert not app.refresh_enabled
            await pilot.press("a")
            assert app.refresh_enabled
            await pilot.press("i")
            assert app.refresh_intervals[app.refresh_interval_index] == 15
    asyncio.run(exercise())
