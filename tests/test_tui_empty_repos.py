"""Headless regression for empty discovery and non-validated NGINX output."""
from __future__ import annotations

import asyncio

import pytest


def test_tui_empty_repositories_are_not_configuration_failures(monkeypatch, tmp_path):
    pytest.importorskip("textual")
    from textual.widgets import DataTable, TabbedContent
    from repocache import tui
    from repocache.core import Settings

    sample = {
        "service": "active", "nginx_config_readable": True,
        "nginx_config_validated": False, "nginx_config_partial": False,
        "nginx_config_source": "NGINX files (direct read)", "repos": [],
        "disk": {"ok": True, "used": 0, "total": 1000, "percent": 0},
        "metrics": {"hit_rate": None, "available": False, "requests": 0,
                    "hit": 0, "miss": 0, "errors_5xx": None, "series": [],
                    "series_unit": "hour", "cache_observed": 0,
                    "bytes_sent": None, "avg_request_ms": None,
                    "first_seen": None, "last_seen": None,
                    "detail": "no metrics", "truncated": False},
    }
    monkeypatch.setattr(tui, "snapshot", lambda *args, **kwargs: sample)
    monkeypatch.setattr(tui, "health", lambda *args, **kwargs: {"checks": []})
    monkeypatch.setattr(tui, "Settings", lambda: Settings(metrics_log=tmp_path / "missing"))
    monkeypatch.setattr(tui, "probe_upstream", lambda *args, **kwargs:
                        pytest.fail("No upstream probe should run without a selection"))

    async def exercise():
        app = tui.RepoCacheApp(auto_refresh=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.2)
            assert app.query_one("#repo-table", DataTable).row_count == 0
            assert app.query_one(TabbedContent).active == "overview"
            await pilot.press("2")
            await pilot.press("t")
            await pilot.pause(0.1)
            assert app._selected_repo == ""
            assert app.query_one("#repo-table", DataTable).row_count == 0

    asyncio.run(exercise())
