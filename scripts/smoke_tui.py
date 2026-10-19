"""Headless Textual smoke test against the installed release, not a checkout."""
from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import DataTable, TabbedContent
from repocache import tui
from repocache.core import Settings

SAMPLE = {
    "service": "active",
    "nginx_config_readable": True,
    "nginx_config_validated": True,
    "nginx_config_source": "test fixture",
    "nginx_config_partial": False,
    "repos": [{"name": "example", "path": "/example/", "upstream": "https://example.org/"}],
    "disk": {"ok": True, "used": 100, "total": 1000, "percent": 10},
    "metrics": {
        "hit_rate": None, "available": False, "requests": 0, "hit": 0,
        "miss": 0, "errors_5xx": None, "series": [], "series_unit": "hour",
        "cache_observed": 0, "bytes_sent": None, "avg_request_ms": None,
        "first_seen": None, "last_seen": None, "detail": "no samples",
        "truncated": False,
    },
}

# All data collection is stubbed. No NGINX, TLS, logs, or caches are touched.
tui.Settings = lambda: Settings(metrics_log=Path("/tmp/repocache-no-metrics"))
tui.snapshot = lambda *args, **kwargs: SAMPLE
tui.health = lambda *args, **kwargs: {"checks": [
    {"name": "NGINX", "result": "OK", "detail": "test fixture"}
]}
tui._tail_bytes = lambda *args, **kwargs: ([], False)
tui.service_status = lambda: "active"
tui.disk_status = lambda *args, **kwargs: SAMPLE["disk"]
tui.metrics = lambda *args, **kwargs: SAMPLE["metrics"]


async def smoke() -> None:
    app = tui.RepoCacheApp(auto_refresh=False)
    async with app.run_test(size=(130, 44)) as pilot:
        await pilot.pause(0.5)
        assert app.query_one("#repo-table", DataTable).row_count == 1, (
            "The initial Textual screen did not render the expected repository"
        )
        tabs = app.query_one(TabbedContent)
        for key, expected in (("2", "repos"), ("3", "metrics"),
                              ("4", "diagnostics"), ("1", "overview")):
            await pilot.press(key)
            assert tabs.active == expected, (
                f"Keyboard shortcut {key} did not select the {expected} screen"
            )
        await pilot.press("a")
        assert app.refresh_enabled, "Auto refresh toggle did not enable refresh"
        await pilot.press("a")
        assert not app.refresh_enabled, "Auto refresh toggle did not disable refresh"


if __name__ == "__main__":
    asyncio.run(smoke())
    print("PASS: Installed Textual TUI starts and switches screens headlessly.")
