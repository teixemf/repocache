"""Corrupted persisted queue data must not authorize a TUI review (#17/#23)."""
from __future__ import annotations

import asyncio

import pytest


def test_tui_corrupt_pending_row_fails_closed(tmp_path, monkeypatch):
    pytest.importorskip("textual")
    from repocache import tui
    from repocache.core import Settings
    from textual.widgets import DataTable, Static

    class BrokenQueue:
        def pending(self):
            return [{"id": "a" * 32, "os": "debian", "version_os": "13",
                     "version": 0, "repositories": []}]

    path = tmp_path / "queue.db"
    path.write_bytes(b"synthetic fake queue")
    monkeypatch.setattr(tui, "SUBMISSION_QUEUE_PATH", path)
    monkeypatch.setattr(tui, "SubmissionQueue", lambda *_: BrokenQueue())
    monkeypatch.setattr(tui.os, "geteuid", lambda: 0)
    monkeypatch.setattr(tui, "Settings",
                        lambda: Settings(metrics_log=tmp_path / "missing"))
    monkeypatch.setattr(tui, "snapshot", lambda *args, **kwargs: {
        "service": "inactive", "nginx_config_readable": True,
        "nginx_config_validated": False, "nginx_config_partial": False,
        "nginx_config_source": "test", "repos": [],
        "disk": {"ok": False, "reason": "no cache"},
        "metrics": {"hit_rate": None, "available": False, "requests": 0,
                    "hit": 0, "miss": 0, "errors_5xx": None, "series": [],
                    "series_unit": "hour", "cache_observed": 0,
                    "bytes_sent": None, "avg_request_ms": None,
                    "first_seen": None, "last_seen": None,
                    "detail": "missing", "truncated": False}})
    monkeypatch.setattr(tui, "health", lambda *a, **kw: {"checks": []})

    async def run():
        app = tui.RepoCacheApp(auto_refresh=False)
        async with app.run_test(size=(120, 42)) as pilot:
            await pilot.pause(0.2)
            await pilot.press("5")
            await pilot.pause(0.1)
            assert app.query_one("#proposal-table", DataTable).row_count == 0
            assert app._proposal_versions == {}
            note = str(app.query_one("#proposal-note", Static).render())
            assert "Cannot access" in note
            await pilot.press("y")
            await pilot.press("n")
            assert app._last_review is None

    asyncio.run(run())
