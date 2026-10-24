"""Bounded gzip rotation and per-repository TUI coverage (#14)."""
from __future__ import annotations

import asyncio
import gzip
import json
from datetime import datetime, timezone

import pytest

from repocache.core import Settings, metrics

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)


def _log(path, uri, cache):
    return json.dumps({
        "time_iso8601": "2026-10-17T23:00:00Z",
        "request_uri": uri,
        "status": 200,
        "upstream_cache_status": cache,
        "body_bytes_sent": 128,
    }) + "\n"


def test_bounded_gzip_history_and_repository_attribution(tmp_path):
    active = tmp_path / "metrics.jsonl"
    active.write_text(_log(active, "/debian/now", "MISS"))
    with gzip.open(tmp_path / "metrics.jsonl.1.gz", "wt") as stream:
        stream.write(_log(active, "/debian/previous", "HIT"))
        stream.write(_log(active, "/alma/elsewhere", "HIT"))
    report = metrics(Settings(metrics_log=active), now=NOW, repo="/debian/", hours=24)
    assert report["requests"] == 2
    assert report["hit"] == 1 and report["miss"] == 1
    assert report["history_files_read"] == 2
    assert not report["rotation_incomplete"]
    assert report["bytes_sent"] == 256


def test_corrupt_gzip_and_symlink_rotation_do_not_leak_or_fake_history(tmp_path):
    active = tmp_path / "metrics.jsonl"
    active.write_text(_log(active, "/debian/now", "HIT"))
    (tmp_path / "metrics.jsonl.1.gz").write_bytes(b"not gzip")
    (tmp_path / "metrics.jsonl.2").symlink_to(tmp_path / "outside")
    report = metrics(Settings(metrics_log=active), now=NOW)
    assert report["requests"] == 1
    assert report["rotation_incomplete"] is True
    assert report["coverage"] == "partial"


def test_gzip_decompression_is_bounded(tmp_path):
    active = tmp_path / "metrics.jsonl"
    active.write_text(_log(active, "/debian/now", "MISS"))
    with gzip.open(tmp_path / "metrics.jsonl.1.gz", "wb") as stream:
        stream.write(b"A" * 8_000_000)
    report = metrics(Settings(metrics_log=active), now=NOW)
    assert report["truncated"] is True
    assert report["requests"] == 1
    assert report["coverage"] == "truncated"


def test_tui_can_switch_from_selected_route_to_global_metrics(monkeypatch, tmp_path):
    pytest.importorskip("textual")
    from textual.widgets import DataTable, TabbedContent
    from repocache import tui

    calls = []
    sample = {
        "service": "active", "nginx_config_readable": True,
        "nginx_config_validated": False, "nginx_config_partial": False,
        "nginx_config_source": "test",
        "repos": [{"name": "debian", "path": "/debian/",
                   "upstream": "https://deb.debian.org/debian/"}],
        "disk": {"ok": True, "used": 0, "total": 1000, "percent": 0},
        "metrics": {"hit_rate": None, "available": False, "requests": 0,
                    "hit": 0, "miss": 0, "errors_5xx": None, "series": [],
                    "series_unit": "hour", "cache_observed": 0,
                    "bytes_sent": None, "avg_request_ms": None,
                    "first_seen": None, "last_seen": None,
                    "detail": "none", "truncated": False}}
    monkeypatch.setattr(tui, "Settings", lambda: Settings(metrics_log=tmp_path / "missing"))
    monkeypatch.setattr(tui, "snapshot", lambda *a, **kw: sample)
    monkeypatch.setattr(tui, "health", lambda *a, **kw: {"checks": []})
    def scoped(settings, hours=24, repo=None):
        calls.append(repo)
        return dict(sample["metrics"], repo=repo)
    monkeypatch.setattr(tui, "metrics", scoped)

    async def exercise():
        app = tui.RepoCacheApp(auto_refresh=False)
        async with app.run_test(size=(130, 44)) as pilot:
            await pilot.pause(0.2)
            await pilot.press("2")
            table = app.query_one("#repo-table", DataTable)
            table.focus()
            await pilot.press("enter")
            await pilot.pause(0.1)
            assert app._selected_repo == "/debian/"
            await pilot.press("f")
            await pilot.pause(0.3)
            assert app.query_one(TabbedContent).active == "metrics"
            assert app._metrics_filter == "/debian/"
            assert "/debian/" in calls
            await pilot.press("g")
            await pilot.pause(0.1)
            assert app._metrics_filter is None
    asyncio.run(exercise())
