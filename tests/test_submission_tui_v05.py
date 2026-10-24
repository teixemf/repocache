"""Issue #23: headless authorized proposal review and undo workflow."""
from __future__ import annotations

import asyncio
import json

import pytest

from repocache.submissions import SubmissionQueue


def test_tui_two_step_review_and_audited_undo(tmp_path, monkeypatch):
    pytest.importorskip("textual")
    from textual.widgets import DataTable, TabbedContent
    from repocache import tui, submissions
    from repocache.core import Settings

    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    from repocache import submission_decisions as decisions
    protected = tmp_path / "root-audit"
    protected.mkdir(mode=0o700)
    protected.chmod(0o700)
    monkeypatch.setattr(decisions, "_trusted_dir", lambda _path: None)
    monkeypatch.setattr(decisions, "_verify_lock_fd", lambda _fd: None)
    monkeypatch.setattr(decisions, "_open_trusted", lambda path: __import__("os").open(
        path, __import__("os").O_RDONLY | getattr(__import__("os"), "O_NOFOLLOW", 0)))
    queue = SubmissionQueue(private / "state.db", journal_dir=protected)
    item = {"schema": 1, "os": {"id": "debian", "version": "13"},
            "repositories": [{"type": "apt-list",
                              "url": "https://mirror.example.org/private/project/",
                              "insecure_http": False}]}
    ident = queue.enqueue("hashed-key", "nonce", "digest", item, now=100000)
    monkeypatch.setattr(tui, "SubmissionQueue", lambda _path: queue)
    monkeypatch.setattr(tui, "SUBMISSION_QUEUE_PATH", queue.path)
    monkeypatch.setattr(tui.os, "geteuid", lambda: 0)

    sample = {
        "service": "active", "nginx_config_readable": True,
        "nginx_config_validated": False, "nginx_config_partial": False,
        "nginx_config_source": "test", "repos": [],
        "disk": {"ok": True, "used": 0, "total": 1000, "percent": 0},
        "metrics": {"hit_rate": None, "available": False, "requests": 0,
                    "hit": 0, "miss": 0, "errors_5xx": None, "series": [],
                    "series_unit": "hour", "cache_observed": 0,
                    "bytes_sent": None, "avg_request_ms": None,
                    "first_seen": None, "last_seen": None,
                    "detail": "none", "truncated": False},
    }
    monkeypatch.setattr(tui, "snapshot", lambda *a, **kw: sample)
    monkeypatch.setattr(tui, "health", lambda *a, **kw: {"checks": []})
    monkeypatch.setattr(tui, "Settings", lambda: Settings(metrics_log=tmp_path / "missing"))

    async def exercise():
        app = tui.RepoCacheApp(auto_refresh=False)
        async with app.run_test(size=(130, 46)) as pilot:
            await pilot.pause(0.2)
            await pilot.press("5")
            assert app.query_one(TabbedContent).active == "submissions"
            table = app.query_one("#proposal-table", DataTable)
            assert table.row_count == 1
            table.focus()
            await pilot.press("enter")
            await pilot.pause(0.1)
            assert app._selected_proposal == ident
            assert app._proposal_versions[ident] == 0
            assert app._proposal_digests[ident] == queue.pending()[0]["metadata_digest"]
            await pilot.press("y")
            await pilot.pause(0.1)
            assert len(queue.pending()) == 1  # first keypress only confirms intent
            await pilot.press("y")
            await pilot.pause(0.1)
            assert queue.pending() == []
            assert queue.audit(ident)[-1][0] == "review"
            await pilot.press("u")
            await pilot.pause(0.1)
            assert len(queue.pending()) == 1
            assert [x[0] for x in queue.audit(ident)] == ["review", "reopen"]
    asyncio.run(exercise())


def test_admin_only_submission_screen(tmp_path, monkeypatch):
    pytest.importorskip("textual")
    from repocache import tui
    from repocache.core import Settings
    from textual.widgets import DataTable
    monkeypatch.setattr(tui.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(tui, "SUBMISSION_QUEUE_PATH", tmp_path / "not-here")
    monkeypatch.setattr(tui, "snapshot", lambda *a, **kw: {
        "service": "unknown", "disk": {"ok": False, "reason": "missing"},
        "nginx_config_readable": False, "nginx_config_validated": False,
        "nginx_config_source": "none", "nginx_config_partial": False,
        "repos": [], "metrics": {
            "hit_rate": None, "available": False, "requests": 0, "hit": 0,
            "miss": 0, "errors_5xx": None, "series": [], "series_unit": "hour",
            "cache_observed": 0, "bytes_sent": None, "avg_request_ms": None,
            "first_seen": None, "last_seen": None, "detail": "missing",
            "truncated": False}})
    monkeypatch.setattr(tui, "health", lambda *a, **kw: {"checks": []})
    monkeypatch.setattr(tui, "Settings", lambda: Settings(metrics_log=tmp_path / "absent"))

    async def exercise():
        app = tui.RepoCacheApp(auto_refresh=False)
        async with app.run_test(size=(130, 45)) as pilot:
            await pilot.pause(0.2)
            await pilot.press("5")
            assert app.query_one("#proposal-table", DataTable).row_count == 0
            await pilot.press("y")
            await pilot.press("n")
            assert app._last_review is None
    asyncio.run(exercise())
