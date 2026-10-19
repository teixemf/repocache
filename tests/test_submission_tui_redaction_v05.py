"""Ensure privileged Textual monitoring never echoes untrusted request paths."""
import json
import pytest


def test_recent_tui_log_event_redacts_url_and_malformed_line():
    pytest.importorskip("textual")
    from repocache.tui import RepoCacheApp
    data = {"time_iso8601": "2026-10-18T10:30:00Z", "status": 200,
            "upstream_cache_status": "HIT",
            "request_uri": "/sensitive/tenant?token=SECRET_VALUE"}
    rendered = RepoCacheApp._short_event(json.dumps(data))
    assert "10:30:00" in rendered and "HIT" in rendered
    assert "SECRET_VALUE" not in rendered and "sensitive" not in rendered
    assert "SECRET_VALUE" not in RepoCacheApp._short_event("raw SECRET_VALUE")
