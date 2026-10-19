"""REPOCACHE config discovery and passive metrics regression tests."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from repocache.core import Settings, discover_repos, disk_status, metrics, timestamp


def test_nginx_repository_locations_are_discovered_without_default_route():
    nginx = """
    server {
       location / { return 404; }
       location /debian/ {
           proxy_pass https://deb.debian.org/debian/;
       }
       location /alma/ {
           proxy_pass https://repo.almalinux.org/almalinux/;
       }
    }"""
    result = discover_repos(nginx)
    assert {r["name"] for r in result} == {"debian", "alma"}
    assert all(r["path"] != "/" for r in result)


def test_timestamps_fail_safe():
    assert timestamp("2026-10-17T22:21:45+00:00") == datetime(
        2026, 10, 17, 22, 21, 45, tzinfo=timezone.utc)
    assert timestamp("not a timestamp") is None


def test_metrics_compute_real_hit_rate_and_reject_outside_interval(tmp_path):
    file = tmp_path / "metrics.jsonl"
    rows = [
        {"time_iso8601": "2026-10-17T23:00:00Z", "request_uri": "/debian/a",
         "status": 200, "upstream_cache_status": "HIT", "request_time": 0.1,
         "body_bytes_sent": 1000},
        {"time_iso8601": "2026-10-17T23:01:00Z", "request_uri": "/debian/b",
         "status": 503, "upstream_cache_status": "MISS", "request_time": 0.3,
         "body_bytes_sent": 2000},
        {"time_iso8601": "2026-09-01T00:00:00Z", "request_uri": "/debian/old",
         "status": 200, "upstream_cache_status": "HIT"}
    ]
    file.write_text("\n".join(json.dumps(x) for x in rows) + "\n")
    report = metrics(Settings(metrics_log=file), hours=24,
                     now=datetime(2026, 10, 18, tzinfo=timezone.utc))
    assert report["available"] is True
    assert report["requests"] == 2
    assert report["hit"] == 1
    assert report["hit_rate"] == 50.0
    assert report["errors_5xx"] == 1
    assert report["bytes_sent"] == 3000


def test_missing_or_corrupt_telemetry_is_not_invented(tmp_path):
    missing = metrics(Settings(metrics_log=tmp_path / "missing"))
    assert not missing["available"]
    assert missing["requests"] == 0 and missing["hit_rate"] is None
    broken = tmp_path / "broken.json"
    broken.write_text("not valid json\n")
    result = metrics(Settings(metrics_log=broken))
    assert result["ignored_records"] == 1


def test_missing_cache_path_does_not_invent_disk_metrics(tmp_path):
    state = disk_status(tmp_path / "absent")
    assert state["ok"] is False
    assert state["percent"] is None
