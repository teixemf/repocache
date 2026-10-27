"""Static opt-in NGINX metrics contract and parser interoperability (#14).

These tests do NOT start NGINX or prove production log routing, permissions,
rotation, SELinux behavior, or data retention on either supported distribution.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from repocache.core import Settings, metrics


ROOT = Path(__file__).resolve().parents[1]
HTTP = ROOT / "deploy/examples/nginx-metrics-http.conf.example"
LOCATION = ROOT / "deploy/examples/nginx-metrics-location.conf.example"
ALLOWED_VARIABLES = {
    "time_iso8601",
    "repocache_metric_repo",
    "status",
    "upstream_cache_status",
    "body_bytes_sent",
    "request_time",
}


def _directives(path: Path) -> str:
    return "\n".join(
        line for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def test_nginx_format_is_privacy_minimal_and_http_only():
    http = _directives(HTTP)
    assert "log_format repocache_metrics escape=json" in http
    assert "access_log " not in http
    assert set(re.findall(r"\$([a-zA-Z_][a-zA-Z0-9_]*)", http)) == ALLOWED_VARIABLES
    assert all(item not in http for item in (
        "request_uri", "remote_addr", "http_", "request_method",
        "user_agent", "authorization", "cookie", "args", "host",
    ))
    assert '"repocache_repository":"$repocache_metric_repo"' in http
    assert '"time_iso8601":"$time_iso8601"' in http


def test_location_fragment_has_literal_approved_label_and_no_route_creation():
    location = _directives(LOCATION)
    assert location.splitlines() == [
        'set $repocache_metric_repo "/debian/";',
        'access_log /var/log/nginx/repocache-metrics.log repocache_metrics;',
    ]
    assert not any(word in location for word in ("proxy_pass", "location ", "listen ", "server "))


def test_ndjson_records_from_proposed_format_are_usable_and_route_isolated(tmp_path):
    rows = [
        {
            "time_iso8601": "2026-10-18T00:00:00+01:00",
            "repocache_repository": "/debian/",
            "status": "200",
            "upstream_cache_status": "HIT",
            "body_bytes_sent": "120",
            "request_time": "0.125",
        },
        {
            "time_iso8601": "2026-10-17T23:10:00Z",
            "repocache_repository": "/almalinux/",
            "status": "503",
            "upstream_cache_status": "MISS",
            "body_bytes_sent": "60",
            "request_time": "0.250",
        },
        {
            "time_iso8601": "2026-10-17T18:20:00-05:00",
            "repocache_repository": "/debian/",
            "status": "200",
            "upstream_cache_status": "BYPASS",
            "body_bytes_sent": "80",
            "request_time": "0.050",
        },
    ]
    assert all(set(row) == {
        "time_iso8601", "repocache_repository", "status",
        "upstream_cache_status", "body_bytes_sent", "request_time",
    } for row in rows)
    file = tmp_path / "repocache-metrics.log"
    file.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    settings = Settings(metrics_log=file)
    report = metrics(
        settings,
        repo="/debian/",
        hours=24,
        now=datetime(2026, 10, 18, tzinfo=timezone.utc),
    )
    assert report["requests"] == 2
    assert report["first_seen"] == "2026-10-17T23:00:00+00:00"
    assert (report["hit"], report["miss"], report["bypass"]) == (1, 0, 1)
    assert report["bytes_sent"] == 200
    assert report["cache_observed"] == 2
    assert report["hit_rate"] == 50.0
    assert report["coverage"] == "sampled"

    other = metrics(
        settings,
        repo="/almalinux/",
        hours=24,
        now=datetime(2026, 10, 18, tzinfo=timezone.utc),
    )
    assert other["requests"] == 1
    assert other["errors_5xx"] == 1
    assert other["bytes_sent"] == 60
