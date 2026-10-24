"""v0.5.0 issue #14: bounded, private, route-specific log aggregation."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from repocache.core import Settings, _metrics_repo_prefix, metrics


NOW = datetime(2026, 10, 18, 0, 0, tzinfo=timezone.utc)


def _write(tmp_path, rows):
    path = tmp_path / "metrics.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    return Settings(metrics_log=path)


def _record(path=None, *, cache="HIT", when="2026-10-17T23:00:00Z", **extra):
    record = {"time_iso8601": when, "status": 200,
              "upstream_cache_status": cache, "body_bytes_sent": 123}
    if path is not None:
        record["request_uri"] = path
    record.update(extra)
    return record


def test_repo_filter_matches_only_anchored_prefix_without_query_string(tmp_path):
    settings = _write(tmp_path, [
        _record("/debian/pool/a.deb"),
        _record("/debian/pool/b.deb?next=/other/&auth=secret", cache="MISS"),
        _record("/else/debian/pool/c.deb"),
        _record("/debianish/pool/d.deb"),
        _record("/other/pkg?target=/debian/pool/e.deb"),
        _record("/debian%2fother/pkg"),
        _record("/debian/../other/pkg"),
    ])
    result = metrics(settings, hours=24, repo="/debian/", now=NOW)
    assert result["requests"] == 2
    assert result["hit"] == 1
    assert result["miss"] == 1
    assert result["hit_rate"] == 50.0
    assert result["bytes_sent"] == 246
    assert result["coverage"] == "sampled"


def test_route_label_log_format_needs_no_request_uri(tmp_path):
    settings = _write(tmp_path, [
        _record(repocache_repository="/debian/", cache="BYPASS"),
        _record(repocache_repository="/almalinux/"),
        _record("/other/?repo=/debian/", repocache_repository="/other/"),
    ])
    result = metrics(settings, repo="debian", hours=24, now=NOW)
    assert result["requests"] == 1
    assert result["hit"] == 0
    assert result["bypass"] == 1
    assert result["hit_rate"] == 0.0
    assert result["errors_5xx"] == 0


@pytest.mark.parametrize("value", ["", "/", "foo//bar", "../debian", "/foo/../debian/",
                                   "/foo?token=yes/", "/foo\\bar/", "debian:stable"])
def test_invalid_route_filters_return_no_metrics(tmp_path, value):
    result = metrics(_write(tmp_path, [_record("/debian/a")]), repo=value, now=NOW)
    assert result["available"] is False
    assert result["coverage"] == "unavailable"
    assert "Invalid repository" in result["detail"]


def test_future_records_are_not_counted(tmp_path):
    settings = _write(tmp_path, [_record("/debian/a", when="2026-10-18T00:03:00Z")])
    report = metrics(settings, now=NOW, repo="/debian/")
    assert report["available"] is False
    assert report["coverage"] == "no_observations"


def test_invalid_records_do_not_imply_complete_sample(tmp_path):
    path = tmp_path / "metrics.jsonl"
    path.write_text('not-json\n' + json.dumps(_record("/debian/a")) + "\n")
    result = metrics(Settings(metrics_log=path), now=NOW, repo="debian")
    assert result["requests"] == 1
    assert result["ignored_records"] == 1
    assert result["coverage"] == "partial"


def test_truncated_sample_is_explicit(tmp_path, monkeypatch):
    from repocache import core
    settings = _write(tmp_path, [_record("/debian/a")])
    monkeypatch.setattr(core, "_tail_bytes",
                        lambda *args, **kwargs: ([json.dumps(_record("/debian/a"))], True))
    result = metrics(settings, now=NOW, repo="/debian/")
    assert result["requests"] == 1
    assert result["truncated"] is True
    assert result["coverage"] == "truncated"


def test_missing_and_symlinked_logs_are_unavailable(tmp_path):
    target = tmp_path / "target.jsonl"
    target.write_text(json.dumps(_record("/debian/a")) + "\n")
    link = tmp_path / "metrics-link"
    link.symlink_to(target)
    for path in (tmp_path / "missing", link):
        result = metrics(Settings(metrics_log=path), now=NOW)
        assert not result["available"]
        assert result["coverage"] == "unavailable"


def test_tui_recent_activity_never_exposes_raw_paths_or_malformed_text():
    pytest.importorskip("textual")
    from repocache.tui import RepoCacheApp

    original = json.dumps(_record(
        "/debian/private/customer-a?access_token=TOP_SECRET",
        upstream_cache_status="BYPASS"))
    rendered = RepoCacheApp._short_event(original)
    assert "23:00:00" in rendered
    assert "BYPASS" in rendered
    assert "TOP_SECRET" not in rendered
    assert "customer-a" not in rendered
    assert "/debian/" not in rendered

    malformed = RepoCacheApp._short_event("token=TOP_SECRET from /private")
    assert "TOP_SECRET" not in malformed
    assert "token=" not in malformed

def test_reads_bounded_numbered_rotation_history(tmp_path):
    current = tmp_path / "metrics.jsonl"
    current.write_text(json.dumps(_record("/debian/new", cache="MISS")) + "\n")
    (tmp_path / "metrics.jsonl.1").write_text(
        json.dumps(_record("/debian/older")) + "\n")
    result = metrics(Settings(metrics_log=current), hours=24, repo="/debian/", now=NOW)
    assert result["requests"] == 2
    assert result["hit"] == 1
    assert result["miss"] == 1
    assert result["history_files_read"] == 2
    assert result["rotation_incomplete"] is False


def test_rotation_gaps_and_compressed_history_remain_explicitly_partial(tmp_path):
    current = tmp_path / "metrics.jsonl"
    current.write_text(json.dumps(_record("/debian/new")) + "\n")
    (tmp_path / "metrics.jsonl.3").write_text(
        json.dumps(_record("/debian/old")) + "\n")
    (tmp_path / "metrics.jsonl.2.gz").write_bytes(b"not actually gzip")
    result = metrics(Settings(metrics_log=current), now=NOW)
    assert result["requests"] == 2
    assert result["coverage"] == "partial"
    assert result["rotation_incomplete"] is True


@pytest.mark.parametrize("hours", [1, 6, 24, 168, 720])
def test_window_boundaries_do_not_invent_out_of_range_samples(tmp_path, hours):
    from datetime import timedelta
    in_window = (NOW - timedelta(minutes=25)).isoformat()
    outside = (NOW - timedelta(hours=hours, minutes=1)).isoformat()
    settings = _write(tmp_path, [
        _record("/debian/inside", when=in_window),
        _record("/debian/outside", when=outside)
    ])
    result = metrics(settings, hours=hours, now=NOW, repo="/debian/")
    assert result["requests"] == 1
    assert result["series_unit"] == ("hour" if hours <= 24 else "day")
