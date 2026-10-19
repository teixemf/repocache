"""REPOCACHE v0.1.2 regressions: permissions, routes, periods and interface."""
from datetime import datetime, timezone
import json
from pathlib import Path

from repocache import core
from repocache.cli import parse_period


def _permission_error(argv, timeout=10):
    if '-t' in argv or '-T' in argv:
        return {'ok': False, 'code': 1, 'stdout': '',
                'stderr': 'nginx: [emerg] cannot load certificate "/etc/letsencrypt/live/repo.example.test/fullchain.pem": BIO_new_file() failed (Permission denied)'}
    return {'ok': False, 'code': 1, 'stdout': '', 'stderr': 'not active'}


def test_nginx_t_permission_denied_is_unverified_not_failed(monkeypatch, tmp_path):
    monkeypatch.setattr(core, 'command', _permission_error)
    monkeypatch.setattr(core, 'service_status', lambda: 'active')
    conf = tmp_path / 'nginx.conf'
    conf.write_text('events {}\nhttp { server { location /debian/ { proxy_pass https://deb.debian.org/debian/; } } }')
    (tmp_path / 'log.json').write_text('')
    report = core.health(core.Settings(nginx_conf=conf, cache_dir=tmp_path, metrics_log=tmp_path / 'log.json'))
    syntax = next(i for i in report['checks'] if i['name'] == 'NGINX syntax')
    assert syntax['result'] == 'WARN'
    assert 'sudo repocache config check' in syntax['detail']
    assert report['ok']


def test_actual_nginx_syntax_error_still_fail(monkeypatch, tmp_path):
    def invalid(argv, timeout=10):
        return {'ok': False, 'code': 1, 'stdout': '',
                'stderr': 'nginx: [emerg] unknown directive "foobar" in /etc/nginx/nginx.conf:7'}
    monkeypatch.setattr(core, 'command', invalid)
    monkeypatch.setattr(core, 'service_status', lambda: 'active')
    conf = tmp_path / 'nginx.conf'
    conf.write_text('events {}')
    (tmp_path / 'log.json').write_text('')
    report = core.health(core.Settings(nginx_conf=conf, cache_dir=tmp_path, metrics_log=tmp_path / 'log.json'))
    syntax = next(i for i in report['checks'] if i['name'] == 'NGINX syntax')
    assert syntax['result'] == 'FAIL'
    assert not report['ok']


def test_repos_fallback_nested_includes(monkeypatch, tmp_path):
    monkeypatch.setattr(core, 'command', _permission_error)
    confd = tmp_path / 'conf.d'
    confd.mkdir()
    configs = tmp_path / 'snippets'
    configs.mkdir()
    (tmp_path / 'nginx.conf').write_text('events {}\nhttp {\n include conf.d/*.conf;\n}\n')
    (confd / 'repos.conf').write_text('server {\n location /debian/ {\n include snippets/debian.conf;\n }\n location /ubuntu/ { proxy_pass http://ubuntu.example.invalid; }\n}\n')
    (configs / 'debian.conf').write_text('proxy_pass https://deb.debian.org/debian/;\n')
    result = core.nginx_config(core.Settings(nginx_conf=tmp_path / 'nginx.conf'))
    assert result['ok'] and not result['validated']
    repos = core.discover_repos(result['stdout'])
    assert {r['name'] for r in repos} == {'debian', 'ubuntu'}
    assert repos[0]['upstream'] == 'https://deb.debian.org/debian/'
    assert 'NGINX files' in result['source']


def test_root_reverse_proxy_detected():
    repos = core.discover_repos('server {\n location / {\n proxy_pass http://backend;\n }\n }')
    assert len(repos) == 1 and repos[0]['name'] == 'root'


def test_no_config_doesnt_make_up_repos(monkeypatch, tmp_path):
    monkeypatch.setattr(core, 'command', _permission_error)
    result = core.nginx_config(core.Settings(nginx_conf=tmp_path / 'missing-nginx.conf'))
    assert not result['ok']
    assert core.discover_repos(result['stdout']) == []


def test_day_periods_are_days_not_hours(tmp_path):
    log = tmp_path / 'metrics.log'
    log.write_text('\n'.join(json.dumps({'time_iso8601': ts, 'status':200}) for ts in [
        '2026-10-14T01:00:00Z', '2026-10-14T20:00:00Z',
        '2026-10-15T04:00:00Z', '2026-10-17T22:00:00Z']) + '\n')
    now = datetime(2026, 10, 18, 0, 0, tzinfo=timezone.utc)
    for hours in (168, 720):
        result = core.metrics(core.Settings(metrics_log=log), hours=hours, now=now)
        assert result['available'] and result['series_unit'] == 'day'
        assert sum(x['requests'] for x in result['series']) == 4
        assert len(result['series']) <= hours // 24 + 1
        assert any(x['requests'] == 2 for x in result['series'])
    assert parse_period('7d') == 168 and parse_period('30d') == 720
    assert parse_period('24h') == 24


def test_tui_auto_keys_declared_and_syntax_valid():
    """This does not replace a real Textual TUI runtime test."""
    import ast
    path = Path(__file__).resolve().parents[1] / 'src' / 'repocache' / 'tui.py'
    source = path.read_text()
    ast.parse(source)
    assert '("a", "toggle_auto"' in source
    assert '("i", "refresh_interval"' in source
    assert 'self.period_labels = ["1h", "6h", "24h", "7d", "30d"]' in source
