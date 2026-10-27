#!/usr/bin/env python3
"""Unprivileged, network-isolated real-NGINX smoke for #14.

Uses a private ephemeral NGINX prefix, high localhost ports, disposable logs,
and no systemd, production configuration, publisher credentials or host paths.
Do not present this as native booted systemd/SELinux acceptance.
"""
from __future__ import annotations

import gzip
import http.client
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
HTTP = ROOT / "deploy/examples/nginx-metrics-http.conf.example"
LOCATION = ROOT / "deploy/examples/nginx-metrics-location.conf.example"
FIELDS = {"time_iso8601", "repocache_repository", "status", "upstream_cache_status", "body_bytes_sent", "request_time"}
SECRET = "PRIVATE_QUERY_SHOULD_NOT_APPEAR_IN_METRICS"


def port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def active_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def wait_count(path: Path, count: int) -> list[str]:
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        lines = active_lines(path)
        if len(lines) >= count:
            return lines
        time.sleep(0.04)
    raise AssertionError(f"timeout waiting for {count} lines in {path.name}; got {len(active_lines(path))}")


def run(*cmd: str, success: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
    if (result.returncode == 0) != success:
        raise AssertionError(f"unexpected exit from {cmd[0]} (status={result.returncode}): {result.stderr[-1200:]}")
    return result


def request(port_: int, target: str, *, retry: bool = False) -> int:
    until = time.monotonic() + (4 if retry else 0)
    while True:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port_, timeout=2)
            conn.request("GET", target, headers={"Connection": "close"})
            response = conn.getresponse()
            status = response.status
            response.read()
            conn.close()
            return status
        except OSError:
            if time.monotonic() > until:
                raise
            time.sleep(0.04)


def config(root: Path, proxy_port: int, origin_port: int, enabled: bool) -> str:
    http_fragment = HTTP.read_text(encoding="utf-8") if enabled else ""
    location_fragment = LOCATION.read_text(encoding="utf-8")
    assert location_fragment.count('set $repocache_metric_repo "/debian/";') == 1
    assert location_fragment.count("/var/log/nginx/repocache-metrics.log") == 1
    location_fragment = "\n".join(
        line for line in location_fragment.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )

    def repo_location(route: str) -> str:
        extra = ""
        if enabled:
            extra = location_fragment.replace('"/debian/"', f'"{route}"').replace(
                "/var/log/nginx/repocache-metrics.log", str(root / "metrics.log")
            )
            # NGINX location access_log overrides inherited http audit logging.
            # Deliberately repeat the existing audit format in opted-in locations.
            extra += f"\naccess_log {root / 'audit.log'} existing_audit;"
        return f"""
        location {route} {{
            {extra}
            proxy_pass http://127.0.0.1:{origin_port};
            proxy_cache demo_cache;
            proxy_cache_valid 200 10m;
            proxy_cache_bypass $arg_bypass;
            proxy_no_cache $arg_bypass;
        }}
        """

    return f"""
    worker_processes 1;
    pid {root / 'nginx.pid'};
    error_log {root / 'error.log'} notice;
    events {{ worker_connections 64; }}
    http {{
        client_body_temp_path {root / 'clientbody'};
        proxy_temp_path {root / 'proxytemp'};
        fastcgi_temp_path {root / 'fastcgitemp'};
        uwsgi_temp_path {root / 'uwsgitemp'};
        scgi_temp_path {root / 'scgitemp'};
        proxy_cache_path {root / 'cache'} keys_zone=demo_cache:1m levels=1:2 inactive=10m max_size=10m;
        log_format existing_audit '$status $request_method';
        access_log {root / 'audit.log'} existing_audit;
        {http_fragment}
        server {{
            listen 127.0.0.1:{origin_port};
            access_log off;
            location / {{ return 200 'payload'; add_header Cache-Control public; }}
        }}
        server {{
            listen 127.0.0.1:{proxy_port};
            {repo_location('/debian/')}
            {repo_location('/almalinux/')}
            location /debian/rewrite/ {{ rewrite ^ /almalinux/rewritten last; }}
            location /unapproved/ {{ return 200 'not-a-repository'; }}
        }}
    }}
    """


def protected(path: Path) -> None:
    assert path.is_file(), f"missing log {path.name}"
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode & 0o077 == 0, f"unsafe log permissions: {path.name}: {mode:o}"
    assert path.stat().st_uid == os.getuid(), f"log owned by unexpected UID: {path.name}"


def smoke() -> None:
    assert os.geteuid() != 0, "unprivileged test user required"
    old_umask = os.umask(0o077)
    try:
        print("Environment:", Path("/etc/os-release").read_text(encoding="utf-8").splitlines()[0], flush=True)
        print(run("nginx", "-v").stderr.strip(), flush=True)
        with tempfile.TemporaryDirectory(prefix="repocache-nginx-14-") as tmp:
            root = Path(tmp)
            assert stat.S_IMODE(root.stat().st_mode) == 0o700
            origin, proxy = port(), port()
            assert origin != proxy
            baseline = root / "baseline.conf"
            opted = root / "opted.conf"
            invalid = root / "invalid.conf"
            baseline.write_text(config(root, proxy, origin, enabled=False), encoding="utf-8")
            opted.write_text(config(root, proxy, origin, enabled=True), encoding="utf-8")
            invalid.write_text(opted.read_text(encoding="utf-8") + "\nBROKEN_DIRECTIVE;\n", encoding="utf-8")
            nginx = "nginx"

            def check(path: Path, success: bool = True) -> None:
                run(nginx, "-p", str(root) + "/", "-c", str(path), "-t", success=success)

            def serve(path: Path):
                check(path)
                err = open(root / "stderr.log", "ab")
                process = subprocess.Popen(
                    [nginx, "-p", str(root) + "/", "-c", str(path), "-g", "daemon off;"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err,
                )
                return process, err

            def stop(process: subprocess.Popen[bytes], err) -> None:
                process.terminate()
                try:
                    process.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                    raise AssertionError("NGINX failed to exit gracefully")
                finally:
                    err.close()

            # Original audit-only configuration, no metrics produced.
            process, err = serve(baseline)
            try:
                assert request(proxy, "/debian/original", retry=True) == 200
                assert len(wait_count(root / "audit.log", 1)) == 1
                assert not (root / "metrics.log").exists()
            finally:
                stop(process, err)
            print("PASS: baseline requests recorded in existing audit log; no opt-in metrics", flush=True)

            process, err = serve(opted)
            try:
                request(proxy, "/debian/pkg?private=" + SECRET, retry=True)
                request(proxy, "/debian/pkg?private=" + SECRET)
                request(proxy, "/debian/pkg?private=" + SECRET + "&bypass=1")
                request(proxy, "/almalinux/pkg")
                request(proxy, "/almalinux/pkg")
                request(proxy, "/unapproved/pkg")
                request(proxy, "/debian/rewrite/file")
                lines = wait_count(root / "metrics.log", 6)
                records = [json.loads(x) for x in lines]
                assert len(records) == 6, f"expected six approved metrics events, got {len(records)}"
                assert len(wait_count(root / "audit.log", 8)) == 8, "inherited audit logging lost after opt-in"
                assert all(set(x) == FIELDS for x in records)
                assert all(x["repocache_repository"] in {"/debian/", "/almalinux/"} for x in records)
                assert [r["repocache_repository"] for r in records].count("/debian/") == 3
                assert [r["repocache_repository"] for r in records].count("/almalinux/") == 3
                assert {r["upstream_cache_status"] for r in records} >= {"MISS", "HIT", "BYPASS"}
                assert SECRET not in "\n".join(lines), "request credentials leaked into metrics"
                assert all("/pkg" not in x for x in lines), "request paths leaked into metrics"
                assert all(str(x["time_iso8601"]).endswith(("+00:00", "Z")) or "+" in str(x["time_iso8601"]) or "-" in str(x["time_iso8601"])[10:] for x in records)
                protected(root / "metrics.log")
                protected(root / "audit.log")
                print("PASS: real HIT/MISS/BYPASS, two trusted route labels, internal rewrite, no leakage, audit preserved", flush=True)

                # The invalid *staged* config must be rejected without disrupting the running instance.
                check(invalid, success=False)
                assert request(proxy, "/debian/after-invalid") == 200
                assert len(wait_count(root / "audit.log", 9)) == 9
                print("PASS: invalid staged config rejected; running NGINX and inherited audit log intact", flush=True)

                # Rename + NGINX reopen; do not use copytruncate and do not touch system paths.
                (root / "metrics.log").rename(root / "metrics.log.1")
                run(nginx, "-p", str(root) + "/", "-c", str(opted), "-s", "reopen")
                assert request(proxy, "/debian/after-reopen") == 200
                protected(root / "metrics.log")
                protected(root / "metrics.log.1")
                assert len(wait_count(root / "metrics.log", 1)) == 1
                assert len(wait_count(root / "audit.log", 10)) == 10
                with gzip.open(root / "metrics.log.1.gz", "wt", encoding="utf-8") as out:
                    out.write((root / "metrics.log.1").read_text(encoding="utf-8"))
                with gzip.open(root / "metrics.log.1.gz", "rt", encoding="utf-8") as archived:
                    assert len([json.loads(x) for x in archived]) == 7
                print("PASS: rename/reopen rotation, fresh metrics file, bounded gzip archive, audit continues", flush=True)
            finally:
                stop(process, err)

            # Roll back by selecting original preserved audit-only config.
            before = len(active_lines(root / "metrics.log"))
            audit_before = len(active_lines(root / "audit.log"))
            process, err = serve(baseline)
            try:
                assert request(proxy, "/debian/after-rollback", retry=True) == 200
                assert len(active_lines(root / "metrics.log")) == before, "metrics still active after rollback"
                assert len(wait_count(root / "audit.log", audit_before + 1)) == audit_before + 1
                protected(root / "audit.log")
                print("PASS: restored audit-only NGINX config, no new metrics after rollback", flush=True)
            finally:
                stop(process, err)
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    smoke()
