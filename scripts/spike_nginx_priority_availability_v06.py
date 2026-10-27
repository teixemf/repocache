#!/usr/bin/env python3
"""Disposable priority/availability observation for #94 (no production changes)."""
from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, build_opener
import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time

BODY_SIZE = 48 * 1024


def body_for(path: str) -> bytes:
    digest = hashlib.sha256(path.encode("ascii")).digest()
    return digest * (BODY_SIZE // len(digest))


class Origin(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if not (path.startswith("/hot/") or path.startswith("/cold/")) or ".." in path:
            self.send_error(404)
            return
        with self.server.request_lock:
            self.server.request_counts[path] += 1
        if path.endswith("/concurrent"):
            time.sleep(0.15)
        body = body_for(path)
        self.send_response(200)
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def config(prefix: Path, origin_port: int, port: int, limit: str) -> str:
    if limit not in ("32m", "128k"):
        raise ValueError("unknown lab-only limit")
    return f"""worker_processes 1;
pid {prefix}/nginx.pid;
error_log {prefix}/error.log notice;
events {{ worker_connections 256; }}
http {{
  access_log off;
  client_body_temp_path {prefix}/tmp/client;
  proxy_temp_path {prefix}/tmp/proxy;
  fastcgi_temp_path {prefix}/tmp/fastcgi;
  uwsgi_temp_path {prefix}/tmp/uwsgi;
  scgi_temp_path {prefix}/tmp/scgi;
  proxy_cache_path {prefix}/cache levels=1:2 keys_zone=shared:1m inactive=5m
      max_size={limit} manager_files=100 manager_sleep=50ms
      manager_threshold=200ms use_temp_path=off;
  server {{
    listen 127.0.0.1:{port};
    location / {{
      proxy_pass http://127.0.0.1:{origin_port};
      proxy_cache shared;
      proxy_cache_key "$scheme$proxy_host$request_uri";
      proxy_cache_valid 200 1h;
      proxy_cache_lock on;
      add_header X-Cache-State $upstream_cache_status always;
    }}
  }}
}}
"""


def fetch(port: int, path: str, expected_status: int = 200) -> str:
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open(f"http://127.0.0.1:{port}{path}", timeout=4) as result:
            status, data = result.status, result.read()
            state = result.headers.get("X-Cache-State", "")
    except HTTPError as failure:
        status, data, state = failure.code, failure.read(), ""
    if status != expected_status:
        raise AssertionError(f"{path}: got HTTP {status}, expected {expected_status}")
    if expected_status == 200 and data != body_for(path):
        raise AssertionError(f"{path}: origin/cache payload integrity failure")
    return state


def usage(cache: Path) -> dict[str, int]:
    files = [p for p in cache.rglob("*") if p.is_file()]
    return {"files": len(files), "bytes": sum(p.stat().st_size for p in files)}


def observe(nginx: str, wait_seconds: int, workers: int) -> dict:
    if os.geteuid() == 0:
        raise RuntimeError("refusing UID 0; unprivileged sandbox only")
    with tempfile.TemporaryDirectory(prefix="repocache94-priority-") as temp:
        prefix = Path(temp)
        (prefix / "cache").mkdir()
        (prefix / "tmp").mkdir()
        origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        origin.request_lock = threading.Lock()
        origin.request_counts = Counter()
        thread = threading.Thread(target=origin.serve_forever, daemon=True)
        thread.start()
        port = free_port()
        conf = prefix / "nginx.conf"
        master: subprocess.Popen | None = None

        def apply(limit: str, reload: bool) -> None:
            conf.write_text(config(prefix, origin.server_port, port, limit))
            check = subprocess.run([nginx, "-p", str(prefix) + "/", "-c", str(conf), "-t"],
                                   capture_output=True, text=True, timeout=8)
            if check.returncode:
                raise RuntimeError(f"sandbox NGINX config rejected: {check.stderr[-800:]}")
            if reload:
                assert master is not None
                master.send_signal(signal.SIGHUP)  # Only OUR private NGINX master.

        try:
            apply("32m", False)
            master = subprocess.Popen(
                [nginx, "-p", str(prefix) + "/", "-c", str(conf), "-g", "daemon off;"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(80):
                if master.poll() is not None:
                    raise RuntimeError("private NGINX exited unexpectedly")
                try:
                    fetch(port, "/missing", expected_status=404)
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                raise TimeoutError("private NGINX did not bind loopback")
            for class_ in ("cold", "hot"):
                for n in range(4):
                    fetch(port, f"/{class_}/package-{n}")
            assert fetch(port, "/hot/package-0") == "HIT"
            pre_pressure = usage(prefix / "cache")
            # Give the hot object's access an unambiguous recency advantage,
            # while NOT treating a particular eviction order as guaranteed.
            time.sleep(1.1)
            assert fetch(port, "/hot/package-0") == "HIT"
            apply("128k", True)
            readings = []
            begin = time.monotonic()
            for offset in range(0, wait_seconds + 1, 5):
                until = begin + offset
                while time.monotonic() < until:
                    if master.poll() is not None:
                        raise RuntimeError("private NGINX exited during manager activity")
                    time.sleep(min(0.1, until - time.monotonic()))
                readings.append({"seconds": offset, **usage(prefix / "cache")})
            # Probe after the pressure window: these requests CAN repopulate
            # entries, so observations are probes, not on-disk object rankings.
            probes = {name: fetch(port, f"/{name}/package-0")
                      for name in ("hot", "cold")}
            with ThreadPoolExecutor(max_workers=workers) as pool:
                states = list(pool.map(lambda _: fetch(port, "/hot/concurrent"),
                                       range(workers)))
            if Counter(states) != Counter({"MISS": 1, "HIT": workers - 1}):
                raise AssertionError("unexpected cache state distribution")
            # Restore a generous quota before verifying origin failure, so the
            # dedicated cached object is unlikely to be under pressure.
            apply("32m", True)
            cache_ready = [fetch(port, "/hot/survivor"), fetch(port, "/hot/survivor")]
            if cache_ready[-1] != "HIT":
                raise AssertionError(f"pre-outage cached object not HIT: {cache_ready}")
            origin.shutdown()
            origin.server_close()
            thread.join(timeout=4)
            offline_hit = fetch(port, "/hot/survivor")
            uncached_code = 502
            fetch(port, "/hot/uncached-offline", expected_status=uncached_code)
            return {"nginx": subprocess.run([nginx, "-v"], capture_output=True,
                    text=True, timeout=8).stderr.strip(),
                    "pre_pressure": pre_pressure, "manager_samples": readings,
                    "post_pressure_probe_states": probes,
                    "concurrent_requests": workers,
                    "concurrent_cache_states": dict(Counter(states)),
                    "origin_outage": {"cached": offline_hit, "uncached_http": uncached_code},
                    "notes": "All content synthetic; probe mutates LRU; no hard ordering guarantee"}
        finally:
            if master is not None and master.poll() is None:
                master.terminate()
                try:
                    master.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    master.kill()
                    master.wait(timeout=5)
            if thread.is_alive():
                origin.shutdown()
                origin.server_close()
                thread.join(timeout=4)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", default=shutil.which("nginx") or "/usr/sbin/nginx")
    parser.add_argument("--wait-seconds", type=int, default=15)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    if not 10 <= args.wait_seconds <= 45 or not 2 <= args.workers <= 12:
        parser.error("bounded args: wait-seconds=10..45, workers=2..12")
    if os.geteuid() == 0:
        parser.error("refusing UID 0")
    if not Path(args.nginx).is_file():
        parser.error("NGINX is not installed")
    print(json.dumps(observe(args.nginx, args.wait_seconds, args.workers),
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
