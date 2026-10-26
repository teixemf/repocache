#!/usr/bin/env python3
"""Disposable, unprivileged, loopback-only stock NGINX cache experiment (#94).

No REPOCACHE production code or configuration is imported or modified.
"""
from __future__ import annotations

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from urllib.error import HTTPError
from urllib.request import ProxyHandler, build_opener

OBJECT_BYTES = 48 * 1024
REPOSITORIES = ("removed", "cold", "hot")


def payload(path: str) -> bytes:
    seed = hashlib.sha256(path.encode("ascii")).digest()
    return (seed * (OBJECT_BYTES // len(seed) + 1))[:OBJECT_BYTES]


class Origin(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if not path.startswith(tuple("/" + repo + "/" for repo in REPOSITORIES)) or ".." in path:
            self.send_error(404)
            return
        body = payload(path)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


def available_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def cache_stats(directory: Path) -> dict[str, int]:
    files = [p for p in directory.rglob("*") if p.is_file()] if directory.exists() else []
    return {"files": len(files), "bytes": sum(p.stat().st_size for p in files)}


def config(prefix: Path, origin_port: int, proxy_port: int, mode: str, *, removed: bool) -> str:
    zones = ("shared",) if mode == "shared" else REPOSITORIES
    # A removed zone is deliberately no longer configured in isolated mode.
    if removed and mode == "isolated":
        zones = tuple(name for name in zones if name != "removed")
    directives = "\n".join(
        f"proxy_cache_path {prefix}/cache/{name} levels=1:2 keys_zone={name}:1m "
        "inactive=2m max_size=160k manager_files=100 manager_sleep=50ms "
        "manager_threshold=200ms use_temp_path=off;"
        for name in zones
    )
    locations = "\n".join(
        f"location /{repo}/ {{\n"
        f"proxy_pass http://127.0.0.1:{origin_port};\n"
        f"proxy_cache {'shared' if mode == 'shared' else repo};\n"
        "proxy_cache_key \"$scheme$proxy_host$request_uri\";\n"
        "proxy_cache_valid 200 1h;\n"
        "proxy_cache_lock on;\n"
        "add_header X-Cache-State $upstream_cache_status always;\n"
        "}\n"
        for repo in REPOSITORIES if not (removed and repo == "removed")
    )
    return f"""worker_processes 1;
pid {prefix}/nginx.pid;
error_log {prefix}/error.log notice;
events {{ worker_connections 256; }}
http {{
    access_log {prefix}/access.log combined;
    client_body_temp_path {prefix}/tmp/client;
    proxy_temp_path {prefix}/tmp/proxy;
    fastcgi_temp_path {prefix}/tmp/fastcgi;
    uwsgi_temp_path {prefix}/tmp/uwsgi;
    scgi_temp_path {prefix}/tmp/scgi;
    {directives}
    server {{
        listen 127.0.0.1:{proxy_port};
        server_name localhost;
        {locations}
        location / {{ return 404; }}
    }}
}}
"""


def request(opener, port: int, path: str, *, expected_code: int = 200) -> str:
    try:
        with opener.open(f"http://127.0.0.1:{port}{path}", timeout=5) as res:
            code, body = res.status, res.read()
            state = res.headers.get("X-Cache-State", "")
    except HTTPError as error:
        code, body, state = error.code, error.read(), ""
    if code != expected_code:
        raise AssertionError(f"{path}: status {code}, expected {expected_code}")
    if expected_code == 200 and body != payload(path):
        raise AssertionError(f"{path}: payload integrity mismatch")
    return state


def wait_for_listener(opener, port: int, process: subprocess.Popen, seconds: float = 5) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if process.poll() is not None:
            raise RuntimeError(f"NGINX exited with {process.returncode}")
        try:
            request(opener, port, "/probe", expected_code=404)
            return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("NGINX loopback listener did not start")


def run_case(nginx: str, mode: str, objects: int, settle: float) -> dict:
    with tempfile.TemporaryDirectory(prefix="repocache94-nginx-") as tmp:
        prefix = Path(tmp)
        (prefix / "cache").mkdir()
        (prefix / "tmp").mkdir()
        origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        worker = threading.Thread(target=origin.serve_forever, daemon=True)
        worker.start()
        proxy_port = available_port()
        config_path = prefix / "nginx.conf"
        opener = build_opener(ProxyHandler({}))  # Never use ambient proxy settings.
        process = None
        try:
            config_path.write_text(config(prefix, origin.server_port, proxy_port, mode, removed=False))
            check = subprocess.run([nginx, "-p", str(prefix) + "/", "-c", str(config_path), "-t"],
                                   capture_output=True, text=True, timeout=10)
            if check.returncode:
                raise RuntimeError(f"NGINX config check failed: {check.stderr[-1000:]}")
            process = subprocess.Popen([nginx, "-p", str(prefix) + "/", "-c", str(config_path),
                                        "-g", "daemon off;"], stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
            wait_for_listener(opener, proxy_port, process)
            warm = {}
            for repo in REPOSITORIES:
                name = f"/{repo}/package-0.rpm"
                warm[repo] = [request(opener, proxy_port, name), request(opener, proxy_port, name)]
                if warm[repo] != ["MISS", "HIT"]:
                    raise AssertionError(f"{mode} {repo}: expected MISS/HIT, got {warm[repo]}")
            before = {name: cache_stats(prefix / "cache" / name)
                      for name in (("shared",) if mode == "shared" else REPOSITORIES)}
            # Validate candidate configuration before targeting ONLY this private master with SIGHUP.
            config_path.write_text(config(prefix, origin.server_port, proxy_port, mode, removed=True))
            check = subprocess.run([nginx, "-p", str(prefix) + "/", "-c", str(config_path), "-t"],
                                   capture_output=True, text=True, timeout=10)
            if check.returncode:
                raise RuntimeError(f"NGINX updated config invalid: {check.stderr[-1000:]}")
            process.send_signal(signal.SIGHUP)
            # Observe only the retired route, not a production service.
            for _ in range(40):
                try:
                    request(opener, proxy_port, "/removed/package-0.rpm", expected_code=404)
                    break
                except AssertionError:
                    time.sleep(0.05)
            else:
                raise AssertionError("removed route still accessible after reload")
            for i in range(1, objects + 1):
                repo = "hot" if i % 3 else "cold"
                request(opener, proxy_port, f"/{repo}/package-{i}.rpm")
                if i % 4 == 0:
                    request(opener, proxy_port, "/hot/package-0.rpm")
            time.sleep(settle)
            after = {name: cache_stats(prefix / "cache" / name)
                     for name in (("shared",) if mode == "shared" else REPOSITORIES)}
            return {"mode": mode, "warm": warm, "before": before, "after": after,
                    "retired_route_http_status": 404,
                    "retired_zone_still_configured": mode == "shared",
                    "objects_added": objects, "observation_seconds": settle}
        finally:
            if process is not None:
                process.terminate()  # Only process spawned in this TemporaryDirectory.
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            origin.shutdown()
            origin.server_close()
            worker.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", default=shutil.which("nginx") or "/usr/sbin/nginx")
    parser.add_argument("--mode", choices=("shared", "isolated", "both"), default="both")
    parser.add_argument("--objects", type=int, default=12)
    parser.add_argument("--settle-seconds", type=float, default=2.0)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("refusing root: run as an unprivileged user on a disposable host")
    if not (1 <= args.objects <= 500) or not (0 <= args.settle_seconds <= 60):
        parser.error("objects must be 1..500 and settle-seconds 0..60")
    if not Path(args.nginx).is_file():
        parser.error("NGINX binary not found")
    version = subprocess.run([args.nginx, "-v"], capture_output=True, text=True, timeout=10)
    if version.returncode:
        parser.error("NGINX -v failed")
    modes = ("shared", "isolated") if args.mode == "both" else (args.mode,)
    results = [run_case(args.nginx, mode, args.objects, args.settle_seconds) for mode in modes]
    info = Path("/etc/os-release").read_text() if Path("/etc/os-release").exists() else ""
    os_id = next((line[3:].strip('"') for line in info.splitlines() if line.startswith("ID=")), "unknown")
    selinux = Path("/sys/fs/selinux/enforce")
    print(json.dumps({"status": "PASS", "nginx": (version.stderr or version.stdout).strip(),
                      "os_id": os_id, "selinux_enforcing": selinux.read_text().strip() == "1" if selinux.exists() else None,
                      "cases": results}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
