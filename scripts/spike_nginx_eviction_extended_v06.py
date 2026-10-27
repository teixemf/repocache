#!/usr/bin/env python3
"""Controlled longer-running #94 experiment; only unprivileged loopback NGINX."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from urllib.request import ProxyHandler, build_opener

import spike_nginx_eviction_v06 as base


def candidate_config(prefix: Path, origin_port: int, proxy_port: int, mode: str, stage: str) -> str:
    if mode not in ("shared", "isolated-drop", "isolated-keep"):
        raise ValueError("unknown mode")
    if stage not in ("warm", "retired", "recover"):
        raise ValueError("unknown stage")
    isolated = mode != "shared"
    zones = ("shared",) if not isolated else base.REPOSITORIES
    if stage == "retired" and mode == "isolated-drop":
        zones = tuple(zone for zone in zones if zone != "removed")
    directives = []
    for zone in zones:
        # After retirement, deliberately pressure ONLY the retained, managed
        # cache containing the retired objects. The drop case has no manager
        # for the removed zone; the recover stage restores the original zone.
        pressure = stage == "retired" and (zone == "shared" or zone == "removed")
        limit = "128k" if pressure else "32m"
        directives.append(
            f"proxy_cache_path {prefix}/cache/{zone} levels=1:2 "
            f"keys_zone={zone}:1m inactive=5m max_size={limit} "
            "manager_files=100 manager_sleep=50ms "
            "manager_threshold=200ms use_temp_path=off;"
        )
    locations = []
    for repo in base.REPOSITORIES:
        if stage == "retired" and repo == "removed":
            continue
        zone = repo if isolated else "shared"
        locations.append(
            f"location /{repo}/ {{\n"
            f"proxy_pass http://127.0.0.1:{origin_port};\n"
            f"proxy_cache {zone};\n"
            'proxy_cache_key "$scheme$proxy_host$request_uri";\n'
            "proxy_cache_valid 200 1h;\n"
            "proxy_cache_lock on;\n"
            "add_header X-Cache-State $upstream_cache_status always;\n"
            "}\n"
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
    {' '.join(directives)}
    server {{
        listen 127.0.0.1:{proxy_port};
        server_name localhost;
        {''.join(locations)}
        location / {{ return 404; }}
    }}
}}
"""


def cache_snapshot(prefix: Path, mode: str, second: float) -> dict:
    zones = ("shared",) if mode == "shared" else base.REPOSITORIES
    return {"elapsed_seconds": round(second, 2),
            "zones": {zone: base.cache_stats(prefix / "cache" / zone) for zone in zones}}


def nginx_check(nginx: str, prefix: Path, config_path: Path) -> None:
    check = subprocess.run([nginx, "-p", str(prefix) + "/", "-c", str(config_path), "-t"],
                           capture_output=True, text=True, timeout=10)
    if check.returncode:
        raise RuntimeError(f"sandbox NGINX config invalid: {check.stderr[-1200:]}")


def stop_private_master(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()  # NEVER a system-wide nginx signal or subprocess lookup.
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def start_private_master(nginx: str, prefix: Path, config_path: Path, opener, port: int) -> subprocess.Popen:
    """Ensure any child is reaped even if loopback readiness raises."""
    proc = subprocess.Popen(
        [nginx, "-p", str(prefix) + "/", "-c", str(config_path),
         "-g", "daemon off;"], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    try:
        base.wait_for_listener(opener, port, proc)
    except BaseException:
        stop_private_master(proc)
        raise
    return proc


def measure(nginx: str, mode: str, object_count: int,
            observe_seconds: int, recovery_seconds: int, poll_seconds: int) -> dict:
    with tempfile.TemporaryDirectory(prefix="repocache94-extended-") as tmp:
        prefix = Path(tmp)
        (prefix / "cache").mkdir()
        (prefix / "tmp").mkdir()
        origin = ThreadingHTTPServer(("127.0.0.1", 0), base.Origin)
        thread = threading.Thread(target=origin.serve_forever, daemon=True)
        thread.start()
        port = base.available_port()
        config_path = prefix / "nginx.conf"
        opener = build_opener(ProxyHandler({}))
        process = None
        started = time.monotonic()
        try:
            def stage(name: str) -> None:
                config_path.write_text(candidate_config(prefix, origin.server_port,
                                                        port, mode, name))
                nginx_check(nginx, prefix, config_path)

            stage("warm")
            process = start_private_master(nginx, prefix, config_path, opener, port)
            warm = {}
            # 12 or more objects retained in a dedicated zone make the
            # lowered 128k retirement limit clearly exceed its target.
            for repo in base.REPOSITORIES:
                for n in range(object_count):
                    url = f"/{repo}/package-{n}.rpm"
                    base.request(opener, port, url)
                example = f"/{repo}/package-0.rpm"
                warm[repo] = base.request(opener, port, example)
                if warm[repo] != "HIT":
                    raise AssertionError(f"{mode}: {repo} expected HIT, got {warm[repo]}")
            before = cache_snapshot(prefix, mode, time.monotonic() - started)

            stage("retired")
            process.send_signal(signal.SIGHUP)  # Only spawned sandbox master.
            reload_sent = time.monotonic()
            for _ in range(100):
                try:
                    base.request(opener, port, "/removed/package-0.rpm", expected_code=404)
                    break
                except AssertionError:
                    time.sleep(0.05)
            else:
                raise AssertionError("retired route remained exposed after SIGHUP")
            active_state = base.request(opener, port, "/hot/package-0.rpm")
            first_snapshot = cache_snapshot(prefix, mode, time.monotonic() - reload_sent)
            snapshots = [first_snapshot]
            begin = time.monotonic()
            for elapsed in range(poll_seconds, observe_seconds + 1, poll_seconds):
                target = begin + elapsed
                while time.monotonic() < target:
                    time.sleep(min(0.2, target - time.monotonic()))
                if process.poll() is not None:
                    raise RuntimeError("sandbox NGINX died during observation")
                snapshots.append(cache_snapshot(prefix, mode, time.monotonic() - begin))
            # For isolated-drop ONLY, perform a clean sandbox-only restart with
            # the original zone attached. NGINX's loader starts about a minute
            # after boot. Do NOT probe the retired URL before it can reload the
            # existing cached object, or the probe itself could create a new one.
            recovered = None
            if mode == "isolated-drop":
                stop_private_master(process)
                process = None
                stage("recover")
                process = start_private_master(nginx, prefix, config_path, opener, port)
                recover_start = time.monotonic()
                while time.monotonic() - recover_start < recovery_seconds:
                    if process.poll() is not None:
                        raise RuntimeError("sandbox NGINX died during recovery-loader wait")
                    time.sleep(0.2)
                recovered = {
                    "first_request_cache_state_after_loader": base.request(
                        opener, port, "/removed/package-0.rpm"),
                    "wait_seconds": recovery_seconds,
                    "bytes_verified": base.OBJECT_BYTES,
                }
            return {"mode": mode, "objects_per_repo": object_count,
                    "retirement_limit": "128k" if mode != "isolated-drop" else "not configured",
                    "before_retirement": before, "post_retirement_samples": snapshots,
                    "active_route_after_retirement": active_state,
                    "removed_route_status": 404, "reattach_after_restart": recovered,
                    "reload_to_first_snapshot_seconds": first_snapshot["elapsed_seconds"],
                    "note": "observations only; no automatic global priority claim"}
        finally:
            stop_private_master(process)
            origin.shutdown()
            origin.server_close()
            thread.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", default=shutil.which("nginx") or "/usr/sbin/nginx")
    parser.add_argument("--mode", choices=("shared", "isolated-drop", "isolated-keep"),
                        default="isolated-drop")
    parser.add_argument("--objects-per-repo", type=int, default=12)
    parser.add_argument("--observe-seconds", type=int, default=40)
    parser.add_argument("--poll-seconds", type=int, default=10)
    parser.add_argument("--recovery-loader-seconds", type=int, default=70)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("refusing UID 0; run in an unprivileged disposable sandbox")
    if not 4 <= args.objects_per_repo <= 60:
        parser.error("objects-per-repo must be 4..60")
    if not 20 <= args.observe_seconds <= 120 or not 5 <= args.poll_seconds <= 30:
        parser.error("observe-seconds must be 20..120 and poll-seconds 5..30")
    if args.observe_seconds % args.poll_seconds:
        parser.error("observe-seconds must be an exact multiple of poll-seconds")
    if not 65 <= args.recovery_loader_seconds <= 120:
        parser.error("recovery-loader-seconds must be 65..120")
    if not Path(args.nginx).is_file():
        parser.error("nginx not installed")
    ver = subprocess.run([args.nginx, "-v"], capture_output=True, text=True, timeout=10)
    if ver.returncode:
        parser.error("nginx -v failed")
    os_release = Path("/etc/os-release").read_text() if Path("/etc/os-release").exists() else ""
    os_id = next((line.split("=", 1)[1].strip('"') for line in os_release.splitlines()
                  if line.startswith("ID=")), "unknown")
    enforce_path = Path("/sys/fs/selinux/enforce")
    enforcement = (enforce_path.read_text().strip() == "1") if enforce_path.exists() else None
    print(json.dumps({"status": "OBSERVED", "platform": os_id,
                      "nginx_version": (ver.stderr or ver.stdout).strip(),
                      "selinux_enforcing": enforcement,
                      "result": measure(args.nginx, args.mode, args.objects_per_repo,
                                        args.observe_seconds, args.recovery_loader_seconds,
                                        args.poll_seconds)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
