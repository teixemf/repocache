#!/usr/bin/env python3
"""Native disposable v0.4.0 -> genuine signed candidate acceptance.

Never runs on a production host. The trusted main-branch verifier authenticates
the candidate before this file or any candidate package hooks are executed.
"""
from __future__ import annotations

import argparse
import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import ci_public_release_native as baseline

ROOT = Path("/repo")
CANDIDATE = Path("/candidate")
MANAGED = Path("/opt/repocache-cli/managed")


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise AssertionError(reason)
    print("PASS: " + reason, flush=True)


def run(*args: str, okay: bool = True, timeout: int = 90,
        env: dict | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                            env=env)
    if (result.returncode == 0) != okay:
        raise AssertionError("Wrong exit status " + str(result.returncode) +
                             " for " + " ".join(args[:4]) + " " +
                             (result.stdout + result.stderr)[-1600:])
    return result


def installed() -> tuple[str, bytes, dict]:
    active = os.readlink(MANAGED / "current")
    raw = (MANAGED / "installed.json").read_bytes()
    return active, raw, json.loads(raw)


def args_for(tag: str, folder: Path) -> tuple[str, ...]:
    b = folder / ("repocache-" + tag + ".tar.gz")
    return ("update", "--version", tag[1:],
            "--bundle", str(b),
            "--checksum", str(folder / (b.name + ".sha256")),
            "--manifest", str(folder / (b.name + ".manifest.json")),
            "--signature", str(folder / (b.name + ".manifest.json.sig")),
            "--wheelhouse", str(folder / (b.name + ".wheelhouse.tar.gz")),
            "--json")


def sentinels() -> dict[str, bytes]:
    # These were created and checked by the real v0.4.0 public acceptance.
    name = ("apt/sources.list.d/repocache-keep.sources"
            if Path("/etc/debian_version").exists()
            else "yum.repos.d/repocache-keep.repo")
    names = ("/etc/nginx/nginx.conf", "/etc/ssl/repocache-test.key",
             "/var/cache/nginx/repocache-keep", "/etc/" + name)
    return {p: Path(p).read_bytes() for p in names}


def run_as_service(script: str, *values: str, okay: bool = True) -> subprocess.CompletedProcess:
    return run("/usr/sbin/runuser", "-u", "repocache", "--",
               str(MANAGED / "current/bin/python"), "-c", script,
               *values, okay=okay)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", default="1")
    parser.add_argument("--release-id", required=True)
    args = parser.parse_args()
    need(os.geteuid() == 0 and Path("/.dockerenv").exists(),
         "only disposable native Docker root setup allowed")
    # No credentials are passed to Docker: verification here is independent
    # of GitHub API state but requires the original owner-signed bytes.
    run("/usr/bin/python3", str(ROOT / "scripts/draft_release_gate.py"),
        "verify-local", "--tag", args.tag, "--commit", args.commit,
        "--run-id", args.run_id, "--run-attempt", args.run_attempt,
        "--release-id", args.release_id, "--dest", str(CANDIDATE),
        "--inventory", "/candidate-inventory/validated.json")
    need(True, "owner-signed draft candidate validated before installer execution")

    # Install genuine ORIGINAL v0.4.0, not a CI-generated prior version fixture.
    # This covers its full public bootstrap and leaves a managed v0.4.0 instance.
    baseline.main()
    old_link, old_raw, old = installed()
    need(old["version"] == "0.4.0" and old["release_commit"] ==
         "063c86c9a138bffca6f76f7407e8f1c86bfe4390",
         "real previous public stable 0.4.0 installed and trusted")
    original = sentinels()
    cmd = ("/usr/local/bin/repocache", *args_for(args.tag, CANDIDATE))
    first = run(*cmd, timeout=240)
    response = json.loads(first.stdout)
    need(response.get("version") == args.tag[1:],
         "normal noninteractive signed offline candidate upgrade from public v0.4.0")
    link, raw, manifest = installed()
    prefix = "repocache-" + args.tag + ".tar.gz"
    evidence = json.loads(Path("/candidate-inventory/validated.json").read_text())
    values = evidence["assets"]
    need(link != old_link and
         manifest["version"] == args.tag[1:]
         and manifest["archive_sha256"] == values[prefix]["sha256"]
         and manifest["wheelhouse_sha256"] == values[prefix + ".wheelhouse.tar.gz"]["sha256"]
         and manifest["release_commit"] == args.commit
         and manifest["publisher_key_id"] == "repocache-2026-10",
         "candidate installed manifest and rootless release identities")
    need(run("/usr/local/bin/repocache", "--version").stdout.strip().endswith(args.tag[1:]),
         "real protected launcher activates candidate version")
    run(str(MANAGED / "current/bin/python"), "-c",
        "from repocache.tui import RepoCacheApp; assert RepoCacheApp")
    need(True, "installed candidate TUI application import")
    result = run(*cmd, timeout=240)
    next_link, next_raw, next_manifest = installed()
    need(json.loads(result.stdout).get("version") == args.tag[1:]
         and next_link not in (old_link, link)
         and next_manifest["archive_sha256"] == manifest["archive_sha256"],
         "same-version owner-signed repair produces a new generation")

    with tempfile.TemporaryDirectory(prefix="repocache-negative-") as temp:
        scratch = Path(temp)
        scratch.chmod(0o755)
        # Never corrupt an actual draft asset: only local disposable copies.
        for file in CANDIDATE.iterdir():
            shutil.copyfile(file, scratch / file.name)
        (scratch / (prefix + ".wheelhouse.tar.gz")).write_bytes(b"locally-tampered-wheel")
        run("/usr/local/bin/repocache", *args_for(args.tag, scratch),
            okay=False, timeout=120)
        need(installed()[:2] == (next_link, next_raw),
             "tampered candidate wheelhouse refused, no active-state mutation")
        # A signed candidate is not yet publicly discoverable as stable.
        # A caller must explicitly provide authenticated local assets.
        run("/usr/local/bin/repocache", "update", "--version", args.tag[1:],
            "--json", okay=False)
        need(installed()[:2] == (next_link, next_raw),
             "premature public update of draft-only tag is refused")
        # The published 0.4.0 must not be used to silently downgrade a 0.5.0+
        # release unless both signed policies permit it.
        downgrade = run("/usr/local/bin/repocache", "update",
                        "--version", "0.4.0", "--json", okay=False)
        need(downgrade.returncode != 0 and installed()[:2] == (next_link, next_raw),
             "unapproved downgrade refused")

    # Inject a manifest transaction failure into trusted signed candidate
    # updater code, then verify journal recovery restores prior generation.
    failure = (
        "import sys; from pathlib import Path; "
        "from repocache import updater; from repocache.upgrade import upgrade; "
        "updater._write_manifest=lambda *_a: "
        "(_ for _ in ()).throw(updater.UpdateError('injected commit failure')); "
        "upgrade(selected=sys.argv[1],bundle=Path(sys.argv[2]),"
        "checksum=Path(sys.argv[3]))"
    )
    run_as_service(failure, args.tag[1:],
                   str(CANDIDATE / prefix),
                   str(CANDIDATE / (prefix + ".sha256")), okay=False)
    need(installed()[:2] == (next_link, next_raw),
         "injected commit failure safely rolls back to previous signed generation")

    # Hold the root-protected advisory updater lock using the real service UID;
    # a second updater must fail BUSY without corrupting the installation.
    holder = subprocess.Popen(
        ["/usr/sbin/runuser", "-u", "repocache", "--",
         "/usr/bin/python3", "-u", "-c",
         "import fcntl,sys; f=open('/opt/repocache-cli/.updater.lock','rb'); "
         "fcntl.flock(f,fcntl.LOCK_EX); print('LOCKED',flush=True); "
         "sys.stdin.readline()"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    try:
        need(holder.stdout is not None, "lock holder stdout is available")
        readable, _, _ = select.select([holder.stdout], [], [], 10)
        need(bool(readable) and holder.stdout.readline().strip() == "LOCKED",
             "persistent update lock acquired by real service account")
        busy = run(*cmd, okay=False, timeout=40)
        need(busy.returncode == 75 and installed()[:2] == (next_link, next_raw),
             "concurrent update fails BUSY without altering installed state")
    finally:
        if holder.poll() is None and holder.stdin:
            try:
                holder.stdin.write("\n")
                holder.stdin.flush()
            except BrokenPipeError:
                pass
        try:
            holder.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            holder.kill()
            holder.communicate(timeout=5)
    need(all(Path(p).read_bytes() == b for p, b in original.items()),
         "NGINX, TLS, cache and APT/DNF source sentinels preserved")
    print("PASS: real signed prepublication candidate upgraded from v0.4.0 with rollback")
    print("NOT TESTED: booted systemd, host SELinux enforcement and real power loss")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, KeyError,
            subprocess.TimeoutExpired) as exc:
        print("FAIL: signed candidate native acceptance: " + str(exc),
              file=sys.stderr)
        raise SystemExit(1)
