#!/usr/bin/env python3
"""Disposable, rootless native installer test for the REAL published v0.4.0.

Run ONLY inside an ephemeral CI container. Root is used for fixture/bootstrap,
never to execute the installed mutable application or Python package hooks.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path("/repo")
ASSETS = Path("/artifacts")
VERSION = "0.4.0"
BUNDLE = ASSETS / "repocache-v0.4.0.tar.gz"
MANAGED = Path("/opt/repocache-cli/managed")
PRESERVE = (
    "/etc/nginx/nginx.conf",
    "/etc/ssl/repocache-test.key",
    "/var/cache/nginx/repocache-keep",
)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print("PASS: " + message, flush=True)


def cmd(*args: str, okay: bool = True, env: dict | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(args, text=True, capture_output=True,
                            timeout=180, env=env)
    if (result.returncode == 0) != okay:
        raise AssertionError(
            "Unexpected return code " + str(result.returncode) + " from " +
            " ".join(args[:4]) + "\n" + (result.stdout + result.stderr)[-1500:])
    return result


def service(source: Path, script: str, *args: str,
            okay: bool = True, extra_env: dict | None = None) -> subprocess.CompletedProcess:
    env = {"HOME": "/var/lib/repocache", "PATH": "/usr/local/bin:/usr/bin:/bin",
           "LANG": "C.UTF-8", "PYTHONPATH": str(source / "src"),
           "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1"}
    env.update(extra_env or {})
    return cmd("/usr/sbin/runuser", "-u", "repocache", "--",
               "/usr/bin/env", "-i", *(k + "=" + v for k, v in env.items()),
               "/usr/bin/python3", "-c", script, *args, okay=okay)


def managed() -> tuple[str, bytes, dict]:
    active = os.readlink(MANAGED / "current")
    raw = (MANAGED / "installed.json").read_bytes()
    return active, raw, json.loads(raw)


def main() -> None:
    check(os.geteuid() == 0 and Path("/.dockerenv").exists(),
          "running as disposable Docker test harness")
    os_release = Path("/etc/os-release").read_text()
    os_fields = dict(line.split("=", 1) for line in os_release.splitlines()
                     if "=" in line)
    distro = os_fields.get("ID", "").strip('"')
    major = os_fields.get("VERSION_ID", "").strip('"').split(".", 1)[0]
    native = (distro, major, sys.version_info[:2]) in (
        ("debian", "13", (3, 13)),
        ("almalinux", "10", (3, 12)),
    )
    check(native, "genuine Debian 13/Python 3.13 or AlmaLinux 10/Python 3.12")

    # Verify every downloaded byte and both authentic publisher signatures
    # before extracting or executing a single byte of the release itself.
    cmd("/usr/bin/python3", str(ROOT / "scripts/public_release_acceptance.py"),
        "verify", "--tag", "v0.4.0", "--dest", str(ASSETS))
    target = json.loads((ROOT / "scripts/public_release_targets.json").read_text())[
        "releases"]["v0.4.0"]

    with tempfile.TemporaryDirectory(prefix="public-repocache-") as tmp:
        work = Path(tmp)
        work.chmod(0o755)
        with tarfile.open(BUNDLE, "r:gz") as archive:
            members = archive.getmembers()
            prefix = "repocache-v0.4.0/"
            check(0 < len(members) < 150
                  and all(m.isfile() and m.name.startswith(prefix)
                          and ".." not in Path(m.name).parts
                          and m.mode & 0o7000 == 0 for m in members),
                  "authenticated source has safe regular-file-only members")
            archive.extractall(work, filter="data")
        source = work / "repocache-v0.4.0"
        launcher = source / "scripts/repocache-launcher.sh"
        recovery = source / "src/repocache/recovery.py"
        check(hashlib.sha256(launcher.read_bytes()).hexdigest() ==
              target["launcher_sha256"] and
              hashlib.sha256(recovery.read_bytes()).hexdigest() ==
              target["recovery_sha256"],
              "independently pinned bootstrap launcher and recovery digest")

        key_dir = Path("/etc/repocache/trust.d")
        key_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
        (key_dir / "repocache-2026-10.pem").write_bytes(
            (ROOT / "keys/repocache-2026-10.pem").read_bytes())
        (key_dir / "repocache-2026-10.pem").chmod(0o644)
        check((key_dir / "repocache-2026-10.pem").stat().st_uid == 0,
              "independently provisioned root-owned release trust anchor")

        distro_sentinel = ("/etc/apt/sources.list.d/repocache-keep.sources"
                           if distro == "debian"
                           else "/etc/yum.repos.d/repocache-keep.repo")
        preserve = (*PRESERVE, distro_sentinel)
        for path in preserve:
            file = Path(path)
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(b"repocache-public-release-acceptance:DO-NOT-CHANGE\n")
        sentinel = {s: Path(s).read_bytes() for s in preserve}

        cmd("/bin/bash", str(source / "scripts/bootstrap-rootless.sh"),
            "--launcher-sha256", target["launcher_sha256"],
            "--recovery-sha256", target["recovery_sha256"])
        check(MANAGED.exists() and (MANAGED.parent / ".updater.lock").exists(),
              "root-protected bootstrap and persistent updater lock created")

        # The root-owned launcher has no runtime yet. Bootstrap only a TEMPORARY
        # user-owned CLI from the authenticated, hash-pinned offline wheelhouse.
        # Then use the real, noninteractive user-facing CLI for the first
        # installation and real public asset download (not a Python API bypass).
        scratch = work / "bootstrap"
        scratch.mkdir(mode=0o700)
        uid = int(cmd("/usr/bin/id", "-u", "repocache").stdout.strip())
        gid = int(cmd("/usr/bin/id", "-g", "repocache").stdout.strip())
        os.chown(scratch, uid, gid)
        temp_wheels = scratch / "wheels"
        temp_venv = scratch / "venv"
        bootstrap = (
            "import sys,subprocess; from pathlib import Path; "
            "from repocache import wheelhouse; "
            "b=Path(sys.argv[1]); "
            "lock=wheelhouse.verified_extract(b.read_bytes(),sys.argv[2],Path(sys.argv[3])); "
            "wheelhouse.verify_application_wheel(lock,'0.4.0'); "
            "subprocess.run([sys.executable,'-m','venv',sys.argv[4]],check=True); "
            "subprocess.run([sys.argv[4]+'/bin/python','-m','pip','install',"
            "'--no-index','--require-hashes','-r',str(lock)],"
            "cwd=str(lock.parent),check=True)"
        )
        service(source, bootstrap,
                str(ASSETS / (BUNDLE.name + ".wheelhouse.tar.gz")),
                target["assets"][BUNDLE.name + ".wheelhouse.tar.gz"]["sha256"],
                str(temp_wheels), str(temp_venv))
        check((temp_venv / "bin/repocache").is_file(),
              "temporary offline CLI bootstrapped from verified public wheelhouse")
        cli_prefix = ("/usr/sbin/runuser", "-u", "repocache", "--",
                      str(temp_venv / "bin/repocache"))
        result = cmd(*cli_prefix, "update", "--version", VERSION, "--json")
        check(json.loads(result.stdout)["version"] == VERSION,
              "normal noninteractive public-CDN initial install via signed CLI")
        old_link, _, old = managed()
        check(old["version"] == VERSION
              and old["archive_sha256"] == target["assets"][BUNDLE.name]["sha256"]
              and old["wheelhouse_sha256"] ==
              target["assets"][BUNDLE.name + ".wheelhouse.tar.gz"]["sha256"]
              and old["release_commit"] == target["commit"]
              and old["publisher_key_id"] == target["publisher_key_id"],
              "installed manifest identities match real public signed assets")

        version = cmd("/usr/local/bin/repocache", "--version")
        check(version.stdout.strip().endswith("0.4.0"),
              "protected launcher dispatches installed v0.4.0")
        for command in ("check", "list"):
            result = cmd("/usr/local/bin/repocache", "update", command, "--json")
            payload = json.loads(result.stdout)
            check(payload.get("latest_version") == VERSION
                  and payload.get("status") == "up-to-date",
                  "live anonymous CLI: repocache update " + command)
            if command == "list":
                check(any(x["version"] == VERSION and x["latest"]
                          for x in payload["releases"]),
                      "live published version list contains exact latest v0.4.0")
        cmd(str(MANAGED / "current/bin/python"), "-c",
            "from repocache.tui import RepoCacheApp; assert RepoCacheApp")
        check(True, "native installed Textual/TUI import")

        # Genuine real-CDN-download path (no --bundle) and new generation.
        repair = cmd("/usr/local/bin/repocache", "update", "--version",
                     VERSION, "--json")
        check(json.loads(repair.stdout).get("version") == VERSION,
              "normal noninteractive public-CDN same-version update")
        after_link, after_raw, after = managed()
        check(after_link != old_link and after["archive_sha256"] ==
              target["assets"][BUNDLE.name]["sha256"],
              "same-version repair created a fresh signed installation generation")
        # Negative requests must fail without changing the existing installation.
        negative = cmd(*cli_prefix, "update", "--version", "0.3.0",
                       "--json", okay=False)
        check(negative.returncode != 0 and managed()[:2] == (after_link, after_raw),
              "unsupported version refused without changing active installation")
        poisoned = work / (BUNDLE.name + ".wheelhouse.tar.gz")
        poisoned.write_bytes(b"local-tampered-wheelhouse-test")
        bad_script = (
            "import sys; from pathlib import Path; "
            "from repocache.upgrade import upgrade; "
            "upgrade(selected='0.4.0',bundle=Path(sys.argv[1]),"
            "checksum=Path(sys.argv[2]),wheels=Path(sys.argv[3]))"
        )
        service(source, bad_script, str(BUNDLE),
                str(ASSETS / (BUNDLE.name + ".sha256")), str(poisoned),
                okay=False)
        check(managed()[:2] == (after_link, after_raw),
              "tampered local wheelhouse refused before activation")
        # Controlled post-build failure: use the exact signed public bundle,
        # then require the old active generation and manifest to survive.
        rollback_script = (
            "import sys; from pathlib import Path; "
            "from repocache import updater; "
            "from repocache.upgrade import upgrade; "
            "updater._write_manifest=lambda *_args: "
            "(_ for _ in ()).throw(updater.UpdateError('injected manifest failure')); "
            "upgrade(selected='0.4.0',bundle=Path(sys.argv[1]),"
            "checksum=Path(sys.argv[2]))"
        )
        service(source, rollback_script, str(BUNDLE),
                str(ASSETS / (BUNDLE.name + ".sha256")), okay=False)
        check(managed()[:2] == (after_link, after_raw),
              "injected manifest-commit failure rolls back signed generation")
        # Simulate a denied network endpoint through an explicit impossible
        # proxy, on the real upgrade code path, not a substitute mock release.
        remote_script = (
            "from repocache.upgrade import upgrade; upgrade(selected='0.4.0')"
        )
        service(source, remote_script, okay=False, extra_env={
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "https_proxy": "http://127.0.0.1:9",
            "NO_PROXY": "", "no_proxy": "",
        })
        check(managed()[:2] == (after_link, after_raw),
              "network outage refused without changing signed active generation")
        check(all(Path(s).read_bytes() == sentinel[s] for s in preserve),
              "NGINX, TLS, cache and APT/DNF source sentinels preserved")
        print("PASS: real immutable public v0.4.0 native rootless install, repair, recovery boundaries")
        print("NOT TESTED: booted systemd/SELinux and physical power loss")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        print("FAIL: native public-release test: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
