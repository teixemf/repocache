#!/usr/bin/env python3
"""CI ONLY: install real hash-locked PyPI wheels and owned REPOCACHE wheel in bwrap.

The checked-in v0.4 legacy lock is NOT a publisher-signed v0.6 online lock.
The source wheel is generated from the checked-out 0.4 source, NOT a signed
release candidate. Never activate, use host pip for wheel installation, or
interpret hosted Ubuntu-kernel Docker evidence as native OS acceptance.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from email.parser import BytesParser

sys.path.insert(0, "/source/src")
sys.path.insert(0, "/source/scripts")
from repocache import application_wheel, candidate_sandbox, online_generation, updater
import build_release

SOURCE = pathlib.Path("/source")
LOCK = SOURCE / "deps/runtime-wheels.lock"
NAME = re.compile(r"[a-z0-9]+(?:_[a-z0-9]+)*\Z")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:\.post[0-9]+)?\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")


def check(ok: bool, label: str) -> None:
    if not ok:
        raise AssertionError(label)
    print("PASS: " + label, flush=True)


def run(argv: list[str], *, timeout: int = 240) -> str:
    # Trusted OS pip is used only to DOWNLOAD bytes to private staging.
    # No untrusted wheel install or candidate code may run outside bwrap.
    env = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
        "HOME": "/var/lib/repocache", "PIP_CONFIG_FILE": "/dev/null",
        "PYTHONNOUSERSITE": "1", "PIP_NO_INPUT": "1",
    }
    result = subprocess.run(argv, text=True, capture_output=True,
                            env=env, cwd="/", timeout=timeout, check=False)
    if result.returncode:
        raise AssertionError(
            f"Trusted wheel download/venv step failed {result.returncode}: "
            f"{argv[0]} {argv[1:4]} stdout={result.stdout[-650:]} "
            f"stderr={result.stderr[-650:]}"
        )
    return result.stdout.strip()


def rows() -> list[tuple[str, str, str]]:
    result = []
    names = set()
    for line in LOCK.read_text(encoding="ascii").splitlines():
        parts = line.split()
        if (len(parts) != 3 or not NAME.fullmatch(parts[0])
                or not VERSION.fullmatch(parts[1])
                or not DIGEST.fullmatch(parts[2])
                or parts[0] in names):
            raise AssertionError("Unsafe or duplicate legacy dependency pin")
        names.add(parts[0])
        result.append(tuple(parts))
    check(len(result) >= 10, "closed legacy wheel lock inventory is present")
    return result


def metadata(wheel: pathlib.Path, name: str, version: str) -> None:
    with zipfile.ZipFile(wheel) as source:
        members = [n for n in source.namelist() if n.endswith(".dist-info/METADATA")]
        check(len(members) == 1, "wheel metadata unambiguous")
        meta = BytesParser().parsebytes(source.read(members[0]))
        normalized = re.sub(r"[-_.]+", "_", meta.get("Name", "").lower())
        check(normalized == name and meta.get("Version") == version,
              "wheel name/version matches reviewed pin")


def main() -> None:
    updater._require_service_account()
    candidate_sandbox.require_executor()  # Fail before any PyPI wheel download.
    target = online_generation._current_host_target()
    root = updater.ROOT
    marker = root / "installed.json"
    old = marker.read_bytes()
    parent = root / "online-preparations"
    check(parent.is_dir() and parent.stat().st_uid == os.geteuid(),
          "private managed preparation exists")
    pins = rows()
    with tempfile.TemporaryDirectory(prefix=".online-v6-", dir=parent) as tmp:
        work = pathlib.Path(tmp)
        work.chmod(0o700)
        download = work / "download"
        download.mkdir(mode=0o700)
        lock_lines = []
        for name, version, digest in pins:
            before = set(download.iterdir())
            run([sys.executable, "-I", "-m", "pip", "--isolated", "download",
                 "--no-deps", "--only-binary=:all:", "--no-cache-dir",
                 "--disable-pip-version-check", "--index-url",
                 "https://pypi.org/simple", "--dest", str(download),
                 f"{name.replace('_', '-')}=={version}"])
            new = set(download.iterdir()) - before
            check(len(new) == 1, f"single upstream wheel selected: {name}")
            wheel = new.pop()
            check(wheel.suffix == ".whl" and wheel.is_file() and not wheel.is_symlink(),
                  f"binary wheel required: {name}")
            check(hashlib.sha256(wheel.read_bytes()).hexdigest() == digest,
                  f"live PyPI SHA-256 matches checked-in pin: {name}")
            metadata(wheel, name, version)
            lock_lines.append(f"./{wheel.name} --hash=sha256:{digest}")
        requirement = download / "requirements.lock"
        requirement.write_text("\n".join(lock_lines) + "\n", encoding="ascii")
        requirement.chmod(0o600)
        run([sys.executable, "-I", "-m", "venv", str(work / "venv")])
        python = work / "venv/bin/python"

        # ALL real third-party wheel execution occurs only within production
        # candidate_sandbox.run_isolated, never with ambient host pip.
        install, pip_check, pip_list = online_generation._install_commands(
            python, requirement)
        candidate_sandbox.run_isolated(
            install, workspace=work, cwd=download, timeout=300)
        check(True, f"{target} real approved upstream wheels installed under bwrap")

        # Build a deterministic ORIGINAL first-party wheel from this checked-out
        # legacy source, with no third-party build backend or target-side source
        # builds. It is NOT a publisher-signed 0.6 candidate.
        source_dir = work / "ci-source"
        package, _checksum = build_release.build_release(source_dir)
        archive = package.read_bytes()
        version = "0.4.0"  # deliberately tested legacy source tree, NOT 0.6
        owned = application_wheel.build(archive, version)
        application_wheel.verify(owned, archive, version)
        app_dir = work / "owned-app"
        app_dir.mkdir(mode=0o700)
        wheel = app_dir / application_wheel.filename(version)
        wheel.write_bytes(owned)
        wheel.chmod(0o600)
        app_lock = app_dir / "application.lock"
        app_lock.write_text(
            f"./{wheel.name} --hash=sha256:{hashlib.sha256(owned).hexdigest()}\n",
            encoding="ascii")
        app_lock.chmod(0o600)
        candidate_sandbox.run_isolated(
            online_generation._application_install_command(python, app_lock),
            workspace=work, cwd=app_dir, timeout=180)
        candidate_sandbox.run_isolated(pip_check, workspace=work, timeout=90)
        inventory = json.loads(candidate_sandbox.run_isolated(
            pip_list, workspace=work, timeout=90))
        installed = {re.sub(r"[-_.]+", "_", x["name"].lower()): x["version"]
                     for x in inventory}
        check(all(installed.get(name) == ver for name, ver, _ in pins)
              and installed.get("repocache_control") == version,
              "installed first-party and transitive wheels match exact pins")
        check(set(installed) <= {name for name, _, _ in pins}
              | {"repocache_control", "pip", "setuptools", "wheel"},
              "no unexpected package inside actual bwrap venv")
        checks = online_generation._smoke_commands(python)
        actual = candidate_sandbox.run_isolated(
            checks[0], workspace=work, timeout=30)
        check(actual == "REPOCACHE Control Center " + version,
              "installed original first-party CLI version in bwrap")
        for argv, expected in zip(checks[1:3], ("Usage:", "list")):
            output = candidate_sandbox.run_isolated(
                argv, workspace=work, timeout=30)
            check(expected in output, "installed CLI help under sandbox")
        candidate_sandbox.run_isolated(
            checks[3], workspace=work, timeout=90)
        check(True, "installed Textual run_test real headless navigation in bwrap")
        check(marker.read_bytes() == old, "installed manifest unchanged")
    check(not list(parent.iterdir()), "no candidate generations survived staging")
    check(marker.read_bytes() == old, "last known good remains unchanged")
    print("LIMITATION: legacy-reviewed lock/source, no signed 0.6 online candidate,"
          " no native target kernel, SELinux, activation or rollback", flush=True)


if __name__ == "__main__":
    main()
