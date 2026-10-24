#!/usr/bin/env python3
"""Live upstream wheel compatibility probe for issue #83/#85.

CI ONLY. This is not a signed v0.6 release install or a production updater.
Downloads exact legacy-reviewed wheel versions; checks their pinned SHA-256;
installs all wheels offline in a disposable native-Python venv as non-root.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from email.parser import BytesParser
from pathlib import Path

SOURCE = Path("/source")
WORK = Path("/work")
LOCK = SOURCE / "deps/runtime-wheels.lock"
EXPECTED = {
    ("debian", "13", (3, 13)): "debian13-py313",
    ("almalinux", "10", (3, 12)): "almalinux10-py312",
}
NAME = re.compile(r"[a-z0-9]+(?:_[a-z0-9]+)*\Z")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:\.post[0-9]+)?\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run(argv: list[str], *, env: dict[str, str] | None = None,
        timeout: int = 180, allow_failure: bool = False) -> subprocess.CompletedProcess[str]:
    p = subprocess.run(argv, cwd=WORK, env=env, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=timeout, check=False)
    if p.returncode and not allow_failure:
        raise RuntimeError(
            f"Command failed ({p.returncode}): {argv[0]} "
            f"{' '.join(argv[1:4])}\n{p.stdout[-1800:]}")
    return p


def native_target() -> str:
    pairs = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if line.startswith(("ID=", "VERSION_ID=")):
            key, value = line.split("=", 1)
            pairs[key] = value.strip("\"'")
    key = (pairs.get("ID"), pairs.get("VERSION_ID", "").split(".")[0],
           sys.version_info[:2])
    require(key in EXPECTED, f"Unexpected native OS/Python target: {key}")
    return EXPECTED[key]


def lock_rows() -> list[tuple[str, str, str]]:
    entries = []
    seen = set()
    for line in LOCK.read_text(encoding="ascii").splitlines():
        items = line.split()
        require(len(items) == 3, "Unexpected legacy wheel lock syntax")
        name, version, digest = items
        require(bool(NAME.fullmatch(name) and VERSION.fullmatch(version)
                     and DIGEST.fullmatch(digest)), "Invalid pinned wheel identity")
        require(name not in seen, "Duplicate pinned wheel")
        seen.add(name)
        entries.append((name, version, digest))
    require(len(entries) >= 3, "Incomplete legacy pinned wheel inventory")
    return entries


def identity(wheel: Path, name: str, version: str) -> None:
    require(wheel.name.endswith(".whl"), "Source distribution selected")
    with zipfile.ZipFile(wheel) as archive:
        members = [p for p in archive.namelist() if p.endswith(".dist-info/METADATA")]
        require(len(members) == 1, "Ambiguous wheel METADATA")
        meta = BytesParser().parsebytes(archive.read(members[0]))
        normalized = re.sub(r"[-_.]+", "_", meta.get("Name", "").lower())
        require(normalized == name and meta.get("Version") == version,
                "Downloaded wheel metadata differs from reviewed pin")


def main() -> None:
    require(os.geteuid() != 0, "Never run PyPI wheel installation as root")
    require(WORK.stat().st_uid == os.geteuid()
            and (WORK.stat().st_mode & 0o077) == 0,
            "Workspace must be owner-private")
    target = native_target()
    rows = lock_rows()
    env = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": str(WORK),
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "PIP_CONFIG_FILE": os.devnull,
        "PYTHONNOUSERSITE": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    }
    wheels = WORK / "wheels"
    wheels.mkdir(mode=0o700)
    offline = []
    for name, version, digest in rows:
        before = set(wheels.iterdir())
        # pip selects ABI-compatible binaries from the *real* public PyPI.
        # No ambient index, cache, proxy, build hook, or dependency resolution.
        run([sys.executable, "-I", "-m", "pip", "--isolated", "download",
             "--no-deps", "--only-binary=:all:", "--no-cache-dir",
             "--disable-pip-version-check", "--index-url",
             "https://pypi.org/simple", "--dest", str(wheels),
             f"{name.replace('_', '-')}=={version}"], env=env, timeout=180)
        added = set(wheels.iterdir()) - before
        require(len(added) == 1, f"Expected one binary wheel for {name}")
        wheel = added.pop()
        require(wheel.is_file() and not wheel.is_symlink(), "Unsafe wheel path")
        actual = hashlib.sha256(wheel.read_bytes()).hexdigest()
        require(actual == digest, f"Pinned upstream SHA-256 mismatch for {name}")
        identity(wheel, name, version)
        offline.append(f"./wheels/{wheel.name} --hash=sha256:{digest}")
        print(f"PASS: {target}: upstream wheel {name}=={version} SHA-256", flush=True)

    requirements = WORK / "requirements.lock"
    requirements.write_text("\n".join(offline) + "\n", encoding="ascii")
    venv = WORK / "venv"
    run([sys.executable, "-I", "-m", "venv", str(venv)], env=env)
    python = str(venv / "bin/python")
    pip_base = [python, "-I", "-m", "pip", "--isolated"]
    installation = pip_base + [
        "install", "--no-index", "--no-deps", "--only-binary=:all:",
        "--require-hashes", "--no-input", "--no-cache-dir",
        "--disable-pip-version-check", "-r", str(requirements),
    ]
    run(installation, env=env, timeout=180)
    run(pip_base + ["check"], env=env)
    inventory = json.loads(run(
        pip_base + ["list", "--format=json"], env=env).stdout)
    installed = {re.sub(r"[-_.]+", "_", x["name"].lower()): x["version"]
                 for x in inventory}
    require(all(installed.get(n) == v for n, v, _ in rows),
            "Installed versions differ from reviewed wheel pins")
    require(set(installed) <= {n for n, _, _ in rows}
            | {"pip", "setuptools", "wheel"},
            "Unexpected package installed in isolated venv")
    print(f"PASS: {target}: rootless native offline hash-only installation, pip check",
          flush=True)

    # Negative hash test: corrupt a separate copy, never the verified wheel.
    tamper = WORK / "tamper"
    (tamper / "wheels").mkdir(parents=True, mode=0o700)
    original = sorted(wheels.iterdir())[0]
    wrong = tamper / "wheels" / original.name
    shutil.copyfile(original, wrong)
    with wrong.open("ab") as stream:
        stream.write(b"tampered")
    matching = next(line for line in offline if original.name in line)
    (tamper / "requirements.lock").write_text(
        matching + "\n", encoding="ascii")
    rejected = run(pip_base + [
        "install", "--no-index", "--no-deps", "--only-binary=:all:",
        "--require-hashes", "--no-input", "--no-cache-dir",
        "-r", str(tamper / "requirements.lock"),
    ], env=env, allow_failure=True)
    require(rejected.returncode != 0, "Corrupt wheel passed hash verification")
    print(f"PASS: {target}: tampered wheel refused", flush=True)

    # REPOCACHE source is read-only for this experiment. The v0.6 first-party
    # signed application wheel is not yet accepted and is NOT being installed.
    smoke_env = dict(env, PYTHONPATH=str(SOURCE / "src"))
    for argv in (
        [python, "-m", "repocache.cli", "--version"],
        [python, "-m", "repocache.cli", "--help"],
        [python, "-m", "repocache.cli", "update", "--help"],
        [python, str(SOURCE / "scripts/smoke_tui.py")],
        [python, str(SOURCE / "client/repocache_client.py"), "repos", "list", "--help"],
        [python, str(SOURCE / "client/repocache_client.py"), "repos", "sync", "--help"],
    ):
        run(argv, env=smoke_env, timeout=90)
    print(f"PASS: {target}: Typer CLI, Textual headless, client read-only help", flush=True)
    print("LIMITATION: unsigned source-tree smoke only; no owner-signed online "
          "release, v0.6 application-wheel installation, sandbox acceptance, "
          "activation, rollback, SELinux or native target kernel", flush=True)


if __name__ == "__main__":
    main()
