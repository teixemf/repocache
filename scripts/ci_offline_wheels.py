#!/usr/bin/env python3
"""CI-only, native-OS offline dependency installation smoke for #49."""
import argparse
import gzip
import hashlib
import importlib.metadata
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

def run(*args, **opts):
    result = subprocess.run([str(a) for a in args], text=True, capture_output=True,
                            check=True, timeout=480, **opts)
    return result.stdout.strip()

def platform():
    if os.geteuid() == 0 or Path(sys.executable).resolve() != Path("/usr/bin/python3").resolve():
        raise RuntimeError("Requires the native system interpreter and a non-root UID")
    values = dict(x.split("=",1) for x in Path("/etc/os-release").read_text().splitlines()
                  if "=" in x and not x.startswith("#"))
    system = (values["ID"].strip('"'), values["VERSION_ID"].strip('"').split(".")[0],
              f"{sys.version_info.major}.{sys.version_info.minor}")
    if system not in (("debian", "13", "3.13"), ("almalinux", "10", "3.12")):
        raise RuntimeError("Unsupported native runtime: " + repr(system))
    return "-".join(system)

def checksum(data):
    return hashlib.sha256(data).hexdigest()

def build(out, release=False, poison_backend=False):
    native = platform()
    # Fixed wheel ZIP timestamps (>= 1980) and deterministic tar/gzip headers.
    # The signed SBOM still records the actual distro-owned pip version.
    os.environ["SOURCE_DATE_EPOCH"] = "315532800"
    source = out / "source"
    shutil.copytree("/src", source, ignore=shutil.ignore_patterns(
        ".git", ".venv", "dist", "__pycache__", ".pytest_cache", "*.egg-info"))
    if poison_backend:
        # Test only, isolated copy: simulate an index that serves a changed
        # build backend. Verification must refuse BEFORE pip wheel executes.
        lock_path = source / "deps/build-wheels.lock"
        entries = lock_path.read_text().splitlines()
        entries[0] = entries[0].rsplit(" ", 1)[0] + " " + "0" * 64
        lock_path.write_text("\n".join(entries) + "\n")
    env = out / "builder"
    # The venv contains only the OS-owned Python/pip baseline. Packaging
    # build tools are downloaded as prebuilt wheels with approved exact hashes
    # and installed offline, BEFORE any source/build hook can run.
    run("/usr/bin/python3", "-m", "venv", env)
    wheels = out / "wheels"
    wheels.mkdir()
    interpreter = env / "bin/python"
    build_tools = out / "build-tools"
    build_tools.mkdir()
    approved_tools = {}
    for line in (source / "deps/build-wheels.lock").read_text().splitlines():
        entry = line.split(" ")
        if (len(entry) != 3 or entry[0] not in ("setuptools", "wheel")
                or not re.fullmatch(r"[0-9][A-Za-z0-9.]*", entry[1])
                or not re.fullmatch(r"[a-f0-9]{64}", entry[2])
                or entry[0] in approved_tools):
            raise RuntimeError("Invalid approved build-tool pin")
        approved_tools[entry[0]] = (entry[1], entry[2])
    if set(approved_tools) != {"setuptools", "wheel"}:
        raise RuntimeError("Missing approved build backend pins")
    backend_lock = []
    for name, (version, expected) in sorted(approved_tools.items()):
        run(interpreter, "-m", "pip", "download", "--only-binary=:all:",
            "--no-deps", "--dest", build_tools, name + "==" + version)
        found = list(build_tools.glob(name + "-" + version + "-*.whl"))
        if len(found) != 1 or checksum(found[0].read_bytes()) != expected:
            raise RuntimeError("Build backend dependency SHA-256 mismatch: " + name)
        backend_lock.append("./build-tools/" + found[0].name +
                            " --hash=sha256:" + expected)
    # The backend wheels are separately pinned before they can execute.
    # Preserve rights metadata evidence for the build-time supply chain too.
    from audit_wheel_licenses import format_inventory
    print("CI BUILD LICENSE EVIDENCE: " +
          format_inventory(sorted(build_tools.glob("*.whl"))).strip(), flush=True)
    lockfile = out / "build-tools.lock"
    lockfile.write_text("\n".join(backend_lock) + "\n")
    run(interpreter, "-m", "pip", "install", "--no-index", "--no-deps",
        "--require-hashes", "-r", lockfile, cwd=out)
    print("PASS: preinstalled approved SHA-256 locked build backend without index",
          flush=True)
    # Build only the application from source; runtime packages must match
    # exact hashes already committed to the repository (never fresh solves).
    run(interpreter, "-m", "pip", "wheel", "--no-build-isolation",
        "--no-index", "--no-deps", "--wheel-dir", wheels, source)
    approved = {}
    for line in (source / "deps/runtime-wheels.lock").read_text().splitlines():
        entry = line.split(" ")
        if (len(entry) != 3 or not re.fullmatch(r"[a-z][a-z0-9_]*", entry[0])
                or not re.fullmatch(r"[0-9][A-Za-z0-9.]*", entry[1])
                or not re.fullmatch(r"[a-f0-9]{64}", entry[2])):
            raise RuntimeError("Invalid reviewed dependency lock")
        if entry[0] in approved:
            raise RuntimeError("Duplicate reviewed dependency")
        approved[entry[0]] = (entry[1], entry[2])
    if not approved:
        raise RuntimeError("No reviewed runtime requirements")
    # Each artifact must match its independently recorded hash. No version
    # resolution or dependency discovery occurs at this stage.
    for name, (version, expected) in sorted(approved.items()):
        run(interpreter, "-m", "pip", "download", "--only-binary=:all:",
            "--no-deps", "--dest", wheels, name + "==" + version)
        matching = list(wheels.glob(name + "-" + version + "-*.whl"))
        if len(matching) != 1 or checksum(matching[0].read_bytes()) != expected:
            raise RuntimeError("Approved runtime artifact SHA-256 mismatch: " + name)
    items = sorted(wheels.glob("*.whl"))
    if len(items) != len(approved) + 1:
        raise RuntimeError("Unexpected wheel set or changed dependency graph")
    if not items:
        raise RuntimeError("Empty resolved wheel set")
    if any(re.fullmatch(r"[A-Za-z0-9_.+-]+\.whl", x.name) is None for x in items):
        raise RuntimeError("Unrecognized wheel filename")
    lock = "".join("./wheels/" + p.name + " --hash=sha256:" +
                   checksum(p.read_bytes()) + "\n" for p in items).encode("ascii")
    # Complete, publisher-digest-bound CycloneDX inventory: include
    # application and every runtime wheel, plus native build tool versions.
    import tomllib
    project_version = tomllib.loads((source / "pyproject.toml").read_text())["project"]["version"]
    components = []
    for package in items:
        parts = package.name.split("-")
        if len(parts) < 5:
            raise RuntimeError("Invalid built wheel filename for dependency SBOM")
        components.append({
            "type": "library",
            "name": parts[0].replace("_", "-"),
            "version": parts[1],
            "hashes": [{"alg": "SHA-256", "content": checksum(package.read_bytes())}],
            "properties": [{"name": "repocache:wheel-file", "value": package.name}],
        })
    installed_backend = json.loads(run(
        interpreter, "-m", "pip", "list", "--format=json"))
    installed_versions = {
        item["name"].lower(): item["version"] for item in installed_backend}
    build_tools = []
    for tool in ("pip", "setuptools", "wheel"):
        if tool not in installed_versions:
            raise RuntimeError("Missing verified build-tool inventory: " + tool)
        version = installed_versions[tool]
        if tool in approved_tools and approved_tools[tool][0] != version:
            raise RuntimeError("Installed build-tool version differs from approved pin")
        result = {"type": "library", "name": tool, "version": version}
        if tool in approved_tools:
            result["hashes"] = [{"alg": "SHA-256",
                                 "content": approved_tools[tool][1]}]
        build_tools.append(result)
    sbom = (json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "repocache-control",
                          "version": project_version},
            "tools": {"components": build_tools},
        },
        "components": components,
    }, sort_keys=True, separators=(",", ":")) + "\n").encode()
    tarpath = out / ("repocache-" + native + ".tar.gz")
    if release:
        # Signing binds this stable artifact name to the exact source archive.
        import tomllib
        project = tomllib.loads((source / "pyproject.toml").read_text())
        version = project["project"]["version"]
        tarpath = out / ("repocache-v" + version + ".tar.gz.wheelhouse.tar.gz")
    with tarpath.open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as stream:
                for name, data in [
                    ("requirements.lock", lock), ("sbom.json", sbom),
                    ("THIRD_PARTY_NOTICES.md", (source / "THIRD_PARTY_NOTICES.md").read_bytes()),
                ] + [
                    ("wheels/" + p.name, p.read_bytes()) for p in items
                ]:
                    member = tarfile.TarInfo(name)
                    member.size, member.mode, member.mtime = len(data), 0o600, 0
                    member.uid = member.gid = 0
                    member.uname = member.gname = "root"
                    stream.addfile(member, io.BytesIO(data))
    (out / (tarpath.name + ".sha256")).write_text(checksum(tarpath.read_bytes()))
    print("PASS: built %d CI-only hash-pinned wheels for %s" % (len(items), native))
    # Audit trail remains available in GitHub Actions logs, not as a release.
    for item in items:
        print("CI-ONLY PIN: %s sha256:%s" % (item.name, checksum(item.read_bytes())))

def verify(out, release=False):
    native = platform()
    tarpath = out / ("repocache-" + native + ".tar.gz")
    if release:
        import tomllib
        package = tomllib.loads(Path("/src/pyproject.toml").read_text())
        tarpath = out / ("repocache-v" + package["project"]["version"] + ".tar.gz.wheelhouse.tar.gz")
    digest = (out / (tarpath.name + ".sha256")).read_text().strip()
    from repocache import wheelhouse
    with tempfile.TemporaryDirectory() as temp:
        where = Path(temp)
        lock = wheelhouse.verified_extract(tarpath.read_bytes(), digest, where / "verified")
        if ((lock.parent / "THIRD_PARTY_NOTICES.md").read_bytes()
                != Path("/src/THIRD_PARTY_NOTICES.md").read_bytes()):
            raise RuntimeError("Signed wheelhouse third-party notices do not match reviewed source")
        env = where / "venv"
        run("/usr/bin/python3", "-m", "venv", env)
        py = env / "bin/python"
        poison = {"PATH": "/usr/bin:/bin", "HOME": str(where),
                  "PIP_INDEX_URL": "https://malicious.invalid/simple",
                  "PIP_EXTRA_INDEX_URL": "https://poison.invalid/simple",
                  "PIP_CONFIG_FILE": "/dev/null", "PYTHONNOUSERSITE": "1"}
        run(*wheelhouse.install_argv(py, lock), cwd=lock.parent, env=poison)
        run(py, "-m", "pip", "check", env=poison)
        # Compare every wheel name/version with the installed graph. This
        # catches unexpected higher versions and missing transitive wheels.
        files = sorted((lock.parent / "wheels").glob("*.whl"))
        from audit_wheel_licenses import format_inventory
        # The wheelhouse digest and per-file SHA-256 were verified above.
        # Report license evidence from the *installed* native artifact set,
        # explicitly leaving legal compatibility for maintainer review.
        print("CI LICENSE EVIDENCE: " + format_inventory(files).strip(), flush=True)
        expected_versions = {}
        for file in files:
            parts = file.name.split("-")
            if len(parts) < 5:
                raise RuntimeError("Unexpected wheel filename in pinned inventory")
            key = re.sub(r"[-_.]+", "-", parts[0]).lower()
            if key in expected_versions:
                raise RuntimeError("Duplicate distribution in pinned inventory")
            expected_versions[key] = parts[1]
        installed = json.loads(run(py, "-m", "pip", "list", "--format=json", env=poison))
        actual_versions = {
            re.sub(r"[-_.]+", "-", row["name"]).lower(): row["version"]
            for row in installed
        }
        for name, version in expected_versions.items():
            if actual_versions.get(name) != version:
                raise RuntimeError("Offline installed dependency graph mismatch: " + name)
        assert "REPOCACHE" in run(env / "bin/repocache", "--version", env=poison)
        # Test the actual release-wheel-installed Textual application on each
        # OS-native target, not an imported source checkout. NGINX collection
        # is mocked within the headless smoke; network is disabled by Docker.
        tui_result = run(py, "/src/scripts/smoke_tui.py", env=poison)
        if "PASS: Installed Textual TUI starts and switches screens headlessly." not in tui_result:
            raise RuntimeError("Installed native Textual UI smoke did not complete")
        print("PASS: native offline installed Textual TUI starts and navigates on " + native)
        # Run the defensive archive matrix against the installed, verified
        # release wheel, in this same network-isolated native OS container.
        hostile = run(py, "/src/scripts/ci_hostile_archive.py", env=poison)
        if "PASS: installed native release/wheelhouse hostile archive refusal" not in hostile:
            raise RuntimeError("Native hostile archive regression did not execute")
        print("PASS: native installed hostile archive safety tests on " + native)
    print("PASS: completely offline pip installation, wheel hashes, CLI and TUI for " + native)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["build", "verify"])
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--simulate-poisoned-backend", action="store_true")
    args = parser.parse_args()
    args.phase == "build" and build(
        Path("/artifacts"), args.release, args.simulate_poisoned_backend)
    args.phase == "verify" and verify(Path("/artifacts"), args.release)
