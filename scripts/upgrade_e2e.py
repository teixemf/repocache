"""Disposable rootless Debian 13 / AlmaLinux 10 rehearsal for issue #48.

This test uses synthetic release fixtures signed with a fresh, ephemeral
CI-only Ed25519 key. It verifies #47 mechanics and the #48 privilege boundary,
not production signing custody or #49 offline dependency acceptance.
It does NOT exercise any actual pre-public in-place migration. The fixture
explicitly enables a synthetic 0.3.0 -> 0.4.0 transition that the real public
v0.4.0 policy rejects, solely to test transaction failure/recovery semantics.
Never run this script on a production host.
"""
from __future__ import annotations

import hashlib
import json
import os
import signal
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ASSETS = Path("/artifacts")
ROOT = Path("/opt/repocache-cli/managed")
PY = "/usr/bin/python3"


def check(condition: bool, description: str) -> None:
    if not condition:
        raise AssertionError(description)
    print("PASS:", description, flush=True)


def cmd(*argv: str, success: bool = True, environment=None) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, text=True, capture_output=True, timeout=420,
                            env=environment, check=False)
    if (result.returncode == 0) != success:
        print(result.stdout[-2000:], result.stderr[-2000:], file=sys.stderr)
        raise AssertionError(f"Unexpected status ({result.returncode}): {argv[:4]}")
    return result


def user_python(source: Path, program: str, *args: str,
                success: bool = True) -> subprocess.CompletedProcess:
    # runuser drops root *before* importing the fixture Python modules.
    env = {"PATH": "/usr/bin:/bin", "HOME": "/var/lib/repocache",
           "LANG": "C.UTF-8", "PYTHONPATH": str(source / "src")}
    return cmd("/usr/sbin/runuser", "-u", "repocache", "--", "/usr/bin/env", "-i",
               *(f"{k}={v}" for k, v in env.items()), PY, "-c",
               program, *args, success=success)


def extracted(archive: Path, folder: Path) -> Path:
    prefix = archive.name.removesuffix(".tar.gz")
    # Only the trusted synthetic CI fixture is handled by the extractor here.
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            check(member.isfile() and member.name.startswith(prefix + "/"),
                  "CI fixture has regular-file-only archive members")
            target = folder / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as stream:
                target.write_bytes(stream.read())
            target.chmod(member.mode & 0o777)
    return folder / prefix


def preservation_markers() -> dict[Path, bytes]:
    targets = (Path("/etc/nginx/nginx.conf"), Path("/var/cache/nginx/keep"),
               Path("/var/log/nginx/keep"), Path("/etc/ssl/repocache-test.key"),
               Path("/etc/apt/sources.list.d/repocache-protection-test.list"))
    for target in targets:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("must remain unchanged by CLI updater\n")
    return {p: p.read_bytes() for p in targets}


def main() -> None:
    os_info = Path("/etc/os-release").read_text()
    check(("ID=debian" in os_info and ("VERSION_ID=\"13\"" in os_info or
           "VERSION_ID=13" in os_info)) or
          ("ID=almalinux" in os_info or "ID=\"almalinux\"" in os_info) and
          ("VERSION_ID=\"10" in os_info or "VERSION_ID=10" in os_info),
          "genuine supported Linux image")
    check(os.geteuid() == 0, "only disposable CI harness is privileged")
    protected = preservation_markers()
    old_bundle = ASSETS / "repocache-v0.3.0.tar.gz"
    new_bundle = ASSETS / "repocache-v0.4.0.tar.gz"
    old_sha = ASSETS / (old_bundle.name + ".sha256")
    new_sha = ASSETS / (new_bundle.name + ".sha256")
    for bundle, sha in ((old_bundle, old_sha), (new_bundle, new_sha)):
        check(bundle.is_file() and sha.is_file(), "synthetic release fixture exists")
        check(hashlib.sha256(bundle.read_bytes()).hexdigest() == sha.read_text().split()[0],
              "synthetic archive checksum matches")
    with tempfile.TemporaryDirectory(prefix="rootless-test-") as work:
        folder = Path(work)
        folder.chmod(0o755)  # disposable fixture readable by the service UID
        old = extracted(old_bundle, folder)
        new = extracted(new_bundle, folder)
        # Fixture hash is NOT an independent trust root. This test is not a
        # replacement for authenticated manifests/signing tests (#47).
        launcher = old / "scripts/repocache-launcher.sh"
        recovery = old / "src/repocache/recovery.py"
        digest = hashlib.sha256(launcher.read_bytes()).hexdigest()
        recovery_digest = hashlib.sha256(recovery.read_bytes()).hexdigest()
        cmd("bash", str(old / "scripts/bootstrap-rootless.sh"),
            "--launcher-sha256", digest,
            "--recovery-sha256", recovery_digest)
        trust = Path("/etc/repocache/trust.d")
        trust.mkdir(parents=True, exist_ok=True, mode=0o755)
        trust.parent.chmod(0o755)
        trust.chmod(0o755)
        key = trust / "ci-fixture.pem"
        shutil.copyfile("/tmp/ci-publisher.pem", key)
        key.chmod(0o644)
        check(key.stat().st_uid == 0, "ephemeral public key independently installed by CI harness")
        uid = int(cmd("id", "-u", "repocache").stdout.strip())
        gid = int(cmd("id", "-g", "repocache").stdout.strip())
        for source in (old, new):
            os.chown(source, uid, gid)
            for member in source.rglob("*"):
                os.chown(member, uid, gid)
        check(uid != 0 and ROOT.stat().st_uid == uid,
              "service-owned rootless state and nonzero UID")
        protected_launcher = Path("/usr/local/bin/repocache")
        launcher_original = protected_launcher.read_bytes()
        check(protected_launcher.stat().st_uid == 0
              and not Path("/usr/bin/repocache").exists(),
              "global launcher is root-owned; no second unmanaged CLI link")
        # Probe the real launcher ancestors in disposable CI images. A service
        # account must never accept a globally writable parent of its root-
        # owned command path, even when the launcher file itself looks safe.
        launcher_parent = protected_launcher.parent
        original_mode = launcher_parent.stat().st_mode & 0o777
        launcher_parent.chmod(0o777)
        try:
            result = user_python(
                old, "from repocache import updater; updater._safe_links()",
                success=False)
            check("Unsafe global launcher ancestor" in result.stderr,
                  "writable global launcher directory rejected before runtime execution")
        finally:
            launcher_parent.chmod(original_mode)
        for protected_file in (Path("/usr/local/bin/repocache"),
                               Path("/etc/ssl/repocache-test.key"),
                               Path("/etc/nginx/nginx.conf")):
            rejected = cmd("/usr/sbin/runuser", "-u", "repocache", "--",
                           "/bin/sh", "-c", 'echo unauthorized >> "$1"',
                           "sh", str(protected_file), success=False)
            check(rejected.returncode != 0,
                  f"service account cannot modify {protected_file}")
        # Read-only no-root execution sentinel via the protected root launcher.
        check(cmd("/usr/sbin/runuser", "-u", "repocache", "--", "id", "-u").stdout.strip()
              == str(uid), "uid can be dropped before Python")
        script = (
            "import json,sys; from pathlib import Path; "
            "from repocache import upgrade; "
            "r=upgrade.upgrade(sys.argv[1],bundle=Path(sys.argv[2]),"
            "checksum=Path(sys.argv[3])); "
            "print(json.dumps(r))"
        )
        baseline = user_python(old, script, "0.3.0", str(old_bundle), str(old_sha))
        check(json.loads(baseline.stdout)["version"] == "0.3.0",
              "fresh synthetic rootless installation")
        check(cmd("repocache", "--version").stdout.strip().endswith("0.3.0"),
              "root-owned launcher executes the service-owned CLI")
        check((ROOT / "installed.json").is_file() and
              (ROOT / "current").is_symlink(),
              "managed manifest and active link")
        previous_link = os.readlink(ROOT / "current")
        previous_manifest = (ROOT / "installed.json").read_bytes()
        for path, data in protected.items():
            check(path.read_bytes() == data, f"privileged resource unchanged: {path}")
        recovery_helper = Path("/usr/local/libexec/repocache-recover.py")
        check(recovery_helper.is_file() and recovery_helper.stat().st_uid == 0
              and not recovery_helper.stat().st_mode & 0o022,
              "independently hashed root-owned pre-CLI recovery helper installed")
        # Simulate a fatal process crash at the most dangerous point: after
        # the current link points to the uncommitted target, but before the
        # installed manifest is written. It must be recovered by the ROOT-
        # OWNED launcher, not by importing candidate managed Python code.
        crash = (
            "import os,signal,sys; from pathlib import Path; "
            "from repocache import upgrade,updater; "
            "original=updater._replace_current; "
            "def_crash=lambda target: (original(target),"
            "os.kill(os.getpid(),signal.SIGKILL)); "
            "updater._replace_current=def_crash; "
            "upgrade.upgrade(sys.argv[1],bundle=Path(sys.argv[2]),"
            "checksum=Path(sys.argv[3]))"
        )
        killed = user_python(new, crash, "0.4.0", str(new_bundle), str(new_sha),
                             success=False)
        # runuser commonly maps a SIGKILL of its child to 128 + signal,
        # while a direct Popen of the killed interpreter reports -SIGKILL.
        check(killed.returncode in (-signal.SIGKILL, 128 + signal.SIGKILL),
              "process forcibly terminated during activation (SIGKILL)")
        check((ROOT / ".update-journal.json").is_file()
              and os.readlink(ROOT / "current") != previous_link,
              "process crash left prepared journal and uncommitted new CLI")
        # Explicitly booby-trap the *uncommitted* candidate's entry point:
        # invoking it would create a sentinel, but the root-owned launcher
        # must restore the prior trusted CLI without ever executing it.
        uncommitted = Path(os.readlink(ROOT / "current")) / "bin/repocache"
        marker = folder / "candidate-executed"
        uncommitted.write_text("#!/bin/sh\nprintf attacked > " + str(marker) + "\n")
        uncommitted.chmod(0o755)
        check(cmd("repocache", "--version").stdout.strip().endswith("0.3.0"),
              "trusted OS-Python recovery runs automatically BEFORE managed CLI")
        check(not marker.exists(),
              "uncommitted candidate executable never ran during startup recovery")
        check(os.readlink(ROOT / "current") == previous_link and
              (ROOT / "installed.json").read_bytes() == previous_manifest
              and not (ROOT / ".update-journal.json").exists(),
              "startup recovery reconciles exact previous generation and manifest")
        check(protected_launcher.read_bytes() == launcher_original
              and protected_launcher.stat().st_uid == 0,
              "CLI launch target and owner unchanged by interrupted activation")
        check(cmd("repocache", "--version").stdout.strip().endswith("0.3.0"),
              "ordinary second CLI startup remains idempotent")

        # Inject an error after activation to verify exception-driven rollback.
        injection = (
            "import sys; from pathlib import Path; "
            "from repocache import upgrade,updater; "
            "updater._write_manifest=lambda *_: (_ for _ in ()).throw("
            "updater.UpdateError('injected manifest failure')); "
            "upgrade.upgrade(sys.argv[1],bundle=Path(sys.argv[2]),"
            "checksum=Path(sys.argv[3]))"
        )
        failed = user_python(new, injection, "0.4.0", str(new_bundle), str(new_sha),
                             success=False)
        check("injected manifest failure" in failed.stderr,
              "failure injection reached manifest write")
        check(os.readlink(ROOT / "current") == previous_link and
              (ROOT / "installed.json").read_bytes() == previous_manifest,
              "failed activation rolled back link and manifest")

        # Exercise the actual noninteractive user-facing CLI, including the
        # root-owned launcher UID drop. The container has --network none.
        result = cmd("repocache", "update", "--version", "0.4.0",
                     "--bundle", str(new_bundle), "--checksum", str(new_sha),
                     "--json")
        check(json.loads(result.stdout)["version"] == "0.4.0",
              "real offline CLI performs signed hash-pinned update without network")
        check(cmd("repocache", "--version").stdout.strip().endswith("0.4.0"),
              "root-owned launcher points to updated service CLI")
        current_link = os.readlink(ROOT / "current")
        current_manifest = (ROOT / "installed.json").read_bytes()

        # Native negative test: a root-owned file substituted inside a
        # service-managed virtualenv cannot be trusted for an update. Fail
        # closed before changing the previous launcher/manifest.
        active_entry = ROOT / "current/bin/repocache"
        os.chown(active_entry, 0, 0)
        try:
            invalid_owner = user_python(
                new, script, "0.4.0", str(new_bundle), str(new_sha),
                success=False)
            check("Unsafe installed environment path" in invalid_owner.stderr
                  and os.readlink(ROOT / "current") == current_link
                  and (ROOT / "installed.json").read_bytes() == current_manifest,
                  "unexpected active executable owner rejects update without state mutation")
        finally:
            os.chown(active_entry, uid, gid)

        changed = folder / new_sha.name
        changed.write_text("0" * 64 + "  " + new_bundle.name + "\n")
        user_python(new, script, "0.4.0", str(new_bundle), str(changed),
                    success=False)
        check(os.readlink(ROOT / "current") == current_link and
              (ROOT / "installed.json").read_bytes() == current_manifest,
              "tampered checksum does not alter active version")

        # Version/filename may be unchanged while dependency content differs;
        # the signed publisher SHA must reject that before touching state.
        poisoned_dir = folder / "poisoned-wheelhouse"
        poisoned_dir.mkdir(mode=0o755)
        malicious_wheels = poisoned_dir / (new_bundle.name + ".wheelhouse.tar.gz")
        malicious_wheels.write_bytes(b"attacker-supplied dependency archive")
        cmd("repocache", "update", "--version", "0.4.0",
            "--bundle", str(new_bundle), "--checksum", str(new_sha),
            "--wheelhouse", str(malicious_wheels), "--json", success=False)
        check(os.readlink(ROOT / "current") == current_link and
              (ROOT / "installed.json").read_bytes() == current_manifest,
              "tampered dependency bundle never alters active version")

        # The launcher must execute any mutable script with the service UID.
        active_cli = ROOT / "current/bin/repocache"
        saved = active_cli.read_bytes()
        try:
            active_cli.write_text("#!/bin/sh\nid -u\n")
            active_cli.chmod(0o755)
            check(cmd("repocache", "--version").stdout.strip() == str(uid),
                  "root caller drops uid before executing mutable CLI")
        finally:
            active_cli.write_bytes(saved)
            active_cli.chmod(0o755)

        # Same-version operations MUST NOT treat a matching mutable manifest
        # and the presence of a modified executable as integrity evidence.
        # Independently authenticated assets rebuild a fresh generation.
        before_repair = os.readlink(ROOT / "current")
        changed_manifest = (ROOT / "installed.json").read_bytes()
        tampered_executable = ROOT / "current/bin/repocache"
        tamper_sentinel = folder / "old-runtime-executed"
        tampered_executable.write_text(
            "#!/bin/sh\\nprintf compromised > " + str(tamper_sentinel) + "\\n")
        tampered_executable.chmod(0o755)
        repaired = user_python(new, script, "0.4.0", str(new_bundle), str(new_sha))
        check(json.loads(repaired.stdout)["status"] == "installed",
              "same-version signed assets create a new environment, not a no-op")
        check(os.readlink(ROOT / "current") != before_repair
              and (ROOT / "installed.json").is_file(),
              "tampered previous virtualenv is never reused")
        check(not tamper_sentinel.exists()
              and cmd("repocache", "--version").stdout.strip().endswith("0.4.0"),
              "the old altered executable was not executed during signed repair")
        for path, data in protected.items():
            check(path.read_bytes() == data,
                  f"resource unchanged after update/rollback: {path}")

    print("PASS: synthetic rootless integration checks completed.")
    print("UNVERIFIED: production key custody (#54), real power-loss durability "
          "(maintainer-waived #51); historical migrations are unsupported in public v0.4.0.")


if __name__ == "__main__":
    main()
