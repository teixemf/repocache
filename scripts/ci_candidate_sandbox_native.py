#!/usr/bin/env python3
"""Native userspace Bubblewrap namespace probe on disposable CI containers.

The Docker security policy and GitHub runner kernel are NOT Debian/AlmaLinux
bare-metal security acceptance. A denied namespace is a failed test, not a skip.
No external network requests are made by the candidate process.
"""
from __future__ import annotations

import os
import pathlib
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile

sys.path.insert(0, "/source/src")
from repocache import candidate_sandbox, online_generation, updater


def check(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)
    print("PASS: " + label, flush=True)


def run(argv: list[str], *, label: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        argv, cwd="/", env=env, text=True, capture_output=True,
        timeout=45, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"{label}: exit={result.returncode} "
            f"stdout={result.stdout[-1300:]} stderr={result.stderr[-1300:]}"
        )
    return result.stdout.strip()


def main() -> None:
    check(os.geteuid() == pwd.getpwnam("repocache").pw_uid != 0,
          "probe runs as dedicated non-root service account")
    check(online_generation._current_host_target() in
          {"debian13-py313", "almalinux10-py312"},
          "native distro and Python version match supported pair")
    candidate_sandbox.require_executor()
    print("PASS: OS-owned, patched, non-setuid bubblewrap executor", flush=True)
    root = updater.ROOT
    check(root.is_dir() and root.stat().st_uid == os.geteuid(),
          "managed candidate root owned by service UID")
    parent = root / "online-preparations"
    parent.mkdir(mode=0o700, exist_ok=True)
    parent.chmod(0o700)
    work = pathlib.Path(tempfile.mkdtemp(prefix=".online-v6-", dir=parent))
    os.chmod(work, 0o700)
    # No package network resolution, pip or external code in the probe venv.
    subprocess.run([sys.executable, "-I", "-m", "venv", "--without-pip",
                    str(work / "venv")], check=True, timeout=60)
    console = work / "venv/bin/repocache"
    console.write_text(
        "#!/usr/bin/python3\n"
        "print('REPOCACHE Control Center 0.6.0')\n", encoding="utf-8")
    console.chmod(0o700)
    marker = root / "installed.json"
    original = marker.read_bytes()
    try:
        output = candidate_sandbox.run_isolated(
            [str(console), "--version"], workspace=work, timeout=30)
        check(output == "REPOCACHE Control Center 0.6.0",
              "real candidate console subprocess runs under rootless namespaces")

        outer_process = subprocess.Popen(["/usr/bin/sleep", "35"])
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        try:
            injected_probe = r"""
import errno
import os
import pathlib
import socket
root = pathlib.Path('/opt/repocache-cli/managed')
assert not (root / 'installed.json').exists(), 'active manifest exposed'
assert not (root / 'current').exists(), 'active pointer exposed'
assert not pathlib.Path('/var/lib/repocache/ci-private-secret').exists(), 'secret exposed'
for candidate in ('/usr/repocache-forbidden-write', '/etc/repocache-forbidden-write'):
    try:
        pathlib.Path(candidate).write_text('corruption')
    except (OSError, PermissionError):
        pass
    else:
        raise AssertionError('OS directory was writable: ' + candidate)
out = pathlib.Path(os.environ['SANDBOX_WORKSPACE']) / 'isolation-proof'
out.write_text('sandbox-only')
# Explicitly require fresh namespaces; an offline runner is not proof of no-network.
assert os.readlink('/proc/self/ns/net') != os.environ['OUTER_NET_NS'], 'host network namespace shared'
assert os.readlink('/proc/self/ns/pid') != os.environ['OUTER_PID_NS'], 'host PID namespace shared'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    assert s.connect_ex(('127.0.0.1', int(os.environ['OUTER_LISTEN_PORT']))) != 0, 'outer loopback reachable'
finally:
    s.close()
host_pid = int(os.environ['OUTER_PID'])
assert host_pid > 8, 'test fixture cannot guarantee distinct outer PID'
assert not pathlib.Path(f'/proc/{host_pid}').exists(), 'host PID visible'
print('SANDBOX_ESCAPE_PROBES_PASS')
"""
            # The final negative test deliberately runs arbitrary probe code
            # with the EXACT constructed namespace argv. It bypasses only
            # Python command allowlisting inside this CI test, NEVER in REPOCACHE.
            trusted = candidate_sandbox.command(
                work, [str(console), "--version"])
            args = trusted[:trusted.index("--") + 1] + [
                str(work / "venv/bin/python"), "-I", "-c", injected_probe]
            # The production sandbox clears the ambient environment. Only
            # test data is explicitly set inside the new namespace.
            insert = args.index("--")
            args[insert:insert] = [
                "--setenv", "SANDBOX_WORKSPACE", str(work),
                "--setenv", "OUTER_PID", str(outer_process.pid),
                "--setenv", "OUTER_NET_NS", os.readlink("/proc/self/ns/net"),
                "--setenv", "OUTER_PID_NS", os.readlink("/proc/self/ns/pid"),
                "--setenv", "OUTER_LISTEN_PORT", str(listener.getsockname()[1]),
            ]
            env = {
                "HOME": "/var/lib/repocache",
                "LANG": "C.UTF-8", "PATH": "/usr/bin:/bin",
                "PYTHONNOUSERSITE": "1", "PIP_CONFIG_FILE": "/dev/null",
            }
            check(run(args, label="real kernel sandbox negative tests",
                      env=env) == "SANDBOX_ESCAPE_PROBES_PASS",
                  "kernel denied host writes, reads, loopback and PID access")
            check((work / "isolation-proof").read_text() == "sandbox-only",
                  "only disposable candidate staging is writable")
            check(marker.read_bytes() == original,
                  "active installed manifest remains byte-for-byte intact")
        finally:
            listener.close()
            outer_process.terminate()
            outer_process.wait(timeout=10)

        # Real-kernel orphan test: time out a candidate which deliberately
        # launches a detached grandchild. bwrap --die-with-parent and its PID
        # namespace must kill it even after subprocess.run kills bwrap itself.
        # Only the disposable candidate workspace can contain the markers.
        from repocache import updater as recovery_updater
        import time
        started = work / "timeout-probe-started"
        escaped = work / "timeout-orphan-escaped"
        child_code = (
            "import pathlib,time;"
            "time.sleep(4);"
            f"pathlib.Path({str(escaped)!r}).write_text('escaped')"
        )
        console.write_text(
            "#!/usr/bin/python3\n"
            "import pathlib,subprocess,sys,time\n"
            f"pathlib.Path({str(started)!r}).write_text('started')\n"
            f"subprocess.Popen([sys.executable, '-I', '-c', {child_code!r}], "
            "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
            "stderr=subprocess.DEVNULL, close_fds=True, "
            "start_new_session=True)\n"
            "time.sleep(30)\n", encoding="utf-8")
        console.chmod(0o700)
        try:
            candidate_sandbox.run_isolated(
                [str(console), "--version"], workspace=work, timeout=2)
        except recovery_updater.UpdateError as exc:
            check("timed out" in str(exc).lower(),
                  "candidate overrun triggers the hard subprocess deadline")
        else:
            raise AssertionError("Long-running candidate unexpectedly finished")
        check(started.is_file() and started.read_text() == "started",
              "timeout probe actually launched inside its sandbox")
        time.sleep(5)
        check(not escaped.exists(),
              "detached grandchild cannot outlive terminated bwrap sandbox")
        check(marker.read_bytes() == original,
              "time-limited candidate never changed active release state")

        # The actual Bubblewrap candidate must not exhaust host memory by
        # flooding stdout. This is an executor resource-defense test, not
        # proof of cgroup CPU/memory/PID or staging disk quotas.
        console.write_text(
            "#!/usr/bin/python3\n"
            "import sys\n"
            "sys.stdout.write('x' * 1100000)\n",
            encoding="utf-8")
        console.chmod(0o700)
        try:
            candidate_sandbox.run_isolated(
                [str(console), "--version"], workspace=work, timeout=30)
        except recovery_updater.UpdateError as exc:
            check("output exceeded limit" in str(exc),
                  "candidate stdout flood is refused with bounded capture")
        else:
            raise AssertionError("Hostile candidate stdout escaped capture budget")
        check(marker.read_bytes() == original,
              "stdout flood left installed state unchanged")

        # A real tmpfs quota must reject a hostile candidate that fills
        # sandbox-private /tmp. This does NOT quota the persistent staging bind.
        console.write_text(
            "#!/usr/bin/python3\n"
            "import errno,pathlib\n"
            "try:\n"
            "    with pathlib.Path('/tmp/exhaustion-probe').open('wb') as out:\n"
            "        for _ in range(66):\n"
            "            out.write(b'x' * 1048576)\n"
            "except OSError as exc:\n"
            "    assert exc.errno == errno.ENOSPC, f'unexpected tmpfs error: {exc}'\n"
            "else:\n"
            "    raise AssertionError('private tmpfs exceeded 64 MiB quota')\n"
            "print('TMPFS_QUOTA_ENFORCED')\n",
            encoding="utf-8")
        console.chmod(0o700)
        output = candidate_sandbox.run_isolated(
            [str(console), "--version"], workspace=work, timeout=30)
        check(output == "TMPFS_QUOTA_ENFORCED",
              "private candidate tmpfs actually refuses disk exhaustion")
        check(marker.read_bytes() == original,
              "tmpfs exhaustion never changed active release state")

        # The real untrusted process inherits native per-process RLIMITs,
        # even though this is NOT an aggregate cgroup resource boundary.
        console.write_text(
            "#!/usr/bin/python3\n"
            "import resource\n"
            "names=('CPU','AS','NPROC','NOFILE','FSIZE','CORE')\n"
            "print(','.join(str(resource.getrlimit(getattr(resource,'RLIMIT_'+n))[0]) for n in names))\n",
            encoding="utf-8")
        console.chmod(0o700)
        output = candidate_sandbox.run_isolated(
            [str(console), "--version"], workspace=work, timeout=30)
        expected_limits = (
            candidate_sandbox.CPU_SECONDS,
            candidate_sandbox.ADDRESS_SPACE_BYTES,
            candidate_sandbox.USER_TASK_COUNT,
            candidate_sandbox.OPEN_FILE_COUNT,
            candidate_sandbox.FILE_SIZE_BYTES,
            0,
        )
        check(output == ",".join(str(value) for value in expected_limits),
              "sandboxed candidate inherits CPU/AS/task/file/core RLIMITs")
        check(marker.read_bytes() == original,
              "resource-limit probe preserved active installation")
    finally:
        shutil.rmtree(work)
    check(marker.read_bytes() == original, "last known good state preserved")
    check(not list(parent.iterdir()), "sandbox staging was cleaned up")
    print("PASS: Linux namespace integration probe completed", flush=True)


if __name__ == "__main__":
    main()
