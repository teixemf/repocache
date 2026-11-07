"""Fail-closed *candidate* subprocess sandbox for proposed v0.6 (#112).

Rootless bubblewrap with explicit user/PID/network/mount namespaces is a
proposed OS-native execution boundary. Never fall back to host execution.
This is not authorization to activate a candidate or claim native acceptance.
"""
from __future__ import annotations

import os
import re
import selectors
import signal
import stat
import subprocess
import time
from pathlib import Path

from repocache import updater


class SandboxError(RuntimeError):
    """Missing or untrusted runtime boundary; candidate must not execute."""


BWRAP = Path("/usr/bin/bwrap")
PRLIMIT = Path("/usr/bin/prlimit")
# RLIMITs inherited by bwrap children: per-process safeguards, not a cgroup.
CPU_SECONDS = 60
ADDRESS_SPACE_BYTES = 2 * 1024 * 1024 * 1024
FILE_SIZE_BYTES = 512 * 1024 * 1024
OPEN_FILE_COUNT = 256
USER_TASK_COUNT = 128
# A per-invocation private /tmp cap; NOT a quota for the persistent staging bind.
TMPFS_MAX_BYTES = 64 * 1024 * 1024
_ALLOWED_OWNED_COMMANDS = {
    ("--version",),
    ("--help",),
    ("update", "--help"),
}
_ALLOWED_PIP_OPS = {"install", "check", "list"}


def _safe_package_query(argv: list[str]) -> str:
    """Use only root-owned native package metadata, never a shell or pip."""
    try:
        result = subprocess.run(
            argv, env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C"},
            text=True, capture_output=True, check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SandboxError("Cannot verify sandbox OS security update") from exc
    if result.returncode != 0 or len(result.stdout) > 256:
        raise SandboxError("Unverifiable sandbox OS package revision")
    return result.stdout.strip()


def _verify_patch_level() -> None:
    """Require fixes for CVE-2026-87766 on both supported platforms."""
    from repocache.online_generation import _current_host_target
    target = _current_host_target()
    if target == "debian13-py313":
        version = _safe_package_query(
            ["/usr/bin/dpkg-query", "-W", "-f=$" "{Version}", "bubblewrap"])
        if not re.fullmatch(r"[0-9A-Za-z.+~:-]{1,100}", version):
            raise SandboxError("Invalid Debian sandbox package version")
        try:
            check = subprocess.run(
                ["/usr/bin/dpkg", "--compare-versions", version, "ge",
                 "0.12.0-1~deb13u1"],
                env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C"},
                capture_output=True, check=False, timeout=5)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SandboxError("Cannot compare native Debian package versions") from exc
        if check.returncode != 0:
            raise SandboxError("Debian DSA-6472-1 bubblewrap update is missing")
    elif target == "almalinux10-py312":
        version = _safe_package_query(
            ["/usr/bin/rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}",
             "bubblewrap"])
        match = re.fullmatch(
            r"(\d+)\.(\d+)\.(\d+)-(\d+)\.el10_(\d+)(?:\.[A-Za-z0-9.]+)?",
            version)
        if match is None:
            raise SandboxError("Unsupported AlmaLinux sandbox package revision")
        major, minor, patch, release, update = map(int, match.groups())
        if not ((major, minor, patch) >= (0, 12, 0) or
                ((major, minor, patch) == (0, 10, 0)
                 and release >= 5 and update >= 2)):
            raise SandboxError("AlmaLinux ALSA-2026:85308 update is missing")
    else:
        raise SandboxError("Unsupported sandbox host")


def require_executor() -> None:
    """Refuse setuid, substituted or unmaintained privilege boundaries.

    Security updates (including AlmaLinux ALSA-2026:85308) still require
    an independent OS/package and functional native acceptance gate.
    """
    updater._require_service_account()
    for path in (Path("/usr"), Path("/usr/bin"), BWRAP, PRLIMIT):
        try:
            meta = path.lstat()
        except OSError as exc:
            raise SandboxError("Required OS sandbox executor is unavailable") from exc
        if path in (BWRAP, PRLIMIT) and meta.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise SandboxError("Setuid/setgid sandbox helpers are forbidden")
        if (meta.st_uid != 0 or meta.st_mode & 0o022
                or (not stat.S_ISDIR(meta.st_mode) if path not in (BWRAP, PRLIMIT)
                    else not stat.S_ISREG(meta.st_mode))):
            raise SandboxError("Untrusted OS sandbox executor path")
    for executable in (BWRAP, PRLIMIT):
        if not executable.lstat().st_mode & 0o111:
            raise SandboxError("Sandbox helper is non-executable")
    _verify_patch_level()


def _checked_workspace(workspace: Path, cwd: Path | None) -> Path:
    """Only owner-private, non-symlinked paths within a new staging root."""
    managed = updater.ROOT
    if (not workspace.is_absolute() or not managed.is_absolute()
            or workspace.parent != managed / "online-preparations"
            or not workspace.name.startswith(".online-v6-")
            or workspace.name in (".", "..")):
        raise SandboxError("Workspace is outside the managed candidate area")
    if os.geteuid() == 0:
        raise SandboxError("Never execute staged code as root")
    for path in (managed, workspace.parent, workspace):
        try:
            meta = path.lstat()
        except OSError as exc:
            raise SandboxError("Candidate workspace is missing") from exc
        if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.geteuid()
                or stat.S_IMODE(meta.st_mode) & 0o077):
            raise SandboxError("Unsafe or shared candidate workspace")
    destination = workspace if cwd is None else cwd
    if destination != workspace and workspace not in destination.parents:
        raise SandboxError("Candidate working directory escapes staging area")
    current = destination
    while current != workspace:
        info = current.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise SandboxError("Unsafe candidate working directory")
        current = current.parent
    return destination


def _checked_command(workspace: Path, argv: list[str]) -> None:
    """No arbitrary shell, OS process or external candidate command."""
    if not argv or not all(isinstance(x, str) and x for x in argv):
        raise SandboxError("Missing sandboxed candidate command")
    interpreter = str(workspace / "venv/bin/python")
    console = str(workspace / "venv/bin/repocache")
    if argv[0] == interpreter:
        if argv[1:5] == ["-I", "-m", "pip", "--isolated"]:
            if len(argv) <= 5 or argv[5] not in _ALLOWED_PIP_OPS:
                raise SandboxError("Unapproved pip operation in sandbox")
            if argv[5] == "install":
                # Exact argument vector: additional pip flags may change
                # install target, permissions, resolver or index behavior.
                required = ["--no-index", "--no-deps", "--only-binary=:all:",
                            "--require-hashes", "--disable-pip-version-check",
                            "--no-cache-dir", "--no-input", "-r"]
                allowed = {
                    str(workspace / "download/requirements.lock"),
                    str(workspace / "owned-app/application.lock"),
                }
                if argv[6:-1] != required or argv[-1] not in allowed:
                    raise SandboxError("Noncanonical offline wheel installation")
            elif argv[5:] not in (["check"], ["list", "--format=json"]):
                raise SandboxError("Unapproved pip inspection command")
        elif argv[1:3] == ["-I", "-c"]:
            from repocache.online_generation import TUI_HEADLESS_SMOKE
            if len(argv) != 4 or argv[3] != TUI_HEADLESS_SMOKE:
                raise SandboxError("Unapproved Python smoke script")
        else:
            raise SandboxError("Unexpected Python command in candidate sandbox")
    elif argv[0] == console and tuple(argv[1:]) in _ALLOWED_OWNED_COMMANDS:
        pass
    else:
        raise SandboxError("Unapproved executable in candidate sandbox")


def command(workspace: Path, argv: list[str], *,
            cwd: Path | None = None) -> list[str]:
    """Construct a namespace invocation with only staging writable.

    A minimal synthetic root exposes OS-managed /usr and dynamic libraries
    read-only, a private /tmp, fresh /proc and /dev, and only this staging
    workspace. It does not mount the parent managed root or operator HOME.
    Linux namespace restrictions are mandatory; failure refuses execution.
    """
    require_executor()
    _checked_workspace(workspace, cwd)
    _checked_command(workspace, argv)
    args = [
        str(BWRAP),
        "--die-with-parent", "--new-session",
        "--unshare-user", "--disable-userns",
        "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts",
        "--clearenv",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind-try", "/bin", "/bin",
        "--ro-bind-try", "/sbin", "/sbin",
        "--ro-bind-try", "/lib", "/lib",
        "--ro-bind-try", "/lib64", "/lib64",
        "--ro-bind-try", "/etc/ssl/certs", "/etc/ssl/certs",
        "--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
        "--ro-bind-try", "/etc/passwd", "/etc/passwd",
        "--ro-bind-try", "/etc/group", "/etc/group",
        "--ro-bind-try", "/etc/nsswitch.conf", "/etc/nsswitch.conf",
        "--proc", "/proc", "--dev", "/dev",
        "--size", str(TMPFS_MAX_BYTES), "--tmpfs", "/tmp",
    ]
    # Mountpoint directories in the new empty namespace. Host-managed state
    # elsewhere (including sibling generations) is never made visible.
    for parent in reversed(workspace.parents):
        if parent == Path("/"):
            continue
        args.extend(("--dir", str(parent)))
    args.extend((
        "--bind", str(workspace), str(workspace),
        # The initial synthetic root is a writable tmpfs by default.
        # Prevent candidate code from writing to synthetic /etc, /opt, etc.
        # This remount affects ONLY /, not the separate writable workspace
        # and private /tmp mounts. Never bind the host's real root or /etc.
        "--remount-ro", "/",
        "--chdir", str(workspace if cwd is None else cwd),
        "--setenv", "HOME", "/tmp",
        "--setenv", "TMPDIR", "/tmp",
        "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "LANG", "C.UTF-8",
        "--setenv", "PYTHONNOUSERSITE", "1",
        "--setenv", "PYTHONSAFEPATH", "1",
        "--setenv", "PIP_NO_INPUT", "1",
        "--setenv", "PIP_CONFIG_FILE", "/dev/null",
        "--",
        *argv,
    ))
    return args



# A cap on captured bytes is defense in depth against hostile console output;
# it is NOT a CPU, process-count, virtual-memory or staging-disk quota.
MAX_CAPTURE_BYTES = 1024 * 1024



def _limited_command(argv: list[str]) -> list[str]:
    """Launch the sandbox with inherited Linux resource ceilings.

    These limits prevent individual-process runaway, but do not replace
    per-candidate cgroup memory/CPU/PIDs or staging filesystem quotas.
    """
    limits = (
        ("cpu", CPU_SECONDS), ("as", ADDRESS_SPACE_BYTES),
        ("nproc", USER_TASK_COUNT), ("nofile", OPEN_FILE_COUNT),
        ("fsize", FILE_SIZE_BYTES), ("core", 0),
    )
    return [str(PRLIMIT), *(f"--{name}={value}:{value}"
                            for name, value in limits), "--", *argv]


def _run_bounded(argv: list[str], *, cwd: Path, timeout: int) -> str:
    """Drain stdout/stderr incrementally; kill the launcher group on failure.

    An untrusted candidate can print indefinitely. subprocess.run with
    capture_output=True accumulates unbounded pipe bytes in the trusted
    updater process. This executor has a strict combined capture budget.
    The Bubblewrap PID namespace and --die-with-parent still provide the
    descendant lifetime boundary; native-host policy needs separate proof.
    """
    if not isinstance(timeout, int) or not 0 < timeout <= 300:
        raise updater.UpdateError("Invalid candidate execution deadline")
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/var/lib/repocache", "LANG": "C.UTF-8",
        "GIT_TERMINAL_PROMPT": "0",
        "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INPUT": "1",
        "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1",
    }
    try:
        process = subprocess.Popen(
            _limited_command(argv), cwd=cwd, env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True)
    except OSError as exc:
        raise updater.UpdateError(
            "Could not start isolated candidate runner") from exc
    selector = selectors.DefaultSelector()
    outputs: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    total = 0
    deadline = time.monotonic() + timeout
    try:
        assert process.stdout is not None and process.stderr is not None
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise updater.UpdateError("Candidate sandbox timed out")
            for key, _ in selector.select(remaining):
                data = os.read(key.fileobj.fileno(),
                               min(65536, MAX_CAPTURE_BYTES + 1 - total))
                if not data:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                total += len(data)
                if total > MAX_CAPTURE_BYTES:
                    raise updater.UpdateError(
                        "Candidate sandbox output exceeded limit")
                outputs[key.data].append(data)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise updater.UpdateError("Candidate sandbox timed out")
        try:
            exit_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise updater.UpdateError("Candidate sandbox timed out") from exc
        stdout = b"".join(outputs["stdout"]).decode("utf-8", errors="replace")
        stderr = b"".join(outputs["stderr"]).decode("utf-8", errors="replace")
        if exit_code:
            raise updater.UpdateError(
                (stderr or stdout).strip()[:700] or
                f"Candidate sandbox exited with status {exit_code}")
        return stdout.strip()
    finally:
        selector.close()
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def run_isolated(argv: list[str], *, workspace: Path,
                 cwd: Path | None = None, timeout: int = 90) -> str:
    """Execute ONLY after enforceable namespace construction succeeds."""
    commandline = command(workspace, argv, cwd=cwd)
    return _run_bounded(commandline, cwd=workspace, timeout=timeout)
