"""Nonmutating local-host observations for the proposed server preflight (#26).

These observations cannot authorize installation. In particular they do not
establish package provenance, NGINX module compatibility, trusted ownership,
SELinux file labels, or a booted native-host acceptance test.
"""
from __future__ import annotations

from dataclasses import dataclass
import errno
import os
import stat
from typing import Literal

from repocache.server_install_v1 import validate_install_document
from repocache.server_preflight_v1 import (
    NativeHostFacts, NativePreflightReport, PreflightCheck, PreflightStatus,
    assess_native_host, capture_native_host_facts,
)

# All paths below are fixed, local, diagnostic paths. Configuration-derived
# paths must first pass validate_install_document(); never log them.
_MAX_PROC_BYTES = 4 * 1024 * 1024
_MAX_PID_BYTES = 128
_MIN_STATE_LOG_FREE_BYTES = 1024 * 1024  # Conservative observation floor, not an approved capacity policy.
_MIN_FREE_INODES = 16  # Low-headroom diagnostic only; not an exhaustion or install threshold.
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
_EXECUTABLES = {
    "debian": ("/usr/bin/apt-get", "/usr/bin/python3.13", "/usr/sbin/nginx"),
    "almalinux": ("/usr/bin/dnf", "/usr/bin/python3.12", "/usr/sbin/nginx"),
}


@dataclass(frozen=True)
class HostInspectionSpec:
    """Trusted, validated projection of the deployment v1 document."""

    bind_address: str
    https_port: int
    state_root: str
    cache_root: str
    log_root: str
    generated_include: str
    warning_free_bytes: int
    critical_free_bytes: int


@dataclass(frozen=True)
class HostProbeResults:
    """Sanitized observations; no raw contents, sensitive names or paths."""

    checks: tuple[PreflightCheck, ...]


def _check(name: str, status: PreflightStatus, code: str) -> PreflightCheck:
    return PreflightCheck(name, status, code)


def _read_fixed(path: str, limit: int) -> bytes:
    """Bounded kernel/fixed file read; only read-only file descriptors."""
    fd = os.open(path, _READ_FLAGS)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular diagnostic file")
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break  # Require EOF rather than treating short read as complete.
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > limit:
            raise OSError(errno.EFBIG, "diagnostic file exceeds limit")
        return data
    finally:
        os.close(fd)


def _executable_at(path: str) -> bool | None:
    try:
        info = os.stat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return None
    return stat.S_ISREG(info.st_mode) and bool(info.st_mode & 0o111)


def _package_binary_check(system: str) -> PreflightCheck:
    seen = [_executable_at(path) for path in _EXECUTABLES[system]]
    if False in seen:
        return _check("native_package_binaries", PreflightStatus.FAIL,
                      "REQUIRED_NATIVE_EXECUTABLE_MISSING")
    if None in seen:
        return _check("native_package_binaries", PreflightStatus.NOT_VERIFIED,
                      "NATIVE_EXECUTABLE_ACCESS_UNVERIFIED")
    return _check("native_package_binaries", PreflightStatus.PASS,
                  "REQUIRED_NATIVE_EXECUTABLES_OBSERVED_ONLY")


def _safe_existing_ancestor(path: str) -> tuple[str | None, str]:
    """Reject symlink or unsafe world-writable components; never create paths.

    Returns the closest existing directory and a static classification.
    Ownership cannot be inferred even for an otherwise safe path.
    """
    parts = path.split("/")[1:]
    if not parts or any(not part or part in (".", "..") for part in parts):
        return None, "UNSAFE_STORAGE_PATH"
    current = "/"
    last_directory = "/"
    for index, part in enumerate(parts):
        current = os.path.join(current, part)
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            # A missing component implies all subsequent components are absent.
            return last_directory, "PATH_PARENT_OBSERVED_ONLY"
        except OSError:
            return None, "STORAGE_PATH_ACCESS_UNVERIFIED"
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            return None, "UNSAFE_STORAGE_PATH"
        if info.st_mode & (stat.S_IWOTH | stat.S_IWGRP):
            # Group trust is not authenticated in this observation layer.
            return None, "UNSAFE_WRITABLE_PATH"
        last_directory = current
    return last_directory, "EXISTING_PATH_OWNERSHIP_UNVERIFIED"


def _storage_checks(spec: HostInspectionSpec) -> tuple[PreflightCheck, PreflightCheck]:
    roots = (spec.state_root, spec.cache_root, spec.log_root)
    observations = [_safe_existing_ancestor(path) for path in roots]
    if any(code.startswith("UNSAFE_") for _, code in observations):
        path_check = _check("storage_path_safety", PreflightStatus.FAIL,
                            "STORAGE_PATH_UNSAFE_OR_CONFLICTING")
    elif any(directory is None for directory, _ in observations):
        path_check = _check("storage_path_safety", PreflightStatus.NOT_VERIFIED,
                            "STORAGE_PATH_ACCESS_UNVERIFIED")
    else:
        path_check = _check("storage_path_safety", PreflightStatus.NOT_VERIFIED,
                            "STORAGE_OWNERSHIP_MANIFEST_UNVERIFIED")
    if any(directory is None for directory, _ in observations):
        return path_check, _check("storage_free_space", PreflightStatus.NOT_VERIFIED,
                                  "STORAGE_CAPACITY_UNVERIFIED")
    try:
        stats = [os.statvfs(directory) for directory, _ in observations]
        if any(item.f_bavail < 0 or item.f_frsize <= 0
               or item.f_favail < 0 for item in stats):
            raise ValueError("invalid filesystem capacity observation")
        free = [item.f_bavail * item.f_frsize for item in stats]
        inodes = [item.f_favail for item in stats]
    except (OSError, ValueError, OverflowError, AttributeError):
        return path_check, _check("storage_free_space", PreflightStatus.NOT_VERIFIED,
                                  "STORAGE_CAPACITY_UNVERIFIED")
    # A cache critical threshold is part of the validated deployment document.
    # State/log byte and filesystem inode floors are diagnostic heuristics:
    # low headroom cannot prove exhaustion or an approved capacity policy.
    if free[1] < spec.critical_free_bytes:
        disk = _check("storage_free_space", PreflightStatus.FAIL,
                      "STORAGE_SPACE_BELOW_CRITICAL_THRESHOLD")
    elif free[0] == 0 or free[2] == 0:
        disk = _check("storage_free_space", PreflightStatus.FAIL,
                      "STATE_OR_LOG_SPACE_EXHAUSTED")
    elif any(count == 0 for count in inodes):
        disk = _check("storage_free_space", PreflightStatus.FAIL,
                      "FILESYSTEM_INODES_EXHAUSTED")
    elif free[0] < _MIN_STATE_LOG_FREE_BYTES or free[2] < _MIN_STATE_LOG_FREE_BYTES:
        disk = _check("storage_free_space", PreflightStatus.NOT_VERIFIED,
                      "STATE_OR_LOG_LOW_HEADROOM_UNVERIFIED")
    elif any(count < _MIN_FREE_INODES for count in inodes):
        disk = _check("storage_free_space", PreflightStatus.NOT_VERIFIED,
                      "FILESYSTEM_INODES_LOW_HEADROOM_UNVERIFIED")
    elif free[1] < spec.warning_free_bytes:
        disk = _check("storage_free_space", PreflightStatus.NOT_VERIFIED,
                      "CACHE_SPACE_BELOW_WARNING_THRESHOLD")
    elif (any(code != "EXISTING_PATH_OWNERSHIP_UNVERIFIED"
              for _, code in observations)
          or any(getattr(item, "f_fsid", None) is None for item in stats)):
        # A missing mount or directory is not proof of its future capacity.
        disk = _check("storage_free_space", PreflightStatus.NOT_VERIFIED,
                      "STORAGE_MOUNT_OR_POLICY_UNVERIFIED")
    else:
        disk = _check("storage_free_space", PreflightStatus.PASS,
                      "CURRENT_STORAGE_SPACE_OBSERVED_ONLY")
    return path_check, disk


_TCP_HEADER = ("sl", "local_address", "rem_address", "st", "tx_queue",
               "rx_queue", "tr", "tm->when", "retrnsmt", "uid",
               "timeout", "inode")
# Linux include/net/tcp_states.h: 01..0C, including TCP_NEW_SYN_RECV.
_TCP_STATES = frozenset(range(1, 0x0D))


def _parse_tcp_listeners(raw: bytes) -> set[int]:
    """Extract kernel LISTEN ports only; fail closed on malformed records."""
    try:
        lines = raw.decode("ascii", "strict").splitlines()
    except UnicodeError as exc:
        raise ValueError("invalid proc net input") from exc
    # Require the complete, ordered common procfs header; optional trailing
    # kernel columns remain compatible with newer distributions.
    if not lines or tuple(lines[0].split()[:len(_TCP_HEADER)]) != _TCP_HEADER:
        raise ValueError("invalid proc net header")
    ports: set[int] = set()
    for line in lines[1:]:
        columns = line.split()
        if len(columns) < 10 or len(columns[1].split(":")) != 2:
            raise ValueError("invalid proc net row")
        endpoint, port_hex = columns[1].split(":", 1)
        if (len(endpoint) not in (8, 32) or not port_hex or len(port_hex) != 4
                or any(c not in "0123456789abcdefABCDEF" for c in endpoint + port_hex)
                or len(columns[3]) != 2
                or any(c not in "0123456789abcdefABCDEF" for c in columns[3])):
            raise ValueError("invalid proc net address or TCP state")
        tcp_state = int(columns[3], 16)
        if tcp_state not in _TCP_STATES:
            raise ValueError("invalid kernel TCP state")
        if tcp_state == 0x0A:
            ports.add(int(port_hex, 16))
    return ports


def _port_check(spec: HostInspectionSpec) -> PreflightCheck:
    """Conservatively refuse *any* listener on the intended HTTPS port.

    Avoid bind(), connect(), DNS and service commands. An observed free port
    is a momentary snapshot, never a lease/reservation or TOCTOU guarantee.
    """
    ports: set[int] = set()
    incomplete = False
    for file in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            ports.update(_parse_tcp_listeners(_read_fixed(file, _MAX_PROC_BYTES)))
        except (OSError, ValueError):
            incomplete = True
    if spec.https_port in ports:
        return _check("listen_port_conflicts", PreflightStatus.FAIL,
                      "HTTPS_PORT_ALREADY_LISTENING")
    if incomplete:
        return _check("listen_port_conflicts", PreflightStatus.NOT_VERIFIED,
                      "LISTEN_PORT_INVENTORY_INCOMPLETE")
    return _check("listen_port_conflicts", PreflightStatus.PASS,
                  "HTTPS_PORT_NOT_OBSERVED_IN_PROC_SNAPSHOT")


def _nginx_checks(spec: HostInspectionSpec) -> tuple[PreflightCheck, ...]:
    present = _executable_at("/usr/sbin/nginx")
    if present is False:
        binary = _check("nginx_native_binary", PreflightStatus.FAIL,
                        "NGINX_EXECUTABLE_MISSING")
    elif present is None:
        binary = _check("nginx_native_binary", PreflightStatus.NOT_VERIFIED,
                        "NGINX_EXECUTABLE_ACCESS_UNVERIFIED")
    else:
        binary = _check("nginx_native_binary", PreflightStatus.PASS,
                        "NGINX_EXECUTABLE_OBSERVED_ONLY")
    # A missing leaf is insufficient when its parent is symlinked or writable
    # by unrelated users. Inspect every existing parent without following links.
    parent, safety = _safe_existing_ancestor(os.path.dirname(spec.generated_include))
    if parent is None or safety.startswith("UNSAFE_"):
        include = _check("nginx_managed_include_collision", PreflightStatus.FAIL
                         if safety.startswith("UNSAFE_") else PreflightStatus.NOT_VERIFIED,
                         "NGINX_INCLUDE_PARENT_UNSAFE" if safety.startswith("UNSAFE_")
                         else "NGINX_INCLUDE_PARENT_ACCESS_UNVERIFIED")
        return binary, include
    # New-managed-only: a pre-existing target file cannot be adopted based on
    # its name, contents, owner, or common distribution layout.
    try:
        os.lstat(spec.generated_include)
    except FileNotFoundError:
        include = _check("nginx_managed_include_collision", PreflightStatus.PASS,
                         "NEW_MANAGED_INCLUDE_NOT_PRESENT")
    except OSError:
        include = _check("nginx_managed_include_collision", PreflightStatus.NOT_VERIFIED,
                         "MANAGED_INCLUDE_ACCESS_UNVERIFIED")
    else:
        include = _check("nginx_managed_include_collision", PreflightStatus.FAIL,
                         "EXISTING_INCLUDE_REQUIRES_OWNERSHIP_PROOF")
    # Even with nginx installed, its modules, existing vhosts, include chain,
    # provenance, live process identity and ownership remain unverified.
    return binary, include


def _systemd_checks() -> tuple[PreflightCheck, ...]:
    binary = _executable_at("/usr/bin/systemctl")
    if binary is False:
        unit = _check("systemd_binary", PreflightStatus.FAIL,
                      "SYSTEMD_CLIENT_MISSING")
    elif binary is None:
        unit = _check("systemd_binary", PreflightStatus.NOT_VERIFIED,
                      "SYSTEMD_CLIENT_ACCESS_UNVERIFIED")
    else:
        unit = _check("systemd_binary", PreflightStatus.PASS,
                      "SYSTEMD_CLIENT_OBSERVED_ONLY")
    try:
        comm = _read_fixed("/proc/1/comm", _MAX_PID_BYTES).strip()
        runtime = os.stat("/run/systemd/system")
        running = comm == b"systemd" and stat.S_ISDIR(runtime.st_mode)
    except OSError:
        return (unit, _check("systemd_pid1_observation", PreflightStatus.NOT_VERIFIED,
                              "SYSTEMD_PID1_NOT_VERIFIED"))
    return (unit, _check("systemd_pid1_observation",
                         PreflightStatus.PASS if running else PreflightStatus.FAIL,
                         "SYSTEMD_PID1_OBSERVED_ONLY" if running else
                         "SYSTEMD_NATIVE_PID1_NOT_OBSERVED"))


def _selinux_check(system: str) -> PreflightCheck:
    """Observe kernel mode only; never change enforcing state or contexts."""
    try:
        raw = _read_fixed("/sys/fs/selinux/enforce", 16).strip()
    except OSError:
        return _check("selinux_kernel_mode", PreflightStatus.NOT_VERIFIED,
                      "SELINUX_KERNEL_MODE_UNAVAILABLE" if system == "almalinux"
                      else "DEBIAN_SELINUX_MODE_NOT_REQUIRED")
    if raw == b"1":
        return _check("selinux_kernel_mode", PreflightStatus.PASS,
                      "SELINUX_ENFORCING_KERNEL_OBSERVED_ONLY")
    if raw == b"0":
        return _check("selinux_kernel_mode", PreflightStatus.FAIL if system == "almalinux"
                      else PreflightStatus.NOT_VERIFIED,
                      "ALMALINUX_SELINUX_NOT_ENFORCING" if system == "almalinux"
                      else "DEBIAN_SELINUX_PERMISSIVE_OBSERVED")
    return _check("selinux_kernel_mode", PreflightStatus.NOT_VERIFIED,
                  "SELINUX_KERNEL_MODE_UNRECOGNIZED")


def _capture_host_probes(system: str, spec: HostInspectionSpec) -> HostProbeResults:
    storage = _storage_checks(spec)
    checks = (
        _package_binary_check(system), *storage,
        _port_check(spec), *_nginx_checks(spec),
        *_systemd_checks(), _selinux_check(system),
    )
    return HostProbeResults(checks)


_PROBE_CODES: dict[str, dict[str, PreflightStatus]] = {
    "native_package_binaries": {
        "REQUIRED_NATIVE_EXECUTABLE_MISSING": PreflightStatus.FAIL,
        "NATIVE_EXECUTABLE_ACCESS_UNVERIFIED": PreflightStatus.NOT_VERIFIED,
        "REQUIRED_NATIVE_EXECUTABLES_OBSERVED_ONLY": PreflightStatus.PASS,
    },
    "storage_path_safety": {
        "STORAGE_PATH_UNSAFE_OR_CONFLICTING": PreflightStatus.FAIL,
        "STORAGE_PATH_ACCESS_UNVERIFIED": PreflightStatus.NOT_VERIFIED,
        "STORAGE_OWNERSHIP_MANIFEST_UNVERIFIED": PreflightStatus.NOT_VERIFIED,
    },
    "storage_free_space": {
        "STORAGE_CAPACITY_UNVERIFIED": PreflightStatus.NOT_VERIFIED,
        "STORAGE_SPACE_BELOW_CRITICAL_THRESHOLD": PreflightStatus.FAIL,
        "STATE_OR_LOG_SPACE_EXHAUSTED": PreflightStatus.FAIL,
        "STATE_OR_LOG_LOW_HEADROOM_UNVERIFIED": PreflightStatus.NOT_VERIFIED,
        "FILESYSTEM_INODES_LOW_HEADROOM_UNVERIFIED": PreflightStatus.NOT_VERIFIED,
        "FILESYSTEM_INODES_EXHAUSTED": PreflightStatus.FAIL,
        "CACHE_SPACE_BELOW_WARNING_THRESHOLD": PreflightStatus.NOT_VERIFIED,
        "STORAGE_MOUNT_OR_POLICY_UNVERIFIED": PreflightStatus.NOT_VERIFIED,
        "CURRENT_STORAGE_SPACE_OBSERVED_ONLY": PreflightStatus.PASS,
    },
    "listen_port_conflicts": {
        "HTTPS_PORT_ALREADY_LISTENING": PreflightStatus.FAIL,
        "LISTEN_PORT_INVENTORY_INCOMPLETE": PreflightStatus.NOT_VERIFIED,
        "HTTPS_PORT_NOT_OBSERVED_IN_PROC_SNAPSHOT": PreflightStatus.PASS,
    },
    "nginx_native_binary": {
        "NGINX_EXECUTABLE_MISSING": PreflightStatus.FAIL,
        "NGINX_EXECUTABLE_ACCESS_UNVERIFIED": PreflightStatus.NOT_VERIFIED,
        "NGINX_EXECUTABLE_OBSERVED_ONLY": PreflightStatus.PASS,
    },
    "nginx_managed_include_collision": {
        "NGINX_INCLUDE_PARENT_UNSAFE": PreflightStatus.FAIL,
        "NGINX_INCLUDE_PARENT_ACCESS_UNVERIFIED": PreflightStatus.NOT_VERIFIED,
        "EXISTING_INCLUDE_REQUIRES_OWNERSHIP_PROOF": PreflightStatus.FAIL,
        "MANAGED_INCLUDE_ACCESS_UNVERIFIED": PreflightStatus.NOT_VERIFIED,
        "NEW_MANAGED_INCLUDE_NOT_PRESENT": PreflightStatus.PASS,
    },
    "systemd_binary": {
        "SYSTEMD_CLIENT_MISSING": PreflightStatus.FAIL,
        "SYSTEMD_CLIENT_ACCESS_UNVERIFIED": PreflightStatus.NOT_VERIFIED,
        "SYSTEMD_CLIENT_OBSERVED_ONLY": PreflightStatus.PASS,
    },
    "systemd_pid1_observation": {
        "SYSTEMD_PID1_NOT_VERIFIED": PreflightStatus.NOT_VERIFIED,
        "SYSTEMD_PID1_OBSERVED_ONLY": PreflightStatus.PASS,
        "SYSTEMD_NATIVE_PID1_NOT_OBSERVED": PreflightStatus.FAIL,
    },
    "selinux_kernel_mode": {
        "SELINUX_KERNEL_MODE_UNAVAILABLE": PreflightStatus.NOT_VERIFIED,
        "DEBIAN_SELINUX_MODE_NOT_REQUIRED": PreflightStatus.NOT_VERIFIED,
        "SELINUX_ENFORCING_KERNEL_OBSERVED_ONLY": PreflightStatus.PASS,
        "ALMALINUX_SELINUX_NOT_ENFORCING": PreflightStatus.FAIL,
        "DEBIAN_SELINUX_PERMISSIVE_OBSERVED": PreflightStatus.NOT_VERIFIED,
        "SELINUX_KERNEL_MODE_UNRECOGNIZED": PreflightStatus.NOT_VERIFIED,
    },
}


def assess_deployment_host(
    facts: NativeHostFacts, probes: HostProbeResults, *,
    intent: Literal["inspect", "install"] = "inspect"
) -> NativePreflightReport:
    """Pure assembly. Unknown/unsupported OS can never inherit probe PASS."""
    baseline = assess_native_host(facts, intent=intent)
    os_supported = any(
        c.name == "supported_os_and_python" and c.status is PreflightStatus.PASS
        for c in baseline.checks
    )
    if not os_supported:
        return baseline
    if (type(probes) is not HostProbeResults or type(probes.checks) is not tuple
            or len(probes.checks) != len(_PROBE_CODES)
            or any(type(c) is not PreflightCheck or type(c.status) is not PreflightStatus
                   or type(c.name) is not str or type(c.code) is not str
                   or _PROBE_CODES.get(c.name, {}).get(c.code) is not c.status
                   for c in probes.checks)):
        raise ValueError("invalid or incomplete sanitized host observations")
    probe_names = [item.name for item in probes.checks]
    if len(set(probe_names)) != len(probe_names) or set(probe_names) != set(_PROBE_CODES):
        raise ValueError("missing, duplicate or unexpected host observations")
    # Only the port inventory replaces a baseline NOT VERIFIED marker. Other
    # readiness gates stay unverified regardless of injected observations.
    replaces = {"listen_port_conflicts"}
    names = {item.name for item in baseline.checks}
    if any(item.name in names and item.name not in replaces for item in probes.checks):
        raise ValueError("host observation overwrites protected readiness gate")
    merged = tuple(c for c in baseline.checks if c.name not in probe_names) + probes.checks
    return NativePreflightReport(merged)


def inspect_deployment_host(
    document: dict, *, intent: Literal["inspect", "install"] = "inspect"
) -> NativePreflightReport:
    """Read-only, noninteractive assessment of a validated deployment request.

    No package commands, network I/O, socket binds, directory creation, NGINX
    command or systemd/SELinux modification. Local findings are non-authorizing.
    """
    valid = validate_install_document(document, for_apply=False)
    facts = capture_native_host_facts()
    baseline = assess_native_host(facts, intent=intent)
    if any(c.name == "supported_os_and_python" and c.status is PreflightStatus.FAIL
           for c in baseline.checks):
        return baseline
    from repocache.server_install_v1 import validate_os_identity
    system = validate_os_identity(facts.os_release, facts.python_version)
    settings = valid["deployment"]
    spec = HostInspectionSpec(
        bind_address=settings["listen"]["bind_address"],
        https_port=settings["listen"]["https_port"],
        state_root=settings["paths"]["state_root"],
        cache_root=settings["paths"]["cache_root"],
        log_root=settings["paths"]["log_root"],
        generated_include=settings["paths"]["generated_include"],
        warning_free_bytes=settings["cache_policy"]["disk_pressure"]["warning_free_bytes"],
        critical_free_bytes=settings["cache_policy"]["disk_pressure"]["critical_free_bytes"],
    )
    return assess_deployment_host(facts, _capture_host_probes(system, spec), intent=intent)
