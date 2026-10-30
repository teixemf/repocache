"""Read-only *partial* native host preflight for server provisioning (#26).

This module reports a bounded set of facts and an explicit NOT_VERIFIED state
for all remaining host safety gates. It is NOT a privileged authorization,
installation readiness certificate, service manager, or installer.

No subprocesses, package transactions, DNS/network probes, writes or CLI wiring.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Literal, Mapping
import errno
import os
import platform
import re
import stat
import sys
from repocache.server_install_v1 import InstallInputError, validate_os_identity

MAX_OS_RELEASE_BYTES = 16 * 1024
_NATIVE_MANAGER = {"debian": "/usr/bin/apt-get", "almalinux": "/usr/bin/dnf"}
_NOT_VERIFIED = (
    ("architecture_supported", "NATIVE_ARCH_POLICY_UNVERIFIED"),
    ("python_package_origin", "OS_PYTHON_PROVENANCE_UNVERIFIED"),
    ("native_package_availability", "NATIVE_PACKAGE_METADATA_UNVERIFIED"),
    ("storage_ownership_and_capacity", "STORAGE_OWNERSHIP_CAPACITY_UNVERIFIED"),
    ("listen_port_conflicts", "LISTENER_OWNERSHIP_UNVERIFIED"),
    ("nginx_ownership_and_features", "NGINX_OWNERSHIP_MODULES_UNVERIFIED"),
    ("tls_and_ca_trust", "TLS_CA_TRUST_UNVERIFIED"),
    ("systemd_native_runtime", "SYSTEMD_NATIVE_RUNTIME_UNVERIFIED"),
    ("selinux_enforcing_native", "SELINUX_NATIVE_ENFORCING_UNVERIFIED"),
    ("application_dependency_profile", "SIGNED_DEPENDENCY_PROFILE_UNVERIFIED"),
    ("managed_state_and_rollback", "PROTECTED_STATE_ROLLBACK_UNVERIFIED"),
)


# Authoritative allowed diagnostic triples for both the public report
# and the host-probe validation boundary. Code allowlisting alone is unsafe.
class PreflightStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_VERIFIED = "NOT VERIFIED"


def _freeze_diagnostic_registry(
    entries: Mapping[str, Mapping[str, PreflightStatus]],
) -> Mapping[str, Mapping[str, PreflightStatus]]:
    """Copy and freeze both levels, leaving no mutable backing-map aliases."""
    return MappingProxyType({
        name: MappingProxyType(dict(codes))
        for name, codes in entries.items()
    })


_BASE_CODES: Mapping[str, Mapping[str, PreflightStatus]] = {
    "supported_os_and_python": {
        "SUPPORTED_OS_AND_PYTHON_VERSION": PreflightStatus.PASS,
        "UNSUPPORTED_OS_OR_PYTHON": PreflightStatus.FAIL,
    },
    "architecture_identity": {
        "ARCHITECTURE_IDENTITY_OBSERVED": PreflightStatus.PASS,
        "INVALID_ARCHITECTURE_IDENTITY": PreflightStatus.FAIL,
    },
    "effective_uid": {
        "INVALID_EFFECTIVE_UID": PreflightStatus.FAIL,
        "PRIVILEGED_INSTALL_REQUIRES_ROOT": PreflightStatus.FAIL,
        "ROOT_EFFECTIVE_UID_OBSERVED_ONLY": PreflightStatus.PASS,
        "READ_ONLY_INSPECTION_NO_ROOT_REQUIRED": PreflightStatus.PASS,
    },
    "native_package_manager_binary": {
        "NATIVE_MANAGER_PRESENCE_UNVERIFIED": PreflightStatus.NOT_VERIFIED,
        "INVALID_PACKAGE_MANAGER_OBSERVATION": PreflightStatus.FAIL,
        "NATIVE_PACKAGE_MANAGER_MISSING": PreflightStatus.FAIL,
        "NATIVE_PACKAGE_MANAGER_FILE_OBSERVED": PreflightStatus.PASS,
    },
    "python_environment": {
        "INVALID_PYTHON_ENVIRONMENT_OBSERVATION": PreflightStatus.FAIL,
        "VENV_PYTHON_NOT_NATIVE_PROVENANCE": PreflightStatus.NOT_VERIFIED,
        "NO_ACTIVE_VENV_OBSERVED": PreflightStatus.PASS,
    },
}
for _name, _code in _NOT_VERIFIED:
    _BASE_CODES.setdefault(_name, {})[_code] = PreflightStatus.NOT_VERIFIED
_BASE_CODES = _freeze_diagnostic_registry(_BASE_CODES)


# Keep the host-probe code/status registry here to avoid circular imports.
# The host-probe assembly imports this very same mapping.
_PROBE_CODES: Mapping[str, Mapping[str, PreflightStatus]] = {
    "tls_reference_files": {
        "TLS_REFERENCE_PARENT_UNSAFE": PreflightStatus.FAIL,
        "TLS_REFERENCE_NONREGULAR": PreflightStatus.FAIL,
        "TLS_REFERENCE_WRITABLE_BY_OTHERS": PreflightStatus.FAIL,
        "TLS_PRIVATE_KEY_WORLD_READABLE": PreflightStatus.FAIL,
        "TLS_REFERENCE_ACCESS_UNVERIFIED": PreflightStatus.NOT_VERIFIED,
        "TLS_REFERENCE_FILE_MISSING": PreflightStatus.NOT_VERIFIED,
        "TLS_REFERENCE_SYMLINK_UNVERIFIED": PreflightStatus.NOT_VERIFIED,
        "TLS_PRIVATE_KEY_GROUP_TRUST_UNVERIFIED": PreflightStatus.NOT_VERIFIED,
        "TLS_REFERENCE_MODES_OBSERVED_ONLY": PreflightStatus.NOT_VERIFIED,
    },
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
_PROBE_CODES = _freeze_diagnostic_registry(_PROBE_CODES)

_REPORT_CHECK_CODES: Mapping[str, Mapping[str, PreflightStatus]] = {
    name: dict(codes) for name, codes in _BASE_CODES.items()
}
for _name, _codes in _PROBE_CODES.items():
    _target = _REPORT_CHECK_CODES.setdefault(_name, {})
    for _code, _status in _codes.items():
        if _code in _target and _target[_code] is not _status:
            raise RuntimeError("conflicting native preflight diagnostic mapping")
        _target[_code] = _status

# Diagnostic codes are globally unambiguous; fail on future accidental reuse.
_seen_code_names: dict[str, str] = {}
for _check_name, _codes in _REPORT_CHECK_CODES.items():
    for _code in _codes:
        if _code in _seen_code_names and _seen_code_names[_code] != _check_name:
            raise RuntimeError("native preflight diagnostic code reused across checks")
        _seen_code_names[_code] = _check_name

# Freeze only after assembling the complete registry, copying away mutable
# construction-time dictionaries and all inner maps. The host module imports
# the already-frozen probe mapping.
_REPORT_CHECK_CODES = _freeze_diagnostic_registry(_REPORT_CHECK_CODES)

# Backward-compatible inventory, generated from the authoritative triples.
_REPORT_CODES = frozenset(
    code for codes in _REPORT_CHECK_CODES.values() for code in codes
)


@dataclass(frozen=True)
class NativeHostFacts:
    """Observation only. Do not construct this from untrusted request JSON."""

    os_release: str
    python_version: tuple[int, int]
    machine: str
    euid: int
    native_manager_visible: bool | None
    running_in_venv: bool


@dataclass(frozen=True)
class PreflightCheck:
    name: str
    status: PreflightStatus
    code: str

    def to_dict(self) -> dict[str, str]:
        return {"check": self.name, "status": self.status.value, "code": self.code}


@dataclass(frozen=True)
class NativePreflightReport:
    checks: tuple[PreflightCheck, ...]

    def __post_init__(self) -> None:
        if (type(self.checks) is not tuple
                or any(type(c) is not PreflightCheck
                       or type(c.name) is not str or not re.fullmatch(
                           r"[a-z][a-z0-9_]{0,63}", c.name, re.ASCII)
                       or type(c.status) is not PreflightStatus
                       or type(c.code) is not str
                       or _REPORT_CHECK_CODES.get(c.name, {}).get(c.code) is not c.status
                       for c in self.checks)
                or len({c.name for c in self.checks}) != len(self.checks)):
            raise ValueError("invalid unsanitized native preflight report")

    @property
    def has_failures(self) -> bool:
        return any(c.status is PreflightStatus.FAIL for c in self.checks)

    @property
    def all_verified(self) -> bool:
        return False  # This API is always a partial observation, never a readiness certificate.

    @property
    def authorizes_installation(self) -> bool:
        # This API can never convey a privileged operation authorization,
        # even if future, separate code adds more observational checks.
        return False

    def to_dict(self) -> dict[str, object]:
        # No user-supplied values, OS-release details, paths or secrets logged.
        return {
            "kind": "repocache.server.native-preflight.partial",
            "can_install": False,
            "checks": [check.to_dict() for check in self.checks],
        }


def _add(checks: list[PreflightCheck], name: str,
         status: PreflightStatus, code: str) -> None:
    checks.append(PreflightCheck(name, status, code))


def assess_native_host(
    facts: NativeHostFacts, *, intent: Literal["inspect", "install"] = "inspect"
) -> NativePreflightReport:
    """Classify injected observations; no host access or mutation.

    'install' checks whether effective UID is root, but never grants permission
    to run as root. The complete native-host acceptance gates are deliberately
    NOT VERIFIED and installation is *always* unauthorized by this result.
    """
    if type(facts) is not NativeHostFacts or intent not in ("inspect", "install"):
        raise ValueError("invalid native preflight arguments")
    checks: list[PreflightCheck] = []
    system: str | None = None
    try:
        system = validate_os_identity(facts.os_release, facts.python_version)
    except (InstallInputError, TypeError, ValueError):
        _add(checks, "supported_os_and_python", PreflightStatus.FAIL,
             "UNSUPPORTED_OS_OR_PYTHON")
    else:
        _add(checks, "supported_os_and_python", PreflightStatus.PASS,
             "SUPPORTED_OS_AND_PYTHON_VERSION")

    if type(facts.machine) is not str or not re.fullmatch(
        r"[A-Za-z0-9_+-]{1,32}", facts.machine, re.ASCII
    ):
        _add(checks, "architecture_identity", PreflightStatus.FAIL,
             "INVALID_ARCHITECTURE_IDENTITY")
    else:
        _add(checks, "architecture_identity", PreflightStatus.PASS,
             "ARCHITECTURE_IDENTITY_OBSERVED")

    if type(facts.euid) is not int or facts.euid < 0:
        _add(checks, "effective_uid", PreflightStatus.FAIL,
             "INVALID_EFFECTIVE_UID")
    elif intent == "install" and facts.euid != 0:
        _add(checks, "effective_uid", PreflightStatus.FAIL,
             "PRIVILEGED_INSTALL_REQUIRES_ROOT")
    elif intent == "install":
        _add(checks, "effective_uid", PreflightStatus.PASS,
             "ROOT_EFFECTIVE_UID_OBSERVED_ONLY")
    else:
        _add(checks, "effective_uid", PreflightStatus.PASS,
             "READ_ONLY_INSPECTION_NO_ROOT_REQUIRED")

    if system is None or facts.native_manager_visible is None:
        _add(checks, "native_package_manager_binary", PreflightStatus.NOT_VERIFIED,
             "NATIVE_MANAGER_PRESENCE_UNVERIFIED")
    elif type(facts.native_manager_visible) is not bool:
        _add(checks, "native_package_manager_binary", PreflightStatus.FAIL,
             "INVALID_PACKAGE_MANAGER_OBSERVATION")
    elif not facts.native_manager_visible:
        _add(checks, "native_package_manager_binary", PreflightStatus.FAIL,
             "NATIVE_PACKAGE_MANAGER_MISSING")
    else:
        _add(checks, "native_package_manager_binary", PreflightStatus.PASS,
             "NATIVE_PACKAGE_MANAGER_FILE_OBSERVED")

    if type(facts.running_in_venv) is not bool:
        _add(checks, "python_environment", PreflightStatus.FAIL,
             "INVALID_PYTHON_ENVIRONMENT_OBSERVATION")
    elif facts.running_in_venv:
        _add(checks, "python_environment", PreflightStatus.NOT_VERIFIED,
             "VENV_PYTHON_NOT_NATIVE_PROVENANCE")
    else:
        _add(checks, "python_environment", PreflightStatus.PASS,
             "NO_ACTIVE_VENV_OBSERVED")

    for name, code in _NOT_VERIFIED:
        _add(checks, name, PreflightStatus.NOT_VERIFIED, code)
    return NativePreflightReport(tuple(checks))


def _read_os_release(path: str) -> str:
    """Bounded local read of an OS identity file; never write to it."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        first = os.fstat(fd)
        if not stat.S_ISREG(first.st_mode):
            raise OSError("os-release is not a regular file")
        # A descriptor identifies the opened inode even when /etc/os-release
        # is a distribution-managed symlink to /usr/lib/os-release.
        identity = lambda value: (
            value.st_dev, value.st_ino, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns,
        )
        chunks = []
        remaining = MAX_OS_RELEASE_BYTES + 1
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break  # Actual EOF; short reads are not proof of completeness.
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > MAX_OS_RELEASE_BYTES:
            raise OSError("os-release exceeds read limit")
        # Detect observable in-place edits and path replacement before
        # accepting a coherent snapshot. Metadata checks are NOT immunity
        # against all races or proof of the file's authentic origin.
        final = os.fstat(fd)
        path_now = os.stat(path)
        if (identity(first) != identity(final)
                or identity(first) != identity(path_now)
                or len(data) != first.st_size):
            raise OSError(errno.ESTALE, "os-release changed during observation")
        return data.decode("utf-8", "strict")
    finally:
        os.close(fd)


def _manager_exists(system: str | None) -> bool | None:
    if system is None:
        return None
    binary = _NATIVE_MANAGER.get(system)
    if binary is None:
        return None
    try:
        info = os.stat(binary)
    except FileNotFoundError:
        return False
    except OSError:
        return None  # Permission/IO errors cannot prove absence.
    return stat.S_ISREG(info.st_mode) and bool(info.st_mode & 0o111)


def capture_native_host_facts() -> NativeHostFacts:
    """Read only the fixed host OS identity, never a caller-provided path.

    This API deliberately accepts no path override from deployment data.
    Unit tests inject observations through the pure assess_native_host API.
    """
    try:
        release_text = _read_os_release("/etc/os-release")
    except (OSError, UnicodeError):
        raise InstallInputError("native preflight: OS identity unreadable") from None

    py_ver = (sys.version_info.major, sys.version_info.minor)
    system = None
    try:
        system = validate_os_identity(release_text, py_ver)
    except InstallInputError:
        pass
    return NativeHostFacts(
        os_release=release_text,
        python_version=py_ver,
        machine=platform.machine(),
        euid=os.geteuid(),
        native_manager_visible=_manager_exists(system),
        running_in_venv=(sys.prefix != sys.base_prefix),
    )


def inspect_native_host() -> NativePreflightReport:
    """Read-only partial observation; never a substitute for native tests."""
    return assess_native_host(capture_native_host_facts(), intent="inspect")
