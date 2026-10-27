"""Read-only *partial* native host preflight for server provisioning (#26).

This module reports a bounded set of facts and an explicit NOT_VERIFIED state
for all remaining host safety gates. It is NOT a privileged authorization,
installation readiness certificate, service manager, or installer.

No subprocesses, package transactions, DNS/network probes, writes or CLI wiring.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import errno
import os
import platform
import re
import stat
import sys
from typing import Literal

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


# Report serialization accepts only audited, static symbolic diagnostics.
# Add new codes here and to their probe status map when extending preflight.
_REPORT_CODES = frozenset((
    "ALMALINUX_SELINUX_NOT_ENFORCING",
    "ARCHITECTURE_IDENTITY_OBSERVED",
    "CACHE_SPACE_BELOW_WARNING_THRESHOLD",
    "CURRENT_STORAGE_SPACE_OBSERVED_ONLY",
    "DEBIAN_SELINUX_MODE_NOT_REQUIRED",
    "DEBIAN_SELINUX_PERMISSIVE_OBSERVED",
    "EXISTING_INCLUDE_REQUIRES_OWNERSHIP_PROOF",
    "FILESYSTEM_INODES_EXHAUSTED",
    "FILESYSTEM_INODES_LOW_HEADROOM_UNVERIFIED",
    "HTTPS_PORT_ALREADY_LISTENING",
    "HTTPS_PORT_NOT_OBSERVED_IN_PROC_SNAPSHOT",
    "INVALID_ARCHITECTURE_IDENTITY",
    "INVALID_EFFECTIVE_UID",
    "INVALID_PACKAGE_MANAGER_OBSERVATION",
    "INVALID_PYTHON_ENVIRONMENT_OBSERVATION",
    "LISTENER_OWNERSHIP_UNVERIFIED",
    "LISTEN_PORT_INVENTORY_INCOMPLETE",
    "MANAGED_INCLUDE_ACCESS_UNVERIFIED",
    "NATIVE_ARCH_POLICY_UNVERIFIED",
    "NATIVE_EXECUTABLE_ACCESS_UNVERIFIED",
    "NATIVE_MANAGER_PRESENCE_UNVERIFIED",
    "NATIVE_PACKAGE_MANAGER_FILE_OBSERVED",
    "NATIVE_PACKAGE_MANAGER_MISSING",
    "NATIVE_PACKAGE_METADATA_UNVERIFIED",
    "NEW_MANAGED_INCLUDE_NOT_PRESENT",
    "NGINX_EXECUTABLE_ACCESS_UNVERIFIED",
    "NGINX_EXECUTABLE_MISSING",
    "NGINX_EXECUTABLE_OBSERVED_ONLY",
    "NGINX_INCLUDE_PARENT_ACCESS_UNVERIFIED",
    "NGINX_INCLUDE_PARENT_UNSAFE",
    "NGINX_OWNERSHIP_MODULES_UNVERIFIED",
    "NO_ACTIVE_VENV_OBSERVED",
    "OS_PYTHON_PROVENANCE_UNVERIFIED",
    "PRIVILEGED_INSTALL_REQUIRES_ROOT",
    "PROTECTED_STATE_ROLLBACK_UNVERIFIED",
    "READ_ONLY_INSPECTION_NO_ROOT_REQUIRED",
    "REQUIRED_NATIVE_EXECUTABLES_OBSERVED_ONLY",
    "REQUIRED_NATIVE_EXECUTABLE_MISSING",
    "ROOT_EFFECTIVE_UID_OBSERVED_ONLY",
    "SELINUX_ENFORCING_KERNEL_OBSERVED_ONLY",
    "SELINUX_KERNEL_MODE_UNAVAILABLE",
    "SELINUX_KERNEL_MODE_UNRECOGNIZED",
    "SELINUX_NATIVE_ENFORCING_UNVERIFIED",
    "SIGNED_DEPENDENCY_PROFILE_UNVERIFIED",
    "STATE_OR_LOG_LOW_HEADROOM_UNVERIFIED",
    "STATE_OR_LOG_SPACE_EXHAUSTED",
    "STORAGE_CAPACITY_UNVERIFIED",
    "STORAGE_MOUNT_OR_POLICY_UNVERIFIED",
    "STORAGE_OWNERSHIP_CAPACITY_UNVERIFIED",
    "STORAGE_OWNERSHIP_MANIFEST_UNVERIFIED",
    "STORAGE_PATH_ACCESS_UNVERIFIED",
    "STORAGE_PATH_UNSAFE_OR_CONFLICTING",
    "STORAGE_SPACE_BELOW_CRITICAL_THRESHOLD",
    "SUPPORTED_OS_AND_PYTHON_VERSION",
    "SYSTEMD_CLIENT_ACCESS_UNVERIFIED",
    "SYSTEMD_CLIENT_MISSING",
    "SYSTEMD_CLIENT_OBSERVED_ONLY",
    "SYSTEMD_NATIVE_PID1_NOT_OBSERVED",
    "SYSTEMD_NATIVE_RUNTIME_UNVERIFIED",
    "SYSTEMD_PID1_NOT_VERIFIED",
    "SYSTEMD_PID1_OBSERVED_ONLY",
    "TLS_CA_TRUST_UNVERIFIED",
    "UNSUPPORTED_OS_OR_PYTHON",
    "VENV_PYTHON_NOT_NATIVE_PROVENANCE",
))


class PreflightStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_VERIFIED = "NOT VERIFIED"


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
                       or type(c.code) is not str or c.code not in _REPORT_CODES
                       for c in self.checks)):
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
