"""Read-only *partial* native host preflight for server provisioning (#26).

This module reports a bounded set of facts and an explicit NOT_VERIFIED state
for all remaining host safety gates. It is NOT a privileged authorization,
installation readiness certificate, service manager, or installer.

No subprocesses, package transactions, DNS/network probes, writes or CLI wiring.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
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

    @property
    def has_failures(self) -> bool:
        return any(c.status is PreflightStatus.FAIL for c in self.checks)

    @property
    def all_verified(self) -> bool:
        return all(c.status is PreflightStatus.PASS for c in self.checks)

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
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("os-release is not a regular file")
        data = os.read(fd, MAX_OS_RELEASE_BYTES + 1)
        if len(data) > MAX_OS_RELEASE_BYTES:
            raise OSError("os-release exceeds read limit")
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
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and bool(info.st_mode & 0o111)


def capture_native_host_facts(*, os_release_path: str = "/etc/os-release") -> NativeHostFacts:
    """Collect minimal read-only facts from the current process and host.

    The path override exists only for isolated fixtures. Do not pass it from
    unauthenticated deployment JSON or treat observations as permission.
    """
    try:
        release_text = _read_os_release(os_release_path)
    except (OSError, UnicodeError) as exc:
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
