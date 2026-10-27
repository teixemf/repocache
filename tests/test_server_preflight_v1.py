"""Read-only native host preflight scaffold tests (#26).

These fixture tests do not establish native booted systemd or SELinux enforcing
acceptance, and do not grant authorization to install anything.
"""
from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

from repocache.server_install_v1 import InstallInputError
from repocache import server_preflight_v1 as native
from repocache.server_preflight_v1 import (
    NativeHostFacts, PreflightStatus, assess_native_host,
    capture_native_host_facts, inspect_native_host,
)

DEBIAN = "ID=debian\nVERSION_ID=13\n"
ALMA = 'ID="almalinux"\nVERSION_ID="10.1"\n'


def facts(**values) -> NativeHostFacts:
    defaults = dict(
        os_release=DEBIAN,
        python_version=(3, 13),
        machine="x86_64",
        euid=1000,
        native_manager_visible=True,
        running_in_venv=False,
    )
    defaults.update(values)
    return NativeHostFacts(**defaults)


def status(report, name: str) -> PreflightStatus:
    return next(item.status for item in report.checks if item.name == name)


@pytest.mark.parametrize("release,python", [
    (DEBIAN, (3, 13)),
    (ALMA, (3, 12)),
    ("ID=debian\nVERSION_ID=13.1\n", (3, 13)),
    ("ID=almalinux\nVERSION_ID=10.0\n", (3, 12)),
])
def test_supported_identity_fixture_only(release, python):
    report = assess_native_host(facts(os_release=release, python_version=python))
    assert status(report, "supported_os_and_python") is PreflightStatus.PASS
    assert report.authorizes_installation is False
    assert report.all_verified is False


@pytest.mark.parametrize("release,python", [
    ("ID=debian\nVERSION_ID=12\n", (3, 13)),
    ("ID=almalinux\nVERSION_ID=9\n", (3, 12)),
    ("ID=ubuntu\nVERSION_ID=24.04\n", (3, 12)),
    (DEBIAN, (3, 12)),
    (ALMA, (3, 13)),
    ("ID=debian\nVERSION_ID=13beta\n", (3, 13)),
    ("VERSION_ID=13\n", (3, 13)),
])
def test_unsupported_identity_refused_before_native_action(release, python):
    report = assess_native_host(facts(os_release=release, python_version=python))
    assert status(report, "supported_os_and_python") is PreflightStatus.FAIL
    assert report.authorizes_installation is False
    assert status(report, "native_package_manager_binary") is PreflightStatus.NOT_VERIFIED


def test_inspection_is_allowed_without_root_but_install_intent_requires_root():
    item = facts(euid=1000)
    inspect = assess_native_host(item, intent="inspect")
    intended = assess_native_host(item, intent="install")
    assert status(inspect, "effective_uid") is PreflightStatus.PASS
    assert status(intended, "effective_uid") is PreflightStatus.FAIL
    assert intended.has_failures is True
    assert intended.authorizes_installation is False


def test_root_observation_is_not_root_install_authorization():
    report = assess_native_host(facts(euid=0), intent="install")
    assert status(report, "effective_uid") is PreflightStatus.PASS
    assert not report.all_verified
    assert not report.authorizes_installation


def test_absent_native_manager_is_failure():
    report = assess_native_host(facts(native_manager_visible=False))
    assert status(report, "native_package_manager_binary") is PreflightStatus.FAIL
    assert not report.authorizes_installation


def test_missing_manager_observation_remains_unverified():
    report = assess_native_host(facts(native_manager_visible=None))
    assert status(report, "native_package_manager_binary") is PreflightStatus.NOT_VERIFIED


def test_venv_is_not_accepted_as_native_python_provenance():
    report = assess_native_host(facts(running_in_venv=True))
    assert status(report, "python_environment") is PreflightStatus.NOT_VERIFIED


def test_unknown_architecture_is_not_silently_accepted():
    report = assess_native_host(facts(machine="x86_64"))
    assert status(report, "architecture_identity") is PreflightStatus.PASS
    assert status(report, "architecture_supported") is PreflightStatus.NOT_VERIFIED
    report = assess_native_host(facts(machine="../amd64"))
    assert status(report, "architecture_identity") is PreflightStatus.FAIL


def test_systemd_and_selinux_are_never_claimed_verified():
    for release, py in [(DEBIAN, (3, 13)), (ALMA, (3, 12))]:
        for intent in ("install", "inspect"):
            report = assess_native_host(
                facts(os_release=release, python_version=py, euid=0),
                intent=intent,
            )
            assert status(report, "systemd_native_runtime") is PreflightStatus.NOT_VERIFIED
            assert status(report, "selinux_enforcing_native") is PreflightStatus.NOT_VERIFIED
            assert status(report, "nginx_ownership_and_features") is PreflightStatus.NOT_VERIFIED
            assert status(report, "listen_port_conflicts") is PreflightStatus.NOT_VERIFIED
            assert not report.all_verified
            assert not report.authorizes_installation


def test_no_unverified_critical_gates_are_omitted():
    report = assess_native_host(facts())
    required = {
        "architecture_supported", "python_package_origin",
        "native_package_availability", "storage_ownership_and_capacity",
        "listen_port_conflicts", "nginx_ownership_and_features",
        "tls_and_ca_trust", "systemd_native_runtime",
        "selinux_enforcing_native", "application_dependency_profile",
        "managed_state_and_rollback",
    }
    assert required.issubset({
        item.name for item in report.checks
        if item.status is PreflightStatus.NOT_VERIFIED
    })


def test_report_is_immutable_sanitized_deterministic():
    malicious = 'ID=debian\nVERSION_ID=13\nSECRET=very-private-data\n'
    item = facts(os_release=malicious)
    report = assess_native_host(item)
    assert report == assess_native_host(item)
    assert report.checks == tuple(report.checks)
    payload = json.dumps(report.to_dict())
    assert "very-private-data" not in payload
    assert "/etc/os-release" not in payload
    assert "can_install" in payload and '"can_install": false' in payload
    with pytest.raises((AttributeError, TypeError)):
        report.checks[0].code = "MUTATED"


@pytest.mark.parametrize("item", [
    facts(euid=-1),
    facts(euid=True),
    facts(machine=""),
    facts(machine="bad arch"),
    facts(running_in_venv=1),
])
def test_invalid_fact_types_are_not_reported_as_pass(item):
    assert assess_native_host(item).has_failures is True


def test_invalid_api_intent_rejected():
    with pytest.raises(ValueError):
        assess_native_host(facts(), intent="apply")
    with pytest.raises(ValueError):
        assess_native_host({"os_release": DEBIAN})


def test_bounded_read_rejects_oversize_and_nonregular(tmp_path):
    file = tmp_path / "os-release"
    file.write_bytes(b"x" * (native.MAX_OS_RELEASE_BYTES + 1))
    with pytest.raises(OSError):
        native._read_os_release(str(file))
    with pytest.raises(OSError):
        native._read_os_release(str(tmp_path))


def test_bounded_read_rejects_invalid_utf8_or_missing(tmp_path):
    file = tmp_path / "os-release"
    file.write_bytes(b"\xff")
    with pytest.raises(UnicodeError):
        native._read_os_release(str(file))
    with pytest.raises(OSError):
        native._read_os_release(str(tmp_path / "does-not-exist"))


def test_capture_is_local_only_without_mutation_or_subprocess(monkeypatch, tmp_path):
    release = tmp_path / "os-release"
    release.write_text(DEBIAN, encoding="utf-8")
    observed_paths = []
    original_reader = native._read_os_release
    def read_release(path):
        observed_paths.append(path)
        return original_reader(str(release))
    monkeypatch.setattr(native, "_read_os_release", read_release)
    monkeypatch.setattr(native, "sys", SimpleNamespace(
        version_info=SimpleNamespace(major=3, minor=13),
        prefix="/usr", base_prefix="/usr",
    ))
    monkeypatch.setattr(native.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(native.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(native, "_manager_exists", lambda system: system == "debian")

    import subprocess
    import socket

    def forbid(*_args, **_kwargs):
        raise AssertionError("Attempted prohibited service/network/system mutation")

    monkeypatch.setattr(subprocess, "run", forbid)
    monkeypatch.setattr(os, "system", forbid)
    monkeypatch.setattr(socket, "create_connection", forbid)
    snapshot = capture_native_host_facts()
    assert observed_paths == ["/etc/os-release"]
    assert snapshot.python_version == (3, 13)
    assert snapshot.native_manager_visible is True
    assert snapshot.euid == 1000
    report = assess_native_host(snapshot)
    assert status(report, "supported_os_and_python") is PreflightStatus.PASS
    assert report.authorizes_installation is False
    assert release.read_text() == DEBIAN


def test_current_host_inspection_without_system_activation(monkeypatch):
    monkeypatch.setattr(native, "capture_native_host_facts", lambda: facts())
    report = inspect_native_host()
    assert status(report, "supported_os_and_python") is PreflightStatus.PASS
    assert report.authorizes_installation is False


def test_manager_presence_only_checks_fixed_native_binary(monkeypatch):
    paths = []

    def stat_stub(path):
        paths.append(path)
        return SimpleNamespace(st_mode=0o100755)

    monkeypatch.setattr(native, "os", SimpleNamespace(stat=stat_stub))
    assert native._manager_exists("debian") is True
    assert native._manager_exists("almalinux") is True
    assert native._manager_exists("unknown") is None
    assert paths == ["/usr/bin/apt-get", "/usr/bin/dnf"]


def test_manager_permission_denied_does_not_claim_missing(monkeypatch):
    import errno
    def deny(_path):
        raise PermissionError(errno.EACCES, "denied")
    monkeypatch.setattr(native, "os", SimpleNamespace(stat=deny))
    assert native._manager_exists("debian") is None
    def absent(_path):
        raise FileNotFoundError(errno.ENOENT, "absent")
    monkeypatch.setattr(native, "os", SimpleNamespace(stat=absent))
    assert native._manager_exists("debian") is False


def test_os_release_short_reads_consume_entire_identity(monkeypatch):
    import stat
    chunks = iter([b"ID=debian\nVERSION_ID=13\n", b"ID=almalinux\n", b""])
    calls = []
    def fake_read(fd, count):
        calls.append((fd, count))
        return next(chunks)
    fake_os = SimpleNamespace(
        O_RDONLY=0, O_CLOEXEC=0, O_NONBLOCK=0,
        open=lambda *_: 42, read=fake_read, close=lambda _: None,
        fstat=lambda _: SimpleNamespace(st_mode=stat.S_IFREG | 0o444),
    )
    monkeypatch.setattr(native, "os", fake_os)
    full = native._read_os_release("/etc/os-release")
    assert full.splitlines() == ["ID=debian", "VERSION_ID=13", "ID=almalinux"] and len(calls) == 3
    result = assess_native_host(facts(os_release=full))
    assert status(result, "supported_os_and_python") is PreflightStatus.FAIL


def test_partial_report_never_claims_complete_readiness():
    assert native.NativePreflightReport(()).all_verified is False
    assert native.NativePreflightReport((
        native.PreflightCheck("effective_uid", PreflightStatus.PASS,
                              "ROOT_EFFECTIVE_UID_OBSERVED_ONLY"),
    )).all_verified is False
