"""Read-only host observation tests; fixtures are NOT native acceptance (#26)."""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from repocache import server_host_checks_v1 as host
from repocache.server_preflight_v1 import NativeHostFacts, PreflightStatus


def fact(release="ID=debian\nVERSION_ID=13\n", py=(3,13)):
    return NativeHostFacts(release, py, "x86_64", 1000, True, False)


def spec(**override):
    base = dict(bind_address="127.0.0.1", https_port=4443, state_root="/var/lib/repocache/server",
                cache_root="/var/cache/nginx/repocache-managed", log_root="/var/log/nginx/repocache-managed",
                generated_include="/etc/nginx/conf.d/repocache-managed.conf",
                warning_free_bytes=2000, critical_free_bytes=1000)
    base.update(override)
    return host.HostInspectionSpec(**base)


def byname(checks, name):
    return next(c for c in checks if c.name == name)


def proc(*ports):
    lines = ["  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"]
    for i, (port, state) in enumerate(ports):
        lines.append(f" {i}: 0100007F:{port:04X} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000 0 0 10000 1")
    return ("\n".join(lines)+"\n").encode()


def test_kernel_port_snapshot_busy_free_and_other_states(monkeypatch):
    monkeypatch.setattr(host, "_read_fixed", lambda path, maxbytes: proc((4443,"0A")) if path.endswith("/tcp") else proc())
    assert host._port_check(spec()).status is PreflightStatus.FAIL
    monkeypatch.setattr(host, "_read_fixed", lambda path, maxbytes: proc((4443,"01")))
    assert host._port_check(spec()).status is PreflightStatus.PASS
    monkeypatch.setattr(host, "_read_fixed", lambda path, maxbytes: proc((4444,"0A")))
    assert host._port_check(spec()).status is PreflightStatus.PASS


def test_ipv6_listener_and_partial_kernel_visibility_fail_closed(monkeypatch):
    def partial(path, maxbytes):
        if path.endswith("tcp6"): raise PermissionError("kernel")
        return proc()
    monkeypatch.setattr(host, "_read_fixed", partial)
    assert host._port_check(spec()).status is PreflightStatus.NOT_VERIFIED
    monkeypatch.setattr(host, "_read_fixed", lambda path, maxbytes: proc((4443,"0A")) if path.endswith("tcp6") else proc())
    assert host._port_check(spec()).status is PreflightStatus.FAIL
    monkeypatch.setattr(host, "_read_fixed", lambda path, maxbytes: b"garbage")
    assert host._port_check(spec()).status is PreflightStatus.NOT_VERIFIED


def test_proc_parser_limits_and_rejects_malformed_rows():
    assert host._parse_tcp_listeners(proc((4443,"0A"))) == {4443}
    assert host._parse_tcp_listeners(proc((4443,"01"))) == set()
    with pytest.raises(ValueError): host._parse_tcp_listeners(b"garbage")
    with pytest.raises(ValueError): host._parse_tcp_listeners(proc()+b"evil malformed record\n")


def test_read_only_bounded_regular_file_validation(tmp_path):
    file = tmp_path/"file"
    file.write_bytes(b"something")
    assert host._read_fixed(str(file), 9) == b"something"
    with pytest.raises(OSError): host._read_fixed(str(file), 2)
    with pytest.raises(OSError): host._read_fixed(str(tmp_path), 10)


def test_paths_refuse_symlink_and_foreign_ownership(tmp_path):
    target = tmp_path/"target"
    target.mkdir()
    link = tmp_path/"link"
    link.symlink_to(target, target_is_directory=True)
    assert host._safe_existing_ancestor(str(link/"child"))[1] == "UNSAFE_WORLD_WRITABLE_PATH" or host._safe_existing_ancestor(str(link/"child"))[1] == "UNSAFE_STORAGE_PATH"
    # Even ordinary missing/existing descendants never prove REPOCACHE ownership.
    assert host._safe_existing_ancestor("/etc/repocache/absent-child")[1] in ("PATH_PARENT_OBSERVED_ONLY", "STORAGE_PATH_ACCESS_UNVERIFIED", "UNSAFE_STORAGE_PATH")


def test_capacity_critical_warning_and_unknown(monkeypatch):
    monkeypatch.setattr(host, "_safe_existing_ancestor", lambda path: ("/", "PATH_PARENT_OBSERVED_ONLY"))
    blocks = [1000]
    monkeypatch.setattr(host.os, "statvfs", lambda path: SimpleNamespace(f_bavail=blocks[0], f_frsize=1))
    assert byname(host._storage_checks(spec()), "storage_free_space").status is PreflightStatus.NOT_VERIFIED
    blocks[0] = 500
    assert byname(host._storage_checks(spec()), "storage_free_space").status is PreflightStatus.FAIL
    blocks[0] = 2500
    assert byname(host._storage_checks(spec()), "storage_free_space").status is PreflightStatus.PASS
    assert byname(host._storage_checks(spec()), "storage_path_safety").status is PreflightStatus.NOT_VERIFIED
    monkeypatch.setattr(host, "_safe_existing_ancestor", lambda path: (None, "STORAGE_PATH_ACCESS_UNVERIFIED"))
    assert byname(host._storage_checks(spec()), "storage_free_space").status is PreflightStatus.NOT_VERIFIED


def test_include_collision_never_adopts_existing_file(tmp_path, monkeypatch):
    incl = tmp_path/"generated.conf"
    incl.write_text("# unrelated vhost; do not overwrite\n")
    monkeypatch.setattr(host, "_executable_at", lambda x: True)
    monkeypatch.setattr(host, "_safe_existing_ancestor", lambda path: ("/", "PATH_PARENT_OBSERVED_ONLY"))
    checks = host._nginx_checks(spec(generated_include=str(incl)))
    assert byname(checks,"nginx_managed_include_collision").status is PreflightStatus.FAIL
    assert incl.read_text() == "# unrelated vhost; do not overwrite\n"
    incl.unlink()
    checks = host._nginx_checks(spec(generated_include=str(incl)))
    assert byname(checks,"nginx_managed_include_collision").status is PreflightStatus.PASS


def test_package_executables_presence_is_not_package_provenance(monkeypatch):
    monkeypatch.setattr(host,"_executable_at",lambda p: False if p.endswith("nginx") else True)
    assert host._package_binary_check("debian").status is PreflightStatus.FAIL
    monkeypatch.setattr(host,"_executable_at",lambda p: None if p.endswith("nginx") else True)
    assert host._package_binary_check("almalinux").status is PreflightStatus.NOT_VERIFIED
    monkeypatch.setattr(host,"_executable_at",lambda p: True)
    assert host._package_binary_check("almalinux").status is PreflightStatus.PASS


def test_systemd_pid1_positive_and_missing_runtime(monkeypatch):
    monkeypatch.setattr(host,"_executable_at",lambda x: True)
    monkeypatch.setattr(host,"_read_fixed",lambda x,n: b"systemd\n")
    monkeypatch.setattr(host.os,"stat",lambda x: SimpleNamespace(st_mode=0o040755))
    assert byname(host._systemd_checks(), "systemd_pid1_observation").status is PreflightStatus.PASS
    monkeypatch.setattr(host,"_read_fixed",lambda x,n: b"python\n")
    assert byname(host._systemd_checks(), "systemd_pid1_observation").status is PreflightStatus.FAIL
    monkeypatch.setattr(host,"_read_fixed",lambda x,n: (_ for _ in ()).throw(PermissionError()))
    assert byname(host._systemd_checks(), "systemd_pid1_observation").status is PreflightStatus.NOT_VERIFIED


def test_selinux_enforcing_permissive_unavailable(monkeypatch):
    monkeypatch.setattr(host,"_read_fixed",lambda x,n: b"1\n")
    assert host._selinux_check("almalinux").status is PreflightStatus.PASS
    monkeypatch.setattr(host,"_read_fixed",lambda x,n: b"0\n")
    assert host._selinux_check("almalinux").status is PreflightStatus.FAIL
    assert host._selinux_check("debian").status is PreflightStatus.NOT_VERIFIED
    monkeypatch.setattr(host,"_read_fixed",lambda x,n: (_ for _ in ()).throw(FileNotFoundError()))
    assert host._selinux_check("almalinux").status is PreflightStatus.NOT_VERIFIED


def test_sanitized_report_has_no_authorization_or_secret_leak():
    fake = host.HostProbeResults((
        host._check("listen_port_conflicts",PreflightStatus.FAIL,"HTTPS_PORT_ALREADY_LISTENING"),
        host._check("storage_free_space",PreflightStatus.FAIL,"STORAGE_SPACE_BELOW_CRITICAL_THRESHOLD"),
    ))
    report = host.assess_deployment_host(fact(),fake,intent="install")
    assert byname(report.checks,"listen_port_conflicts").status is PreflightStatus.FAIL
    assert byname(report.checks,"nginx_ownership_and_features").status is PreflightStatus.NOT_VERIFIED
    assert not report.authorizes_installation and not report.all_verified
    assert "can_install" in report.to_dict()
    assert "/var" not in json.dumps(report.to_dict())
    with pytest.raises(ValueError):
        host.assess_deployment_host(fact(),host.HostProbeResults((
            host._check("nginx_ownership_and_features",PreflightStatus.PASS,"FAKE_CERTIFIED"),)))
    assert byname(host.assess_deployment_host(fact("ID=debian\nVERSION_ID=12\n"),fake).checks,
                  "supported_os_and_python").status is PreflightStatus.FAIL


def test_capture_skips_host_probes_on_unsupported_os_and_retains_false_auth(monkeypatch):
    doc = json.loads((Path(__file__).parents[1]/"docs/examples/server-install-v1.json").read_text())
    monkeypatch.setattr(host,"capture_native_host_facts",lambda:fact("ID=debian\nVERSION_ID=12\n"))
    monkeypatch.setattr(host,"_capture_host_probes",lambda *_: (_ for _ in ()).throw(AssertionError("unsupported OS probed")))
    result=host.inspect_deployment_host(doc)
    assert result.has_failures
    assert not result.authorizes_installation


def test_inspect_uses_strict_validated_document_and_report(monkeypatch):
    doc = json.loads((Path(__file__).parents[1]/"docs/examples/server-install-v1.json").read_text())
    monkeypatch.setattr(host,"capture_native_host_facts",lambda:fact())
    seen=[]
    def observe(system,settings):
        seen.append((system,settings.https_port,settings.generated_include))
        return host.HostProbeResults((host._check("listen_port_conflicts",PreflightStatus.FAIL,"HTTPS_PORT_ALREADY_LISTENING"),))
    monkeypatch.setattr(host,"_capture_host_probes",observe)
    result=host.inspect_deployment_host(doc)
    assert seen == [("debian",443,"/etc/nginx/conf.d/repocache-managed.conf")]
    assert byname(result.checks,"listen_port_conflicts").status is PreflightStatus.FAIL
    assert not result.authorizes_installation
    assert "example" not in json.dumps(result.to_dict())
