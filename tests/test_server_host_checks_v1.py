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


def complete_probes(**overrides):
    checks = []
    for name, pairs in host._PROBE_CODES.items():
        code, state = next(
            ((code, status) for code, status in pairs.items()
             if status is PreflightStatus.NOT_VERIFIED), next(iter(pairs.items()))
        )
        if name in overrides:
            state, code = overrides[name]
        checks.append(host._check(name, state, code))
    return host.HostProbeResults(tuple(checks))


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
    assert host._parse_tcp_listeners(proc((4443,"0a"))) == {4443}
    with pytest.raises(ValueError): host._parse_tcp_listeners(b"garbage")
    with pytest.raises(ValueError): host._parse_tcp_listeners(b"local_address\n")
    with pytest.raises(ValueError): host._parse_tcp_listeners(proc((4443,"GG")))
    for state in ("FF", "00", "0D"):
        with pytest.raises(ValueError):
            host._parse_tcp_listeners(proc((4443, state)))
    assert host._parse_tcp_listeners(proc((4443, "0C"))) == set()
    assert host._parse_tcp_listeners(proc((4443, "0a"))) == {4443}
    for header in (
        "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout",
        "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt inode timeout uid",
        "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt inode",
    ):
        with pytest.raises(ValueError):
            host._parse_tcp_listeners((header + "\n").encode())
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
    assert host._safe_existing_ancestor(str(link/"child"))[1].startswith("UNSAFE_")
    # Even ordinary missing/existing descendants never prove REPOCACHE ownership.
    assert host._safe_existing_ancestor("/etc/repocache/absent-child")[1] in ("PATH_PARENT_OBSERVED_ONLY", "STORAGE_PATH_ACCESS_UNVERIFIED", "UNSAFE_STORAGE_PATH")


def test_capacity_critical_warning_and_unknown(monkeypatch):
    monkeypatch.setattr(host, "_safe_existing_ancestor",
                        lambda path: ("/", "EXISTING_PATH_OWNERSHIP_UNVERIFIED"))
    state = [3000, 3000, 3000]
    inode = [20, 20, 20]
    ids = [1, 2, 3]
    idx = {"a": 0}
    def fake_statvfs(_path):
        position = idx["a"]
        idx["a"] = (position + 1) % 3
        return SimpleNamespace(f_bavail=state[position], f_frsize=1024,
                               f_favail=inode[position], f_fsid=ids[position])
    monkeypatch.setattr(host.os, "statvfs", fake_statvfs)
    assert byname(host._storage_checks(spec()), "storage_free_space").status is PreflightStatus.PASS
    state[1] = 0
    assert byname(host._storage_checks(spec()), "storage_free_space").status is PreflightStatus.FAIL
    state[1] = 1
    # Cache threshold in fixture is in bytes; cache 1 KiB < configured warning 2000.
    assert byname(host._storage_checks(spec()), "storage_free_space").status is PreflightStatus.NOT_VERIFIED
    state[1] = 3000
    state[0] = 0
    assert byname(host._storage_checks(spec()), "storage_free_space").status is PreflightStatus.FAIL
    state[0] = 3000
    state[2] = 0
    assert byname(host._storage_checks(spec()), "storage_free_space").status is PreflightStatus.FAIL
    state[2] = 3000
    inode[0] = 0
    assert byname(host._storage_checks(spec()), "storage_free_space").status is PreflightStatus.FAIL
    inode[0] = 20
    monkeypatch.setattr(host, "_safe_existing_ancestor",
                        lambda path: ("/", "PATH_PARENT_OBSERVED_ONLY"))
    assert byname(host._storage_checks(spec()), "storage_free_space").status is PreflightStatus.NOT_VERIFIED
    monkeypatch.setattr(host, "_safe_existing_ancestor",
                        lambda path: (None, "STORAGE_PATH_ACCESS_UNVERIFIED"))
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
    fake = complete_probes(
        listen_port_conflicts=(PreflightStatus.FAIL, "HTTPS_PORT_ALREADY_LISTENING"),
        storage_free_space=(PreflightStatus.FAIL, "STORAGE_SPACE_BELOW_CRITICAL_THRESHOLD"),
    )
    report = host.assess_deployment_host(fact(), fake, intent="install")
    assert byname(report.checks,"listen_port_conflicts").status is PreflightStatus.FAIL
    assert byname(report.checks,"nginx_ownership_and_features").status is PreflightStatus.NOT_VERIFIED
    assert not report.authorizes_installation and not report.all_verified
    assert "can_install" in report.to_dict()
    assert "/var" not in json.dumps(report.to_dict())
    with pytest.raises(ValueError):
        host.assess_deployment_host(fact(), complete_probes(
            nginx_native_binary=(PreflightStatus.PASS, "/private/untrusted/path"),
        ))
    assert byname(host.assess_deployment_host(
        fact("ID=debian\nVERSION_ID=12\n"), fake).checks,
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
        return complete_probes(
            listen_port_conflicts=(PreflightStatus.FAIL, "HTTPS_PORT_ALREADY_LISTENING"),
        )
    monkeypatch.setattr(host,"_capture_host_probes",observe)
    result=host.inspect_deployment_host(doc)
    assert seen == [("debian",443,"/etc/nginx/conf.d/repocache-managed.conf")]
    assert byname(result.checks,"listen_port_conflicts").status is PreflightStatus.FAIL
    assert not result.authorizes_installation
    assert "example" not in json.dumps(result.to_dict())


def test_incomplete_or_forged_probe_reports_are_rejected():
    import dataclasses
    valid = complete_probes()
    for bad in (
        host.HostProbeResults(()),
        host.HostProbeResults(valid.checks[:-1]),
        host.HostProbeResults(valid.checks + (valid.checks[0],)),
        host.HostProbeResults(valid.checks + (host._check("bogus", PreflightStatus.PASS, "PASS"),)),
        host.HostProbeResults(tuple(dataclasses.replace(c, code="/private/secret")
                                    if c.name == "storage_free_space" else c for c in valid.checks)),
        host.HostProbeResults(tuple(dataclasses.replace(c, status=PreflightStatus.PASS)
                                    if c.name == "storage_free_space" else c for c in valid.checks)),
    ):
        with pytest.raises(ValueError):
            host.assess_deployment_host(fact(), bad)


@pytest.mark.parametrize("mode,expected", [
    (0o770, "UNSAFE_WRITABLE_PATH"),
    (0o775, "UNSAFE_WRITABLE_PATH"),
    (0o777, "UNSAFE_WRITABLE_PATH"),
    (0o700, "PATH_PARENT_OBSERVED_ONLY"),
    (0o750, "PATH_PARENT_OBSERVED_ONLY"),
    (0o755, "PATH_PARENT_OBSERVED_ONLY"),
])
def test_nginx_untrusted_group_or_world_writable_ancestor(monkeypatch, mode, expected):
    import stat
    def mocked_lstat(path):
        if path == "/srv":
            return SimpleNamespace(st_mode=stat.S_IFDIR | mode)
        if path == "/":
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755)
        raise FileNotFoundError()
    monkeypatch.setattr(host, "os", SimpleNamespace(lstat=mocked_lstat, path=os.path))
    directory, code = host._safe_existing_ancestor("/srv/nginx/repocache.conf")
    assert code == expected
    if mode & 0o022:
        assert directory is None


def test_proc_short_reads_are_drained_and_oversize_rejected(monkeypatch):
    import errno
    import stat
    data = proc((4443, "0A"))
    chunks = iter([data[:13], data[13:30], data[30:], b""])
    reads = []
    fake_os = SimpleNamespace(
        O_RDONLY=0, O_CLOEXEC=0, O_NONBLOCK=0,
        open=lambda *_: 7, read=lambda fd, n: (reads.append(n), next(chunks))[1],
        close=lambda fd: None, fstat=lambda fd: SimpleNamespace(st_mode=stat.S_IFREG | 0o444),
    )
    monkeypatch.setattr(host, "os", fake_os)
    assert host._read_fixed("/proc/net/tcp", len(data)) == data
    assert len(reads) == 4
    chunks = iter([data[:13], data[13:30], data[30:], b""])
    with pytest.raises(OSError) as err:
        host._read_fixed("/proc/net/tcp", len(data)-1)
    assert err.value.errno == errno.EFBIG


def test_malformed_tcp_header_or_state_never_means_port_free(monkeypatch):
    for bad in (b"local_address\n", proc((4443,"GG")), proc() + b"missing\n"):
        monkeypatch.setattr(host, "_read_fixed", lambda *_: bad)
        assert host._port_check(spec()).status is PreflightStatus.NOT_VERIFIED


def test_capacity_unknown_fsid_and_inodes_are_not_success(monkeypatch):
    monkeypatch.setattr(host, "_safe_existing_ancestor",
                        lambda path: ("/", "EXISTING_PATH_OWNERSHIP_UNVERIFIED"))
    def untrusted_statvfs(_path):
        return SimpleNamespace(f_bavail=100000, f_frsize=4096, f_favail=100)
    monkeypatch.setattr(host.os, "statvfs", untrusted_statvfs)
    assert byname(host._storage_checks(spec()), "storage_free_space").status is PreflightStatus.NOT_VERIFIED
    monkeypatch.setattr(host.os, "statvfs", lambda _: SimpleNamespace(
        f_bavail=100000, f_frsize=4096, f_fsid=1
    ))
    assert byname(host._storage_checks(spec()), "storage_free_space").status is PreflightStatus.NOT_VERIFIED


def test_full_readonly_probe_orchestration_with_isolated_os_paths(monkeypatch, tmp_path):
    import stat
    roots = (tmp_path/"state", tmp_path/"cache", tmp_path/"logs")
    for root in roots:
        root.mkdir()
    include = tmp_path/"nginx"/"managed.conf"
    include.parent.mkdir()
    cfg = spec(
        state_root=str(roots[0]), cache_root=str(roots[1]), log_root=str(roots[2]),
        generated_include=str(include)
    )
    monkeypatch.setattr(host, "_safe_existing_ancestor",
                        lambda path: (path, "EXISTING_PATH_OWNERSHIP_UNVERIFIED"))
    monkeypatch.setattr(host, "_executable_at", lambda path: True)
    monkeypatch.setattr(host, "_read_fixed",
                        lambda path, limit: proc() if path.startswith("/proc/net/tcp")
                        else b"systemd\n" if path == "/proc/1/comm" else b"1\n")
    monkeypatch.setattr(host.os, "statvfs", lambda path: SimpleNamespace(
        f_bavail=100000, f_frsize=4096, f_favail=100, f_fsid=1
    ))
    original_stat = host.os.stat
    monkeypatch.setattr(host.os, "stat",
                        lambda path, *args, **kwargs: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755)
                        if path == "/run/systemd/system" else original_stat(path, *args, **kwargs))
    observed = host._capture_host_probes("almalinux", cfg)
    report = host.assess_deployment_host(fact("ID=almalinux\nVERSION_ID=10\n", (3,12)), observed)
    assert len(observed.checks) == len(host._PROBE_CODES)
    assert byname(report.checks, "listen_port_conflicts").status is PreflightStatus.PASS
    assert byname(report.checks, "selinux_kernel_mode").status is PreflightStatus.PASS
    assert byname(report.checks, "storage_free_space").status is PreflightStatus.PASS
    assert not report.all_verified and not report.authorizes_installation



@pytest.mark.parametrize("tcp", [
    proc((4443, "FF")),
    proc((4443, "00")),
    proc((4443, "0D")),
    b"sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout\n",
    b"sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt inode timeout uid\n",
])
def test_invalid_kernel_inventory_never_claims_listen_port_free(monkeypatch, tcp):
    monkeypatch.setattr(host, "_read_fixed", lambda *_: tcp)
    result = host._port_check(spec())
    assert result.status is PreflightStatus.NOT_VERIFIED
    assert result.code == "LISTEN_PORT_INVENTORY_INCOMPLETE"


@pytest.mark.parametrize("root,index,capacity,inode_count,expected,code", [
    ("state", 0, 0, 20, PreflightStatus.FAIL, "STATE_OR_LOG_SPACE_EXHAUSTED"),
    ("state", 0, 1, 20, PreflightStatus.NOT_VERIFIED, "STATE_OR_LOG_LOW_HEADROOM_UNVERIFIED"),
    ("state", 0, 1024*1024 - 1, 20, PreflightStatus.NOT_VERIFIED, "STATE_OR_LOG_LOW_HEADROOM_UNVERIFIED"),
    ("state", 0, 1024*1024, 20, PreflightStatus.PASS, "CURRENT_STORAGE_SPACE_OBSERVED_ONLY"),
    ("log", 2, 0, 20, PreflightStatus.FAIL, "STATE_OR_LOG_SPACE_EXHAUSTED"),
    ("log", 2, 1024*1024 - 1, 20, PreflightStatus.NOT_VERIFIED, "STATE_OR_LOG_LOW_HEADROOM_UNVERIFIED"),
    ("log", 2, 1024*1024, 20, PreflightStatus.PASS, "CURRENT_STORAGE_SPACE_OBSERVED_ONLY"),
    ("inode", 0, 1024*1024, 0, PreflightStatus.FAIL, "FILESYSTEM_INODES_EXHAUSTED"),
    ("inode", 0, 1024*1024, 1, PreflightStatus.NOT_VERIFIED, "FILESYSTEM_INODES_LOW_HEADROOM_UNVERIFIED"),
    ("inode", 0, 1024*1024, 15, PreflightStatus.NOT_VERIFIED, "FILESYSTEM_INODES_LOW_HEADROOM_UNVERIFIED"),
    ("inode", 0, 1024*1024, 16, PreflightStatus.PASS, "CURRENT_STORAGE_SPACE_OBSERVED_ONLY"),
    ("cache", 1, 999, 20, PreflightStatus.FAIL, "STORAGE_SPACE_BELOW_CRITICAL_THRESHOLD"),
    ("cache", 1, 1000, 20, PreflightStatus.NOT_VERIFIED, "CACHE_SPACE_BELOW_WARNING_THRESHOLD"),
    ("cache", 1, 1999, 20, PreflightStatus.NOT_VERIFIED, "CACHE_SPACE_BELOW_WARNING_THRESHOLD"),
    ("cache", 1, 2000, 20, PreflightStatus.PASS, "CURRENT_STORAGE_SPACE_OBSERVED_ONLY"),
])
def test_space_and_inode_policy_boundaries(
        monkeypatch, root, index, capacity, inode_count, expected, code):
    monkeypatch.setattr(host, "_safe_existing_ancestor",
                        lambda path: (path, "EXISTING_PATH_OWNERSHIP_UNVERIFIED"))
    free = [3*1024*1024, 3000, 3*1024*1024]
    free[index] = capacity
    inodes = [20, 20, 20]
    inodes[index] = inode_count
    counter = {"i": 0}
    def statvfs(_path):
        i = counter["i"] % 3
        counter["i"] += 1
        return SimpleNamespace(f_bavail=free[i], f_frsize=1,
                               f_favail=inodes[i], f_fsid=i+1)
    monkeypatch.setattr(host.os, "statvfs", statvfs)
    result = byname(host._storage_checks(spec()), "storage_free_space")
    assert (result.status, result.code) == (expected, code)
