"""Fail-closed cgroup-v2 delegation contract (NOT a native host acceptance)."""
from __future__ import annotations

import os
import stat

import pytest

from repocache import candidate_cgroup, candidate_sandbox


@pytest.fixture
def delegated(tmp_path, monkeypatch):
    root = tmp_path / "cgroup2"
    service = root / "system.slice/repocache-candidate.service"
    manager = service / "repocache-manager"
    candidates = service / "repocache-candidates"
    manager.mkdir(parents=True)
    candidates.mkdir()
    proc = tmp_path / "proc_cgroup"
    proc.write_text("0::/system.slice/repocache-candidate.service/repocache-manager\n")
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(f"32 22 0:27 / {root} rw - cgroup2 cgroup rw\n")
    monkeypatch.setattr(candidate_cgroup.os, "geteuid", lambda: os.stat(root).st_uid or 1000)
    for node in (service, candidates):
        (node / "cgroup.subtree_control").write_text("cpu memory pids\n")
    (candidates / "cgroup.procs").write_text("")
    (candidates / "cgroup.events").write_text("populated 0\nfrozen 0\n")
    # The kernel cgroup.kill controller is write-only, unlike cgroup.procs.
    for key in (*candidate_cgroup.LEAF_LIMITS, "cgroup.kill"):
        (candidates / key).write_text("")
    return root, service, manager, candidates, proc, mountinfo


def _gate(data):
    root, _, _, _, proc, mountinfo = data
    return candidate_cgroup.require_delegation(
        root=root, proc_cgroup=proc, mountinfo=mountinfo)


def test_explicit_delegated_hierarchy_can_pass_read_only_gate(delegated):
    result = _gate(delegated)
    assert result.manager.name == "repocache-manager"
    assert result.candidates.name == "repocache-candidates"


@pytest.mark.parametrize("source,contents", [
    ("proc", "2:cpu,cpuacct:/system.slice/repocache-candidate.service/repocache-manager\n"),
    ("proc", "0::/system.slice/not-repocache.service/repocache-manager\n"),
    ("proc", "0::/system.slice/repocache-candidate.service/other\n"),
    ("proc", "0::/system.slice/repocache-candidate.service/../repocache-manager\n"),
    ("proc", "0::/system.slice/repocache-candidate.service/repocache-manager\n2:cpu:/bad\n"),
    ("mount", "32 22 0:27 / /not-this-root rw - cgroup2 cgroup rw\n"),
    ("mount", "32 22 0:27 / /sys/fs/cgroup rw - cgroup cgroup rw\n"),
])
def test_noncanonical_hierarchy_refuses(delegated, source, contents):
    _, _, _, _, proc, mountinfo = delegated
    (proc if source == "proc" else mountinfo).write_text(contents)
    with pytest.raises(candidate_cgroup.CgroupGateError):
        _gate(delegated)


@pytest.mark.parametrize("case", [
    "no-cpu", "no-memory", "no-pids", "parent-populated",
    "symlink-candidates", "missing-kill", "shared-candidates",
    "descendant-populated",
])
def test_missing_or_unsafe_delegation_fails_closed(delegated, case):
    _, service, _, candidates, _, _ = delegated
    if case.startswith("no-"):
        missing = case[3:]
        (candidates / "cgroup.subtree_control").write_text(
            " ".join(sorted(candidate_cgroup.REQUIRED_CONTROLLERS - {missing})))
    elif case == "parent-populated":
        (candidates / "cgroup.procs").write_text("123\n")
    elif case == "symlink-candidates":
        target = candidates.parent / "original"
        candidates.rename(target)
        candidates.symlink_to(target, target_is_directory=True)
    elif case == "missing-kill":
        (candidates / "cgroup.kill").unlink()
    elif case == "shared-candidates":
        candidates.chmod(0o777)
    elif case == "descendant-populated":
        (candidates / "cgroup.events").write_text("populated 1\n")
    with pytest.raises(candidate_cgroup.CgroupGateError):
        _gate(delegated)


def test_hierarchy_rejects_root_uid(delegated, monkeypatch):
    monkeypatch.setattr(candidate_cgroup.os, "geteuid", lambda: 0)
    with pytest.raises(candidate_cgroup.CgroupGateError, match="root"):
        _gate(delegated)


def test_limit_controller_contract_and_readback(delegated, monkeypatch):
    _, _, _, candidates, _, _ = delegated
    leaf = candidates / ("candidate-" + "a" * 32)
    leaf.mkdir(mode=0o700)
    (leaf / "cgroup.procs").write_text("")
    for name, initial in candidate_cgroup.LEAF_LIMITS.items():
        (leaf / name).write_text(initial)
    monkeypatch.setattr(candidate_cgroup.os, "geteuid", lambda: os.stat(leaf).st_uid)
    candidate_cgroup.write_leaf_limits(_gate(delegated), leaf)
    for key, value in candidate_cgroup.LEAF_LIMITS.items():
        assert (leaf / key).read_text() == value


@pytest.mark.parametrize("case", ["populated", "missing", "symlink", "readback"])
def test_limit_configuration_must_never_silently_continue(delegated, monkeypatch, case):
    _, _, _, candidates, _, _ = delegated
    leaf = candidates / ("candidate-" + "b" * 32)
    leaf.mkdir()
    (leaf / "cgroup.procs").write_text("42" if case == "populated" else "")
    for name in candidate_cgroup.LEAF_LIMITS:
        (leaf / name).write_text("unlimited")
    monkeypatch.setattr(candidate_cgroup.os, "geteuid", lambda: os.stat(leaf).st_uid)
    if case == "missing":
        (leaf / "memory.max").unlink()
    elif case == "symlink":
        control = leaf / "memory.max"
        control.unlink()
        control.symlink_to(leaf / "cpu.max")
    elif case == "readback":
        monkeypatch.setattr(candidate_cgroup, "_read",
                            lambda p: "wrong" if p.name == "memory.max"
                            else p.read_text())
    with pytest.raises(candidate_cgroup.CgroupGateError):
        candidate_cgroup.write_leaf_limits(_gate(delegated), leaf)


def test_no_interpreter_or_shell_is_launched_by_cgroup_preflight(
        delegated, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("preflight must not launch a process")
    monkeypatch.setattr(candidate_cgroup.os, "system", forbidden)
    _gate(delegated)


def test_write_only_cgroup_kill_gate_is_not_read(delegated, monkeypatch):
    _, _, _, candidates, _, _ = delegated
    kill = candidates / "cgroup.kill"
    kill.chmod(0o200)
    original = candidate_cgroup._read

    def forbid_kill_reads(path):
        if path == kill:
            raise AssertionError("cgroup.kill must never be read or probed")
        return original(path)

    monkeypatch.setattr(candidate_cgroup, "_read", forbid_kill_reads)
    assert _gate(delegated).candidates == candidates
    assert kill.stat().st_size == 0


def test_limit_write_refuses_unrelated_directory(delegated, tmp_path):
    other = tmp_path / ("candidate-" + "c" * 32)
    other.mkdir()
    with pytest.raises(candidate_cgroup.CgroupGateError,
                       match="outside verified delegation"):
        candidate_cgroup.write_leaf_limits(_gate(delegated), other)


def test_limit_write_refuses_untrusted_leaf_name(delegated):
    _, _, _, candidates, _, _ = delegated
    wrong = candidates / "candidate-../escape"
    with pytest.raises(candidate_cgroup.CgroupGateError,
                       match="outside verified delegation"):
        candidate_cgroup.write_leaf_limits(_gate(delegated), wrong)



def _configured_leaf(delegated, suffix="d"):
    _, _, _, candidates, _, _ = delegated
    leaf = candidates / ("candidate-" + suffix * 32)
    leaf.mkdir(mode=0o700)
    (leaf / "cgroup.procs").write_text("")
    for name, value in candidate_cgroup.LEAF_LIMITS.items():
        (leaf / name).write_text(value)
    return leaf


def _trusted_command(marker):
    # Testing only: a harmless system Python payload, not a third-party wheel.
    code = "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('ran')"
    return candidate_sandbox._limited_command([
        "/usr/bin/python3", "-I", "-S", "-c", code, str(marker)])


def test_pre_exec_wrapper_places_child_before_executing_payload(
        delegated, tmp_path, monkeypatch):
    import subprocess
    # A harmless OS Python script substitutes for the *inner* bwrap target;
    # this fixture is not a native cgroup/kernel isolation claim.
    monkeypatch.setattr(candidate_sandbox, "BWRAP",
                        __import__("pathlib").Path("/usr/bin/python3"))
    leaf = _configured_leaf(delegated)
    marker = tmp_path / "payload-executed"
    argv = candidate_cgroup.entry_argv(
        _gate(delegated), leaf, _trusted_command(marker))
    assert argv[:4] == ["/usr/bin/python3", "-I", "-S", "-c"]
    assert argv[5] == str(leaf / "cgroup.procs")
    result = subprocess.run(argv, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr[-400:]
    assert (leaf / "cgroup.procs").read_text() == "0"
    assert marker.read_text() == "ran"


@pytest.mark.parametrize("case", [
    "missing", "symlink", "directory", "unconfigured", "populated",
    "wrong-argv", "wrong-path", "missing-limit", "wrong-executable",
])
def test_pre_exec_refuses_before_payload_if_membership_is_untrusted(
        delegated, tmp_path, monkeypatch, case):
    import subprocess
    monkeypatch.setattr(candidate_sandbox, "BWRAP",
                        __import__("pathlib").Path("/usr/bin/python3"))
    leaf = _configured_leaf(delegated, "e")
    marker = tmp_path / "must-not-execute"
    cmd = _trusted_command(marker)
    if case == "unconfigured":
        (leaf / "memory.max").write_text("max")
    elif case == "populated":
        (leaf / "cgroup.procs").write_text("12345")
    elif case == "wrong-argv":
        cmd[0] = "/bin/sh"
    elif case == "missing-limit":
        cmd.pop(1)
    elif case == "wrong-executable":
        cmd[cmd.index("--") + 1] = "/bin/sh"
    elif case == "wrong-path":
        leaf = tmp_path / ("candidate-" + "f" * 32)
        leaf.mkdir()
    if case in ("unconfigured", "populated", "wrong-argv", "wrong-path",
                "missing-limit", "wrong-executable"):
        with pytest.raises(candidate_cgroup.CgroupGateError):
            candidate_cgroup.entry_argv(_gate(delegated), leaf, cmd)
    else:
        argv = candidate_cgroup.entry_argv(_gate(delegated), leaf, cmd)
        procs = leaf / "cgroup.procs"
        procs.unlink()
        if case == "symlink":
            procs.symlink_to(tmp_path / "outside")
        elif case == "directory":
            procs.mkdir()
        result = subprocess.run(argv, text=True, capture_output=True, timeout=10)
        assert result.returncode != 0
    assert not marker.exists()


def test_entry_requires_pinned_resource_limits(delegated, monkeypatch):
    monkeypatch.setattr(candidate_sandbox, "BWRAP",
                        __import__("pathlib").Path("/usr/bin/python3"))
    leaf = _configured_leaf(delegated)
    (leaf / "cpu.max").unlink()
    with pytest.raises(candidate_cgroup.CgroupGateError):
        candidate_cgroup.entry_argv(
            _gate(delegated), leaf,
            candidate_sandbox._limited_command(["/usr/bin/python3", "--version"]))



def test_system_python_symlink_metadata_is_accepted_but_untrusted_path_denied():
    # OS Python is commonly /usr/bin/python3 -> python3.13/python3.12:
    # symlink mode is 0777 even though the resolved binary is root-owned 0755.
    candidate_cgroup._trusted_interpreter(candidate_cgroup.SYSTEM_PYTHON)
    with pytest.raises(candidate_cgroup.CgroupGateError,
                       match="Noncanonical"):
        candidate_cgroup._trusted_interpreter(
            __import__("pathlib").Path("/usr/local/bin/python3"))



def _mock_cleanup_leaf(delegated):
    _, _, _, candidates, _, _ = delegated
    leaf = candidates / ("candidate-" + "9" * 32)
    leaf.mkdir(mode=0o700)
    (leaf / "cgroup.kill").write_text("")
    (leaf / "cgroup.events").write_text("populated 0\n")
    return leaf


def test_candidate_cgroup_kill_drain_is_scoped_and_never_reads_kill(
        delegated, monkeypatch):
    leaf = _mock_cleanup_leaf(delegated)
    original_read = candidate_cgroup._read
    removed = []

    def guarded_read(path):
        if path.name == "cgroup.kill":
            raise AssertionError("The kernel kill controller is write-only")
        return original_read(path)

    def pretend_kernel_rmdir(path):
        removed.append(path)

    monkeypatch.setattr(candidate_cgroup, "_read", guarded_read)
    monkeypatch.setattr(candidate_cgroup.os, "rmdir", pretend_kernel_rmdir)
    candidate_cgroup.kill_and_drain_leaf(_gate(delegated), leaf)
    assert (leaf / "cgroup.kill").read_text() == "1"
    assert removed == [leaf]
    # The parent delegation must never be killed or removed.
    assert (delegated[3] / "cgroup.kill").read_text() == ""


def test_candidate_cgroup_cleanup_times_out_without_removing_populated_leaf(
        delegated, monkeypatch):
    leaf = _mock_cleanup_leaf(delegated)
    (leaf / "cgroup.events").write_text("populated 1\n")
    removed = []

    monkeypatch.setattr(candidate_cgroup.os, "rmdir",
                        lambda path: removed.append(path))
    with pytest.raises(candidate_cgroup.CgroupGateError,
                       match="remains populated"):
        candidate_cgroup.kill_and_drain_leaf(
            _gate(delegated), leaf, timeout=0)
    assert (leaf / "cgroup.kill").read_text() == "1"
    assert not removed


@pytest.mark.parametrize("kind", ["outside", "symlink", "missing-events",
                                   "invalid-events", "no-kill"])
def test_cgroup_cleanup_invalid_target_refuses_without_killing(
        delegated, tmp_path, kind):
    leaf = _mock_cleanup_leaf(delegated)
    outside = tmp_path / "outside"
    outside.write_text("untouched")
    if kind == "outside":
        target = tmp_path / leaf.name
        target.mkdir()
        with pytest.raises(candidate_cgroup.CgroupGateError,
                           match="escapes approved subtree"):
            candidate_cgroup.kill_and_drain_leaf(_gate(delegated), target)
    else:
        kill = leaf / "cgroup.kill"
        events = leaf / "cgroup.events"
        if kind == "symlink":
            kill.unlink()
            kill.symlink_to(outside)
        elif kind == "missing-events":
            events.unlink()
        elif kind == "invalid-events":
            events.write_text("unexpected 0\n")
        elif kind == "no-kill":
            kill.unlink()
        with pytest.raises(candidate_cgroup.CgroupGateError):
            candidate_cgroup.kill_and_drain_leaf(_gate(delegated), leaf)
    assert outside.read_text() == "untouched"
    assert (delegated[3] / "cgroup.kill").read_text() == ""


def test_candidate_cgroup_cleanup_requires_real_rmdir_success(
        delegated, monkeypatch):
    import errno
    leaf = _mock_cleanup_leaf(delegated)

    def busy(path):
        raise OSError(errno.EBUSY, "Still in use", path)

    monkeypatch.setattr(candidate_cgroup.os, "rmdir", busy)
    with pytest.raises(candidate_cgroup.CgroupGateError,
                       match="Cannot remove drained"):
        candidate_cgroup.kill_and_drain_leaf(_gate(delegated), leaf)
    assert (leaf / "cgroup.kill").read_text() == "1"


@pytest.mark.parametrize("deadline", [-1, 31, None, True, "5"])
def test_candidate_cgroup_cleanup_rejects_invalid_timeout_before_kill(
        delegated, deadline):
    leaf = _mock_cleanup_leaf(delegated)
    with pytest.raises(candidate_cgroup.CgroupGateError,
                       match="Invalid candidate cleanup deadline"):
        candidate_cgroup.kill_and_drain_leaf(
            _gate(delegated), leaf, timeout=deadline)
    assert (leaf / "cgroup.kill").read_text() == ""



def _mock_kernel_leaf_creation(delegated, monkeypatch):
    """Kernel cgroupfs auto-creates controller files; tmp_path does not."""
    _, _, _, candidates, _, _ = delegated
    created = []
    closed = []
    actual_create = candidate_cgroup._create_candidate_leaf

    def create(parent_fd, name):
        actual_create(parent_fd, name)
        leaf = candidates / name
        created.append(leaf)
        (leaf / "cgroup.procs").write_text("")
        (leaf / "cgroup.events").write_text("populated 0\n")
        (leaf / "cgroup.kill").write_text("")
        for control in candidate_cgroup.LEAF_LIMITS:
            # Ordinary test files retain trailing bytes on writes without
            # O_TRUNC; kernel cgroupfs files do not. Start empty to mirror
            # the replacement semantics of cgroup controller writes.
            (leaf / control).write_text("")

    def cleanup(delegation, leaf, *, timeout=5.0):
        assert delegation.candidates == candidates
        assert leaf == created[-1]
        assert (leaf / "cgroup.procs").read_text() == ""
        closed.append(leaf)
        for child in leaf.iterdir():
            child.unlink()
        leaf.rmdir()

    monkeypatch.setattr(candidate_cgroup, "_create_candidate_leaf", create)
    monkeypatch.setattr(candidate_cgroup, "kill_and_drain_leaf", cleanup)
    return created, closed


def test_candidate_leaf_reserves_applies_limits_and_cleans_exclusively(
        delegated, monkeypatch):
    created, closed = _mock_kernel_leaf_creation(delegated, monkeypatch)
    gate = _gate(delegated)
    with candidate_cgroup.candidate_leaf(gate) as leaf:
        assert leaf == created[0]
        assert leaf.name.startswith("candidate-")
        for name, expected in candidate_cgroup.LEAF_LIMITS.items():
            assert (leaf / name).read_text() == expected
        assert not closed
    assert closed == created
    assert not leaf.exists()
    assert gate.candidates.exists()


def test_candidate_leaf_cleanup_on_body_exception(delegated, monkeypatch):
    created, closed = _mock_kernel_leaf_creation(delegated, monkeypatch)
    with pytest.raises(RuntimeError, match="candidate failed"):
        with candidate_cgroup.candidate_leaf(_gate(delegated)) as leaf:
            raise RuntimeError("candidate failed")
    assert closed == created
    assert not leaf.exists()


def test_candidate_leaf_cleanup_on_partial_limit_failure(delegated, monkeypatch):
    created, closed = _mock_kernel_leaf_creation(delegated, monkeypatch)

    def broken_limits(delegation, leaf):
        (leaf / "memory.max").unlink()
        raise candidate_cgroup.CgroupGateError("Cannot impose limits")

    monkeypatch.setattr(candidate_cgroup, "write_leaf_limits", broken_limits)
    with pytest.raises(candidate_cgroup.CgroupGateError, match="Cannot impose"):
        with candidate_cgroup.candidate_leaf(_gate(delegated)):
            pytest.fail("Must not enter body after failed limits")
    assert closed == created
    assert not created[0].exists()


def test_candidate_leaf_collision_never_takes_over_or_kills_existing(
        delegated, monkeypatch):
    _, _, _, candidates, _, _ = delegated
    monkeypatch.setattr(candidate_cgroup.secrets, "token_hex",
                        lambda n: "a" * 32)
    original = candidates / ("candidate-" + "a" * 32)
    original.mkdir()
    sentinel = original / "not-ours"
    sentinel.write_text("must be preserved")
    monkeypatch.setattr(candidate_cgroup, "kill_and_drain_leaf",
                        lambda *a, **kw: pytest.fail("Collision must not kill"))
    with pytest.raises(candidate_cgroup.CgroupGateError,
                       match="exclusively reserve"):
        with candidate_cgroup.candidate_leaf(_gate(delegated)):
            pytest.fail("Collision must not be adopted")
    assert sentinel.read_text() == "must be preserved"


def test_candidate_leaf_bad_token_refuses_without_mkdir(delegated, monkeypatch):
    monkeypatch.setattr(candidate_cgroup.secrets, "token_hex",
                        lambda n: "../../wrong")
    monkeypatch.setattr(candidate_cgroup, "_create_candidate_leaf",
                        lambda *a: pytest.fail("Invalid token must not mkdir"))
    with pytest.raises(candidate_cgroup.CgroupGateError, match="reservation token"):
        with candidate_cgroup.candidate_leaf(_gate(delegated)):
            pytest.fail("Invalid token cannot acquire leaf")


def test_candidate_leaf_refuses_changed_parent_and_forged_delegation(
        delegated, monkeypatch):
    gate = _gate(delegated)
    _, service, _, candidates, _, _ = delegated
    bad = candidate_cgroup.Delegation(
        service=service, manager=gate.manager,
        candidates=service / "unreviewed-cgroups")
    with pytest.raises(candidate_cgroup.CgroupGateError,
                       match="Noncanonical"):
        with candidate_cgroup.candidate_leaf(bad):
            pytest.fail("Noncanonical delegation cannot be used")
    swapped = service / "swapped-candidates"
    candidates.rename(swapped)
    candidates.symlink_to(swapped, target_is_directory=True)
    with pytest.raises(candidate_cgroup.CgroupGateError,
                       match="delegation path"):
        with candidate_cgroup.candidate_leaf(gate):
            pytest.fail("Symlinked cgroup parent cannot be used")


def test_candidate_leaf_drain_failure_remains_blocking(delegated, monkeypatch):
    created, closed = _mock_kernel_leaf_creation(delegated, monkeypatch)

    def failed_cleanup(*args, **kwargs):
        raise candidate_cgroup.CgroupGateError("Candidate remains populated")

    monkeypatch.setattr(candidate_cgroup, "kill_and_drain_leaf", failed_cleanup)
    with pytest.raises(candidate_cgroup.CgroupGateError,
                       match="remains populated"):
        with candidate_cgroup.candidate_leaf(_gate(delegated)):
            pass
    assert created[0].exists()
    assert not closed


def test_candidate_leaf_never_runs_as_root(delegated, monkeypatch):
    gate = _gate(delegated)
    monkeypatch.setattr(candidate_cgroup.os, "geteuid", lambda: 0)
    with pytest.raises(candidate_cgroup.CgroupGateError, match="Root"):
        with candidate_cgroup.candidate_leaf(gate):
            pytest.fail("Root cannot create an untrusted candidate leaf")
