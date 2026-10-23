"""Fail-closed OS candidate namespace policy tests, issue #112.

No claim that real Debian13 or Alma10 allows unprivileged namespaces;
this suite inspects command policy and confirms refusal without bwrap.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from repocache import candidate_sandbox, updater


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "managed"
    parent = root / "online-preparations"
    work = parent / ".online-v6-case"
    (work / "venv/bin").mkdir(parents=True, mode=0o700)
    (work / "download").mkdir(mode=0o700)
    (work / "owned-app").mkdir(mode=0o700)
    for path in (root, parent, work, work / "venv", work / "venv/bin"):
        path.chmod(0o700)
    monkeypatch.setattr(updater, "ROOT", root)
    monkeypatch.setattr(candidate_sandbox.os, "geteuid", lambda: os.stat(root).st_uid)
    monkeypatch.setattr(candidate_sandbox, "require_executor", lambda: None)
    return root, work


def _pip(work: Path):
    return [str(work / "venv/bin/python"), "-I", "-m", "pip", "install",
            "--no-index", "--no-deps", "--only-binary=:all:",
            "--require-hashes", "-r", str(work / "download/requirements.lock")]


def test_candidate_has_only_private_writable_root_and_no_network(workspace):
    root, work = workspace
    command = candidate_sandbox.command(work, _pip(work), cwd=work / "download")
    assert command[0] == "/usr/bin/bwrap"
    assert command[command.index("--") + 1:] == _pip(work)
    assert command.index("--unshare-user") < command.index("--ro-bind")
    for protection in ("--unshare-user", "--disable-userns",
                       "--unshare-pid", "--unshare-net", "--unshare-ipc",
                       "--unshare-uts", "--die-with-parent", "--new-session",
                       "--clearenv", "--proc", "--dev", "--tmpfs"):
        assert protection in command
    writable = [command[i+1:i+3] for i, arg in enumerate(command) if arg == "--bind"]
    assert writable == [[str(work), str(work)]]
    assert str(root / "current") not in command
    assert str(root / "installed.json") not in command
    assert "/var/lib/repocache" not in command
    assert ["--ro-bind", "/usr", "/usr"] == command[
        command.index("--ro-bind"):command.index("--ro-bind") + 3]
    assert ["--chdir", str(work / "download")] == command[
        command.index("--chdir"):command.index("--chdir") + 2]
    assert command.index("--unshare-net") < command.index("--")
    assert command.index("--clearenv") < command.index("--")
    assert "LD_PRELOAD" not in command and "PIP_INDEX_URL" not in command


@pytest.mark.parametrize("command", [
    lambda w: ["/bin/sh", "-c", "id"],
    lambda w: [str(w / "venv/bin/python"), "-c", "exec('malicious')"],
    lambda w: [str(w / "venv/bin/python"), "-I", "-m", "pip", "download"],
    lambda w: [str(w / "venv/bin/python"), "-I", "-m", "pip", "install", "typer"],
    lambda w: [str(w / "venv/bin/repocache"), "update", "--yes"],
    lambda w: [str(w / "venv/bin/repocache"), "health", "--deep"],
])
def test_sandbox_never_accepts_arbitrary_commands(workspace, command):
    _, work = workspace
    with pytest.raises(candidate_sandbox.SandboxError):
        candidate_sandbox.command(work, command(work))


def test_approved_python_metadata_and_headless_smoke_commands(workspace):
    _, work = workspace
    python = str(work / "venv/bin/python")
    for argv in (
        [python, "-I", "-m", "pip", "check"],
        [python, "-I", "-m", "pip", "list", "--format=json"],
        [python, "-I", "-c", "assert 'run_test'"],
        [str(work / "venv/bin/repocache"), "--version"],
        [str(work / "venv/bin/repocache"), "--help"],
        [str(work / "venv/bin/repocache"), "update", "--help"],
    ):
        out = candidate_sandbox.command(work, argv)
        assert out[out.index("--") + 1:] == argv


@pytest.mark.parametrize("case", [
    "bad-root", "symlink-workspace", "shared-stage", "escape-cwd",
    "symlink-cwd", "nested-mutable-cwd",
])
def test_sandbox_refuses_untrusted_working_paths(workspace, tmp_path, case):
    root, work = workspace
    cwd = work / "download"
    if case == "bad-root":
        root.chmod(0o755)
    elif case == "symlink-workspace":
        external = tmp_path / "external"
        external.mkdir()
        work.rename(parent := work.parent / ".moved")
        work.symlink_to(parent)
    elif case == "shared-stage":
        work.chmod(0o755)
    elif case == "escape-cwd":
        cwd = tmp_path
    elif case == "symlink-cwd":
        alias = work / "shortcut"
        alias.symlink_to(cwd)
        cwd = alias
    elif case == "nested-mutable-cwd":
        cwd = work / "nested"
        cwd.mkdir(mode=0o777)
        cwd.chmod(0o777)
    with pytest.raises(candidate_sandbox.SandboxError):
        candidate_sandbox.command(work, _pip(work), cwd=cwd)


def test_executor_unavailable_and_symlink_denied_even_before_any_run(
        workspace, monkeypatch, tmp_path):
    _, work = workspace
    monkeypatch.undo()
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    missing = tmp_path / "missing-bwrap"
    monkeypatch.setattr(candidate_sandbox, "BWRAP", missing)
    with pytest.raises(candidate_sandbox.SandboxError):
        candidate_sandbox.require_executor()
    link = tmp_path / "linked-bwrap"
    link.symlink_to("/usr/bin/env")
    monkeypatch.setattr(candidate_sandbox, "BWRAP", link)
    with pytest.raises(candidate_sandbox.SandboxError):
        candidate_sandbox.require_executor()


def test_setuid_or_setgid_executables_unconditionally_refused(monkeypatch):
    """Simulate a root-owned OS package without needing root during unit CI."""
    orig = Path.lstat
    target = Path("/usr/bin/env")
    monkeypatch.setattr(candidate_sandbox, "BWRAP", target)
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    def substitute(path):
        meta = orig(path)
        if path == target:
            vals = list(meta)
            vals[0] |= stat.S_ISUID | stat.S_ISGID
            vals[4] = 0
            return os.stat_result(vals)
        return meta
    monkeypatch.setattr(Path, "lstat", substitute)
    with pytest.raises(candidate_sandbox.SandboxError, match="Setuid"):
        candidate_sandbox.require_executor()



@pytest.mark.parametrize("version,accepted", [
    ("0.10.0-4.el10_2", False),
    ("0.10.0-5.el10_1", False),
    ("0.10.0-5.el10_2", True),
    ("0.10.0-6.el10_3", True),
    ("0.12.0-1.el10_2", True),
    ("0.10.0-5.el9_8", False),
    ("corrupted", False),
])
def test_almalinux_security_advisory_backport_gate(version, accepted, monkeypatch):
    from repocache import online_generation
    monkeypatch.setattr(online_generation, "_current_host_target",
                        lambda: "almalinux10-py312")
    monkeypatch.setattr(candidate_sandbox, "_safe_package_query", lambda argv: version)
    if accepted:
        candidate_sandbox._verify_patch_level()
    else:
        with pytest.raises(candidate_sandbox.SandboxError):
            candidate_sandbox._verify_patch_level()


@pytest.mark.parametrize("comparison_returncode", [0, 1, 2])
def test_debian_native_version_gate_never_ignores_failed_comparison(
        comparison_returncode, monkeypatch):
    from repocache import online_generation
    monkeypatch.setattr(online_generation, "_current_host_target",
                        lambda: "debian13-py313")
    monkeypatch.setattr(candidate_sandbox, "_safe_package_query",
                        lambda argv: "0.12.0-1~deb13u1")
    commands = []
    class Result:
        returncode = comparison_returncode
    def compare(argv, **kwargs):
        commands.append(argv)
        assert kwargs["timeout"] == 5
        assert kwargs["check"] is False
        return Result()
    monkeypatch.setattr(candidate_sandbox.subprocess, "run", compare)
    if comparison_returncode == 0:
        candidate_sandbox._verify_patch_level()
    else:
        with pytest.raises(candidate_sandbox.SandboxError, match="DSA-6472-1"):
            candidate_sandbox._verify_patch_level()
    assert commands[0][:2] == ["/usr/bin/dpkg", "--compare-versions"]
    assert commands[0][-2:] == ["ge", "0.12.0-1~deb13u1"]


def test_missing_security_package_metadata_fails_before_namespace(
        monkeypatch):
    class Result:
        returncode = 1
        stdout = ""
    monkeypatch.setattr(candidate_sandbox.subprocess, "run",
                        lambda argv, **kwargs: Result())
    with pytest.raises(candidate_sandbox.SandboxError, match="Unverifiable"):
        candidate_sandbox._safe_package_query(
            ["/usr/bin/rpm", "-q", "bubblewrap"])
