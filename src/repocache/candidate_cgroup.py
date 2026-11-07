"""Strict cgroup-v2 delegation/resource preflight for online candidates (#112).

This is deliberately NOT a candidate launcher. A future executor must attach
the entire child process tree to a freshly limited cgroup before *any*
untrusted exec and kill/drain it afterward. The current bwrap prototype is
NON-ACTIVATING; no absence of cgroups may be interpreted as permission to
run an online candidate in production.
"""
from __future__ import annotations

import os
import re
import secrets
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator
from pathlib import Path


class CgroupGateError(RuntimeError):
    """A mandatory resource-containment prerequisite is missing or untrusted."""


CGROUP_ROOT = Path("/sys/fs/cgroup")
PROC_CGROUP = Path("/proc/self/cgroup")
PROC_MOUNTINFO = Path("/proc/self/mountinfo")
MANAGER_LEAF = "repocache-manager"
CANDIDATE_SUBTREE = "repocache-candidates"
REQUIRED_CONTROLLERS = frozenset(("cpu", "memory", "pids"))
# These are aggregate limits for an eventual dedicated *candidate* leaf,
# not per-process RLIMITs or staging filesystem quotas.
LEAF_LIMITS = {
    "cpu.max": "200000 100000",
    "memory.max": str(1024 * 1024 * 1024),
    "memory.swap.max": "0",
    "pids.max": "64",
}


@dataclass(frozen=True)
class Delegation:
    """Preflight-verified manager path and dedicated empty candidate subtree."""
    service: Path
    manager: Path
    candidates: Path


def _read(path: Path) -> str:
    try:
        if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
            raise CgroupGateError("Untrusted cgroup control file")
        return path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise CgroupGateError("Cannot inspect required cgroup control") from exc


def _directory(path: Path, *, owned: bool = False) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CgroupGateError("Missing cgroup-v2 service delegation") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise CgroupGateError("Untrusted cgroup delegation path")
    if owned and (metadata.st_uid != os.geteuid()
                  or metadata.st_mode & 0o022):
        raise CgroupGateError("Shared or unowned candidate cgroup delegation")


def _mount_is_v2(root: Path, mountinfo: str) -> bool:
    # Kernel mountinfo has exactly one ' - ' separator per entry.
    for line in mountinfo.splitlines():
        before, separator, after = line.partition(" - ")
        left, right = before.split(), after.split()
        if (separator and len(left) > 5 and len(right) >= 3
                and left[4] == str(root) and right[0] == "cgroup2"):
            return True
    return False


def _service_from_self(root: Path, proc_cgroup: str) -> tuple[Path, Path]:
    lines = proc_cgroup.splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        raise CgroupGateError("Unified cgroup v2 service identity is unavailable")
    relative = lines[0][4:]
    # Never accept a proc-cgroup path with ambiguous or traversal components.
    components = relative.split("/")
    if (len(components) < 3 or components[-1] != MANAGER_LEAF
            or any(not part or part in (".", "..") or
                   not re.fullmatch(r"[A-Za-z0-9_.@-]+", part)
                   for part in components)):
        raise CgroupGateError("Unexpected cgroup service manager location")
    if not re.fullmatch(r"repocache(?:-[a-z0-9-]+)?\.service",
                        components[-2]):
        raise CgroupGateError("Candidate runner is outside its dedicated service")
    manager = root.joinpath(*components)
    return manager.parent, manager


def require_delegation(*, root: Path = CGROUP_ROOT,
                       proc_cgroup: Path = PROC_CGROUP,
                       mountinfo: Path = PROC_MOUNTINFO) -> Delegation:
    """Read-only gate for an explicitly provisioned delegated systemd service.

    The service manager must already be in the 'repocache-manager' leaf,
    leaving its sibling 'repocache-candidates' empty with cpu/memory/pids
    controllers enabled by its service manager. Never change systemd or
    parent cgroup permissions from the unprivileged updater.
    """
    if os.geteuid() == 0:
        raise CgroupGateError("Online candidate resource manager cannot run as root")
    if not _mount_is_v2(root, _read(mountinfo)):
        raise CgroupGateError("Unified cgroup v2 mount is required")
    service, manager = _service_from_self(root, _read(proc_cgroup))
    candidates = service / CANDIDATE_SUBTREE
    _directory(root)
    current = root
    for part in manager.relative_to(root).parts:
        current = current / part
        _directory(current)
    _directory(service, owned=True)
    _directory(manager, owned=True)
    _directory(candidates, owned=True)
    for node in (service, candidates):
        available = set(_read(node / "cgroup.subtree_control").split())
        if not REQUIRED_CONTROLLERS.issubset(available):
            raise CgroupGateError("Missing delegated cpu/memory/pids controllers")
    if _read(candidates / "cgroup.procs").strip():
        raise CgroupGateError("Candidate cgroup parent contains processes")
    # cgroup.procs covers only this level; cgroup.events includes descendants.
    if "populated 0" not in _read(candidates / "cgroup.events").splitlines():
        raise CgroupGateError("Candidate cgroup subtree is already populated")
    # cgroup-v2 controller files and cgroup.kill must exist before accepting
    # a delegated subtree. Group limits will be applied to individual leaves.
    for control in (*LEAF_LIMITS, "cgroup.procs"):
        _read(candidates / control)
    # cgroup.kill is a write-only kernel interface: never attempt to read it
    # (or write a probe value, which would terminate the entire subtree).
    kill = candidates / "cgroup.kill"
    try:
        if (not stat.S_ISREG(kill.lstat().st_mode)
                or not os.access(kill, os.W_OK)):
            raise CgroupGateError("Cannot safely terminate candidate processes")
    except OSError as exc:
        raise CgroupGateError("Missing cgroup kill controller") from exc
    if not os.access(candidates, os.W_OK):
        raise CgroupGateError("Candidate cgroup subtree is read-only")
    return Delegation(service=service, manager=manager, candidates=candidates)


def write_leaf_limits(delegation: Delegation, leaf: Path) -> None:
    """Configure an *empty* new leaf; never claim it launches a process.

    A future supervised launcher must create this leaf under an accepted
    Delegation, attach before exec, and fail closed on any write/readback
    mismatch. No caller may use this as a standalone isolation mechanism.
    """
    if (leaf.parent != delegation.candidates
            or not re.fullmatch(r"candidate-[a-f0-9]{32}", leaf.name)):
        raise CgroupGateError("Candidate leaf is outside verified delegation")
    _directory(leaf, owned=True)
    if _read(leaf / "cgroup.procs").strip():
        raise CgroupGateError("Cannot configure a populated candidate leaf")
    for filename, value in LEAF_LIMITS.items():
        target = leaf / filename
        try:
            if not stat.S_ISREG(target.lstat().st_mode):
                raise CgroupGateError("Untrusted candidate resource controller")
            descriptor = os.open(target, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                if os.write(descriptor, value.encode("ascii")) != len(value):
                    raise CgroupGateError("Incomplete cgroup controller write")
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise CgroupGateError("Cannot impose mandatory cgroup limits") from exc
        if _read(target).strip() != value:
            raise CgroupGateError("Cgroup controller did not enforce requested limit")


# Trusted OS Python only: it runs a literal, isolated stdlib bootstrap before
# prlimit/bwrap. Avoid subprocess preexec_fn: Python fork hooks are unsafe when
# the long-lived manager has other threads.
SYSTEM_PYTHON = Path("/usr/bin/python3")
_ENTRY_CODE = (
    "import os,sys\n"
    "try:\n"
    " fd=os.open(sys.argv[1],os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC)\n"
    " try:\n"
    "  if os.write(fd,b'0') != 1: os._exit(125)\n"
    " finally:\n"
    "  os.close(fd)\n"
    " os.execv(sys.argv[2],sys.argv[2:])\n"
    "except (OSError,ValueError):\n"
    " os._exit(125)\n"
)


def _trusted_interpreter(path: Path) -> None:
    """Permit only the OS-owned Python symlink and resolved OS binary."""
    if path != SYSTEM_PYTHON:
        raise CgroupGateError("Noncanonical candidate bootstrap interpreter")
    try:
        resolved = path.resolve(strict=True)
        link = path.lstat()
        binary = resolved.lstat()
        parent = resolved.parent.lstat()
    except (OSError, RuntimeError) as exc:
        raise CgroupGateError("Required native candidate bootstrap unavailable") from exc
    if (resolved.parent != Path("/usr/bin")
            or not re.fullmatch(r"python3[.][0-9]+", resolved.name)
            or not (stat.S_ISLNK(link.st_mode) or stat.S_ISREG(link.st_mode))
            # Symlink mode bits are conventionally 0777 on Linux, but have
            # no permission semantics. Only the root-owned link placement
            # and its canonical resolved executable are security-relevant.
            or link.st_uid != 0
            or (stat.S_ISREG(link.st_mode)
                and link.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID))
            or not stat.S_ISREG(binary.st_mode) or binary.st_uid != 0
            or binary.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
            or not binary.st_mode & 0o111
            or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
            or parent.st_mode & 0o022):
        raise CgroupGateError("Untrusted native candidate bootstrap interpreter")


def entry_argv(delegation: Delegation, leaf: Path,
               limited_command: list[str]) -> list[str]:
    """Construct an attach-BEFORE-exec wrapper, not a standalone launcher.

    The supervisor must allocate a unique, freshly limited candidate leaf,
    hold it throughout the child lifetime and kill/drain residual descendants.
    No untrusted process code can run until the bootstrap writes '0' to
    cgroup.procs, which attaches the calling process before os.execv.
    """
    if (leaf.parent != delegation.candidates
            or not re.fullmatch(r"candidate-[a-f0-9]{32}", leaf.name)):
        raise CgroupGateError("Candidate entry escapes approved cgroup subtree")
    _directory(leaf, owned=True)
    # Do not let the entry bootstrap become a generic same-UID executor.
    # Require the exact trusted prlimit flags and Bubblewrap argv generated
    # by the separate allowlisted candidate policy, with no missing ceilings.
    from repocache import candidate_sandbox
    try:
        separator = limited_command.index("--")
    except ValueError as exc:
        raise CgroupGateError("Missing canonical candidate limit separator") from exc
    wrapped = limited_command[separator + 1:]
    if (not wrapped or wrapped[0] != str(candidate_sandbox.BWRAP)
            or limited_command != candidate_sandbox._limited_command(wrapped)):
        raise CgroupGateError("Noncanonical limited Bubblewrap invocation")
    _trusted_interpreter(SYSTEM_PYTHON)
    if _read(leaf / "cgroup.procs").strip():
        raise CgroupGateError("Cannot attach to populated candidate leaf")
    for control, desired in LEAF_LIMITS.items():
        if _read(leaf / control).strip() != desired:
            raise CgroupGateError("Candidate resource limit is not enforced")
    procs = leaf / "cgroup.procs"
    try:
        if not stat.S_ISREG(procs.lstat().st_mode):
            raise CgroupGateError("Untrusted cgroup membership control")
    except OSError as exc:
        raise CgroupGateError("Missing cgroup membership control") from exc
    return [str(SYSTEM_PYTHON), "-I", "-S", "-c", _ENTRY_CODE,
            str(procs), *limited_command]


def kill_and_drain_leaf(delegation: Delegation, leaf: Path, *,
                        timeout: float = 5.0) -> None:
    """Kill all tasks in one owned candidate leaf, await empty, remove it.

    Only a caller already holding an exclusive fresh-leaf lease may invoke
    this function. It NEVER targets the service or candidates parent.
    The kernel owns the virtual files: rmdir removes the empty cgroup
    directly, without unlinking or recursively deleting any filesystem.
    """
    if (not isinstance(timeout, (float, int)) or isinstance(timeout, bool)
            or not 0 <= timeout <= 30):
        raise CgroupGateError("Invalid candidate cleanup deadline")
    if (leaf.parent != delegation.candidates
            or not re.fullmatch(r"candidate-[a-f0-9]{32}", leaf.name)):
        raise CgroupGateError("Candidate cleanup escapes approved subtree")
    _directory(delegation.candidates, owned=True)
    _directory(leaf, owned=True)
    kill = leaf / "cgroup.kill"
    events = leaf / "cgroup.events"
    try:
        if (not stat.S_ISREG(kill.lstat().st_mode)
                or not os.access(kill, os.W_OK)):
            raise CgroupGateError("Untrusted candidate kill controller")
        # Validate the event controller before sending a kill.
        event_lines = _read(events).splitlines()
        if not any(line in ("populated 0", "populated 1")
                   for line in event_lines):
            raise CgroupGateError("Unverifiable candidate population status")
        descriptor = os.open(
            kill, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if os.write(descriptor, b"1") != 1:
                raise CgroupGateError("Incomplete candidate cgroup kill")
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise CgroupGateError("Cannot terminate candidate cgroup") from exc

    deadline = time.monotonic() + timeout
    while True:
        status = _read(events).splitlines()
        if "populated 0" in status:
            break
        if "populated 1" not in status:
            raise CgroupGateError("Unverifiable candidate cgroup drain")
        if time.monotonic() >= deadline:
            raise CgroupGateError("Candidate cgroup remains populated")
        time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    try:
        leaf.rmdir()
    except OSError as exc:
        raise CgroupGateError("Cannot remove drained candidate cgroup") from exc


def _create_candidate_leaf(parent_fd: int, name: str) -> None:
    """Use exclusive mkdir relative to an open, no-follow cgroup parent."""
    os.mkdir(name, mode=0o700, dir_fd=parent_fd)


@contextmanager
def candidate_leaf(delegation: Delegation) -> Iterator[Path]:
    """Reserve exactly one private, limited leaf and always attempt cleanup.

    This source-only lifecycle primitive does not launch an untrusted process.
    A real supervisor must retain exclusive ownership of the leaf, use the
    pre-exec attachment bootstrap and verify group-wide resource/kill events.
    """
    if os.geteuid() == 0:
        raise CgroupGateError("Root cannot manage online candidate cgroups")
    if (delegation.manager != delegation.service / MANAGER_LEAF
            or delegation.candidates != delegation.service / CANDIDATE_SUBTREE):
        raise CgroupGateError("Noncanonical delegated candidate hierarchy")
    _directory(delegation.candidates, owned=True)

    # A fresh unpredictable name and kernel-atomic mkdir avoid reuse and
    # cross-candidate collisions. Never take over an existing candidate leaf.
    name = "candidate-" + secrets.token_hex(16)
    if not re.fullmatch(r"candidate-[a-f0-9]{32}", name):
        raise CgroupGateError("Invalid candidate cgroup reservation token")

    try:
        parent_fd = os.open(
            delegation.candidates,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise CgroupGateError("Cannot open candidate cgroup delegation") from exc
    try:
        parent_stat = os.fstat(parent_fd)
        if (not stat.S_ISDIR(parent_stat.st_mode)
                or parent_stat.st_uid != os.geteuid()
                or parent_stat.st_mode & 0o022):
            raise CgroupGateError("Untrusted open cgroup parent")
        try:
            _create_candidate_leaf(parent_fd, name)
        except OSError as exc:
            raise CgroupGateError(
                "Cannot exclusively reserve candidate cgroup leaf") from exc
    finally:
        os.close(parent_fd)

    leaf = delegation.candidates / name
    # Even if resource setup fails, the newly reserved leaf must be killed,
    # drained and removed. Never adopt or delete an existing collided leaf.
    try:
        write_leaf_limits(delegation, leaf)
        yield leaf
    finally:
        kill_and_drain_leaf(delegation, leaf)
