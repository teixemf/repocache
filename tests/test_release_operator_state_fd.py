"""Fail-closed local state inode checks for the optional release operator (#88).

These tests never use signing keys, network, GitHub releases or publish APIs.
"""
from __future__ import annotations

import os
import select
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "workstation/src"))
from repocache_release import cli as release


def _state(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    version = "v0.5.0"
    release.state_root().mkdir(mode=0o700)
    record = {
        "schema": 1, "version": version, "commit": "a" * 40,
        "run_id": 123, "attempt": 1, "phase": "prepared",
        "assets": {name: "b" * 64 for name in release.files_for(version)},
    }
    release.save_state(version, record)
    return release.state_file(version), record


def test_state_refuses_hardlinked_private_record(monkeypatch, tmp_path):
    path, record = _state(monkeypatch, tmp_path)
    assert release.read_state("v0.5.0") == record
    os.link(path, path.with_name("another-link.json"))
    with pytest.raises(release.OperatorError) as caught:
        release.read_state("v0.5.0")
    assert caught.value.code == "UNSAFE_STATE"


def test_state_refuses_symlink_swapped_at_open(monkeypatch, tmp_path):
    path, _ = _state(monkeypatch, tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text('{"not": "a release state"}')
    original_open = os.open
    swapped = False

    def replace_before_open(file, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if os.fspath(file) == os.fspath(path) and not swapped:
            swapped = True
            path.rename(path.with_name("original.json"))
            path.symlink_to(outside)
        if dir_fd is None:
            return original_open(file, flags, mode)
        return original_open(file, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(release.os, "open", replace_before_open)
    with pytest.raises(release.OperatorError) as caught:
        release.read_state("v0.5.0")
    assert swapped
    assert caught.value.code == "UNSAFE_STATE"
    assert outside.read_text() == '{"not": "a release state"}'


def test_state_refuses_path_replacement_after_open(monkeypatch, tmp_path):
    path, record = _state(monkeypatch, tmp_path)
    original_open = os.open
    swapped = False

    def replace_after_open(file, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if dir_fd is None:
            fd = original_open(file, flags, mode)
        else:
            fd = original_open(file, flags, mode, dir_fd=dir_fd)
        if os.fspath(file) == os.fspath(path) and not swapped:
            swapped = True
            path.rename(path.with_name("original.json"))
            path.write_text('{"untrusted": true}')
        return fd

    monkeypatch.setattr(release.os, "open", replace_after_open)
    with pytest.raises(release.OperatorError) as caught:
        release.read_state("v0.5.0")
    assert caught.value.code == "UNSAFE_STATE"
    assert swapped
    assert path.read_text() == '{"untrusted": true}'

def test_state_refuses_fifo_swapped_before_open_without_blocking(monkeypatch, tmp_path):
    """A FIFO substituted for the JSON record must not block before fstat."""
    path, _ = _state(monkeypatch, tmp_path)
    original_open = os.open
    swapped = False

    def replace_before_open(file, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if os.fspath(file) == os.fspath(path) and not swapped:
            swapped = True
            # Fail the test before a blocking open if this protection regresses.
            assert flags & os.O_NONBLOCK, "state read must open nonblocking"
            path.rename(path.with_name("original.json"))
            os.mkfifo(path, mode=0o600)
        if dir_fd is None:
            return original_open(file, flags, mode)
        return original_open(file, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(release.os, "open", replace_before_open)
    with pytest.raises(release.OperatorError) as caught:
        release.read_state("v0.5.0")
    assert swapped
    assert caught.value.code == "UNSAFE_STATE"
    assert path.is_fifo()


def test_asset_digest_refuses_symlink_swapped_at_open(monkeypatch, tmp_path):
    """The release operator must never hash a substituted private-file link."""
    import hashlib
    asset = tmp_path / "candidate.tar.gz"
    asset.write_bytes(b"original unsigned candidate")
    private = tmp_path / "private-secret"
    private.write_bytes(b"not an asset")
    original_open = os.open
    swapped = False

    def replace_before_open(file, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if os.fspath(file) == os.fspath(asset) and not swapped:
            swapped = True
            assert flags & os.O_NOFOLLOW
            asset.unlink()
            asset.symlink_to(private)
        if dir_fd is None:
            return original_open(file, flags, mode)
        return original_open(file, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(release.os, "open", replace_before_open)
    with pytest.raises(release.OperatorError) as caught:
        release.digest(asset)
    assert swapped and caught.value.code == "UNSAFE_ASSET"
    assert private.read_bytes() == b"not an asset"


def test_asset_digest_refuses_path_replacement_after_open(monkeypatch, tmp_path):
    """A changed pathname after open cannot change the bytes being hashed."""
    import hashlib
    asset = tmp_path / "candidate.tar.gz"
    original = b"approved unsigned candidate bytes"
    asset.write_bytes(original)
    original_open = os.open
    swapped = False

    def replace_after_open(file, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if dir_fd is None:
            fd = original_open(file, flags, mode)
        else:
            fd = original_open(file, flags, mode, dir_fd=dir_fd)
        if os.fspath(file) == os.fspath(asset) and not swapped:
            swapped = True
            asset.rename(tmp_path / "old-candidate")
            asset.write_bytes(b"substituted candidate")
        return fd

    monkeypatch.setattr(release.os, "open", replace_after_open)
    with pytest.raises(release.OperatorError) as caught:
        release.digest(asset)
    assert caught.value.code == "UNSAFE_ASSET"
    assert swapped and asset.read_bytes() == b"substituted candidate"


def test_asset_digest_refuses_fifo_swapped_at_open(monkeypatch, tmp_path):
    """Reject a FIFO before a blocking read or a misleading size check."""
    asset = tmp_path / "candidate.tar.gz"
    asset.write_bytes(b"original")
    original_open = os.open
    swapped = False

    def replace_before_open(file, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if os.fspath(file) == os.fspath(asset) and not swapped:
            swapped = True
            assert flags & os.O_NONBLOCK
            asset.unlink()
            os.mkfifo(asset, mode=0o600)
        if dir_fd is None:
            return original_open(file, flags, mode)
        return original_open(file, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(release.os, "open", replace_before_open)
    with pytest.raises(release.OperatorError) as caught:
        release.digest(asset)
    assert swapped and caught.value.code == "UNSAFE_ASSET"
    assert asset.is_fifo()


def test_asset_digest_refuses_hardlinked_inode(monkeypatch, tmp_path):
    asset = tmp_path / "candidate.tar.gz"
    asset.write_bytes(b"original")
    os.link(asset, tmp_path / "second-link")
    with pytest.raises(release.OperatorError) as caught:
        release.digest(asset)
    assert caught.value.code == "UNSAFE_ASSET"


def test_asset_digest_rechecks_limit_during_read(monkeypatch, tmp_path):
    """A stale size observation cannot permit reading past the hard cap."""
    asset = tmp_path / "candidate.tar.gz"
    asset.write_bytes(b"12345")
    monkeypatch.setattr(release, "MAX_ASSET", 4)
    real_fstat = os.fstat
    from types import SimpleNamespace

    def stale_size(fd):
        st = real_fstat(fd)
        return SimpleNamespace(st_mode=st.st_mode, st_size=4,
                               st_nlink=st.st_nlink)

    monkeypatch.setattr(release.os, "fstat", stale_size)
    with pytest.raises(release.OperatorError) as caught:
        release.digest(asset)
    assert caught.value.code == "UNSAFE_ASSET"


def test_checksum_read_refuses_path_replacement_after_open(monkeypatch, tmp_path):
    path = tmp_path / "candidate.sha256"
    original = "a" * 64 + "  candidate.tar.gz\n"
    path.write_text(original, encoding="ascii")
    real_open = os.open
    swapped = False

    def replace_after_open(file, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        fd = (real_open(file, flags, mode) if dir_fd is None
              else real_open(file, flags, mode, dir_fd=dir_fd))
        if os.fspath(file) == os.fspath(path) and not swapped:
            swapped = True
            path.rename(tmp_path / "original.sha256")
            path.write_text("untrusted replacement", encoding="ascii")
        return fd

    monkeypatch.setattr(release.os, "open", replace_after_open)
    with pytest.raises(release.OperatorError) as caught:
        release.read_checksum(path)
    assert caught.value.code == "UNSAFE_ASSET"
    assert swapped
    assert path.read_text() == "untrusted replacement"



def test_checksum_read_accepts_stable_small_ascii_file(tmp_path):
    path = tmp_path / "candidate.sha256"
    expected = "a" * 64 + "  candidate.tar.gz\n"
    path.write_text(expected, encoding="ascii")
    assert release.read_checksum(path) == expected


def test_asset_digest_refuses_inplace_growth_during_stream(monkeypatch, tmp_path):
    """An opened inode changing mid-hash must not be reported as verified."""
    asset = tmp_path / "candidate.tar.gz"
    asset.write_bytes(b"original unsigned bytes")
    original_fdopen = os.fdopen
    mutated = False

    class MutatingReader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def read(self, size=-1):
            nonlocal mutated
            chunk = self.stream.read(size)
            if chunk and not mutated:
                mutated = True
                with asset.open("ab") as stream:
                    stream.write(b"unreviewed appended bytes")
            return chunk

    monkeypatch.setattr(release.os, "fdopen",
                        lambda fd, *a, **kw: MutatingReader(
                            original_fdopen(fd, *a, **kw)))
    with pytest.raises(release.OperatorError) as caught:
        release.digest(asset)
    assert mutated and caught.value.code == "UNSAFE_ASSET"


def test_checksum_read_refuses_symlink_swapped_at_open(monkeypatch, tmp_path):
    path = tmp_path / "candidate.sha256"
    path.write_text("a" * 64, encoding="ascii")
    private = tmp_path / "private-data"
    private.write_text("not a checksum")
    real_open = os.open
    swapped = False

    def replace_before_open(file, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if os.fspath(file) == os.fspath(path) and not swapped:
            swapped = True
            assert flags & os.O_NOFOLLOW
            path.unlink()
            path.symlink_to(private)
        return (real_open(file, flags, mode) if dir_fd is None
                else real_open(file, flags, mode, dir_fd=dir_fd))

    monkeypatch.setattr(release.os, "open", replace_before_open)
    with pytest.raises(release.OperatorError) as caught:
        release.read_checksum(path)
    assert swapped and caught.value.code == "UNSAFE_ASSET"
    assert private.read_text() == "not a checksum"


def test_checksum_read_refuses_fifo_swapped_at_open(monkeypatch, tmp_path):
    path = tmp_path / "candidate.sha256"
    path.write_text("a" * 64, encoding="ascii")
    real_open = os.open
    swapped = False

    def replace_before_open(file, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if os.fspath(file) == os.fspath(path) and not swapped:
            swapped = True
            assert flags & os.O_NONBLOCK, "FIFO checksum must never block"
            path.unlink()
            os.mkfifo(path, 0o600)
        return (real_open(file, flags, mode) if dir_fd is None
                else real_open(file, flags, mode, dir_fd=dir_fd))

    monkeypatch.setattr(release.os, "open", replace_before_open)
    with pytest.raises(release.OperatorError) as caught:
        release.read_checksum(path)
    assert swapped and caught.value.code == "UNSAFE_ASSET"
    assert path.is_fifo()


def test_checksum_read_refuses_hardlink_and_oversized_inode(tmp_path):
    path = tmp_path / "candidate.sha256"
    path.write_text("a" * 64, encoding="ascii")
    second = tmp_path / "second-link"
    os.link(path, second)
    with pytest.raises(release.OperatorError) as caught:
        release.read_checksum(path)
    assert caught.value.code == "UNSAFE_ASSET"
    second.unlink()
    path.write_bytes(b"a" * 513)
    with pytest.raises(release.OperatorError) as caught:
        release.read_checksum(path)
    assert caught.value.code == "UNSAFE_ASSET"


def test_checksum_read_rechecks_limit_after_stale_inode_size(monkeypatch, tmp_path):
    path = tmp_path / "candidate.sha256"
    path.write_bytes(b"a" * 513)
    real_fstat = os.fstat
    from types import SimpleNamespace

    def stale_size(fd):
        st = real_fstat(fd)
        return SimpleNamespace(st_mode=st.st_mode, st_size=512,
                               st_nlink=st.st_nlink, st_dev=st.st_dev,
                               st_ino=st.st_ino, st_mtime_ns=st.st_mtime_ns,
                               st_ctime_ns=st.st_ctime_ns)

    monkeypatch.setattr(release.os, "fstat", stale_size)
    with pytest.raises(release.OperatorError) as caught:
        release.read_checksum(path)
    assert caught.value.code == "UNSAFE_ASSET"


def test_state_refuses_excessively_nested_json_without_traceback(monkeypatch, tmp_path):
    path, _ = _state(monkeypatch, tmp_path)
    # Less than the 64 KiB size limit, but beyond typical JSON decoder depth.
    path.write_text("[" * 12000 + "0" + "]" * 12000, encoding="utf-8")
    with pytest.raises(release.OperatorError) as caught:
        release.read_state("v0.5.0")
    assert caught.value.code == "INVALID_STATE"


def test_state_maps_json_decoder_recursion_to_invalid_state(monkeypatch, tmp_path):
    _state(monkeypatch, tmp_path)

    def recursion_limit(_raw):
        raise RecursionError("decoder nesting exceeded")

    monkeypatch.setattr(release.json, "loads", recursion_limit)
    with pytest.raises(release.OperatorError) as caught:
        release.read_state("v0.5.0")
    assert caught.value.code == "INVALID_STATE"



def test_gh_json_refuses_excessively_nested_remote_json(monkeypatch):
    """A small but deeply nested remote response must fail as INVALID_RESPONSE."""
    payload = b"[" * 12000 + b"0" + b"]" * 12000
    monkeypatch.setattr(release, "command", lambda argv, **kwargs: payload)
    with pytest.raises(release.OperatorError) as caught:
        release.gh_json("repos/teixemf/repocache/actions/runs/123")
    assert caught.value.code == "INVALID_RESPONSE"


def test_gh_json_maps_decoder_recursion_to_invalid_response(monkeypatch):
    """Decoder recursion faults must not escape the CLI's finite error contract."""
    monkeypatch.setattr(release, "command",
                        lambda argv, **kwargs: b'{"ok": true}')

    def recurse(_raw):
        raise RecursionError("nested remote metadata")

    monkeypatch.setattr(release.json, "loads", recurse)
    with pytest.raises(release.OperatorError) as caught:
        release.gh_json("repos/teixemf/repocache/actions/runs/123")
    assert caught.value.code == "INVALID_RESPONSE"


# The release operator runs Git/GitHub/OpenSSL locally. Tests intercept the
# allowed command before spawn and execute a Python fixture instead: no GitHub
# token, network, private key, signature, stage or publication is used.
_COMMAND_FIXTURE = ["gh", "api", "repos/teixemf/repocache/actions/runs/1"]


def _local_command_fixture(monkeypatch, script):
    original = release.subprocess.Popen
    launched = []

    def launch(argv, **kwargs):
        assert argv == _COMMAND_FIXTURE
        assert kwargs["stdin"] == release.subprocess.DEVNULL
        assert kwargs["stderr"] == release.subprocess.DEVNULL
        child = original([sys.executable, "-c", script], **kwargs)
        launched.append(child)
        return child

    monkeypatch.setattr(release.subprocess, "Popen", launch)
    return launched


def test_command_fails_closed_on_stdout_flood_before_child_exit(monkeypatch):
    """A tool cannot fill unbounded parent memory before returning."""
    monkeypatch.setattr(release, "MAX_METADATA", 1024)
    children = _local_command_fixture(
        monkeypatch,
        'import sys,time;sys.stdout.buffer.write(b"x"*8192);'
        'sys.stdout.flush();time.sleep(10)')
    with pytest.raises(release.OperatorError) as caught:
        release.command(_COMMAND_FIXTURE, timeout=4)
    assert caught.value.code == "OVERSIZED_RESPONSE"
    assert len(children) == 1 and children[0].poll() is not None


def test_command_returns_small_output_and_discards_sensitive_stderr(monkeypatch):
    children = _local_command_fixture(
        monkeypatch,
        'import sys;sys.stdout.write("ok\\n");'
        'sys.stderr.write("sensitive stderr\\n")')
    assert release.command(_COMMAND_FIXTURE, timeout=4) == b"ok\n"
    assert len(children) == 1 and children[0].returncode == 0


def test_command_timeout_terminates_unresponsive_child(monkeypatch):
    children = _local_command_fixture(monkeypatch, 'import time;time.sleep(10)')
    with pytest.raises(release.OperatorError) as caught:
        release.command(_COMMAND_FIXTURE, timeout=0.2)
    assert caught.value.code == "TOOL_UNAVAILABLE"
    assert len(children) == 1 and children[0].poll() is not None


def test_command_nonzero_exit_remains_fail_closed(monkeypatch):
    children = _local_command_fixture(monkeypatch, 'import sys;sys.exit(7)')
    with pytest.raises(release.OperatorError) as caught:
        release.command(_COMMAND_FIXTURE, timeout=4)
    assert caught.value.code == "OPERATION_FAILED"
    assert len(children) == 1 and children[0].returncode == 7


def _unsigned_verifier_fixture(tmp_path):
    """Four harmless local placeholders; no candidate, signing or network."""
    import hashlib

    version = "v0.5.0"
    assets = tmp_path / "assets"
    assets.mkdir()
    base = "repocache-" + version + ".tar.gz"
    for suffix in ("", ".wheelhouse.tar.gz"):
        name = base + suffix
        payload = ("synthetic " + suffix).encode()
        (assets / name).write_bytes(payload)
        checksum = hashlib.sha256(payload).hexdigest() + "  " + name + "\n"
        (assets / (name + ".sha256")).write_text(checksum, encoding="ascii")
    return version, assets


def test_verify_unsigned_discards_verifier_output_and_limits_runtime(
        monkeypatch, tmp_path, capsys):
    """Verifier output is unused and must never be buffered or exposed."""
    version, assets = _unsigned_verifier_fixture(tmp_path)
    original_run = release.subprocess.run
    calls = []

    def local_verifier(argv, **kwargs):
        calls.append((argv, kwargs))
        assert kwargs["stdin"] == release.subprocess.DEVNULL
        assert kwargs["stdout"] == release.subprocess.DEVNULL
        assert kwargs["stderr"] == release.subprocess.DEVNULL
        assert kwargs["timeout"] == 180
        # Local-only fixture simulates a verifier flooding both streams.
        return original_run(
            [sys.executable, "-c",
             'import sys; sys.stdout.buffer.write(b"x"*5000000); '
             'sys.stderr.buffer.write(b"y"*5000000)'],
            **kwargs)

    monkeypatch.setattr(release.subprocess, "run", local_verifier)
    release.verify_unsigned(tmp_path, assets, version)
    assert len(calls) == 1
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("failure", ["timeout", "unavailable", "nonzero"])
def test_verify_unsigned_verifier_failures_are_sanitized(
        monkeypatch, tmp_path, failure):
    """Never surface a subprocess traceback or output on verifier failure."""
    version, assets = _unsigned_verifier_fixture(tmp_path)

    def failing_verifier(argv, **kwargs):
        if failure == "timeout":
            raise release.subprocess.TimeoutExpired(argv, kwargs["timeout"])
        if failure == "unavailable":
            raise OSError("fixture verifier unavailable")
        return release.subprocess.CompletedProcess(argv, 7)

    monkeypatch.setattr(release.subprocess, "run", failing_verifier)
    with pytest.raises(release.OperatorError) as caught:
        release.verify_unsigned(tmp_path, assets, version)
    assert caught.value.code == "BUILD_NOT_VERIFIED"
    assert str(caught.value) == (
        "Source rebuild or signed dependency-lock verification failed")


def test_state_rejects_symlinked_xdg_ancestor_before_creation(monkeypatch, tmp_path):
    """A private leaf under a redirected XDG parent is not trusted state."""
    actual = tmp_path / "actual-state-home"
    actual.mkdir(mode=0o700)
    alias = tmp_path / "linked-state-home"
    alias.symlink_to(actual, target_is_directory=True)
    monkeypatch.setenv("XDG_STATE_HOME", str(alias))
    with pytest.raises(release.OperatorError) as caught:
        release.guard_state_dir(release.state_root(), create=True)
    assert caught.value.code == "UNSAFE_STATE"
    assert not (actual / "repocache-release").exists()


@pytest.mark.parametrize("mode", [0o770, 0o777])
def test_state_rejects_nonroot_writable_xdg_ancestor(monkeypatch, tmp_path, mode):
    """An owner-controlled but shared writable parent is renameable."""
    parent = tmp_path / "shared-state-home"
    parent.mkdir()
    parent.chmod(mode)
    monkeypatch.setenv("XDG_STATE_HOME", str(parent))
    with pytest.raises(release.OperatorError) as caught:
        release.guard_state_dir(release.state_root(), create=True)
    assert caught.value.code == "UNSAFE_STATE"
    assert not (parent / "repocache-release").exists()


def test_candidate_lock_refuses_fifo_without_blocking(monkeypatch, tmp_path):
    """A malicious FIFO in place of a lock must not hang an owner operation."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    base = release.state_root()
    base.mkdir(mode=0o700)
    path = base / "v0.5.0.lock"
    os.mkfifo(path, mode=0o600)
    with pytest.raises(release.OperatorError) as caught:
        with release.candidate_lock("v0.5.0"):
            pytest.fail("FIFO must never acquire the release lock")
    assert caught.value.code == "UNSAFE_STATE"


def test_candidate_lock_refuses_named_inode_swapped_after_open(monkeypatch, tmp_path):
    """An inode lock no longer named by the path cannot serialize candidates."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    base = release.state_root()
    base.mkdir(mode=0o700)
    path = base / "v0.5.0.lock"
    real_open = os.open
    swapped = False

    def replace_after_open(file, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        fd = (real_open(file, flags, mode) if dir_fd is None
              else real_open(file, flags, mode, dir_fd=dir_fd))
        if os.fspath(file) == os.fspath(path) and not swapped:
            swapped = True
            assert flags & os.O_NONBLOCK
            path.rename(base / "detached.lock")
            path.write_bytes(b"new untrusted lock")
        return fd

    monkeypatch.setattr(release.os, "open", replace_after_open)
    with pytest.raises(release.OperatorError) as caught:
        with release.candidate_lock("v0.5.0"):
            pytest.fail("Detached lock must never protect a candidate")
    assert swapped and caught.value.code == "UNSAFE_STATE"
    assert path.read_bytes() == b"new untrusted lock"


def _release_subprocess_env(tmp_path):
    return dict(os.environ, XDG_STATE_HOME=str(tmp_path),
                PYTHONPATH=str(ROOT / "workstation/src"))


def test_candidate_lock_remains_exclusive_if_name_detached_mid_operation(tmp_path):
    """Two independent OS processes cannot acquire different same-version locks."""
    owner_script = """
import sys
from repocache_release.cli import candidate_lock, OperatorError
try:
    with candidate_lock("v0.5.0"):
        print("ENTERED", flush=True)
        sys.stdin.buffer.read(1)
except OperatorError as exc:
    print(exc.code, flush=True)
"""
    contender_script = """
from repocache_release.cli import candidate_lock, OperatorError
try:
    with candidate_lock("v0.5.0"):
        print("UNSAFE_DOUBLE_ENTRY", flush=True)
except OperatorError as exc:
    print(exc.code, flush=True)
"""
    env = _release_subprocess_env(tmp_path)
    first = subprocess.Popen(
        [sys.executable, "-c", owner_script], env=env, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert first.stdout is not None and first.stdin is not None
        assert select.select([first.stdout], [], [], 5)[0], "First lock timed out"
        assert first.stdout.readline() == b"ENTERED\n", (
            first.stderr.read() if first.poll() is not None else "No lock acquired")
        lock = tmp_path / "repocache-release" / "v0.5.0.lock"
        lock.rename(lock.with_name("detached.lock"))
        # A replacement pathname has a distinct inode, but B must not enter.
        lock.write_bytes(b"replacement")
        second = subprocess.run(
            [sys.executable, "-c", contender_script], env=env,
            capture_output=True, timeout=5, check=True)
        assert second.stdout.strip() == b"BUSY", second.stderr
        first.stdin.write(b"x")
        first.stdin.flush()
        assert first.wait(timeout=5) == 0
        assert first.stdout.read().strip() == b"UNSAFE_STATE"
    finally:
        if first.poll() is None:
            first.kill()
            first.wait(timeout=5)
        if first.stdin is not None:
            first.stdin.close()
        if first.stdout is not None:
            first.stdout.close()
        if first.stderr is not None:
            first.stderr.close()


def test_oversized_passphrase_pipe_refuses_without_waiting_for_writer_close(tmp_path):
    """4097 bytes are already an error; a second pipe read would deadlock."""
    script = """
import os
from repocache_release.cli import read_passphrase, OperatorError
reader, writer = os.pipe()
os.write(writer, b"x" * 4097)
try:
    read_passphrase(reader)
except OperatorError as exc:
    assert exc.code == "INVALID_SECRET_FD"
else:
    raise AssertionError("Oversized secret was accepted")
finally:
    os.close(reader)
    os.close(writer)
"""
    result = subprocess.run(
        [sys.executable, "-c", script], env=_release_subprocess_env(tmp_path),
        capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
