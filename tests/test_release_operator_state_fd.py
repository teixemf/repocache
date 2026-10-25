"""Fail-closed local state inode checks for the optional release operator (#88).

These tests never use signing keys, network, GitHub releases or publish APIs.
"""
from __future__ import annotations

import os
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


def test_state_reads_open_inode_not_replacement_path(monkeypatch, tmp_path):
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
    assert release.read_state("v0.5.0") == record
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


def test_asset_digest_reads_opened_inode_after_path_replacement(monkeypatch, tmp_path):
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
    assert release.digest(asset) == hashlib.sha256(original).hexdigest()
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


def test_checksum_read_accepts_small_ascii_and_opened_inode(monkeypatch, tmp_path):
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
    assert release.read_checksum(path) == original
    assert swapped
    assert path.read_text() == "untrusted replacement"


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
                               st_nlink=st.st_nlink)

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
