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
