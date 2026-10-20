"""Regression checks for untrusted installed virtualenv paths (#35).

These checks establish structural path safety. A compromised service account
can modify both its virtualenv and mutable manifest; authentication of existing
bytes is therefore never inferred from this inventory or file existence.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from repocache import updater


@pytest.fixture
def active(monkeypatch, tmp_path):
    root = tmp_path / "managed"
    root.mkdir(mode=0o700)
    releases = root / "releases"
    releases.mkdir(mode=0o700)
    version = "0.4.0"
    digest = "a" * 64
    target = releases / (version + "-" + digest[:12] + "-fixture")
    (target / "bin").mkdir(parents=True, mode=0o700)
    binary = target / "bin" / "repocache"
    binary.write_bytes(b"#!/bin/sh\n# not executed by path checks\n")
    binary.chmod(0o700)
    (root / "current").symlink_to(target)
    monkeypatch.setattr(updater, "ROOT", root)
    monkeypatch.setattr(updater, "CURRENT", root / "current")
    return root, target, binary, {"version": version, "source_digest": digest}


def test_structurally_safe_installed_generation(active):
    root, target, binary, installed = active
    updater._check_active_layout(installed)
    assert binary.read_bytes().endswith(b"path checks\n")


@pytest.mark.parametrize("mutation", [
    "escaped-current", "relative-current", "swapped-generation", "wrong-version",
    "wrong-digest", "symlink-generation", "symlink-bin",
    "symlink-executable", "hardlink-executable", "world-writable-executable",
    "world-writable-bin", "world-writable-releases", "missing-executable",
])
def test_untrusted_active_environment_fails_closed(active, tmp_path, mutation):
    root, target, binary, installed = active
    canary = tmp_path / "canary"
    canary.write_text("do not overwrite")
    if mutation == "escaped-current":
        (root / "current").unlink()
        (root / "current").symlink_to(canary)
    elif mutation == "relative-current":
        (root / "current").unlink()
        (root / "current").symlink_to("releases/" + target.name)
    elif mutation == "swapped-generation":
        (root / "current").unlink()
        (root / "current").symlink_to(root / "releases" / "other-generation")
    elif mutation == "wrong-version":
        installed["version"] = "0.5.0"
    elif mutation == "wrong-digest":
        installed["source_digest"] = "b" * 64
    elif mutation == "symlink-generation":
        (root / "current").unlink()
        other = tmp_path / "other"
        other.mkdir()
        target.rename(other / "real")
        target.symlink_to(other / "real")
        (root / "current").symlink_to(target)
    elif mutation == "symlink-bin":
        other = tmp_path / "outside-bin"
        (target / "bin").rename(other)
        (target / "bin").symlink_to(other)
    elif mutation == "symlink-executable":
        binary.unlink()
        binary.symlink_to(canary)
    elif mutation == "hardlink-executable":
        os.link(binary, target / "bin/other")
    elif mutation == "world-writable-executable":
        binary.chmod(0o722)
    elif mutation == "world-writable-bin":
        (target / "bin").chmod(0o777)
    elif mutation == "world-writable-releases":
        (root / "releases").chmod(0o777)
    else:
        binary.unlink()
    with pytest.raises(updater.UpdateError):
        updater._check_active_layout(installed)
    assert canary.read_text() == "do not overwrite"


@pytest.mark.parametrize("mutation", [
    "symlink-bin", "symlink-executable", "writable-staging", "hardlink-executable"
])
def test_staging_refuses_path_redirection_before_execution(active, tmp_path, mutation):
    _, destination, binary, _ = active
    canary = tmp_path / "canary"
    canary.write_text("protected")
    if mutation == "symlink-bin":
        (destination / "bin").rename(tmp_path / "bin-real")
        (destination / "bin").symlink_to(tmp_path / "bin-real")
    elif mutation == "symlink-executable":
        binary.unlink()
        binary.symlink_to(canary)
    elif mutation == "writable-staging":
        destination.chmod(0o777)
    else:
        os.link(binary, destination / "bin/extra")
    with pytest.raises(updater.UpdateError):
        updater._check_staged_layout(destination)
    assert canary.read_text() == "protected"


def test_clean_install_refuses_preexisting_active_link(active):
    _, _, _, _ = active
    with pytest.raises(updater.UpdateError, match="Unexpected active environment"):
        updater._check_active_layout({"version": "0.0.0"})


def test_missing_runtime_is_not_a_trusted_same_version(active):
    _, _, binary, installed = active
    binary.unlink()
    with pytest.raises(updater.UpdateError, match="missing"):
        updater._check_active_layout(installed)
