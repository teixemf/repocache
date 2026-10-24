"""Adversarial sandbox-only source metadata round-trip tests.

The source path is NEVER replaced. The disposable hidden clone is isolated
inside a test-private /tmp root, not a deployed APT/DNF configuration file.
"""
from __future__ import annotations

import hashlib
import importlib
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


CLIENT = Path(__file__).resolve().parents[1] / "client"
sys.path.insert(0, str(CLIENT))
lab = importlib.import_module("source_metadata_lab")
pre = importlib.import_module("source_preflight")
APT = "etc/apt/sources.list.d/ci.sources"
DNF = "etc/yum.repos.d/ci.repo"
APT_BYTES = b"Types: deb\nURIs: https://deb.debian.org/debian\nSuites: trixie\nComponents: main\n"
DNF_BYTES = b"[ci]\nbaseurl=https://rpm.example.org/\ngpgcheck=1\n"


@pytest.fixture
def root(tmp_path):
    tmp_path.chmod(0o700)
    marker = tmp_path / pre.MARKER
    marker.write_bytes(pre.TEST_MAGIC)
    marker.chmod(0o600)
    for relative, data in ((APT, APT_BYTES), (DNF, DNF_BYTES)):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return tmp_path


def clone_file(root, relative):
    result = lab.clone_sandbox_source(root, relative)
    return result, root / Path(relative).parent / result["clone_name"]


def test_no_attributes_roundtrip_on_both_formats(root):
    for relative, original in ((APT, APT_BYTES), (DNF, DNF_BYTES)):
        source = root / relative
        before = source.stat()
        result, clone = clone_file(root, relative)
        assert clone.read_bytes() == original
        assert result["sha256"] == hashlib.sha256(original).hexdigest()
        assert result["source_unmodified"] is True
        assert result["production_apply_eligible"] is False
        assert result["attribute_count"] == 0
        assert source.read_bytes() == original
        assert source.stat().st_ino == before.st_ino
        assert clone.stat().st_ino != before.st_ino
        assert clone.name.startswith(lab.TEMP_PREFIX)
        clone.unlink()


def test_user_xattrs_are_preserved_without_leaking_values(root):
    original = root / APT
    try:
        os.setxattr(original, "user.repocache-ci", b"secret-value")
        os.setxattr(original, "user.repocache-flag", b"\x00\xff\x01")
    except OSError:
        pytest.skip("Filesystem does not support user xattrs")
    before = original.stat()
    result, clone = clone_file(root, APT)
    assert result["attribute_count"] == 2
    assert "secret-value" not in repr(result)
    assert "user.repocache-ci" not in repr(result)
    assert os.getxattr(clone, "user.repocache-ci") == b"secret-value"
    assert os.getxattr(clone, "user.repocache-flag") == b"\x00\xff\x01"
    assert original.stat().st_ino == before.st_ino
    assert original.read_bytes() == APT_BYTES
    clone.unlink()


def test_posix_access_acl_is_preserved_with_native_setfacl(root):
    command = shutil.which("setfacl")
    if command is None:
        pytest.skip("setfacl not available (required in native metadata CI)")
    original = root / APT
    subprocess.run([command, "-m", "u:65534:r", str(original)],
                   check=True, capture_output=True, timeout=10)
    assert "system.posix_acl_access" in os.listxattr(original)
    before_acl = os.getxattr(original, "system.posix_acl_access")
    mode = original.stat().st_mode & 0o777
    result, clone = clone_file(root, APT)
    assert result["contains_posix_access_acl"] is True
    assert clone.stat().st_mode & 0o777 == mode
    assert os.getxattr(clone, "system.posix_acl_access") == before_acl
    assert os.getxattr(original, "system.posix_acl_access") == before_acl
    clone.unlink()


def test_combined_user_attribute_and_posix_acl(root):
    if not shutil.which("setfacl"):
        pytest.skip("native POSIX ACL utility missing")
    source = root / DNF
    subprocess.run(["setfacl", "-m", "u:65534:r", str(source)],
                   check=True, timeout=10, capture_output=True)
    os.setxattr(source, "user.note", b"private")
    result, clone = clone_file(root, DNF)
    assert result["attribute_count"] == 2
    assert result["contains_posix_access_acl"]
    for key in os.listxattr(source):
        assert os.getxattr(source, key) == os.getxattr(clone, key)
    clone.unlink()


def test_reject_invalid_path_or_unmarked_root(root):
    with pytest.raises(pre.PreflightError, match="Unapproved"):
        lab.clone_sandbox_source(root, "../etc/passwd")
    (root / pre.MARKER).unlink()
    with pytest.raises(pre.PreflightError, match="marker"):
        lab.clone_sandbox_source(root, APT)
    with pytest.raises(pre.PreflightError, match="restricted|fixture|/tmp"):
        lab.clone_sandbox_source(Path("/"), APT)


def test_reject_source_symlink_hardlink_and_external_mode(root):
    path = root / APT
    os.link(path, path.parent / "linked.sources")
    with pytest.raises(pre.PreflightError, match="inode"):
        lab.clone_sandbox_source(root, APT)
    (path.parent / "linked.sources").unlink()
    path.chmod(0o666)
    with pytest.raises(pre.PreflightError, match="inode"):
        lab.clone_sandbox_source(root, APT)
    path.chmod(0o644)
    path.unlink()
    path.symlink_to(root / DNF)
    with pytest.raises(pre.PreflightError, match="source"):
        lab.clone_sandbox_source(root, APT)


def test_refuse_security_selinux_label_even_without_actual_host_selinux(root, monkeypatch):
    real = lab.os.listxattr
    def mocked(path):
        value = real(path)
        # Only inject when the source FD is inspected; not the fixture marker.
        return value + ["security.selinux"]
    monkeypatch.setattr(lab.os, "listxattr", mocked)
    with pytest.raises(pre.PreflightError, match="Security label"):
        lab.clone_sandbox_source(root, APT)
    assert not list((root / "etc/apt/sources.list.d").glob(lab.TEMP_PREFIX + "*"))


def test_refuse_unknown_trusted_or_security_namespace(root, monkeypatch):
    original = lab.os.listxattr
    monkeypatch.setattr(lab.os, "listxattr", lambda fd: original(fd) + ["trusted.unreviewed"])
    with pytest.raises(pre.PreflightError, match="unsupported"):
        lab.clone_sandbox_source(root, APT)


def test_reject_too_many_attributes(root, monkeypatch):
    original = lab.os.listxattr
    monkeypatch.setattr(lab.os, "listxattr",
                        lambda fd: original(fd) + [f"user.fake-{i}" for i in range(lab.MAX_ATTRS + 1)])
    with pytest.raises(pre.PreflightError, match="Too many"):
        lab.clone_sandbox_source(root, APT)


def test_metadata_value_limit_refused_and_source_unchanged(root, monkeypatch):
    real_list = lab.os.listxattr
    real_get = lab.os.getxattr
    monkeypatch.setattr(lab.os, "listxattr", lambda fd: real_list(fd) + ["user.synthetic"])
    def oversized(fd, name):
        return b"x" * (lab.MAX_ATTRIBUTE_BYTES + 1) if name == "user.synthetic" else real_get(fd, name)
    monkeypatch.setattr(lab.os, "getxattr", oversized)
    with pytest.raises(pre.PreflightError, match="limits"):
        lab.clone_sandbox_source(root, APT)
    assert (root / APT).read_bytes() == APT_BYTES


def test_source_xattr_drift_after_clone_creation_removes_incomplete_clone(root, monkeypatch):
    source = root / APT
    original = lab.os.fchmod
    changed = False
    def external_change(fd, mode):
        nonlocal changed
        original(fd, mode)
        if not changed:
            changed = True
            os.setxattr(source, "user.external", b"changed")
    monkeypatch.setattr(lab.os, "fchmod", external_change)
    with pytest.raises(pre.PreflightError, match="Source changed"):
        lab.clone_sandbox_source(root, APT)
    assert changed
    assert (root / APT).read_bytes() == APT_BYTES
    assert not list((root / APT).parent.glob(lab.TEMP_PREFIX + "*"))


def test_copy_failure_deletes_temporary_output(root, monkeypatch):
    os.setxattr(root / APT, "user.repocache", b"value")
    def unavailable(fd, name, value):
        raise OSError("xattr not supported")
    monkeypatch.setattr(lab.os, "setxattr", unavailable)
    with pytest.raises(pre.PreflightError, match="not supported"):
        lab.clone_sandbox_source(root, APT)
    assert not list((root / APT).parent.glob(lab.TEMP_PREFIX + "*"))
    assert os.getxattr(root / APT, "user.repocache") == b"value"
