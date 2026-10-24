"""Isolated Linux dirfd source preflight security tests (#24).

All fixture writes target test-private /tmp directories, never native /etc.
The preflight module itself must not expose or mutate source bytes.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import stat
from pathlib import Path

import pytest


MODULE = Path(__file__).resolve().parents[1] / "client" / "source_preflight.py"
spec = importlib.util.spec_from_file_location("source_preflight_under_test", MODULE)
pre = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(pre)

DATA = b"deb https://deb.debian.org/debian trixie main\n"
LIST = "etc/apt/sources.list.d/ci.list"
DEB822 = "etc/apt/sources.list.d/ci.sources"
DNF = "etc/yum.repos.d/ci.repo"
MIRRORS = "etc/apt/mirrors/repocache"


@pytest.fixture()
def root(tmp_path):
    tmp_path.chmod(0o700)
    marker = tmp_path / pre.MARKER
    marker.write_bytes(pre.TEST_MAGIC)
    marker.chmod(0o600)
    for parent in ("etc/apt/sources.list.d", "etc/yum.repos.d", "etc/apt/mirrors"):
        (tmp_path / parent).mkdir(parents=True, exist_ok=True)
    for relative, content in (
        (LIST, DATA),
        (DEB822, b"Types: deb\nURIs: https://deb.debian.org/debian\n"
                 b"Suites: trixie\nComponents: main\n"),
        (DNF, b"[ci]\nbaseurl=https://rpm.example.org/linux/\ngpgcheck=1\n"),
        (MIRRORS, b"https://cache.example.org/repo/ priority:1\n"
                  b"https://upstream.example.org/repo/ priority:2\n"),
    ):
        (tmp_path / relative).write_bytes(content)
    return tmp_path


@pytest.mark.parametrize("source", [LIST, DEB822, DNF, MIRRORS])
def test_read_only_inspection_with_private_trusted_root(root, source):
    file = root / source
    before = file.stat()
    contents = file.read_bytes()
    result = pre.inspect_source(source, root=root)
    assert result["source"] == source
    assert result["sha256"] == hashlib.sha256(contents).hexdigest()
    assert result["size"] == len(contents)
    assert result["inode"] == before.st_ino
    assert result["mode"] == stat.S_IMODE(before.st_mode)
    assert result["write_eligible"] is False
    assert result["write_blocker"] == "privileged-writer-not-implemented"
    assert file.read_bytes() == contents
    assert file.stat().st_ino == before.st_ino
    assert contents.decode() not in repr(result)


@pytest.mark.parametrize("source", [
    "/etc/apt/sources.list", "etc/apt/../yum.repos.d/foo.repo",
    "etc/apt/sources.list.d/.hidden.list",
    "etc/apt/sources.list.d/file.conf",
    "etc/yum.repos.d/../../etc/shadow",
    "etc/apt/mirrors/../sources.list",
    "etc/passwd", "etc/yum.repos.d/foo.repo\0",
    "etc/apt/sources.list.d/subdir/ci.list",
])
def test_reject_path_escape_and_unknown_formats(root, source):
    with pytest.raises(pre.PreflightError, match="allowlist"):
        pre.inspect_source(source, root=root)


def test_missing_private_marker_fails_before_source_access(root):
    (root / pre.MARKER).unlink()
    with pytest.raises(pre.PreflightError, match="marker"):
        pre.inspect_source(LIST, root=root)


@pytest.mark.parametrize("mutation", ["symlink", "mode", "contents", "hardlink"])
def test_malformed_private_marker_rejected(root, mutation):
    marker = root / pre.MARKER
    if mutation == "symlink":
        marker.unlink()
        marker.symlink_to(root / LIST)
    elif mutation == "mode":
        marker.chmod(0o644)
    elif mutation == "contents":
        marker.write_bytes(b"x")
    else:
        os.link(marker, root / "other-marker")
    with pytest.raises(pre.PreflightError):
        pre.inspect_source(LIST, root=root)


def test_symlinked_parent_not_followed(root):
    parent = root / "etc/apt/sources.list.d"
    parent.rename(root / "etc/apt/source-real")
    parent.symlink_to(root / "etc/apt/source-real", target_is_directory=True)
    with pytest.raises(pre.PreflightError, match="source directory"):
        pre.inspect_source(LIST, root=root)


def test_symlinked_leaf_not_followed(root):
    path = root / LIST
    path.unlink()
    path.symlink_to(root / DNF)
    with pytest.raises(pre.PreflightError, match="source file"):
        pre.inspect_source(LIST, root=root)


def test_hardlink_not_followed(root):
    file = root / LIST
    os.link(file, file.parent / "other.list")
    with pytest.raises(pre.PreflightError, match="source inode"):
        pre.inspect_source(LIST, root=root)


@pytest.mark.parametrize("mode", [0o666, 0o664, 0o777])
def test_source_group_or_world_writable_rejected(root, mode):
    (root / LIST).chmod(mode)
    with pytest.raises(pre.PreflightError, match="source inode"):
        pre.inspect_source(LIST, root=root)


def test_writable_source_directory_rejected(root):
    (root / "etc/apt/sources.list.d").chmod(0o777)
    with pytest.raises(pre.PreflightError, match="source directory"):
        pre.inspect_source(LIST, root=root)


def test_unmarked_arbitrary_root_is_not_accepted(root):
    other = root / "nested"
    other.mkdir(mode=0o700)
    with pytest.raises(pre.PreflightError, match="marker"):
        pre.inspect_source(LIST, root=other)


def test_unhandled_xattrs_flagged_as_not_eligible(root):
    path = root / LIST
    try:
        os.setxattr(path, "user.repocache-test", b"secret-value")
    except (OSError, AttributeError):
        pytest.skip("test fixture filesystem does not support user xattrs")
    result = pre.inspect_source(LIST, root=root)
    assert result["extended_attributes_present"] is True
    assert result["write_eligible"] is False
    assert result["write_blocker"] == "security-metadata-preservation-not-implemented"
    assert "secret-value" not in repr(result)
    assert os.getxattr(path, "user.repocache-test") == b"secret-value"


def test_empty_source_is_bounded_and_hashed(root):
    (root / LIST).write_bytes(b"")
    result = pre.inspect_source(LIST, root=root)
    assert result["size"] == 0
    assert result["sha256"] == hashlib.sha256(b"").hexdigest()


def test_source_size_limit_rejects_without_mutation(root):
    path = root / LIST
    path.write_bytes(b"x" * (pre.MAX_SOURCE_BYTES + 1))
    with pytest.raises(pre.PreflightError, match="size"):
        pre.inspect_source(LIST, root=root)
    assert path.stat().st_size == pre.MAX_SOURCE_BYTES + 1


def test_external_inode_replacement_during_read_detected(root, monkeypatch):
    original_read = pre.os.read
    swapped = False

    def replace_after_read(fd, length):
        nonlocal swapped
        data = original_read(fd, length)
        # The test marker was read first; this only triggers after source open.
        if length == min(65536, pre.MAX_SOURCE_BYTES + 1) and not swapped:
            swapped = True
            new = root / "other-temp"
            new.write_bytes(DATA)
            os.replace(new, root / LIST)
        return data

    monkeypatch.setattr(pre.os, "read", replace_after_read)
    with pytest.raises(pre.PreflightError, match="drift"):
        pre.inspect_source(LIST, root=root)
    assert swapped
    assert (root / LIST).read_bytes() == DATA


def test_file_descriptor_flags_block_symlink_and_write_intent():
    assert pre.FILE_FLAGS & os.O_NOFOLLOW
    assert pre.FILE_FLAGS & os.O_RDONLY == 0  # O_RDONLY is zero on Linux.
    assert pre.FILE_FLAGS & os.O_NONBLOCK
    assert pre.DIR_FLAGS & os.O_DIRECTORY


def test_native_root_requires_root_authorization(monkeypatch):
    monkeypatch.setattr(pre.os, "geteuid", lambda: 1001)
    with pytest.raises(pre.PreflightError, match="Root authorization"):
        pre.inspect_source(LIST, root=Path("/"))
