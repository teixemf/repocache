"""Root-owned lock pathname and inode validation, independent of updater mocks.

Unit fixtures substitute their process owner for root; actual root:service
permission boundaries are exercised in disposable native Docker smoke.
"""
import fcntl
import os
from pathlib import Path

import pytest
from repocache import recovery


@pytest.fixture
def secure_dir(tmp_path):
    tmp_path.chmod(0o700)
    managed = tmp_path / "managed"
    managed.mkdir(mode=0o700)
    lock = tmp_path / ".updater.lock"
    lock.touch(mode=0o440)
    lock.chmod(0o440)
    return managed, lock


def acquire(root):
    return recovery.acquire_update_lock(
        root, expected_owner=os.geteuid(), expected_group=os.getegid())


def test_fixed_parent_lock_can_be_acquired_read_only(secure_dir):
    root, lock = secure_dir
    fd = acquire(root)
    try:
        assert Path(f"/proc/self/fd/{fd}").resolve() == lock
        assert (fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE) == os.O_RDONLY
        with pytest.raises(recovery.RecoveryBusy):
            acquire(root)
    finally:
        os.close(fd)
    fd = acquire(root)
    os.close(fd)


@pytest.mark.parametrize("mutation", [
    "missing", "symlink", "hardlink", "writable", "wrong-mode", "parent-write"
])
def test_unsafe_inode_or_parent_fails_closed(secure_dir, mutation):
    root, lock = secure_dir
    if mutation == "missing":
        lock.unlink()
    elif mutation == "symlink":
        lock.unlink()
        target = lock.parent / "other-file"
        target.write_bytes(b"canary")
        lock.symlink_to(target)
    elif mutation == "hardlink":
        os.link(lock, lock.parent / "other-hardlink")
    elif mutation == "writable":
        lock.chmod(0o660)
    elif mutation == "wrong-mode":
        lock.chmod(0o400)
    else:
        root.parent.chmod(0o770)
    with pytest.raises(recovery.RecoveryError):
        acquire(root)


def test_lock_parent_is_not_managed_service_state(secure_dir):
    root, lock = secure_dir
    assert lock.parent == root.parent
    assert lock != root / ".updater.lock"
    assert str(recovery.LOCK_FILE) == "/opt/repocache-cli/.updater.lock"
    assert not (root / ".updater.lock").exists()
