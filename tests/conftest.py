"""Trusted-lock fixtures for legacy rootless updater behavior tests.

Only legacy test modules use disposable same-process owner substitutes; the
production lock opener remains strictly root-owned. Separate lock security
tests exercise the real validation function without these substitutions.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

LEGACY_MODULES = {
    "test_updater", "test_updater_rollback", "test_update_journal",
    "test_update_concurrency",
}


@pytest.fixture(autouse=True)
def disposable_legacy_test_lock(request, monkeypatch):
    if request.module.__name__.rsplit(".", 1)[-1] not in LEGACY_MODULES:
        return
    from repocache import recovery
    original = recovery.acquire_update_lock

    def open_test_lock(root: Path):
        # Never create a lock at a production path in unit tests.
        if root == recovery.ROOT:
            return original(root)
        path = root.parent / ".updater.lock"
        if not path.exists() and not path.is_symlink():
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o400)
            try:
                os.fchmod(descriptor, 0o440)
            finally:
                os.close(descriptor)
        return original(root, expected_owner=os.geteuid(),
                        expected_group=os.getegid())

    monkeypatch.setattr(recovery, "acquire_update_lock", open_test_lock)
