"""Issue #50: interprocess transaction lock regression tests."""
from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from repocache import updater


@pytest.fixture
def lock_root(monkeypatch, tmp_path):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(updater, "ROOT", tmp_path)
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    return tmp_path


def test_nested_update_uses_one_process_lock(lock_root):
    with updater.update_transaction():
        with updater.update_transaction():
            assert (lock_root / ".updater.lock").is_file()


def test_untrusted_lock_symlink_fails_closed(lock_root, tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text("do not touch")
    (lock_root / ".updater.lock").symlink_to(target)
    with pytest.raises(updater.UpdateError, match="lock"):
        with updater.update_transaction():
            pytest.fail("Insecure symlink acquired")
    assert target.read_text() == "do not touch"


def test_insecure_lock_file_permissions_fail_closed(lock_root):
    file = lock_root / ".updater.lock"
    file.write_text("fixture")
    file.chmod(0o666)
    with pytest.raises(updater.UpdateError, match="insecure"):
        with updater.update_transaction():
            pytest.fail("Insecure lock acquired")


def test_second_process_rejected_and_lock_recovers_after_termination(lock_root):
    # The subprocess uses its own process descriptor, proving kernel flock
    # behavior rather than a same-process/test-monkeypatch mock.
    root = Path(__file__).resolve().parents[1]
    program = (
        "import os,sys,time; "
        "from pathlib import Path; "
        "from repocache import updater; "
        "updater.ROOT=Path(sys.argv[1]); "
        "updater._require_service_account=lambda:None; "
        "ctx=updater.update_transaction(); ctx.__enter__(); "
        "print('LOCKED',flush=True); time.sleep(60)"
    )
    environment = dict(os.environ, PYTHONPATH=str(root / "src"))
    process = subprocess.Popen(
        [sys.executable, "-c", program, str(lock_root)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
    try:
        assert process.stdout.readline().strip() == "LOCKED"
        with pytest.raises(updater.UpdateError, match="Another REPOCACHE update"):
            with updater.update_transaction():
                pytest.fail("Concurrent updater obtained lock")
    finally:
        process.kill()
        process.communicate(timeout=10)
    with updater.update_transaction():
        pass  # Kernel automatically released lock after SIGKILL.
