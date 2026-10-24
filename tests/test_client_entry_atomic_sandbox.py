"""Negative-only unit gate for the non-installed per-entry atomic sandbox adapter.

Positive operations need actual UID 0 and pinned #131/#132 writer, executed
by client-shared-entry-atomic.yml on Debian 13 and AlmaLinux 10. This suite
does not pretend to exercise atomic source writes in a generic CI runner.
"""
from __future__ import annotations

import importlib
import os
from pathlib import Path
import sys

import pytest


CLIENT = Path(__file__).resolve().parents[1] / "client"
sys.path.insert(0, str(CLIENT))
atomic_entry = importlib.import_module("entry_atomic_sandbox")
approval = importlib.import_module("entry_approval_plan_sandbox")


@pytest.mark.parametrize("action", (
    atomic_entry.apply_entry_sandbox,
    atomic_entry.rollback_entry_sandbox,
    atomic_entry.recover_entry_sandbox,
))
def test_unprivileged_process_cannot_invoke_entry_writer(action, monkeypatch):
    monkeypatch.setattr(atomic_entry.os, "geteuid", lambda: 65534)
    with pytest.raises(approval.ApprovalRefused, match="Root required"):
        action(Path("/"), "a" * 32, "b" * 32, "https://cache.invalid/repo")


def test_adapter_has_no_production_entrypoint_or_implicit_cli_integration():
    import inspect
    exported = {
        name for name, obj in vars(atomic_entry).items()
        if inspect.isfunction(obj) and obj.__module__ == atomic_entry.__name__
    }
    assert {"apply_entry_sandbox", "rollback_entry_sandbox",
            "recover_entry_sandbox"}.issubset(exported)
    assert "source_helper_preview" not in (
        CLIENT / "repocache_client.py").read_text()
    assert "entry_atomic_sandbox" not in (
        CLIENT / "repocache_client.py").read_text()
    assert "entry_atomic_sandbox" not in (
        CLIENT / "install.sh").read_text()
