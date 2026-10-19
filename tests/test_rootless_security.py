"""Rootless updater boundaries — #48 acceptance unit tests.

No test in this file uses privileged host paths or requires root.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from repocache import updater


def test_root_is_rejected_before_any_install_work(monkeypatch):
    monkeypatch.setattr(updater.os, "geteuid", lambda: 0)
    with pytest.raises(updater.UpdateError, match="never execute as root"):
        updater._require_service_account()


def test_unrelated_uid_is_rejected(monkeypatch):
    monkeypatch.setattr(updater.os, "geteuid", lambda: 2001)
    monkeypatch.setattr(updater.pwd, "getpwnam",
                        lambda name: SimpleNamespace(pw_uid=2002))
    with pytest.raises(updater.UpdateError, match="dedicated repocache"):
        updater._require_service_account()


def test_missing_or_root_service_identity_rejected(monkeypatch):
    monkeypatch.setattr(updater.os, "geteuid", lambda: 2001)
    def missing(name):
        raise KeyError(name)
    monkeypatch.setattr(updater.pwd, "getpwnam", missing)
    with pytest.raises(updater.UpdateError, match="Missing repocache"):
        updater._require_service_account()
    monkeypatch.setattr(updater.pwd, "getpwnam",
                        lambda name: SimpleNamespace(pw_uid=0))
    with pytest.raises(updater.UpdateError, match="dedicated repocache"):
        updater._require_service_account()


def test_dedicated_nonroot_identity_accepted(monkeypatch):
    monkeypatch.setattr(updater.os, "geteuid", lambda: 2099)
    monkeypatch.setattr(updater.pwd, "getpwnam",
                        lambda name: SimpleNamespace(pw_uid=2099))
    updater._require_service_account()


def test_subprocess_environment_is_not_inherited(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/tmp/evil")
    monkeypatch.setenv("PIP_INDEX_URL", "https://evil.invalid")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
    seen = {}
    def fake_run(argv, **kw):
        seen.update(kw)
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")
    monkeypatch.setattr(updater.subprocess, "run", fake_run)
    assert updater._run(["/usr/bin/true"]) == "ok"
    env = seen["env"]
    assert "PYTHONPATH" not in env and "PIP_INDEX_URL" not in env
    assert "LD_PRELOAD" not in env
    assert env["PIP_CONFIG_FILE"] == os.devnull
    assert env["PYTHONNOUSERSITE"] == "1"


def test_unmanaged_launcher_is_rejected(tmp_path, monkeypatch):
    foreign = tmp_path / "repocache"
    foreign.write_text("#!/bin/sh\necho unexpected\n")
    monkeypatch.setattr(updater, "LINKS", (foreign,))
    with pytest.raises(updater.UpdateError, match="launcher|Foreign"):
        updater._safe_links()


def test_symlinked_global_launcher_is_rejected(tmp_path, monkeypatch):
    foreign = tmp_path / "target"
    foreign.write_text("# REPOCACHE ROOTLESS LAUNCHER")
    link = tmp_path / "repocache"
    link.symlink_to(foreign)
    monkeypatch.setattr(updater, "LINKS", (link,))
    with pytest.raises(updater.UpdateError, match="Unmanaged"):
        updater._safe_links()


def test_privileged_launcher_drops_before_loading_python():
    launcher = Path(__file__).resolve().parents[1] / "scripts/repocache-launcher.sh"
    content = launcher.read_text()
    assert content.startswith("#!/bin/sh\n# REPOCACHE ROOTLESS LAUNCHER")
    assert '/usr/sbin/runuser -u repocache -- /usr/bin/env -i' in content
    assert "/opt/repocache-cli/managed/current/bin/repocache" in content
    assert "$(id " not in content
    assert not re.search(r"(?m)^\\s*(?:exec\\s+)?sudo\\b", content)
    assert "\nsource " not in content


def test_bootstrap_requires_explicit_independent_launcher_digest():
    content = (Path(__file__).resolve().parents[1] /
               "scripts/bootstrap-rootless.sh").read_text()
    assert "--launcher-sha256" in content
    assert "sha256sum -c --status" in content
    assert "useradd --system" in content
    assert "install -d -o repocache -g repocache -m 0700" in content
    assert "install -o root -g root -m 0755" in content
    assert "Foreign/legacy launcher" in content


def test_shell_scripts_are_syntactically_valid():
    import subprocess
    root = Path(__file__).resolve().parents[1]
    for script in ("scripts/bootstrap-rootless.sh", "install.sh"):
        subprocess.run(["bash", "-n", str(root / script)], check=True)
    subprocess.run(["sh", "-n", str(root / "scripts/repocache-launcher.sh")],
                   check=True)


def test_root_bootstrap_checks_native_runtime_without_importing_bundle_python():
    """The root-only bootstrap executes no Python loaded from a writable bundle."""
    source = (Path(__file__).resolve().parents[1] /
              "scripts/bootstrap-rootless.sh").read_text()
    assert '/usr/bin/python3 -I - <<\'PY\'' in source
    assert '("debian", "13"): (3, 13)' in source
    assert '("almalinux", "10"): (3, 12)' in source
    assert 'sys.version_info[:2] != expected' in source
    assert source.index('/usr/bin/python3 -I -') < source.index('useradd --system')
    assert 'platform_check.py' not in source
