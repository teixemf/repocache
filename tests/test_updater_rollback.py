"""An interrupted activation never leaves an unusable active command."""
from pathlib import Path

import pytest

from repocache import updater


@pytest.fixture
def staged(monkeypatch, tmp_path):
    root = tmp_path / "opt"
    (root / "releases").mkdir(parents=True)
    existing = root / "releases" / "0.2.0-previous"
    (existing / "bin").mkdir(parents=True)
    (existing / "bin" / "repocache").write_text("previous\n")
    current = root / "current"
    current.symlink_to(existing)
    installed = root / "installed.json"
    installed.write_text('{"version":"0.2.0","source_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n')
    before = installed.read_bytes()
    source = tmp_path / "bundle"
    (source / "src/repocache").mkdir(parents=True)
    (source / "pyproject.toml").write_text('[project]\nversion = "0.3.0"\n')
    (source / "install.sh").write_text("#!/bin/sh\n")
    (source / "src/repocache/__init__.py").write_text('__version__ = "0.3.0"\n')
    link = tmp_path / "usr/local/bin/repocache"
    link.parent.mkdir(parents=True)
    link.write_text("#!/bin/sh\n# REPOCACHE ROOTLESS LAUNCHER\n")
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    monkeypatch.setattr(updater, "_safe_links", lambda: None)
    for key, value in {
        "ROOT": root, "MANIFEST": installed, "CURRENT": current,
        "EXECUTABLE": current / "bin/repocache",
        "LINKS": (link,),
        "LEGACY": root / "venv/bin/repocache"
    }.items():
        monkeypatch.setattr(updater, key, value)

    def run(args, **kwargs):
        if len(args) >= 3 and args[1:3] == ["-m", "venv"]:
            path = Path(args[3])
            (path / "bin").mkdir(parents=True, exist_ok=True)
            (path / "bin/repocache").write_text("new\n")
        if args[-1] == "--version":
            return "REPOCACHE Control Center 0.3.0"
        return ""
    monkeypatch.setattr(updater, "_run", run)
    return root, source, existing, installed, before, link


def test_manifest_write_failure_restores_previous_activation(monkeypatch, staged):
    root, source, existing, installed, before, link = staged
    def failure(*a):
        raise updater.UpdateError("simulated manifest write failure")
    monkeypatch.setattr(updater, "_write_manifest", failure)
    with pytest.raises(updater.UpdateError, match="simulated"):
        updater.install_source(source)
    assert (root / "current").resolve() == existing
    assert installed.read_bytes() == before
    assert "REPOCACHE ROOTLESS LAUNCHER" in link.read_text()


def test_post_activation_cli_failure_rolls_back(monkeypatch, staged):
    root, source, existing, installed, before, link = staged
    def run(args, **kwargs):
        if len(args) >= 3 and args[1:3] == ["-m", "venv"]:
            dest = Path(args[3])
            (dest / "bin").mkdir(parents=True, exist_ok=True)
            (dest / "bin/repocache").write_text("new\n")
        if args[-1] == "--version":
            return ("CORRUPT CLI" if args[0] == str(updater.EXECUTABLE)
                    else "REPOCACHE Control Center 0.3.0")
        return ""
    monkeypatch.setattr(updater, "_run", run)
    with pytest.raises(updater.UpdateError, match="Post-activation"):
        updater.install_source(source)
    assert (root / "current").resolve() == existing
    assert installed.read_bytes() == before


def test_no_downgrade_without_explicit_policy(staged):
    root, source, existing, installed, before, link = staged
    newer = root / "releases" / "0.4.0-previous"
    (newer / "bin").mkdir(parents=True)
    (newer / "bin/repocache").write_text("newer\n")
    (root / "current").unlink()
    (root / "current").symlink_to(newer)
    installed.write_text('{"version":"0.4.0","source_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}\n')
    with pytest.raises(updater.UpdateError, match="downgrade"):
        updater.install_source(source)
    assert (root / "current").resolve() == newer


def test_corrupted_manifest_blocks_activation(staged):
    root, source, existing, installed, before, link = staged
    installed.write_text("{invalid json")
    with pytest.raises(updater.UpdateError, match="corrupt"):
        updater.install_source(source)
    assert (root / "current").resolve() == existing


@pytest.mark.parametrize("value", [
    "{}", '{"version":"0.3.0"}', '{"version":"0.0.0","source_digest":"' + "a" * 64 + '"}',
    '{"version":"garbage","source_digest":"' + "a" * 64 + '"}',
    '{"version":"0.3.0","source_digest":"nonsense"}'
])
def test_structurally_invalid_manifest_is_not_a_fresh_install(staged, value):
    root, source, existing, installed, before, link = staged
    installed.write_text(value)
    with pytest.raises(updater.UpdateError, match="manifest"):
        updater.install_source(source)
    assert (root / "current").resolve() == existing


def test_missing_manifest_does_not_bypass_existing_install(staged):
    root, source, existing, installed, before, link = staged
    installed.unlink()
    with pytest.raises(updater.UpdateError, match="manifest"):
        updater.install_source(source)
    assert (root / "current").resolve() == existing


def test_symlinked_manifest_is_rejected(staged, tmp_path):
    root, source, existing, installed, before, link = staged
    original = tmp_path / "outside-manifest.json"
    original.write_bytes(before)
    installed.unlink()
    installed.symlink_to(original)
    with pytest.raises(updater.UpdateError, match="symlink"):
        updater.install_source(source)
    assert original.read_bytes() == before
    assert (root / "current").resolve() == existing
