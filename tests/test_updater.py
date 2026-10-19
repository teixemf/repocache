"""Update commands are single-line and fully offline."""
import json
import pytest
from typer.testing import CliRunner
from repocache import updater
from repocache.cli import app


def test_update_check_uses_read_only_discovery(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Discovery must never invoke subprocesses or Git")
    monkeypatch.setattr(updater.subprocess, "run", forbidden)
    monkeypatch.setattr(updater, "_installed", lambda: {"version": "0.3.0"})
    from repocache import releases
    monkeypatch.setattr(releases, "discover", lambda token_file=None: [])
    assert updater.check()["performed"] is False
    assert updater.check()["status"] == "invalid-release"


def test_update_and_check_are_noninteractive(monkeypatch):
    monkeypatch.setattr(updater, "check", lambda: {
        "status": "up-to-date", "installed_version": "0.3.0",
        "latest_version": "0.3.0", "message": "No newer release"})
    result = CliRunner().invoke(app, ["update", "check"])
    assert result.exit_code == 0, result.output
    assert "up-to-date" in result.output
    monkeypatch.setattr(updater, "apply", lambda **kw: {
        "status": "already-installed", "version": "0.3.0",
        "previous_version": "0.3.0"})
    assert CliRunner().invoke(app, ["update"]).exit_code == 0


def test_json_check(monkeypatch):
    monkeypatch.setattr(updater, "check", lambda: {
        "status": "up-to-date", "performed": False, "installed_version": "0.3.0",
        "latest_version": "0.3.0", "message": "No newer release"})
    result = CliRunner().invoke(app, ["update", "check", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.output)["performed"] is False


def test_error_exit_code(monkeypatch):
    monkeypatch.setattr(updater, "check", lambda: {
        "status": "authentication-required", "performed": False,
        "installed_version": "0.3.0", "latest_version": None,
        "message": "Authentication required"})
    assert CliRunner().invoke(app, ["update", "check", "--json"]).exit_code == 2


def test_foreign_command_not_overwritten(monkeypatch, tmp_path):
    file = tmp_path / "repocache"
    file.write_text("another program")
    monkeypatch.setattr(updater, "LINKS", (file,))
    with pytest.raises(updater.UpdateError):
        updater._safe_links()


def test_installs_extracted_bundle_without_git_revision(monkeypatch, tmp_path):
    """v0.2.1 regression: tar.gz has no Git commit and must not require SHA-1."""
    from pathlib import Path
    source = tmp_path / "repocache-v0.2.2"
    package = source / "src" / "repocache"
    package.mkdir(parents=True)
    (source / "pyproject.toml").write_text('[project]\nversion = "0.2.2"\n')
    (source / "install.sh").write_text("#!/bin/bash\n")
    (package / "__init__.py").write_text('__version__ = "0.2.2"\n')
    root = tmp_path / "opt"
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    root.mkdir()
    monkeypatch.setattr(updater, "ROOT", root)
    monkeypatch.setattr(updater, "MANIFEST", root / "installed.json")
    monkeypatch.setattr(updater, "CURRENT", root / "current")
    monkeypatch.setattr(updater, "EXECUTABLE", root / "current/bin/repocache")
    monkeypatch.setattr(updater, "LINKS", (tmp_path / "usr/bin/repocache",))
    monkeypatch.setattr(updater, "_installed", lambda: {"version": "0.1.3"})

    commands = []
    def fake_run(argv, **kwargs):
        commands.append(argv)
        if argv[1:3] == ["-m", "venv"]:
            destination = Path(argv[3])
            (destination / "bin").mkdir(parents=True, exist_ok=True)
            (destination / "bin/repocache").write_text("#!/bin/sh\n")
        if argv[-1] == "--version":
            return "REPOCACHE Control Center 0.2.2"
        return ""

    monkeypatch.setattr(updater, "_run", fake_run)
    result = updater.install_source(source)
    assert result["version"] == "0.2.2"
    assert len(result["source_digest"]) == 64
    assert (root / "current").is_symlink()
    assert (root / "installed.json").exists()
    assert not (tmp_path / "usr/bin/repocache").exists()
    assert commands[0][-1] == str((root / "current").resolve())


def test_install_script_never_requires_git_commit():
    from pathlib import Path
    script = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
    assert "install_source(Path(sys.argv[1]))" in script
    assert "commit=" not in script

def test_new_releases_refuse_unsigned_online_source_bootstrap(monkeypatch, tmp_path):
    source = tmp_path / "v040-source"
    (source / "src/repocache").mkdir(parents=True)
    (source / "pyproject.toml").write_text('[project]\nversion = "0.4.0"\n')
    (source / "install.sh").write_text("#!/bin/sh\n")
    (source / "src/repocache/__init__.py").write_text('__version__ = "0.4.0"\n')
    monkeypatch.setattr(updater, "_require_service_account", lambda: None)
    import contextlib
    monkeypatch.setattr(updater, "update_transaction", contextlib.nullcontext)
    monkeypatch.setattr(updater, "recover_transaction", lambda: None)
    monkeypatch.setattr(updater, "_run", lambda *a, **kw:
                        pytest.fail("Unsigned source reached pip/build hooks"))
    with pytest.raises(updater.UpdateError, match="source-only installation is disabled"):
        updater.install_source(source)
