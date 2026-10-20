"""Non-interactive NGINX operations for the production frontend (#12).

NGINX is administered separately in v0.4.0. Explicit CLI reload must be safe
in scripts and must never change service state without --yes.
"""
import pytest
from typer.testing import CliRunner

from repocache import cli


@pytest.fixture
def commands(monkeypatch):
    calls = []

    def tracked(argv, timeout=10):
        calls.append(tuple(argv))
        return {"ok": True, "code": 0, "stderr": "", "stdout": "syntax is ok"}

    monkeypatch.setattr(cli, "command", tracked)
    monkeypatch.setattr(cli, "settings", lambda: type(
        "SettingsFixture", (), {"nginx_bin": "/usr/sbin/nginx"})())
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **kw:
                        pytest.fail("CLI must never prompt"))
    return calls


def test_service_reload_without_yes_refuses_without_commands(commands):
    result = CliRunner().invoke(cli.app, ["service", "reload"])
    assert result.exit_code == 2, result.output
    assert "pass --yes explicitly" in result.output
    assert "no changes made" in result.output
    assert commands == []


def test_service_reload_yes_checks_syntax_then_reloads(commands):
    result = CliRunner().invoke(cli.app, ["service", "reload", "--yes"])
    assert result.exit_code == 0, result.output
    assert commands == [
        ("/usr/sbin/nginx", "-t"),
        ("systemctl", "reload", "nginx"),
    ]


def test_service_reload_yes_refuses_invalid_syntax(commands, monkeypatch):
    def reject_syntax(argv, timeout=10):
        commands.append(tuple(argv))
        return {"ok": False, "code": 1, "stderr": "synthetic invalid config",
                "stdout": ""}

    monkeypatch.setattr(cli, "command", reject_syntax)
    result = CliRunner().invoke(cli.app, ["service", "reload", "--yes"])
    assert result.exit_code == 1
    assert commands == [("/usr/sbin/nginx", "-t")]
    assert "Reload skipped" in result.output


def test_service_reload_yes_reports_systemd_failure(commands, monkeypatch):
    def reject_reload(argv, timeout=10):
        commands.append(tuple(argv))
        ok = list(argv) == ["/usr/sbin/nginx", "-t"]
        return {"ok": ok, "code": 0 if ok else 1, "stderr":
                "" if ok else "synthetic permission refusal", "stdout": ""}

    monkeypatch.setattr(cli, "command", reject_reload)
    result = CliRunner().invoke(cli.app, ["service", "reload", "--yes"])
    assert result.exit_code == 1
    assert commands == [
        ("/usr/sbin/nginx", "-t"),
        ("systemctl", "reload", "nginx"),
    ]
    assert "Reload failed" in result.output


def test_reload_help_documents_explicit_acknowledgement(commands):
    result = CliRunner().invoke(cli.app, ["service", "reload", "--help"])
    assert result.exit_code == 0, result.output
    assert "--yes" in result.output
