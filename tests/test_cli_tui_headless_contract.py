"""Actual Textual keyboard and real Typer help, without NGINX or network.

These run against the checked-out in-tree application and CI dependencies.
The preactivation subprocess runs the same Textual script in the installed,
disposable venv; publisher-signed native candidate tests remain outstanding.
"""
from __future__ import annotations

import re

import pytest
from typer.testing import CliRunner

from repocache import cli, online_generation


@pytest.mark.parametrize("argv,expected", [
    (["--version"], "REPOCACHE Control Center"),
    (["--help"], "update"),
    (["update", "--help"], "list"),
    (["update", "list", "--help"], "--json"),
    (["update", "check", "--help"], "--json"),
    (["repos", "--help"], "list"),
    (["health", "--help"], "--deep"),
])
def test_actual_noninteractive_typer_contract_does_not_access_upstream(
        argv, expected, monkeypatch):
    """Executing help and version must not call a release index or prompt."""
    from repocache import releases, updater

    def unavailable(*args, **kwargs):
        pytest.fail("Help/version must not fetch releases or modify managed state")

    monkeypatch.setattr(releases, "discover", unavailable)
    monkeypatch.setattr(updater, "apply", unavailable)
    monkeypatch.setattr(updater, "check", unavailable)
    runner = CliRunner()
    result = runner.invoke(cli.app, argv)
    assert result.exit_code == 0, result.output
    plain = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
    assert expected in plain
    assert "Continue?" not in result.output
    assert "Would you like" not in result.output


def test_real_textual_headless_keyboard_navigation_on_installed_api():
    """Exercise actual Textual run_test, not simulated subprocess output.

    The test-script prevents App.poll from reading NGINX/logs/sockets and
    remains independent of real services and network availability.
    """
    compile(online_generation.TUI_HEADLESS_SMOKE, "<signed-tui-smoke>", "exec")
    exec(online_generation.TUI_HEADLESS_SMOKE, {"__name__": "__main__"})
