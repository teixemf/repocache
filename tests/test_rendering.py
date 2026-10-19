"""Regressions for the Rich markup failure in dashboard v0.1.0."""
from pathlib import Path

from rich.markup import escape
from rich.text import Text

from repocache.rendering import safe_markup


def test_compound_styles_use_a_valid_closing_tag():
    """KPIs must render even when the color is dynamic."""
    for color in ("green", "yellow", "cyan", "#75bfff", "#65e2c3"):
        result = safe_markup(f"[dim]TITULO[/dim]\n[bold {color}]100[/]\n[dim]nota[/dim]")
        assert result.plain == "TITULO\n100\nnota"
        assert isinstance(result, Text)


def test_markup_error_falls_back_to_literal_text():
    broken = "[bold green]ONLINE[/bold]"
    result = safe_markup(broken)
    assert result.plain == broken


def test_error_notification_must_escape_user_or_exception_text():
    error = "closing tag '[/bold]' does not match any open tag"
    value = "Failed to collect data: " + escape(error)
    assert safe_markup(value).plain == "Failed to collect data: " + error
    assert safe_markup("Failed to collect data: " + escape("[/red] [bold]x")).plain.endswith("[/red] [bold]x")


def test_regression_source_keeps_safety_guards():
    source = (Path(__file__).resolve().parents[1] / "src" / "repocache" / "tui.py").read_text()
    assert "safe_markup(" in source
    assert "escape(message[:120])" in source
    assert "[/bold]\n[dim]" not in source
