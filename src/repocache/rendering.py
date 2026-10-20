"""Safely render Rich markup in the TUI.

Malformed markup must never crash the dashboard or notifications.
"""
from rich.errors import MarkupError
from rich.text import Text


def safe_markup(value: str) -> Text:
    """Render Rich markup, falling back to literal text on errors."""
    try:
        return Text.from_markup(value)
    except MarkupError:
        return Text(value)
