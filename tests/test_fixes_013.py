"""v0.1.3 regressions: Textual naming collision and sudo installation."""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_tui_does_not_assign_to_reserved_textual_auto_refresh(monkeypatch):
    """Load the TUI with a stub for the DOMNode.auto_refresh property."""
    class MockApp:
        def __init__(self):
            self.sub_title = ""
            self.notifications = []

        @property
        def auto_refresh(self):
            return None

        @auto_refresh.setter
        def auto_refresh(self, _value):
            raise RuntimeError("Attempt to start timer outside the event loop")

        def notify(self, message, **kwargs):
            self.notifications.append(message)

    class DummyWidget:
        RowSelected = object

    fake_textual = types.ModuleType("textual")
    fake_textual.__path__ = []
    fake_textual.work = lambda **kw: lambda fn: fn
    fake_app = types.ModuleType("textual.app")
    fake_app.App = MockApp
    fake_app.ComposeResult = object
    fake_containers = types.ModuleType("textual.containers")
    fake_containers.Horizontal = DummyWidget
    fake_containers.VerticalScroll = DummyWidget
    fake_widgets = types.ModuleType("textual.widgets")
    for name in ["DataTable", "Footer", "Header", "Sparkline", "Static", "TabbedContent", "TabPane"]:
        setattr(fake_widgets, name, DummyWidget)

    with monkeypatch.context() as patcher:
        for name, module in [("textual", fake_textual), ("textual.app", fake_app),
                             ("textual.containers", fake_containers), ("textual.widgets", fake_widgets)]:
            patcher.setitem(sys.modules, name, module)
        spec = importlib.util.spec_from_file_location("repocache._stub_tui", ROOT / "src" / "repocache" / "tui.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        app = module.RepoCacheApp(auto_refresh=True, refresh_interval=30)
        assert app.refresh_enabled is True
        assert app.refresh_intervals[app.refresh_interval_index] == 30
        app.action_toggle_auto()
        assert app.refresh_enabled is False
        app.action_toggle_auto()
        assert app.refresh_enabled is True
        assert any("enabled" in x for x in app.notifications)


def test_install_uses_sudo_compatible_location_without_overwriting_others():
    installer = (ROOT / "install.sh").read_text()
    updater = (ROOT / 'src/repocache/updater.py').read_text()
    assert 'Path("/usr/bin/repocache")' in updater
    assert 'not link.exists() and not link.is_symlink()' in updater
    assert 'link_metadata.st_uid != 0 or link_metadata.st_mode & 0o022' in updater
    assert 'Unsafe global launcher ancestor' in updater
    assert '_require_service_account()' in updater
    assert 'Run as the dedicated repocache service account' in installer
    assert 'repocache repos list' in installer
