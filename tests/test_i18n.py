"""English-facing CLI and runtime privacy regression checks."""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

from typer.testing import CliRunner
from repocache.cli import app
from repocache.core import Settings, metrics

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "public_client_i18n", ROOT / "client/repocache_client.py")
client = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(client)


def test_server_help_and_machine_readable_update(monkeypatch):
    from repocache import updater
    monkeypatch.setattr(updater, "check", lambda: {
        "status": "up-to-date", "performed": False, "message": "No new release",
        "installed_version": "0.4.0", "latest_version": "0.4.0",
        "update_available": False, "release_url": None, "releases": []})
    assert CliRunner().invoke(app, ["--help"]).exit_code == 0
    result = CliRunner().invoke(app, ["update", "check", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["performed"] is False


def test_unavailable_metrics_are_not_invented(tmp_path):
    sample = metrics(Settings(metrics_log=tmp_path / "does-not-exist"))
    assert not sample["available"] and sample["requests"] == 0


def test_public_runtime_has_no_private_lan_domain_names():
    sources = list((ROOT / "src/repocache").glob("*.py")) + [
        ROOT / "client/repocache_client.py", ROOT / "client/install.sh",
        ROOT / "install.sh", ROOT / "scripts/build_release.py"]
    private_pattern = re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.lan(?:\.[a-z0-9-]+)+\b", re.I)
    for path in sources:
        data = path.read_text(encoding="utf-8")
        assert private_pattern.search(data) is None, path
    assert client.DEFAULT_SERVER == "https://cache.example.org"
