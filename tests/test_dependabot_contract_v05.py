"""Guard the reviewed Dependabot policy without importing YAML at runtime.

This validates configuration, NOT GitHub effective security settings,
transitive ingestion, or advisory processing. See issue #81.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".github" / "dependabot.yml"
LABELS = ROOT / ".github" / "labels.json"


def _sections():
    text = CONFIG.read_text(encoding="utf-8")
    significant = "\n".join(
        line for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ) + "\n"
    assert significant.startswith("version: 2\nupdates:\n")
    blocks = re.split(r'(?=^  - package-ecosystem: )', significant, flags=re.M)[1:]
    assert len(blocks) == 3
    for block in blocks:
        assert not re.search(r'^\S', block, flags=re.M)
        match = re.search(r'^  - package-ecosystem: "([a-z-]+)"$', block, re.M)
        directory = re.search(r'^    directory: "([^"]+)"$', block, re.M)
        assert match is not None and directory is not None
        assert "    schedule:\n      interval: \"weekly\"\n" in block
        assert "    labels:\n" in block
        yield (match.group(1), directory.group(1)), block


def test_weekly_ecosystems_and_bounded_update_volume():
    configs = dict(_sections())
    assert set(configs) == {("pip", "/"), ("pip", "/deps"), ("github-actions", "/")}
    assert "open-pull-requests-limit: 5\n" in configs[("pip", "/")]
    assert "open-pull-requests-limit: 2\n" in configs[("pip", "/deps")]
    assert "open-pull-requests-limit: 3\n" in configs[("github-actions", "/")]
    assert 'versioning-strategy: "increase-if-necessary"' in configs[("pip", "/")]
    for content in configs.values():
        assert "auto-merge" not in content
        assert "allow:" not in content
        assert "ignore:" not in content
        assert "insecure-external-code-execution:" not in content


def test_dependabot_labels_are_in_the_repository_palette():
    supported = {
        label["name"] for label in json.loads(LABELS.read_text(encoding="utf-8"))
    }
    configs = dict(_sections())
    for (_, _), block in configs.items():
        assigned = re.findall(r'^      - "([^"]+)"$', block, flags=re.M)
        assert len(assigned) == 2
        assert set(assigned) <= supported
        assert "type:maintenance" in assigned
    assert "area:security" in configs[("pip", "/")]
    assert "area:security" in configs[("pip", "/deps")]
    assert "area:release" in configs[("github-actions", "/")]


def test_python_manifests_keep_cli_tui_declared_without_claiming_lock_graph():
    with (ROOT / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)
    requirements = project["project"]["dependencies"]
    declared = {
        re.match(r"^([A-Za-z][A-Za-z0-9_-]*)", entry).group(1).lower()
        for entry in requirements
    }
    assert {"typer", "rich", "textual"} <= declared
    assert all("://" not in entry and "@" not in entry for entry in requirements)
    assert (ROOT / "deps" / "runtime-wheels.lock").is_file()
