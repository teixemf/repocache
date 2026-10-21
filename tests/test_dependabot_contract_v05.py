"""Guard the reviewed Dependabot policy without importing YAML at runtime.

This validates the intentionally small tracked configuration, NOT GitHub's
effective security settings, update jobs, or complete transitive lock coverage.
The live GitHub integration and operator alerts are separate #81 acceptance.
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
    # The complete configuration is intentionally limited to these top-level
    # sections. Any new YAML syntax requires an explicit review of this test.
    assert significant.startswith("version: 2\nupdates:\n")
    blocks = re.split(r'(?=^  - package-ecosystem: )', significant, flags=re.M)[1:]
    assert len(blocks) == 2
    for block in blocks:
        assert not re.search(r'^\S', block, flags=re.M)
        assert "    directory: \"/\"\n" in block
        assert "    schedule:\n      interval: \"weekly\"\n" in block
        assert "    labels:\n" in block
        match = re.search(r'^  - package-ecosystem: "([a-z-]+)"$', block, re.M)
        assert match is not None
        yield match.group(1), block


def test_weekly_ecosystems_and_bounded_update_volume():
    configs = dict(_sections())
    assert set(configs) == {"pip", "github-actions"}
    assert "open-pull-requests-limit: 5\n" in configs["pip"]
    assert "open-pull-requests-limit: 3\n" in configs["github-actions"]
    assert 'versioning-strategy: "increase-if-necessary"' in configs["pip"]
    # No unsupported policy that silently refreshes release dependencies.
    for content in configs.values():
        assert "auto-merge" not in content
        assert "allow:" not in content
        assert "ignore:" not in content
        assert "insecure-external-code-execution:" not in content


def test_dependabot_labels_are_in_the_repository_palette():
    supported = {
        label["name"] for label in json.loads(LABELS.read_text(encoding="utf-8"))
    }
    for ecosystem, block in _sections():
        assigned = re.findall(r'^      - "([^"]+)"$', block, flags=re.M)
        assert len(assigned) == 2, ecosystem
        assert set(assigned) <= supported
        assert "type:maintenance" in assigned
    assert "area:security" in dict(_sections())["pip"]
    assert "area:release" in dict(_sections())["github-actions"]


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
    # The v0.4.0 custom wheel lock is independently maintained, and MUST NOT
    # be claimed as recognized by Dependabot without a live dependency graph.
    assert (ROOT / "deps" / "runtime-wheels.lock").is_file()
