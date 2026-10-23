"""Pin Node.js 24-native GitHub Actions without weakening release gates (#74).

These are repository-contract tests, not substitutes for a real workflow run.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
EXPECTED = {
    "actions/checkout": ("93cb6efe18208431cddfb8368fd83d5badbf9bfd", "v5.0.1"),
    "actions/setup-python": ("e797f83bcb11b83ae66e0230d6156d7c80228e7c", "v6.0.0"),
    "actions/upload-artifact": ("b7c566a772e6b6bfb58ed0dc250532a479d7789f", "v6.0.0"),
    # The pending signed draft acceptance PR (#77) adds this action.
    "actions/download-artifact": ("37930b1c2abaa49bbe596cd826c3c89aef350131", "v7.0.0"),
}
USE = re.compile(r"^\s*-\s+uses:\s+([^\s#]+)", re.MULTILINE)
PINNED = re.compile(
    r"^(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@"
    r"(?P<sha>[0-9a-f]{40})$"
)


def workflow_files() -> list[Path]:
    return sorted((*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")))


@pytest.mark.parametrize("workflow", workflow_files(), ids=lambda p: p.name)
def test_every_action_uses_reviewed_node24_full_sha(workflow: Path) -> None:
    text = workflow.read_text(encoding="utf-8")
    refs = USE.findall(text)
    for ref in refs:
        match = PINNED.fullmatch(ref)
        assert match is not None, f"{workflow.name}: non-SHA action ref {ref}"
        action, sha = match.group("action", "sha")
        assert action in EXPECTED, f"{workflow.name}: unknown action {action}"
        assert sha == EXPECTED[action][0], f"{workflow.name}: unreviewed SHA {ref}"
        assert f"{ref} # {EXPECTED[action][1]}" in text


@pytest.mark.parametrize("workflow", workflow_files(), ids=lambda p: p.name)
def test_checkout_does_not_persist_credentials(workflow: Path) -> None:
    lines = workflow.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if "- uses: actions/checkout@" in line:
            assert index + 2 < len(lines)
            assert lines[index + 1].strip() == "with:"
            assert lines[index + 2].strip() == "persist-credentials: false"


def test_official_actions_present_and_legacy_refs_absent() -> None:
    combined = "\n".join(p.read_text(encoding="utf-8") for p in workflow_files())
    for action in ("actions/checkout", "actions/setup-python", "actions/upload-artifact"):
        sha, version = EXPECTED[action]
        assert f"{action}@{sha} # {version}" in combined
    for legacy in (
        "11bd71901bbe5b1630ceea73d27597364c9af683",
        "a26af69be951a213d495a4c3e4e4022e16d87065",
        "ea165f8d65b6e75b540449e92b4886f43607fa02",
    ):
        assert legacy not in combined


def test_nine_existing_required_context_definitions_remain_unchanged() -> None:
    tests = (WORKFLOWS / "tests.yml").read_text(encoding="utf-8")
    wheels = (WORKFLOWS / "offline-wheelhouse.yml").read_text(encoding="utf-8")
    upgrade = (WORKFLOWS / "upgrade-distros.yml").read_text(encoding="utf-8")
    for name in (
        "Unit tests (Python ${{ matrix.python-version }})",
        "Bundle integrity and unsigned-source refusal (${{ matrix.platform }})",
    ):
        assert name in tests
    for name in (
        "Offline wheels (${{ matrix.os }})",
        "Signed release and native offline dependency artifact",
    ):
        assert name in wheels
    assert "Synthetic rootless update and rollback (${{ matrix.image }})" in upgrade
    for expected_size, text in ((2, tests), (2, wheels), (1, upgrade)):
        assert text.count("    name: ") >= expected_size


def test_node24_upload_pr_rehearsal_is_not_a_release() -> None:
    tests = (WORKFLOWS / "tests.yml").read_text(encoding="utf-8")
    assert "Rehearse Node.js 24 artifact upload without publishing (#74)" in tests
    assert "name: node24-rehearsal-${{ matrix.platform }}" in tests
    assert "retention-days: 1" in tests
    assert "if-no-files-found: error" in tests
    assert "permissions:\n  contents: read" in tests


def test_real_release_upload_remains_owner_and_tag_gated() -> None:
    release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    assert "if: startsWith(github.ref, 'refs/tags/v') && github.actor == 'teixemf'" in release
    assert "if-no-files-found: error" in release
    assert "retention-days: 7" in release
    assert "persist-credentials: false" in release
    assert "permissions:\n  contents: read" in release
    assert "actions/upload-artifact@" + EXPECTED["actions/upload-artifact"][0] in release


def test_runner_minimum_and_exception_policy_documented() -> None:
    doc = (ROOT / "docs" / "CI_NODE24_ACTIONS.md").read_text(encoding="utf-8")
    assert "2.327.1" in doc
    assert "NOT VERIFIED" in doc
    assert "v0.4.0" in doc
