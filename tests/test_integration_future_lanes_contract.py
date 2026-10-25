"""Static future-lane CI contract (#175); not evidence of a real protected push."""
from __future__ import annotations

import re
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
MANDATORY = ("tests.yml", "offline-wheelhouse.yml", "upgrade-distros.yml")
BRANCHES = ("main", "release/v0.4.0", "integration/**")
JOBS = {
    "tests.yml": (
        "Unit tests (Python $" + "{{ matrix.python-version }})",
        "Bundle integrity and unsigned-source refusal ($" + "{{ matrix.platform }})",
    ),
    "offline-wheelhouse.yml": (
        "Offline wheels ($" + "{{ matrix.os }})",
        "Signed release and native offline dependency artifact",
    ),
    "upgrade-distros.yml": (
        "Synthetic rootless update and rollback ($" + "{{ matrix.image }})",
    ),
}
MATRICES = {
    "tests.yml": ("python-version: ['3.12', '3.13']",
                  "platform: ['debian13', 'almalinux10']"),
    "offline-wheelhouse.yml": ("os: ['debian:trixie-slim', 'almalinux:10']",),
    "upgrade-distros.yml": ("image: ['debian:trixie-slim', 'almalinux:10']",),
}


def _header(text):
    assert text.startswith("name: ") and "\non:\n" in text
    assert "\npermissions:\n" in text
    return text.split("\npermissions:\n", 1)[0]


def _events(text):
    return set(re.findall(r"(?m)^  ([a-z_]+):[^\n]*$", _header(text)))


def _event_block(text, event):
    lines = _header(text).splitlines()
    start = lines.index("  " + event + ":")
    block = []
    for line in lines[start + 1:]:
        if line and not line.startswith("    "):
            break
        block.append(line)
    return "\n".join(block)


def _branches(text):
    block = _event_block(text, "push")
    matches = re.findall(r"(?m)^    branches: \[([^\]]+)\]$", block)
    assert len(matches) == 1 and "tags:" not in block
    return tuple(item.strip().strip("'\"") for item in matches[0].split(","))


def _required(name, text):
    events = {"push", "pull_request"}
    if name != "tests.yml":
        events.add("workflow_dispatch")
    assert _events(text) == events
    assert _branches(text) == BRANCHES
    for event in ("push", "pull_request"):
        block = _event_block(text, event)
        assert "paths:" not in block and "paths-ignore:" not in block
    assert "permissions:\n  contents: read\n\njobs:" in text
    assert "persist-credentials: false" in text
    assert not re.search(r"(?m)^    if:|^    continue-on-error:", text)
    assert tuple(re.findall(r"(?m)^    name: (.+)$", text)) == JOBS[name]
    for matrix in MATRICES[name]:
        assert matrix in text


@pytest.mark.parametrize("name", MANDATORY)
def test_nine_required_contexts_unfiltered_on_pr_and_future_push(name):
    _required(name, (WORKFLOWS / name).read_text("utf-8"))


def _glob(pattern, branch):
    # GitHub Actions ** crosses slashes; fnmatch.fnmatchcase is unsuitable.
    assert not any(c in pattern for c in "?+![]{}")
    regex = re.escape(pattern).replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    return re.fullmatch(regex, branch) is not None


def test_future_nested_and_experimental_branches_are_intentionally_covered():
    for branch in ("main", "release/v0.4.0", "integration/v0.5.0",
                   "integration/v0.6.0", "integration/v0.7.0",
                   "integration/maintenance/v0.7.0",
                   "integration/v0.5.0-experiment"):
        assert any(_glob(pattern, branch) for pattern in BRANCHES)
    for branch in ("feature/v0.7.0", "integrations/v0.7.0",
                   "release/v0.4.1", "release/v0.7.0"):
        assert not any(_glob(pattern, branch) for pattern in BRANCHES)


def test_upstream_wheels_remains_path_filtered_and_supplemental():
    text = (WORKFLOWS / "native-upstream-wheels.yml").read_text("utf-8")
    assert _events(text) == {"push", "pull_request", "workflow_dispatch"}
    assert _branches(text) == ("main", "integration/**")
    assert "paths:" in _event_block(text, "push")
    assert "paths:" in _event_block(text, "pull_request")
    assert "permissions:\n  contents: read\n\njobs:" in text
    assert "persist-credentials: false" in text


@pytest.mark.parametrize(("name", "before", "after"), [
    ("tests.yml", "  pull_request:\n", "  pull_request_target:\n"),
    ("tests.yml", "    name: Unit tests (Python ", "    name: Unit suite (Python "),
    ("tests.yml", "python-version: ['3.12', '3.13']", "python-version: ['3.12']"),
    ("tests.yml", "branches: [main,", "branches: [feature/*, main,"),
    ("offline-wheelhouse.yml", "    name: Signed release and native offline dependency artifact",
     "    name: Unreviewed artifact job"),
    ("offline-wheelhouse.yml", "permissions:\n  contents: read",
     "permissions:\n  contents: write"),
    ("offline-wheelhouse.yml", "  pull_request:\n",
     "  pull_request:\n    paths:\n      - 'src/**'\n"),
    ("upgrade-distros.yml", "  push:\n", "  workflow_run:\n"),
    ("upgrade-distros.yml", "    branches: [", "    tags: ["),
    ("upgrade-distros.yml", "    name: Synthetic rootless update and rollback (",
     "    name: Synthetic install only ("),
])
def test_mutations_cannot_silently_remove_or_escalate_required_checks(name, before, after):
    original = (WORKFLOWS / name).read_text("utf-8")
    assert before in original
    with pytest.raises(AssertionError):
        _required(name, original.replace(before, after, 1))


def test_release_workflow_remains_manual_and_owner_tag_gated():
    text = (WORKFLOWS / "release.yml").read_text("utf-8")
    assert _events(text) == {"workflow_dispatch"}
    assert "github.actor == 'teixemf'" in text
    assert "startsWith(github.ref, 'refs/tags/v')" in text
    assert "permissions:\n  contents: read\n" in text
