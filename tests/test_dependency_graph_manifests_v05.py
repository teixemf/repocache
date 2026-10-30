"""Guard monitoring pins against drift from reviewed legacy wheel locks.

Source-only checks; ingestion, advisory and native resolver behavior require
separate GitHub/target evidence for issue #81. Never execute pip here.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

DEPS = Path(__file__).resolve().parents[1] / "deps"
LOCK_LINE = re.compile(r"([a-z][a-z0-9_]*) (\d+(?:\.\d+){2}) ([0-9a-f]{64})\Z")
PIN_LINE = re.compile(r"([a-z][a-z0-9-]*)==(\d+(?:\.\d+){2}) --hash=sha256:([0-9a-f]{64})\Z")
TARGETS = (
    "requirements-debian13-py313.txt",
    "requirements-almalinux10-py312.txt",
)


def _parse(content: str, pattern: re.Pattern[str], comments: bool) -> dict[str, tuple[str, str]]:
    assert content and content.endswith("\n")
    assert len(content) < 16_384
    result: dict[str, tuple[str, str]] = {}
    for line in content.splitlines():
        if comments and line.startswith("#"):
            continue
        match = pattern.fullmatch(line)
        assert match is not None, "Unsafe requirement or unexpected pin syntax"
        raw_name, version, sha256 = match.groups()
        name = raw_name.replace("_", "-")
        assert name not in result, "Duplicate normalized package"
        result[name] = (version, sha256)
    return result


def _lock(name: str) -> dict[str, tuple[str, str]]:
    return _parse((DEPS / name).read_text(encoding="utf-8"), LOCK_LINE, False)


def _monitor(name: str) -> dict[str, tuple[str, str]]:
    return _parse((DEPS / name).read_text(encoding="utf-8"), PIN_LINE, True)


@pytest.mark.parametrize("name", TARGETS)
def test_target_runtime_monitor_matches_reviewed_wheel_lock(name):
    actual = _monitor(name)
    assert len(actual) == 12
    assert actual == _lock("runtime-wheels.lock")
    assert {"typer", "rich", "textual"} <= set(actual)


def test_build_monitor_is_separate_from_runtime():
    build = _monitor("requirements-build-v05.txt")
    assert len(build) == 2
    assert build == _lock("build-wheels.lock")
    assert not (set(build) & set(_monitor(TARGETS[0])))


@pytest.mark.parametrize("malformed", [
    "rich>=15.0.0 --hash=sha256:" + "a" * 64 + "\n",
    "rich==15.0.0 --extra-index-url=https://invalid.example\n",
    "rich==15.0.0 --hash=sha256:" + "z" * 64 + "\n",
    "rich==15.0.0 --hash=sha256:" + "a" * 64,
    "rich==15.0.0 --hash=sha256:" + "a" * 64 + "\n" +
    "rich==15.0.0 --hash=sha256:" + "b" * 64 + "\n",
])
def test_monitor_parser_rejects_malformed_or_duplicated_pins(malformed):
    with pytest.raises(AssertionError):
        _parse(malformed, PIN_LINE, True)
