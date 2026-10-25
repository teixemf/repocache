"""Protect the reviewed legacy wheel-lock inventory (issue #81).

This is a static release-input check, not evidence that GitHub ingested the
transitive dependency graph or enabled Dependabot vulnerability alerts. Native
wheels, Python compatibility and actual resolver closure have separate gates.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
LOCK_LINE = re.compile(r"([a-z][a-z0-9_]*) ([0-9]+(?:\.[0-9]+){2}) ([0-9a-f]{64})\Z")

# Reviewed legacy inventory from the immutable v0.4.0 dependency profile.
# A changed graph requires explicit dependency/security review, not a silent
# new source archive or signed-wheelhouse substitution.
REVIEWED_RUNTIME_NAMES = {
    "annotated-doc", "linkify-it-py", "markdown-it-py", "mdit-py-plugins",
    "mdurl", "platformdirs", "pygments", "rich", "shellingham",
    "textual", "typer", "typing-extensions",
}
REVIEWED_BUILD_NAMES = {"setuptools", "wheel"}


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_legacy_lock(path: Path) -> dict[str, tuple[str, str]]:
    """Parse strict, source-controlled name/version/SHA pins without executing pip."""
    content = path.read_text(encoding="utf-8")
    assert content and content.endswith("\n"), "Missing lock contents or terminal newline"
    assert len(content) <= 16_384, "Unexpectedly large legacy dependency lock"
    result = {}
    for line in content.splitlines():
        match = LOCK_LINE.fullmatch(line)
        assert match is not None, "Malformed legacy lock entry"
        raw_name, version, digest = match.groups()
        assert HEX_SHA256.fullmatch(digest) is not None
        name = _normalize_name(raw_name)
        assert name not in result, "Ambiguous/duplicate normalized dependency name"
        result[name] = (version, digest)
    return result


def _parse_direct_requirement(value: str) -> str:
    """Extract a bounded direct name; do not treat PEP 621 ranges as exact pins."""
    assert isinstance(value, str)
    assert len(value) < 200 and all(token not in value for token in ("@", "://", ";", "[", "]"))
    match = re.fullmatch(r"([A-Za-z][A-Za-z0-9_-]*)(?:[<>=!~].+)", value)
    assert match is not None, "Direct dependency must declare an explicit range"
    return _normalize_name(match.group(1))


def test_reviewed_legacy_dependency_names_and_hashes_are_bounded():
    runtime = _parse_legacy_lock(ROOT / "deps" / "runtime-wheels.lock")
    build = _parse_legacy_lock(ROOT / "deps" / "build-wheels.lock")
    assert set(runtime) == REVIEWED_RUNTIME_NAMES
    assert set(build) == REVIEWED_BUILD_NAMES
    assert set(runtime).isdisjoint(build)
    assert len(runtime) == 12 and len(build) == 2


def test_direct_runtime_and_build_requirements_have_approved_legacy_pins():
    with (ROOT / "pyproject.toml").open("rb") as stream:
        metadata = tomllib.load(stream)
    declared = {_parse_direct_requirement(x) for x in metadata["project"]["dependencies"]}
    assert declared == {"typer", "rich", "textual"}
    runtime = _parse_legacy_lock(ROOT / "deps" / "runtime-wheels.lock")
    assert declared <= set(runtime)
    backend = {_parse_direct_requirement(x) for x in metadata["build-system"]["requires"]}
    assert backend == {"setuptools"}
    build = _parse_legacy_lock(ROOT / "deps" / "build-wheels.lock")
    assert backend <= set(build)


@pytest.mark.parametrize("bad", [
    "",
    "rich 15.0.0 " + "a" * 64,  # no terminal newline
    "rich 15.0.0 " + "z" * 64 + "\n",  # non-hex digest
    "rich 15.0.0 " + "A" * 64 + "\n",  # noncanonical digest
    "Rich 15.0.0 " + "a" * 64 + "\n",  # invalid distribution name
    "rich >=15 " + "a" * 64 + "\n",  # broad constraint
    "rich 15.0.0 " + "a" * 64 + "\nrich 15.0.0 " + "b" * 64 + "\n",
    "rich 15.0.0 " + "a" * 64 + "\n--extra-index-url https://evil.invalid\n",
])
def test_legacy_lock_parser_rejects_malformed_unreviewed_inputs(tmp_path, bad):
    candidate = tmp_path / "lock"
    candidate.write_text(bad, encoding="utf-8")
    with pytest.raises(AssertionError):
        _parse_legacy_lock(candidate)
