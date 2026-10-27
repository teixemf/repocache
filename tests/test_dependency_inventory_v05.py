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

# Independently pinned from reviewed protected-main release-input blobs:
# runtime: 1e93f48fa03414fca3fd1986e470ebedaa4a79ac; build: 49751ba0c1bcd92552ad4fe6d0d89d8d11d2177f.
# Pin changes require explicit owner/dependency review and updated expectations.
REVIEWED_RUNTIME_PINS = {
    "annotated-doc": ("0.0.5", "117bac03a25ede5df5440e855b32d556049ca169ead221505badf432fed4b101"),
    "linkify-it-py": ("2.2.0", "3adc40eb5af300b2605fcfdb968c24e1d780a90f1f2221af7c15e5111e94d443"),
    "markdown-it-py": ("4.2.0", "9f7ebbcd14fe59494226453aed97c1070d83f8d24b6fc3a3bcf9a38092641c4a"),
    "mdit-py-plugins": ("0.6.1", "214c82fb2ac524472ab6a5bcab1de80f73b50443e187f401bfd77efbc7c6481d"),
    "mdurl": ("0.1.2", "84008a41e51615a49fc9966191ff91509e3c40b939176e643fd50a5c2196b8f8"),
    "platformdirs": ("4.13.5", "53d3ec4280b815c1e0b02edad7f9ee8fda1ba9c0865dd9c2e6e63849ce82fc1e"),
    "pygments": ("2.21.0", "2363c69b61c4a97c838da3b130dcd6468f4848992b21a82f2a63ec34377137d9"),
    "rich": ("15.0.0", "33bd4ef74232fb73fe9279a257718407f169c09b78a87ad3d296f548e27de0bb"),
    "shellingham": ("1.5.4", "7ecfff8f2fd72616f7481040475a65b2bf8af90a56c89140852d1120324e8686"),
    "textual": ("8.2.8", "267375fd402dc8d981457212efa71f0e3365fd17bba144ba9bb3ed7563cb374a"),
    "typer": ("0.27.3", "e50022f28b82a86313e54501317a1db64bf8f8d036ff8cfe5ca7e47675454aff"),
    "typing-extensions": ("4.16.0", "481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8"),
}
REVIEWED_BUILD_PINS = {
    "setuptools": ("80.9.0", "062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922"),
    "wheel": ("0.45.1", "708e7481cc80179af0e556bbf0cc00b8444c7321e2700b8d8580231d13017248"),
}
REVIEWED_RUNTIME_NAMES = set(REVIEWED_RUNTIME_PINS)
REVIEWED_BUILD_NAMES = set(REVIEWED_BUILD_PINS)
REVIEWED_DIRECT_RUNTIME = {
    "typer": "typer>=0.12,<1",
    "rich": "rich>=13,<16",
    "textual": "textual>=0.80,<10",
}
REVIEWED_DIRECT_BUILD = {"setuptools": "setuptools>=77"}


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


# Deliberately narrow PEP 440 release-specifier subset used by the reviewed
# pyproject: numeric releases and comparison operators only. Unsupported syntax
# (markers, extras, direct refs, pre-releases, ~=, wildcards) requires review.
REQUIREMENT = re.compile(
    r"([A-Za-z][A-Za-z0-9_-]*)((?:(?:<=|>=|==|!=|<|>)\d+(?:\.\d+){0,2})(?:,(?:<=|>=|==|!=|<|>)\d+(?:\.\d+){0,2})*)\\Z"
)
SPECIFIER = re.compile(r"(<=|>=|==|!=|<|>)(\d+(?:\.\d+){0,2})\\Z")


def _parse_direct_requirement(value: str) -> tuple[str, tuple[tuple[str, tuple[int, ...]], ...]]:
    """Require a supported, explicit PEP 440 release range without side effects."""
    assert isinstance(value, str) and len(value) < 200
    match = REQUIREMENT.fullmatch(value)
    assert match is not None, "Unreviewed or invalid direct requirement"
    name = _normalize_name(match.group(1))
    specs = []
    for item in re.split(r",(?=[<>=!])", match.group(2)):
        spec = SPECIFIER.fullmatch(item)
        assert spec is not None, "Invalid direct version specifier"
        specs.append((spec.group(1), tuple(int(i) for i in spec.group(2).split("."))))
    return name, tuple(specs)


def _assert_direct_requirements(values, locked, approved):
    """Check both approved declarations and pinned semantic compatibility."""
    assert isinstance(values, list)
    declarations = {}
    for raw in values:
        name, specs = _parse_direct_requirement(raw)
        assert name not in declarations, "Duplicate/contradictory direct requirement"
        assert name in locked, "No pinned wheel for direct requirement"
        pinned = tuple(int(i) for i in locked[name][0].split("."))
        for operator, required in specs:
            left, right = pinned + (0,) * (3 - len(pinned)), required + (0,) * (3 - len(required))
            valid = {"<": left < right, "<=": left <= right,
                     ">": left > right, ">=": left >= right,
                     "==": left == right, "!=": left != right}[operator]
            assert valid, "Locked version violates declared direct requirement"
        declarations[name] = raw
    assert declarations == approved, "Direct requirement drift requires review"

def test_reviewed_legacy_dependency_names_and_hashes_are_bounded():
    runtime = _parse_legacy_lock(ROOT / "deps" / "runtime-wheels.lock")
    build = _parse_legacy_lock(ROOT / "deps" / "build-wheels.lock")
    assert set(runtime) == REVIEWED_RUNTIME_NAMES
    assert set(build) == REVIEWED_BUILD_NAMES
    assert set(runtime).isdisjoint(build)
    assert len(runtime) == 12 and len(build) == 2
    assert runtime == REVIEWED_RUNTIME_PINS, "Reviewed runtime pin/version/hash drift"
    assert build == REVIEWED_BUILD_PINS, "Reviewed build pin/version/hash drift"


def test_direct_runtime_and_build_requirements_have_approved_legacy_pins():
    with (ROOT / "pyproject.toml").open("rb") as stream:
        metadata = tomllib.load(stream)
    runtime = _parse_legacy_lock(ROOT / "deps" / "runtime-wheels.lock")
    _assert_direct_requirements(metadata["project"]["dependencies"],
                                runtime, REVIEWED_DIRECT_RUNTIME)
    assert metadata["build-system"]["build-backend"] == "setuptools.build_meta"
    build = _parse_legacy_lock(ROOT / "deps" / "build-wheels.lock")
    _assert_direct_requirements(metadata["build-system"]["requires"],
                                build, REVIEWED_DIRECT_BUILD)



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


@pytest.mark.parametrize("mutation", ["version", "hash"])
def test_reviewed_pins_reject_independent_value_drift(tmp_path, mutation):
    original = (ROOT / "deps" / "runtime-wheels.lock").read_text(encoding="utf-8")
    if mutation == "version":
        changed = original.replace("rich 15.0.0 ", "rich 15.0.1 ", 1)
    else:
        changed = original.replace(REVIEWED_RUNTIME_PINS["rich"][1], "a" * 64, 1)
    assert changed != original
    candidate = tmp_path / "runtime.lock"
    candidate.write_text(changed, encoding="utf-8")
    parsed = _parse_legacy_lock(candidate)
    assert set(parsed) == REVIEWED_RUNTIME_NAMES  # names alone must not pass
    with pytest.raises(AssertionError):
        assert parsed == REVIEWED_RUNTIME_PINS


@pytest.mark.parametrize("declarations", [
    ["typer>=0.12,<1", "rich>=999", "textual>=0.80,<10"],
    ["typer>=0.12,<1", "typer>=999", "rich>=13,<16", "textual>=0.80,<10"],
    ["typer>=0.12,<1", "rich @ https://example.invalid/evil.whl", "textual>=0.80,<10"],
    ["typer>=0.12,<1", "rich[extra]>=13,<16", "textual>=0.80,<10"],
    ["typer>=0.12,<1", "rich>=13; python_version>'3'", "textual>=0.80,<10"],
    ["typer>=0.12,<1", "rich~=15", "textual>=0.80,<10"],
    ["typer>=0.12,<1", "rich>=invalid", "textual>=0.80,<10"],
])
def test_direct_requirements_fail_closed_on_unreviewed_semantics(declarations):
    with pytest.raises(AssertionError):
        _assert_direct_requirements(declarations, REVIEWED_RUNTIME_PINS,
                                    REVIEWED_DIRECT_RUNTIME)
