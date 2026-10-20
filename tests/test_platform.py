"""Executable negative OS/Python contract for both supported native runtimes.

These tests validate the production preflight with synthetic /etc/os-release
inputs. The installer scripts and native bundle smoke separately exercise
the actual OS interpreter and fail-closed installation ordering.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("repocache_platform", ROOT / "platform_check.py")
platform = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(platform)


@pytest.mark.parametrize(("os_release", "python"), [
    ('ID=debian\nVERSION_ID="13"\n', (3, 13)),
    ("ID=debian\nVERSION_ID=13.0\n", (3, 13)),
    ('ID="almalinux"\nVERSION_ID="10"\n', (3, 12)),
    ("ID=almalinux\nVERSION_ID=10.1\n", (3, 12)),
])
def test_validate_accepts_only_expected_native_pairs(os_release, python):
    platform.validate(os_release, python)


@pytest.mark.parametrize(("os_release", "python", "expected"), [
    ("ID=debian\nVERSION_ID=12\n", (3, 13), "Unsupported OS"),
    ("ID=debian\nVERSION_ID=14\n", (3, 13), "Unsupported OS"),
    ("ID=almalinux\nVERSION_ID=9\n", (3, 12), "Unsupported OS"),
    ("ID=almalinux\nVERSION_ID=11\n", (3, 12), "Unsupported OS"),
    ("ID=ubuntu\nVERSION_ID=24.04\n", (3, 12), "Unsupported OS"),
    ("ID=rhel\nVERSION_ID=10\n", (3, 12), "Unsupported OS"),
    ("ID=debian\nVERSION_ID=13\n", (3, 12), "Unsupported system Python"),
    ("ID=almalinux\nVERSION_ID=10\n", (3, 13), "Unsupported system Python"),
    ("ID=debian\nVERSION_ID=13\n", (3, 9), "Unsupported system Python"),
    ("ID=almalinux\nVERSION_ID=10\n", (3, 11), "Unsupported system Python"),
    ("ID=debian\nVERSION_ID=thirteen\n", (3, 13), "invalid VERSION_ID"),
    ("ID=debian\nVERSION_ID=\n", (3, 13), "invalid VERSION_ID"),
    ("ID=debian\n", (3, 13), "invalid VERSION_ID"),
    ("VERSION_ID=13\n", (3, 13), "Unsupported OS"),
    ("ID=debian\nID=almalinux\nVERSION_ID=13\n", (3, 13), "Duplicate ID"),
    ("ID=debian\nVERSION_ID=13\nVERSION_ID=14\n", (3, 13), "Duplicate VERSION_ID"),
])
def test_unsupported_or_ambiguous_platform_fails_closed(os_release, python, expected):
    with pytest.raises(platform.PlatformError, match=expected):
        platform.validate(os_release, python)


def test_preflight_is_nonmutating(monkeypatch):
    class Source:
        def read_text(self, encoding):
            assert encoding == "utf-8"
            return "ID=debian\nVERSION_ID=12\n"

    accessed = []
    def only_os_release(path):
        accessed.append(path)
        assert path == "/etc/os-release"
        return Source()

    monkeypatch.setattr(platform, "Path", only_os_release)
    assert platform.main() == 1
    assert accessed == ["/etc/os-release"]


def test_installers_run_native_preflight_before_system_mutations():
    for file in ("install.sh", "client/install.sh"):
        text = (ROOT / file).read_text(encoding="utf-8")
        pos = text.index('"/usr/bin/python3" -I')
        assert "platform_check.py" in text[pos:pos + 180]
        writes = ("install -d", "install -m", "cat >")
        for marker in writes:
            if marker in text:
                assert pos < text.index(marker)
        assert "PYTHON=" not in text[:pos] or file == "client/install.sh"


def test_python_dependency_floor_is_not_platform_support():
    metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.12"' in metadata
    assert sys.version_info[:2] in ((3, 12), (3, 13))
    assert platform.SUPPORTED == {
        ("debian", "13"): (3, 13),
        ("almalinux", "10"): (3, 12),
    }
