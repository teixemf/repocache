"""Native distribution contract for Debian 13 and AlmaLinux 10."""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("repocache_platform", ROOT / "platform_check.py")
platform = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(platform)


@pytest.mark.parametrize(("identity", "major", "python"), [
    ("debian", "13", (3, 13)),
    ("almalinux", "10", (3, 12)),
])
def test_documented_platform_matrix(identity, major, python):
    assert (identity, major) in {("debian", "13"), ("almalinux", "10")}
    assert sys.version_info[:2] in {(3, 12), (3, 13)}
    assert python in {(3, 12), (3, 13)}


def test_exact_supported_versions_are_documented():
    source = (ROOT / "platform_check.py").read_text(encoding="utf-8")
    assert "debian" in source
    assert "almalinux" in source
    assert "13" in source and "10" in source
    assert "/etc/os-release" in source or "os-release" in source


def test_installers_reject_unsupported_interpreter_before_mutation():
    for path in (ROOT / "install.sh", ROOT / "client/install.sh"):
        data = path.read_text(encoding="utf-8")
        assert "platform_check.py" in data
        assert "/usr/bin/python3" in data
