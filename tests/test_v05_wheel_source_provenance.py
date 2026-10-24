"""Source-to-signed-first-party-wheel inventory negatives for v0.5 bridge."""
from __future__ import annotations

import importlib.util
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "ci_offline_wheels_provenance", ROOT / "scripts/ci_offline_wheels.py")
assert spec and spec.loader
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


@pytest.fixture
def source(tmp_path):
    package = tmp_path / "src/repocache"
    package.mkdir(parents=True)
    (package / "__init__.py").write_bytes(b"__version__ = '0.5.0'\n")
    (package / "submissions.py").write_bytes(b"def accept():\n    return False\n")
    return tmp_path


def wheel(tmp_path, members):
    output = tmp_path / "app.whl"
    with zipfile.ZipFile(output, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return output


def test_reviewed_module_inventory_and_exact_bytes_pass(source, tmp_path):
    modules = {f"repocache/{p.name}": p.read_bytes()
               for p in (source / "src/repocache").glob("*.py")}
    builder.verify_first_party_modules(source, wheel(tmp_path, modules))


@pytest.mark.parametrize("attack", ["missing", "extra", "modified"])
def test_first_party_wheel_refuses_missing_extra_or_modified_module(
    source, tmp_path, attack
):
    modules = {f"repocache/{p.name}": p.read_bytes()
               for p in (source / "src/repocache").glob("*.py")}
    if attack == "missing":
        del modules["repocache/submissions.py"]
    elif attack == "extra":
        modules["repocache/unreviewed.py"] = b"print('unreviewed')\n"
    else:
        modules["repocache/submissions.py"] += b"# changed\n"
    with pytest.raises(RuntimeError, match="First-party wheel"):
        builder.verify_first_party_modules(source, wheel(tmp_path, modules))


def test_empty_source_is_not_accepted(tmp_path):
    (tmp_path / "src/repocache").mkdir(parents=True)
    with pytest.raises(RuntimeError, match="Missing reviewed"):
        builder.verify_first_party_modules(tmp_path, wheel(tmp_path, {}))
