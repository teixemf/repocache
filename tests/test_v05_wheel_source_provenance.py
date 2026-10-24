"""Source-to-signed-first-party-wheel inventory negatives for v0.5 bridge."""
from __future__ import annotations

import importlib.util
import zipfile
import stat
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


def test_reviewed_nested_first_party_modules_are_verified(source, tmp_path):
    package = source / "src/repocache"
    nested = package / "extensions"
    nested.mkdir()
    (nested / "__init__.py").write_bytes(b"# reviewed nested package\\n")
    (nested / "worker.py").write_bytes(b"def guard(): return True\\n")
    modules = {f"repocache/{p.relative_to(package).as_posix()}": p.read_bytes()
               for p in package.rglob("*.py")}
    builder.verify_first_party_modules(source, wheel(tmp_path, modules))
    del modules["repocache/extensions/worker.py"]
    with pytest.raises(RuntimeError, match="module inventory"):
        builder.verify_first_party_modules(source, wheel(tmp_path, modules))


def test_unreviewed_nested_wheel_module_is_rejected(source, tmp_path):
    modules = {f"repocache/{p.name}": p.read_bytes()
               for p in (source / "src/repocache").glob("*.py")}
    modules["repocache/hidden/entry.py"] = b"def side_effect(): pass\\n"
    with pytest.raises(RuntimeError, match="module inventory"):
        builder.verify_first_party_modules(source, wheel(tmp_path, modules))


def test_duplicate_first_party_wheel_zip_member_is_rejected(source, tmp_path):
    modules = {f"repocache/{p.name}": p.read_bytes()
               for p in (source / "src/repocache").glob("*.py")}
    output = wheel(tmp_path, modules)
    with pytest.warns(UserWarning, match="Duplicate name"):
        with zipfile.ZipFile(output, "a") as archive:
            archive.writestr("repocache/submissions.py",
                             b"def accept(): return True\\n")
    with pytest.raises(RuntimeError, match="duplicate ZIP members"):
        builder.verify_first_party_modules(source, output)


def test_first_party_wheel_symlinked_python_module_is_rejected(source, tmp_path):
    output = tmp_path / "linked.whl"
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("repocache/__init__.py",
                         (source / "src/repocache/__init__.py").read_bytes())
        member = zipfile.ZipInfo("repocache/submissions.py")
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(member, "repocache/__init__.py")
    with pytest.raises(RuntimeError, match="symlinked module"):
        builder.verify_first_party_modules(source, output)


@pytest.mark.parametrize("unreviewed_member", (
    "repocache/extension.so",
    "repocache/compiled.pyc",
    "repocache/loader.pth",
    "repocache/config.bin",
))
def test_non_python_package_payload_is_not_audit_bypass(
    source, tmp_path, unreviewed_member
):
    modules = {f"repocache/{p.name}": p.read_bytes()
               for p in (source / "src/repocache").glob("*.py")}
    modules[unreviewed_member] = b"unreviewed payload"
    with pytest.raises(RuntimeError, match="unreviewed package payload"):
        builder.verify_first_party_modules(source, wheel(tmp_path, modules))


# Independently frozen from genuine public v0.4.0 source-tar contract.
# The immutable v0.4.0 upgrader rejects any extra/missing archive member;
# newly approved v0.5 application modules must ship through the signed,
# hash-pinned first-party wheel in the legacy wheelhouse instead.
PUBLIC_V04_SOURCE_FILES = frozenset({
    "README.md", "CHANGELOG.md", "LICENSE", "THIRD_PARTY_NOTICES.md",
    "pyproject.toml", "install.sh", "platform_check.py", "release-policy.json",
    "docs/PRODUCTION_EXISTING_NGINX.md",
    "src/repocache/__init__.py", "src/repocache/cli.py",
    "src/repocache/core.py", "src/repocache/catalog.py",
    "src/repocache/rendering.py", "src/repocache/tui.py",
    "src/repocache/updater.py", "src/repocache/releases.py",
    "src/repocache/upgrade.py", "src/repocache/signatures.py",
    "src/repocache/recovery.py", "src/repocache/wheelhouse.py",
    "client/repocache_client.py", "client/install.sh",
    "scripts/bootstrap-rootless.sh", "scripts/repocache-launcher.sh",
})


def test_frozen_public_v04_archive_parser_remains_compatible_with_v05_builder():
    from repocache import upgrade
    from scripts import build_release

    assert upgrade.RELEASE_FILES == PUBLIC_V04_SOURCE_FILES
    assert set(build_release.FILES) == PUBLIC_V04_SOURCE_FILES
    # These v0.5 feature modules are intentionally omitted from the old tar
    # format but MUST be represented in the separately signed app wheel.
    for name in (
        "src/repocache/submissions.py",
        "src/repocache/submission_decisions.py",
        "src/repocache/submission_db_worker.py",
        "src/repocache/submission_recovery.py",
        "src/repocache/intake.py",
    ):
        assert name not in PUBLIC_V04_SOURCE_FILES
        assert (ROOT / name).is_file()
