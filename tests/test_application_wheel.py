"""First-party application wheel must be reproducible and source-identical."""
from __future__ import annotations

import io
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from repocache import application_wheel


def _archive(version="0.6.0"):
    members = {
        "pyproject.toml": (
            '[project]\nname = "repocache-control"\nversion = "' + version +
            '"\nrequires-python = ">=3.12"\nlicense = "Apache-2.0"\n'
            'dependencies = ["typer>=0.12,<1", "rich>=13,<16", "textual>=0.80,<10"]\n'
            '[project.scripts]\nrepocache = "repocache.cli:app"\n'
        ).encode(),
        "LICENSE": b"Original project license fixture\n",
        "src/repocache/__init__.py": ('__version__ = "' + version + '"\n').encode(),
        "src/repocache/cli.py": b"# real REPOCACHE code represented by fixture\n",
    }
    sink = io.BytesIO()
    with tarfile.open(fileobj=sink, mode="w:gz") as archive:
        for name, contents in sorted(members.items()):
            member = tarfile.TarInfo(f"repocache-v{version}/{name}")
            member.mode = 0o644
            member.size = len(contents)
            archive.addfile(member, io.BytesIO(contents))
    return sink.getvalue()


def test_wheel_deterministic_and_has_original_application_files():
    source = _archive()
    first = application_wheel.build(source, "0.6.0")
    second = application_wheel.build(source, "0.6.0")
    assert first == second
    application_wheel.verify(first, source, "0.6.0")
    with zipfile.ZipFile(io.BytesIO(first)) as wheel:
        paths = set(wheel.namelist())
        assert "repocache/__init__.py" in paths
        assert "repocache/cli.py" in paths
        base = "repocache_control-0.6.0.dist-info/"
        assert base + "METADATA" in paths
        assert base + "RECORD" in paths
        assert wheel.read(base + "entry_points.txt") == (
            b"[console_scripts]\nrepocache = repocache.cli:app\n")
        assert b"Requires-Dist: typer>=0.12,<1" in wheel.read(base + "METADATA")
        assert b"Root-Is-Purelib: true" in wheel.read(base + "WHEEL")
        assert not any("rich/" in x or "textual/" in x for x in paths)


def test_wheel_exact_signature_bound_bytes_reject_substitution():
    source = _archive()
    wheel = application_wheel.build(source, "0.6.0")
    with pytest.raises(application_wheel.ApplicationWheelError, match="differs"):
        application_wheel.verify(wheel + b"appended", source, "0.6.0")
    with pytest.raises(application_wheel.ApplicationWheelError, match="differs"):
        application_wheel.verify(
            wheel, _archive("0.6.1"), "0.6.0")


@pytest.mark.parametrize("version", ["0.4.0rc1", "v0.6.0", "0.06.0", "../../0.6.0"])
def test_noncanonical_application_wheel_versions_refused(version):
    with pytest.raises(application_wheel.ApplicationWheelError):
        application_wheel.filename(version)


def test_synthetic_first_party_wheel_installs_offline_without_build_backend(tmp_path):
    """Actually exercise target-independent wheel format using native CI Python.

    This does not prove the complete CLI/TUI or upstream dependency venv.
    """
    wheel = application_wheel.build(_archive(), "0.6.0")
    binary = tmp_path / application_wheel.filename("0.6.0")
    binary.write_bytes(wheel)
    venv = tmp_path / "isolated"
    subprocess.run([sys.executable, "-I", "-m", "venv", str(venv)],
                   check=True, timeout=60, capture_output=True)
    python = venv / "bin" / "python"
    commands = [
        [str(python), "-I", "-m", "pip", "--isolated", "install",
         "--no-index", "--no-deps", "--only-binary=:all:",
         "--no-input", "--disable-pip-version-check", str(binary)],
        [str(python), "-I", "-m", "pip", "--isolated", "show", "repocache-control"],
    ]
    for command in commands:
        subprocess.run(command, check=True, timeout=60, capture_output=True,
                       env={"PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1",
                            "PIP_CONFIG_FILE": "/dev/null", "PIP_NO_INPUT": "1"})
    assert (venv / "bin" / "repocache").is_file()
