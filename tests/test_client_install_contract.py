"""UC-10 installer argument preflight: isolated, unprivileged regression checks.

Execute only the explicitly marked, side-effect-free preflight segment from
client/install.sh. Never run the real privileged installer in a unit test.
Native clean-install, permissions and upgrade behavior remain NOT VERIFIED.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "client/install.sh"
BEGIN = "# BEGIN SERVER_ARGUMENT_PREFLIGHT"
END = "# END SERVER_ARGUMENT_PREFLIGHT"


def _preflight(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    script = INSTALLER.read_text(encoding="utf-8")
    assert script.count(BEGIN) == script.count(END) == 1
    isolated = script.split(BEGIN, 1)[1].split(END, 1)[0]
    assert "install -d" not in isolated
    assert "os.replace" not in isolated
    bash = (
        "set -Eeuo pipefail\n"
        + isolated
        + '\nprintf "SERVER=%s\\n" "$SERVER"\n'
    )
    return subprocess.run(
        ["bash", "-c", bash, "preflight", *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )


def test_installer_shell_syntax():
    result = subprocess.run(
        ["bash", "-n", str(INSTALLER)], capture_output=True,
        text=True, check=False, timeout=10,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("origin", (
    "https://cache.example.org",
    "https://cache.example.org/",
    "https://cache.example.org:8443",
    "https://[2001:db8::1]:8443",
))
def test_explicit_https_origin_is_accepted(origin, tmp_path):
    result = _preflight("--server", origin, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"SERVER={origin}\n"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("args", (
    (),
    ("--server",),
    ("--server", ""),
    ("--unknown", "x"),
    ("--server", "http://cache.example.org"),
    ("--server", "https://user:secret@cache.example.org"),
    ("--server", "https://cache.example.org/path"),
    ("--server", "https://cache.example.org?query=1"),
    ("--server", "https://cache.example.org#fragment"),
    ("--server", "https://cache.example.org:0"),
    ("--server", "https://cache.example.org:65536"),
    ("--server", " https://cache.example.org"),
    ("--server", "https://cache.example.org", "--server", "https://other.example.org"),
))
def test_invalid_server_or_ambiguous_arguments_fail_without_changes(args, tmp_path):
    result = _preflight(*args, cwd=tmp_path)
    assert result.returncode != 0
    assert "SERVER=" not in result.stdout
    assert list(tmp_path.iterdir()) == []


def test_installer_requires_preflight_before_managed_file_writes():
    script = INSTALLER.read_text(encoding="utf-8")
    assert "SERVER=\"https://cache.example.org\"" not in script
    assert script.index(BEGIN) < script.index(END)
    assert script.index(END) < script.index('install -d -m 0755 "$TARGET_DIR"')
    assert '[[ -n "$SERVER" ]]' in script
