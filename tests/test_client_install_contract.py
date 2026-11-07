"""UC-10 installer argument preflight: isolated, unprivileged regression checks.

Execute only the explicitly marked, side-effect-free preflight segment from
client/install.sh. Never run the real privileged installer in a unit test.
Native clean-install, permissions and upgrade behavior remain NOT VERIFIED.
"""
from __future__ import annotations

import os
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
    "https://127.0.0.1:8443",
    "https://xn--bcher-kva.example.org",
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
    ("--server", "https://cache.example.org?"),
    ("--server", "https://cache.example.org#"),
    ("--server", "https://cache.example.org/?"),
    ("--server", "https://cache.example.org/#"),
    ("--server", "https://cache.example.org:0"),
    ("--server", "https://cache.example.org:65536"),
    ("--server", "https://cache.example.org:"),
    ("--server", "https://cache.example.org."),
    ("--server", "https://bad_host.example.org"),
    ("--server", "https://cache..example.org"),
    ("--server", "https://-bad.example.org"),
    ("--server", "https://cache.example.org%0a.evil.org"),
    ("--server", "https://0x7f000001"),
    ("--server", "https://127.1"),
    ("--server", "https://ca\\\\che.example.org"),
    ("--server", "https://☃.example.org"),
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
    # Regressions here can silently break an otherwise valid root installer.
    for assignment in (
        'SOURCE="$HERE/repocache_client.py"',
        'TARGET_DIR="/opt/repocache-client"',
        'CONFIG_DIR="/etc/repocache-client"',
        'LAUNCHER="/usr/local/bin/repocache-client"',
        'PYTHON="/usr/bin/python3"',
    ):
        assert script.count(assignment) == 1
        assert script.index(assignment) < script.index('install -d -m 0755 "$TARGET_DIR"')


# Managed path safety: execute only the non-writing preflight in a disposable
# root. The actual root installer and real /etc and /opt are never invoked.
PATH_BEGIN = "# BEGIN MANAGED_PATH_PREFLIGHT"
PATH_END = "# END MANAGED_PATH_PREFLIGHT"


def _managed_path_preflight(target_dir: Path, config_dir: Path, cwd: Path):
    script = INSTALLER.read_text(encoding="utf-8")
    assert script.count(PATH_BEGIN) == script.count(PATH_END) == 1
    isolated = script.split(PATH_BEGIN, 1)[1].split(PATH_END, 1)[0]
    for forbidden in ("install -d", "os.replace", "cat >", "mv -f"):
        assert forbidden not in isolated
    bash = (
        "set -Eeuo pipefail\n"
        'TARGET_DIR="$1"\nCONFIG_DIR="$2"\n'
        + isolated
        + 'printf "PREFLIGHT_OK\n"\n'
    )
    return subprocess.run(
        ["bash", "-c", bash, "path-preflight", str(target_dir), str(config_dir)],
        cwd=cwd, capture_output=True, text=True, check=False, timeout=10,
    )


@pytest.mark.parametrize(("component", "kind"), (
    ("target_dir", "symlink"),
    ("config_dir", "symlink"),
    ("target_file", "symlink"),
    ("config_file", "symlink"),
    ("target_dir", "file"),
    ("config_dir", "file"),
    ("target_file", "fifo"),
    ("config_file", "directory"),
))
def test_managed_path_preflight_rejects_unsafe_existing_paths(
        component, kind, tmp_path):
    target_dir = tmp_path / "opt/repocache-client"
    config_dir = tmp_path / "etc/repocache-client"
    target_dir.parent.mkdir()
    config_dir.parent.mkdir()
    if component.endswith("_file"):
        target_dir.mkdir()
        config_dir.mkdir()
    targets = {
        "target_dir": target_dir,
        "config_dir": config_dir,
        "target_file": target_dir / "repocache_client.py",
        "config_file": config_dir / "config.json",
    }
    path = targets[component]
    outside = tmp_path / "outside"
    outside.mkdir()
    if kind == "symlink":
        path.symlink_to(outside, target_is_directory=True)
    elif kind == "file":
        path.write_text("not a managed directory")
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        path.mkdir()
    result = _managed_path_preflight(target_dir, config_dir, tmp_path)
    assert result.returncode != 0
    assert "Unsafe client managed" in result.stderr
    assert not any(outside.iterdir())


@pytest.mark.parametrize("existing", (False, True))
def test_managed_path_preflight_accepts_safe_regular_paths(existing, tmp_path):
    target_dir = tmp_path / "opt/repocache-client"
    config_dir = tmp_path / "etc/repocache-client"
    target_dir.parent.mkdir()
    config_dir.parent.mkdir()
    if existing:
        target_dir.mkdir()
        config_dir.mkdir()
        (target_dir / "repocache_client.py").write_text("# managed")
        (config_dir / "config.json").write_text('{"server": "https://cache.example.org"}')
    result = _managed_path_preflight(target_dir, config_dir, tmp_path)
    assert result.returncode == 0, result.stderr
    assert "PREFLIGHT_OK" in result.stdout


def test_path_preflight_precedes_all_managed_writes_and_launcher_is_unique():
    script = INSTALLER.read_text(encoding="utf-8")
    assert script.index(PATH_BEGIN) < script.index(PATH_END)
    assert script.index(PATH_END) < script.index('install -d -m 0755 "$TARGET_DIR"')
    assert 'cat > "$LAUNCHER.tmp"' not in script
    assert '/usr/bin/mktemp "$' + '{LAUNCHER}.XXXXXXXX"' in script
    assert 'cat > "$LAUNCHER_TEMP"' in script
    assert 'mv -f -- "$LAUNCHER_TEMP" "$LAUNCHER"' in script
    assert 'trap ' in script and 'LAUNCHER_TEMP=""' in script
