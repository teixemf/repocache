"""Rootless, disposable offline venv rehearsal of publisher-signed online wheels.

This is an intentionally NON-ACTIVATING preparation boundary for #83/#84.
The original REPOCACHE application wheel and true transactional activation
remain #84/#85 work. Never treat a prepared venv as trusted executable state.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping

from repocache import application_wheel, online_deps, signed_dependency_staging, updater


class PreparationInstallError(RuntimeError):
    """No active release has been modified; retry only with a trusted candidate."""


def _private_directory(path: Path) -> None:
    try:
        entry = path.lstat()
    except OSError as exc:
        raise PreparationInstallError("Missing managed preparation directory") from exc
    if (not stat.S_ISDIR(entry.st_mode)
            or entry.st_uid != os.geteuid()
            or stat.S_IMODE(entry.st_mode) & 0o077):
        raise PreparationInstallError("Unsafe managed preparation ownership or permissions")


def _managed_parent() -> Path:
    """Create only an owner-private child of the existing trusted managed root."""
    if os.geteuid() == 0:
        raise PreparationInstallError("Online dependency preparation must never run as root")
    root = updater.ROOT
    _private_directory(root)
    parent = root / "online-preparations"
    if parent.is_symlink():
        raise PreparationInstallError("Symlinked online preparation directory")
    if not parent.exists():
        parent.mkdir(mode=0o700)
    _private_directory(parent)
    return parent


def _host_target(os_release: str, python_version: tuple[int, int]) -> str:
    """Bind a signed lock target to a real supported OS + native interpreter."""
    values: dict[str, str] = {}
    for line in os_release.splitlines():
        row = line.strip()
        if not row or row.startswith("#") or "=" not in row:
            continue
        name, value = row.split("=", 1)
        if name not in {"ID", "VERSION_ID"}:
            continue
        if name in values:
            raise PreparationInstallError("Duplicate local OS-release identity")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[name] = value
    version = values.get("VERSION_ID", "")
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", version):
        raise PreparationInstallError("Invalid native OS version")
    target = {
        ("debian", "13", (3, 13)): "debian13-py313",
        ("almalinux", "10", (3, 12)): "almalinux10-py312",
    }.get((values.get("ID", ""), version.split(".")[0], tuple(python_version)))
    if target is None:
        raise PreparationInstallError("Unsupported native OS or Python interpreter")
    return target


def _current_host_target() -> str:
    try:
        os_release = Path("/etc/os-release").read_text(encoding="utf-8")
    except OSError as exc:
        raise PreparationInstallError("Unreadable native platform identity") from exc
    return _host_target(os_release, sys.version_info[:2])


def _install_commands(interpreter: Path, lock: Path) -> tuple[list[str], ...]:
    """Run no resolver, build backend, network index or user pip configuration."""
    if not lock.is_file() or lock.is_symlink() or lock.name != "requirements.lock":
        raise PreparationInstallError("Verified offline dependency lock is missing")
    base = [str(interpreter), "-I", "-m", "pip", "--isolated"]
    install = base + [
        "install", "--no-index", "--no-deps", "--only-binary=:all:",
        "--require-hashes", "--disable-pip-version-check", "--no-cache-dir",
        "--no-input", "-r", str(lock),
    ]
    return (install, base + ["check"], base + ["list", "--format=json"])


def _check_installed(packages: str, expected: tuple[online_deps.Wheel, ...],
                     application_version: str | None = None) -> None:
    """Verify every approved package/version after pip, ignoring bootstrap pip."""
    try:
        data = json.loads(packages)
    except (ValueError, TypeError) as exc:
        raise PreparationInstallError("Invalid staged package inventory") from exc
    if not isinstance(data, list) or len(data) > online_deps.MAX_ENTRIES + 5:
        raise PreparationInstallError("Invalid staged package inventory")
    found = {}
    for entry in data:
        if (not isinstance(entry, dict) or type(entry.get("name")) is not str
                or type(entry.get("version")) is not str):
            raise PreparationInstallError("Malformed staged package identity")
        name = re.sub(r"[-_.]+", "-", entry["name"].lower())
        if name in found:
            raise PreparationInstallError("Duplicate staged package metadata")
        found[name] = entry["version"]
    approved = {wheel.name: wheel.version for wheel in expected}
    if application_version is not None:
        if "repocache-control" in approved:
            raise PreparationInstallError("First-party identity must not appear in upstream lock")
        approved["repocache-control"] = application_version
    for name, version in approved.items():
        if found.get(name) != version:
            raise PreparationInstallError("Staged package versions do not match signed lock")
    # Bootstrapped pip/setuptools/wheel may be present but must never become
    # sources for resolving or installing the signed runtime requirements.
    if set(found) - set(approved) - {"pip", "setuptools", "wheel"}:
        raise PreparationInstallError("Unapproved package was installed in staged venv")


def _stage_owned_application(directory: Path, archive: bytes, version: str,
                             assets: Mapping[str, bytes]) -> Path:
    """Only stage canonical source-equivalent bytes from the verified candidate."""
    source = assets.get("application_wheel")
    try:
        application_wheel.verify(source, archive, version)
    except application_wheel.ApplicationWheelError as exc:
        raise PreparationInstallError("Publisher-owned application wheel rejected") from exc
    if not isinstance(source, bytes):
        raise PreparationInstallError("Missing authenticated application wheel")
    if directory.is_symlink() or directory.exists():
        raise PreparationInstallError("Unexpected first-party wheel staging path")
    directory.mkdir(mode=0o700)
    path = directory / application_wheel.filename(version)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as owned:
            owned.write(source)
            owned.flush()
            os.fsync(owned.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    digest = hashlib.sha256(source).hexdigest()
    requirements = directory / "application.lock"
    fd = os.open(requirements, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as stream:
        stream.write("./" + path.name + " --hash=sha256:" + digest + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return requirements


def _application_install_command(interpreter: Path, requirement: Path) -> list[str]:
    if (requirement.name != "application.lock" or requirement.is_symlink()
            or not requirement.is_file()):
        raise PreparationInstallError("Authenticated application install lock missing")
    return [str(interpreter), "-I", "-m", "pip", "--isolated", "install",
            "--no-index", "--no-deps", "--only-binary=:all:",
            "--require-hashes", "--disable-pip-version-check",
            "--no-cache-dir", "--no-input", "-r", str(requirement)]


def _smoke_commands(interpreter: Path) -> tuple[list[str], ...]:
    """Read-only CLI and import-time TUI smoke; not an interactive run_test."""
    console = interpreter.parent / "repocache"
    if console.is_symlink() or not console.is_file():
        raise PreparationInstallError("First-party CLI console entrypoint missing")
    # Do not invoke network-dependent update commands or a terminal UI here.
    tui_import = (
        "from textual.app import App; "
        "from repocache.tui import RepoCacheApp; "
        "assert issubclass(RepoCacheApp, App); "
        "assert len(RepoCacheApp.BINDINGS) > 0"
    )
    return ([str(console), "--version"], [str(console), "--help"],
            [str(interpreter), "-I", "-c", tui_import])


def rehearse_signed_install(
    archive: bytes, manifest: bytes, signature: bytes, version: str,
    inventory: bytes, assets: Mapping[str, bytes], target: str,
    *, cafile: Path,
) -> dict[str, Any]:
    """Install signed third-party and first-party wheels, NEVER activate.

    This method holds the existing root-owned exclusive update lock for the
    entire read/verify/download/pip/cleanup operation. Success only means a
    non-root rehearsal completed. It is NOT sufficient for a real upgrade,
    repair, release acceptance or executable trust.
    """
    with updater.update_transaction():
        updater.recover_transaction()
        prior = updater._installed()
        updater._check_active_layout(prior)
        if target != _current_host_target():
            raise PreparationInstallError("Signed wheels do not match the native OS/Python")
        if updater._version_tuple(version) <= updater._version_tuple(
                str(prior.get("version", "0.0.0"))):
            raise PreparationInstallError(
                "Online staging cannot repair or downgrade an existing generation")
        # Verify Ed25519 trust, the archive/policy/SBOM and locked URLs before
        # creating the private working directory or making a network request.
        try:
            wheels = signed_dependency_staging.verified_candidate_wheels(
                archive, manifest, signature, version, inventory, assets, target)
        except signed_dependency_staging.PreparationError as exc:
            raise PreparationInstallError(
                "Publisher-signed online candidate was rejected before download") from exc
        # The candidate signature/inventory has already been checked;
        # enforce byte-for-byte original-source equivalence again before I/O.
        try:
            application_wheel.verify(assets.get("application_wheel"), archive, version)
        except application_wheel.ApplicationWheelError as exc:
            raise PreparationInstallError("Signed first-party wheel is invalid") from exc
        try:
            parent = _managed_parent()
            with tempfile.TemporaryDirectory(prefix=".online-v6-", dir=parent) as work:
                workdir = Path(work)
                _private_directory(workdir)
                lock = signed_dependency_staging.stage_signed_candidate(
                    archive, manifest, signature, version, inventory, assets,
                    target, workdir / "download", cafile=cafile)
                interpreter = workdir / "venv" / "bin" / "python"
                # Only the native Python/venv module bootstraps the environment.
                # Downloaded wheels are never processed by root or system pip.
                updater._run([
                    sys.executable, "-I", "-m", "venv",
                    str(workdir / "venv"),
                ], timeout=120)
                _private_directory(workdir / "venv")
                if not interpreter.exists() or not interpreter.is_file():
                    raise PreparationInstallError("Native isolated Python venv was not created")
                install, check, package_list = _install_commands(interpreter, lock)
                updater._run(install, cwd=lock.parent, timeout=300)
                app_lock = _stage_owned_application(
                    workdir / "owned-app", archive, version, assets)
                updater._run(_application_install_command(interpreter, app_lock),
                             cwd=app_lock.parent, timeout=180)
                updater._run(check, timeout=90)
                installed_json = updater._run(package_list, timeout=90)
                _check_installed(installed_json, wheels, application_version=version)
                cli_version, cli_help, tui_import = _smoke_commands(interpreter)
                version_output = updater._run(cli_version, timeout=30)
                if version_output.strip() != f"REPOCACHE Control Center {version}":
                    raise PreparationInstallError("Staged CLI reports unexpected version")
                help_output = updater._run(cli_help, timeout=30)
                if "Usage:" not in help_output or "update" not in help_output:
                    raise PreparationInstallError("Staged CLI help is invalid")
                updater._run(tui_import, timeout=30)
                # TemporaryDirectory destroys the entire (potentially
                # executable) staged environment on success as well as error.
                # It is intentionally NEVER named as an active generation.
                return {
                    "status": "application-and-dependencies-verified-only",
                    "version": version, "target": target,
                    "dependency_count": len(wheels),
                    "cli_smoke": "passed", "tui_import_smoke": "passed",
                    "activated": False,
                }
        except (online_deps.DependencyError, signed_dependency_staging.PreparationError,
                updater.UpdateError, OSError) as exc:
            raise PreparationInstallError(
                "Verified online environment rehearsal failed without activation") from exc
