"""Rootless, disposable offline venv rehearsal of publisher-signed online wheels.

This is an intentionally NON-ACTIVATING preparation boundary for #83/#84.
The original REPOCACHE application wheel and true transactional activation
remain #84/#85 work. Never treat a prepared venv as trusted executable state.
"""
from __future__ import annotations

import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping

from repocache import online_deps, signed_dependency_staging, updater


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
    root = updater.ROOT
    _private_directory(root)
    parent = root / "online-preparations"
    if parent.is_symlink():
        raise PreparationInstallError("Symlinked online preparation directory")
    if not parent.exists():
        parent.mkdir(mode=0o700)
    _private_directory(parent)
    return parent


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


def _check_installed(packages: str, expected: tuple[online_deps.Wheel, ...]) -> None:
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
    for name, version in approved.items():
        if found.get(name) != version:
            raise PreparationInstallError("Staged package versions do not match signed lock")
    # Bootstrapped pip/setuptools/wheel may be present but must never become
    # sources for resolving or installing the signed runtime requirements.
    if set(found) - set(approved) - {"pip", "setuptools", "wheel"}:
        raise PreparationInstallError("Unapproved package was installed in staged venv")


def rehearse_signed_install(
    archive: bytes, manifest: bytes, signature: bytes, version: str,
    inventory: bytes, assets: Mapping[str, bytes], target: str,
    *, cafile: Path,
) -> dict[str, Any]:
    """Install dependencies in a throwaway managed venv, NEVER activate it.

    This method holds the existing root-owned exclusive update lock for the
    entire read/verify/download/pip/cleanup operation. Success only means a
    non-root rehearsal completed. It is NOT sufficient for a real upgrade,
    repair, release acceptance or executable trust.
    """
    with updater.update_transaction():
        updater.recover_transaction()
        prior = updater._installed()
        updater._check_active_layout(prior)
        if updater._version_tuple(version) <= updater._version_tuple(
                str(prior.get("version", "0.0.0"))):
            raise PreparationInstallError(
                "Online staging cannot repair or downgrade an existing generation")
        # Verify Ed25519 trust, the archive/policy/SBOM and locked URLs before
        # creating the private working directory or making a network request.
        wheels = signed_dependency_staging.verified_candidate_wheels(
            archive, manifest, signature, version, inventory, assets, target)
        previous_umask = os.umask(0o077)
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
                updater._run(check, timeout=90)
                installed_json = updater._run(package_list, timeout=90)
                _check_installed(installed_json, wheels)
                # TemporaryDirectory destroys the entire (potentially
                # executable) staged environment on success as well as error.
                # It is intentionally NEVER named as an active generation.
                return {
                    "status": "dependencies-verified-only",
                    "version": version, "target": target,
                    "dependency_count": len(wheels),
                    "activated": False,
                }
        except (online_deps.DependencyError, signed_dependency_staging.PreparationError,
                updater.UpdateError, OSError) as exc:
            raise PreparationInstallError(
                "Verified online environment rehearsal failed without activation") from exc
        finally:
            os.umask(previous_umask)
