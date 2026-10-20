"""Fail-closed release archive verification, compatibility and safe upgrade.

Untrusted GitHub metadata only selects asset IDs. Neither asset content nor a
version tag is considered trusted until the official archive and checksum
match. No NGINX/cache/APT/DNF configuration is touched by this module.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import ssl
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from repocache import releases, updater, signatures, wheelhouse

MAX_ARCHIVE = 12_000_000
MAX_CHECKSUM = 256
MAX_MANIFEST = signatures.MAX_MANIFEST
MAX_SIGNATURE = signatures.MAX_SIGNATURE
MAX_WHEELHOUSE = wheelhouse.MAX_WHEELHOUSE
MAX_UNPACKED = 30_000_000
RELEASE_FILES = frozenset((
    "README.md", "CHANGELOG.md", "LICENSE", "pyproject.toml", "install.sh", "platform_check.py", "release-policy.json",
    "docs/PRODUCTION_EXISTING_NGINX.md",
    "src/repocache/__init__.py", "src/repocache/cli.py",
    "src/repocache/core.py", "src/repocache/catalog.py",
    "src/repocache/rendering.py", "src/repocache/tui.py",
    "src/repocache/updater.py", "src/repocache/releases.py",
    "src/repocache/upgrade.py", "src/repocache/signatures.py",
    "src/repocache/recovery.py", "src/repocache/wheelhouse.py",
    "client/repocache_client.py",
    "client/install.sh",
    "scripts/bootstrap-rootless.sh", "scripts/repocache-launcher.sh",
))


class UpgradeError(updater.UpdateError):
    """Upgrade declined or failed without exposing URLs or credentials."""


def _safe_version(value: Optional[str]) -> str:
    if not isinstance(value, str) or releases._version("v" + value) is None:
        raise UpgradeError("A stable X.Y.Z release version is required")
    return value


def _request_bytes(url: str, max_bytes: int, token: Optional[str] = None) -> bytes:
    """Bounded HTTPS request; do not follow redirects or log signed URLs."""
    parsed = urllib.parse.urlsplit(url)
    api = (parsed.netloc == "api.github.com" and re.fullmatch(
        r"/repos/" + re.escape(releases.REPOSITORY) + r"/releases/assets/[1-9][0-9]*",
        parsed.path) is not None)
    cdn = parsed.netloc in (
        "release-assets.githubusercontent.com", "objects.githubusercontent.com",
        "github-releases.githubusercontent.com")
    # URLs may contain short-lived signed CDN query parameters, but never
    # credentials, an alternate port, a fragment or a misleading GitHub host.
    if (parsed.scheme != "https" or parsed.username or parsed.password
            or parsed.fragment or not (api or cdn) or (token is not None and not api)):
        raise UpgradeError("Refusing a non-GitHub asset URL or credential redirect")
    if token is not None:
        raise UpgradeError("Public release assets must never receive private credentials")
    headers = {"User-Agent": "repocache-safe-upgrade/1",
               "Accept": "application/octet-stream" if api else "*/*"}
    opener = urllib.request.build_opener(
        releases.NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(request, timeout=12) as response:
            data = response.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        if exc.code in (301, 302, 303, 307, 308):
            target = exc.headers.get("Location", "")
            # Exactly one hop: official API -> approved HTTPS CDN. An
            # API-to-API loop or a second CDN redirect is rejected outright,
            # before contacting the new origin. Never log signed URL queries.
            signed = urllib.parse.urlsplit(target)
            if (not api or signed.scheme != "https" or
                    signed.netloc not in (
                        "release-assets.githubusercontent.com",
                        "objects.githubusercontent.com",
                        "github-releases.githubusercontent.com") or
                    signed.username or signed.password or signed.fragment):
                raise UpgradeError("Unexpected asset download redirect")
            return _request_bytes(target, max_bytes, token=None)
        if exc.code in (401, 404):
            raise releases.DiscoveryError(
                "authentication-required", "Release asset is unavailable or authentication is required")
        if exc.code == 403:
            raise UpgradeError("GitHub asset access denied or rate limited")
        raise UpgradeError("GitHub asset download failed with HTTP " + str(exc.code))
    except (OSError, urllib.error.URLError, TimeoutError):
        raise UpgradeError("Could not download a release asset securely")
    if len(data) > max_bytes:
        raise UpgradeError("Release asset exceeds the maximum allowed size")
    return data


def _download_asset(asset: Dict[str, Any], token_file: Path,
                    max_bytes: int) -> bytes:
    asset_id, size = asset.get("id"), asset.get("size")
    if (type(asset_id) is not int or asset_id <= 0
            or type(size) is not int or size <= 0 or size > max_bytes):
        raise UpgradeError("Invalid release asset metadata or size")
    url = (releases.API_ORIGIN + "/repos/" + releases.REPOSITORY +
           "/releases/assets/" + str(asset_id))
    # Public asset acquisition is always anonymous. Legacy token_file is
    # retained only as a caller-compatible unused parameter.
    content = _request_bytes(url, max_bytes)
    if len(content) != size:
        raise UpgradeError("Release asset does not match the reported size")
    return content


def _verify_checksum(archive: bytes, checksum: bytes, version: str) -> None:
    filename = "repocache-v" + version + ".tar.gz"
    expected = hashlib.sha256(archive).hexdigest()
    try:
        actual = checksum.decode("ascii")
    except UnicodeError:
        raise UpgradeError("Checksum file is not ASCII")
    if actual != expected + "  " + filename + "\n":
        raise UpgradeError("Release archive SHA-256 verification failed")


def _validate_native_runtime(system: Dict[str, str], python_version: Tuple[int, int]) -> None:
    """Check OS and native Python pairs independently of signed release policy."""
    major = system.get("VERSION_ID", "").split(".", 1)[0]
    expected = {("debian", "13"): (3, 13), ("almalinux", "10"): (3, 12)}.get(
        (system.get("ID", ""), major))
    if expected is None:
        raise UpgradeError("Selected release is not approved for this Linux OS/version")
    if python_version != expected:
        raise UpgradeError("OS-native Python version does not match the supported target")


def _policy(data: Any, version: str, previous: Dict[str, Any],
            system: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Explicit allowlist of supported paths between release versions."""
    if not isinstance(data, dict) or set(data) != {
        "schema", "version", "python_min", "python_max_exclusive",
        "targets", "compatible_from", "downgrade_from",
        "config_schema", "api_schema"
    } or data["schema"] != 1 or data["version"] != version:
        raise UpgradeError("Missing or mismatched compatibility policy")
    def py_pair(raw: Any) -> Tuple[int, int]:
        if not isinstance(raw, str) or not re.fullmatch(r"[0-9]+\.[0-9]+", raw):
            raise UpgradeError("Invalid Python compatibility policy")
        parts = raw.split(".")
        return int(parts[0]), int(parts[1])
    low, high = py_pair(data["python_min"]), py_pair(data["python_max_exclusive"])
    if not low <= sys.version_info[:2] < high:
        raise UpgradeError("Selected release does not support this Python runtime")
    if data["config_schema"] != 1 or data["api_schema"] != 1:
        raise UpgradeError("Unsupported configuration or API compatibility schema")
    targets = data["targets"]
    if (not isinstance(targets, list) or not targets or len(targets) > 20 or
            not all(isinstance(x, dict) and set(x) == {"id", "major"} and
                    isinstance(x["id"], str) and isinstance(x["major"], str)
                    for x in targets)):
        raise UpgradeError("Invalid supported OS policy")
    live_host = system is None
    if system is None:
        system = {}
        try:
            for line in Path("/etc/os-release").read_text().splitlines():
                if "=" in line:
                    key, val = line.split("=", 1)
                    if key in ("ID", "VERSION_ID"):
                        system[key] = val.strip().strip("'\"")
        except OSError:
            pass
    if live_host:
        _validate_native_runtime(system, sys.version_info[:2])
    identifier = system.get("ID", "")
    major = system.get("VERSION_ID", "").split(".")[0]
    if not any(t["id"] == identifier and t["major"] == major for t in targets):
        raise UpgradeError("Selected release is not approved for this Linux OS/version")
    for name in ("compatible_from", "downgrade_from"):
        values = data[name]
        if (not isinstance(values, list) or len(values) > 100 or
                any(not isinstance(x, str) or releases._version("v" + x) is None for x in values)
                or len(values) != len(set(values))):
            raise UpgradeError("Invalid version compatibility allowlist")
    current = str(previous.get("version", "0.0.0"))
    # "0.0.0" represents a clean host. An empty compatible_from list means
    # first standalone public release, never permission to migrate older hosts.
    # Exact same-version retries are checked against the original installed
    # source_digest in install_source; reject attempts to replace mutated code.
    if current not in ("0.0.0", version) and current not in data["compatible_from"]:
        raise UpgradeError("Compatibility with the installed version is not established")
    if updater._version_tuple(version) < updater._version_tuple(current):
        current_policy = previous.get("release_policy")
        if (not isinstance(current_policy, dict)
                or version not in current_policy.get("downgrade_from", [])
                or current_policy.get("config_schema") != data["config_schema"]
                or current_policy.get("api_schema") != data["api_schema"]):
            raise UpgradeError("Downgrade is not explicitly compatible with the installed release")
    return data


def _extract_verified(data: bytes, version: str, directory: Path,
                      previous: Dict[str, Any],
                      system: Optional[Dict[str, str]] = None,
                      signed_policy_sha256: Optional[str] = None) -> Tuple[Path, Dict[str, Any]]:
    """Only extract an exact set of regular source files, without tar.extractall."""
    prefix = "repocache-v" + version + "/"
    source = directory / ("repocache-v" + version)
    source.mkdir(parents=True, mode=0o700)
    found = set()
    unpacked = 0
    policy: Optional[Dict[str, Any]] = None
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r|gz") as tar:
            for item in tar:
                path = item.name
                if (not item.isfile() or not path.startswith(prefix)
                        or path[len(prefix):] not in RELEASE_FILES
                        or path in found or item.size < 0
                        or item.mode & 0o7000):
                    raise UpgradeError("Unsafe or unexpected release archive layout")
                found.add(path)
                unpacked += item.size
                if len(found) > len(RELEASE_FILES) or unpacked > MAX_UNPACKED:
                    raise UpgradeError("Release archive exceeds extraction limits")
                relative = path[len(prefix):]
                target = source / relative
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                stream = tar.extractfile(item)
                if stream is None:
                    raise UpgradeError("Invalid release archive member")
                contents = stream.read(item.size + 1)
                if len(contents) != item.size:
                    raise UpgradeError("Release archive member length mismatch")
                target.write_bytes(contents)
                target.chmod(0o755 if relative in ("install.sh", "client/install.sh",
                                                    "client/repocache_client.py",
                                                    "scripts/bootstrap-rootless.sh",
                                                    "scripts/repocache-launcher.sh") else 0o644)
        if found != {prefix + name for name in RELEASE_FILES}:
            raise UpgradeError("Incomplete or unexpected release archive")
        raw = (source / "release-policy.json").read_bytes()
        if (signed_policy_sha256 is not None
                and hashlib.sha256(raw).hexdigest() != signed_policy_sha256):
            raise UpgradeError("Signed release compatibility policy digest mismatch")
        if len(raw) > 16_384:
            raise UpgradeError("Compatibility policy is too large")
        try:
            document = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise UpgradeError("Invalid compatibility policy JSON")
        policy = _policy(document, version, previous, system)
        if updater._project_version(source) != version:
            raise UpgradeError("Archive and project versions differ")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise UpgradeError("Damaged or unsafe release archive") from exc
    return source, policy


def _local_bytes(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise UpgradeError("Missing, symlinked, or oversized local release file")
    data = path.read_bytes()
    if len(data) > limit:
        raise UpgradeError("Local release asset exceeds size limit")
    return data


def _upgrade_locked(selected: Optional[str] = None, bundle: Optional[Path] = None,
            checksum: Optional[Path] = None,
            token_file: Optional[Path] = None,
            system: Optional[Dict[str, str]] = None,
            manifest: Optional[Path] = None,
            signature: Optional[Path] = None,
            wheels: Optional[Path] = None) -> Dict[str, Any]:
    """Verify compatibility before installing; preserve old active CLI on error."""
    updater._require_service_account()
    token_file = token_file if token_file is not None else releases.credential_path()
    if (bundle is None) != (checksum is None):
        raise UpgradeError("Both --bundle and --checksum are required for offline installation")
    if bundle is None and (manifest is not None or signature is not None or wheels is not None):
        raise UpgradeError("Local signed wheelhouse inputs require a local release bundle")
    previous = updater._installed()
    if bundle is not None:
        version = _safe_version(selected)
        expected_archive_name = "repocache-v" + version + ".tar.gz"
        if bundle.name != expected_archive_name or checksum.name != expected_archive_name + ".sha256":
            raise UpgradeError("Local release filenames do not match the selected version")
        expected_manifest_name = expected_archive_name + ".manifest.json"
        manifest = manifest if manifest is not None else bundle.with_name(expected_manifest_name)
        signature = signature if signature is not None else bundle.with_name(expected_manifest_name + ".sig")
        if (manifest.name != expected_manifest_name
                or signature.name != expected_manifest_name + ".sig"):
            raise UpgradeError("Release signing asset filenames do not match the selected version")
        manifest_data = _local_bytes(manifest, MAX_MANIFEST)
        signature_data = _local_bytes(signature, MAX_SIGNATURE)
        expected_wheels_name = expected_archive_name + ".wheelhouse.tar.gz"
        wheels = wheels if wheels is not None else bundle.with_name(expected_wheels_name)
        if wheels.name != expected_wheels_name:
            raise UpgradeError("Wheelhouse filename does not match release version")
        wheels_data = _local_bytes(wheels, MAX_WHEELHOUSE)
        archive_data = _local_bytes(bundle, MAX_ARCHIVE)
        checksum_data = _local_bytes(checksum, MAX_CHECKSUM)
    else:
        found = releases.discover(token_file)
        if not found:
            raise UpgradeError("No verified stable release assets are available")
        version = _safe_version(selected or found[0]["version"])
        matching = [r for r in found if r["version"] == version]
        if len(matching) != 1:
            raise UpgradeError("Selected stable release is not available")
        release = matching[0]
        manifest_data = _download_asset(release["assets"]["manifest"], token_file, MAX_MANIFEST)
        signature_data = _download_asset(release["assets"]["signature"], token_file, MAX_SIGNATURE)
        archive_data = _download_asset(release["assets"]["archive"], token_file, MAX_ARCHIVE)
        checksum_data = _download_asset(release["assets"]["checksum"], token_file, MAX_CHECKSUM)
        wheels_data = _download_asset(release["assets"]["wheelhouse"], token_file, MAX_WHEELHOUSE)
    # The publisher signature is verified before archive extraction or any
    # invocation of release-supplied Python, pip or build hooks.
    try:
        signed = signatures.verify(archive_data, manifest_data, signature_data, version)
    except signatures.SignatureError as exc:
        raise UpgradeError(str(exc)) from exc
    _verify_checksum(archive_data, checksum_data, version)
    wheel_digest = signed.get("wheelhouse_sha256")
    if not isinstance(wheel_digest, str) or len(wheel_digest) != 64:
        raise UpgradeError("Authenticated release requires signed pinned dependency wheelhouse")
    if hashlib.sha256(wheels_data).hexdigest() != wheel_digest:
        raise UpgradeError("Signed dependency wheelhouse SHA-256 mismatch")
    archive_digest = signed["archive_sha256"]
    if previous.get("version") == version:
        if (previous.get("archive_sha256") != archive_digest
                or previous.get("wheelhouse_sha256") != wheel_digest
                or previous.get("publisher_key_id") != signed["key_id"]
                or previous.get("release_commit") != signed["commit"]
                or previous.get("signed_manifest_sha256") != hashlib.sha256(
                    manifest_data).hexdigest()):
            raise UpgradeError("Same-version installation lacks matching signed release identity")
        # There is no independently authenticated inventory of the installed
        # virtualenv: service-owned manifests and executable existence cannot
        # establish its integrity. Rebuild into a unique fresh generation from
        # the signed archive and offline wheels instead of returning a no-op.
    with tempfile.TemporaryDirectory(prefix="repocache-upgrade-") as temp:
        source, policy = _extract_verified(
            archive_data, version, Path(temp), previous, system,
            signed_policy_sha256=signed["policy_sha256"])
        # Signed digest validation precedes any zip/tar interpretation; all
        # wheel bytes and lock directives are verified before source execution.
        try:
            wheel_lock = wheelhouse.verified_extract(
                wheels_data, wheel_digest, Path(temp) / "wheelhouse")
            wheelhouse.verify_application_wheel(wheel_lock, version)
        except wheelhouse.WheelhouseError as exc:
            raise UpgradeError(str(exc)) from exc
        downgrade = updater._version_tuple(version) < updater._version_tuple(
            str(previous.get("version", "0.0.0")))
        return updater.install_source(
            source, approved_downgrade=downgrade, release_policy=policy,
            wheel_lock=wheel_lock,
            release_identity={
                "archive_sha256": archive_digest,
                "signed_manifest_sha256": hashlib.sha256(manifest_data).hexdigest(),
                "publisher_key_id": signed["key_id"],
                "release_commit": signed["commit"],
                "wheelhouse_sha256": wheel_digest,
            })


def upgrade(selected: Optional[str] = None, bundle: Optional[Path] = None,
            checksum: Optional[Path] = None,
            token_file: Optional[Path] = None,
            system: Optional[Dict[str, str]] = None,
            manifest: Optional[Path] = None,
            signature: Optional[Path] = None,
            wheels: Optional[Path] = None) -> Dict[str, Any]:
    """Hold the exclusive updater lock from preflight through rollback."""
    with updater.update_transaction():
        updater.recover_transaction()
        return _upgrade_locked(
            selected=selected, bundle=bundle, checksum=checksum,
            token_file=token_file, system=system,
            manifest=manifest, signature=signature, wheels=wheels)
