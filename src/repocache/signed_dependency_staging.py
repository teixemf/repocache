"""Authenticate a publisher-owned candidate before preparing upstream wheels.

This staging API is deliberately NOT connected to updater, release discovery,
pip execution, venv activation or release publication. It accepts NO caller
supplied checksum as an independent trust root. Issue #83 / #84.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
from pathlib import Path
from typing import Any, Mapping

from repocache import online_deps, release_inventory


class PreparationError(RuntimeError):
    """The signed release or its dependency closure is not approved."""


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise PreparationError("Duplicate signed policy or SBOM field")
        result[name] = value
    return result


def _strict_json(raw: bytes, maximum: int) -> Any:
    if not raw or len(raw) > maximum:
        raise PreparationError("Missing or oversized signed policy or SBOM")
    try:
        online_deps._bounded_json_nesting(raw)
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (ValueError, UnicodeError, RecursionError, online_deps.DependencyError) as exc:
        raise PreparationError("Invalid authenticated policy or SBOM") from exc


def _validate_compatibility_policy(archive: bytes, signed: Mapping[str, Any],
                                   version: str) -> None:
    """Verify release-policy bytes are truly bound to Ed25519-signed hash."""
    member_name = f"repocache-v{version}/release-policy.json"
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
            matching = source.getmembers()
            policy_members = [m for m in matching if m.name == member_name]
            if len(policy_members) != 1 or not policy_members[0].isfile():
                raise PreparationError("Signed candidate lacks unique release policy")
            item = policy_members[0]
            if item.size <= 0 or item.size > 16384:
                raise PreparationError("Signed release policy has invalid size")
            stream = source.extractfile(item)
            if stream is None:
                raise PreparationError("Signed release policy is unreadable")
            raw = stream.read(16385)
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise PreparationError("Invalid signed source archive") from exc
    if (not isinstance(signed.get("policy_sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", signed["policy_sha256"])
            or hashlib.sha256(raw).hexdigest() != signed["policy_sha256"]):
        raise PreparationError("Signed release policy digest mismatch")
    policy = _strict_json(raw, 16384)
    fields = {
        "schema", "version", "python_min", "python_max_exclusive",
        "targets", "compatible_from", "downgrade_from",
        "config_schema", "api_schema",
    }
    if (not isinstance(policy, dict) or set(policy) != fields
            or type(policy["schema"]) is not int or policy["schema"] != 1
            or policy["version"] != version
            or policy["python_min"] != "3.12"
            or policy["python_max_exclusive"] != "3.14"
            or policy["targets"] != [
                {"id": "debian", "major": "13"},
                {"id": "almalinux", "major": "10"},
            ]
            or policy["compatible_from"] != ["0.5.0"]
            or policy["downgrade_from"] != []
            or type(policy["config_schema"]) is not int
            or type(policy["api_schema"]) is not int):
        raise PreparationError("Unsupported signed online release compatibility policy")


def _validate_sbom(sbom_raw: bytes, lock_raw: bytes) -> None:
    """Require SBOM package identities equal both verified target closures."""
    sbom = _strict_json(sbom_raw, release_inventory.MAX_SBOM)
    if (not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX"
            or sbom.get("specVersion") != "1.5"
            or type(sbom.get("version")) is not int
            or not isinstance(sbom.get("components"), list)):
        raise PreparationError("Unsupported dependency SBOM metadata")
    components: set[tuple[str, str]] = set()
    for row in sbom["components"]:
        if not isinstance(row, dict):
            raise PreparationError("Unexpected dependency SBOM component")
        name, version = row.get("name"), row.get("version")
        if (not isinstance(name, str) or not isinstance(version, str)
                or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name)
                or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}(?:\.post[0-9]+)?", version)
                or (name, version) in components):
            raise PreparationError("Unexpected or duplicate dependency SBOM identity")
        components.add((name, version))
    closure = set()
    trusted_digest = hashlib.sha256(lock_raw).hexdigest()
    for target in online_deps.TARGETS:
        wheels = online_deps.parse_verified_lock(lock_raw, trusted_digest, target)
        closure.update((wheel.name, wheel.version) for wheel in wheels)
    if components != closure:
        raise PreparationError("Authenticated SBOM does not match locked package closure")


def verified_candidate_wheels(archive: bytes, manifest: bytes, signature: bytes,
                              version: str, inventory: bytes,
                              assets: Mapping[str, bytes], target: str
                              ) -> tuple[online_deps.Wheel, ...]:
    """Verify trust anchor, asset inventory, release policy, both lock targets and SBOM.

    The only supported caller of the raw lock parser in this workflow gets
    expected_signed_digest directly from signatures.verify's output. No network
    access occurs during these checks. An authenticated manifest still requires
    approved upstream versions and a separately tested downloader.
    """
    try:
        signed, raw_lock = release_inventory.verify_signed_candidate(
            archive, manifest, signature, version, inventory, assets)
        _validate_compatibility_policy(archive, signed, version)
        _validate_sbom(assets["sbom"], raw_lock)
        return online_deps.parse_verified_lock(
            raw_lock, signed["dependency_lock_sha256"], target)
    except (release_inventory.InventoryError, online_deps.DependencyError) as exc:
        raise PreparationError("Authenticated dependency candidate was rejected") from exc


def stage_signed_candidate(archive: bytes, manifest: bytes, signature: bytes,
                           version: str, inventory: bytes,
                           assets: Mapping[str, bytes], target: str,
                           destination: Path, *, cafile: Path) -> Path:
    """Stage verified bytes, with NO pip, application execution or activation.

    The production caller MUST also own updater's exclusive transaction lock;
    this module is currently UNWIRED until #83/#84 transactional integration.
    """
    wheels = verified_candidate_wheels(
        archive, manifest, signature, version, inventory, assets, target)
    try:
        return online_deps.stage_wheels(wheels, destination, cafile=cafile)
    except online_deps.DependencyError as exc:
        raise PreparationError("Authenticated candidate wheel staging failed") from exc
