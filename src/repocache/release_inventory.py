"""Strict, publisher-signed source-only release inventory. Issue #84.

Only verify_signed_candidate authenticates input with the independent Ed25519
trust anchor. Never accept a plain GitHub checksum as publisher authority.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
from pathlib import Path
from typing import Any, Mapping

from repocache import signatures

MAX_INVENTORY = 4096
MAX_LOCK = 131072
MAX_SBOM = 262144
MAX_ARCHIVE = 25000000
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
ROLES = ("archive", "checksum", "dependency_lock", "sbom")


class InventoryError(RuntimeError):
    """Candidate assets are not authenticated or safe to process."""


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InventoryError("Duplicate candidate metadata field")
        result[key] = value
    return result


def _json(raw, limit):
    if not isinstance(raw, bytes) or not raw or len(raw) > limit:
        raise InventoryError("Missing or oversized candidate metadata")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InventoryError("Malformed candidate JSON") from exc


def names(version):
    if (not isinstance(version, str) or not VERSION.fullmatch(version)
            or tuple(map(int, version.split("."))) < (0, 6, 0)):
        raise InventoryError("Online profile requires v0.6.0 or later")
    source = "repocache-v" + version + ".tar.gz"
    return {"archive": source, "checksum": source + ".sha256",
            "dependency_lock": source + ".dependency-lock.json",
            "sbom": source + ".sbom.json"}


def digest(value):
    return hashlib.sha256(value).hexdigest()


def _check_archive(archive, version):
    """Bounded source-only check; complete attribution audit is still pending."""
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
            total = 0
            seen = set()
            for item in source:
                prefix = "repocache-v" + version + "/"
                if (len(seen) >= 100 or not item.isfile() or item.pax_headers
                        or item.name in seen or not item.name.startswith(prefix)
                        or item.mode & 0o7000):
                    raise InventoryError("Unsafe source-only archive entry")
                seen.add(item.name)
                rel = item.name[len(prefix):]
                if (not rel or len(rel) > 240 or "\\" in rel
                        or any(x in ("", ".", "..") for x in rel.split("/"))
                        or rel.lower().endswith((".whl", ".so", ".pyd", ".dll",
                                                 ".exe", ".a", ".o", ".class"))):
                    raise InventoryError("Bundled wheel or unsafe source path")
                total += item.size
                if item.size > MAX_ARCHIVE or total > 30000000:
                    raise InventoryError("Source-only archive too large")
                member = source.extractfile(item)
                if member is None:
                    raise InventoryError("Unreadable source-only member")
                if member.read(8).startswith((b"\x7fELF", b"MZ", b"PK\x03\x04")):
                    raise InventoryError("Binary or ZIP payload in source-only archive")
            if not seen:
                raise InventoryError("Empty source-only archive")
    except (OSError, tarfile.TarError, EOFError) as exc:
        raise InventoryError("Malformed source-only archive") from exc


def _validate(version, assets):
    expected = names(version)
    if not isinstance(assets, Mapping) or set(assets) != set(ROLES):
        raise InventoryError("Unexpected candidate artifact set")
    limits = {"archive": MAX_ARCHIVE, "checksum": 200,
              "dependency_lock": MAX_LOCK, "sbom": MAX_SBOM}
    for role in ROLES:
        raw = assets[role]
        if not isinstance(raw, bytes) or not raw or len(raw) > limits[role]:
            raise InventoryError("Missing or oversized candidate artifact")
    checksum = (digest(assets["archive"]) + "  " + expected["archive"] + "\n").encode()
    if assets["checksum"] != checksum:
        raise InventoryError("Candidate source checksum mismatch")
    _check_archive(assets["archive"], version)
    sbom = _json(assets["sbom"], MAX_SBOM)
    if (not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX"
            or sbom.get("specVersion") != "1.5"
            or type(sbom.get("version")) is not int
            or not isinstance(sbom.get("components"), list)
            or not sbom["components"]):
        raise InventoryError("Invalid online dependency SBOM")
    lock = _json(assets["dependency_lock"], MAX_LOCK)
    if (not isinstance(lock, dict) or set(lock) != {"schema", "profiles"}
            or type(lock["schema"]) is not int or lock["schema"] != 1
            or not isinstance(lock["profiles"], dict)
            or set(lock["profiles"]) != {"debian13-py313", "almalinux10-py312"}
            or any(not isinstance(rows, list) or not rows
                   for rows in lock["profiles"].values())):
        raise InventoryError("Invalid online dependency closure")
    return expected


def build_inventory(version, assets):
    """Deterministic inventory bytes for owner offline signing."""
    expected = _validate(version, assets)
    body = {"schema": 1, "version": version, "assets": {
        role: {"name": expected[role], "size": len(assets[role]),
               "sha256": digest(assets[role])} for role in ROLES
    }}
    return (json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n").encode()


def verify_bound_assets(signed, inventory, assets):
    """Call only on the result of signatures.verify, never on raw JSON."""
    if (not isinstance(signed, Mapping) or signed.get("schema") != 2
            or signed.get("dependency_profile") != "online-hash-locked-wheels"
            or signed.get("wheelhouse_sha256") is not None
            or not isinstance(signed.get("asset_inventory_sha256"), str)
            or not HEX64.fullmatch(signed["asset_inventory_sha256"])
            or not isinstance(signed.get("dependency_lock_sha256"), str)
            or not HEX64.fullmatch(signed["dependency_lock_sha256"])
            or not isinstance(signed.get("archive_sha256"), str)
            or not HEX64.fullmatch(signed["archive_sha256"])):
        raise InventoryError("Unapproved signed online profile")
    if (not isinstance(inventory, bytes) or len(inventory) > MAX_INVENTORY
            or digest(inventory) != signed["asset_inventory_sha256"]):
        raise InventoryError("Signed inventory digest mismatch")
    body = _json(inventory, MAX_INVENTORY)
    version = signed.get("version")
    expected = _validate(version, assets)
    if (not isinstance(body, dict) or set(body) != {"schema", "version", "assets"}
            or type(body["schema"]) is not int or body["schema"] != 1
            or body["version"] != version or not isinstance(body["assets"], dict)
            or set(body["assets"]) != set(ROLES)):
        raise InventoryError("Invalid signed inventory schema")
    for role in ROLES:
        entry = body["assets"][role]
        if (not isinstance(entry, dict) or set(entry) != {"name", "size", "sha256"}
                or entry["name"] != expected[role]
                or type(entry["size"]) is not int or entry["size"] != len(assets[role])
                or not isinstance(entry["sha256"], str)
                or not HEX64.fullmatch(entry["sha256"])
                or entry["sha256"] != digest(assets[role])):
            raise InventoryError("Signed candidate asset mismatch")
    if (signed["archive_sha256"] != digest(assets["archive"])
            or signed["dependency_lock_sha256"] != digest(assets["dependency_lock"])):
        raise InventoryError("Signed source/lock digest mismatch")
    return assets["dependency_lock"]


def verify_signed_candidate(archive, manifest, signature, version, inventory, assets):
    """Authenticate Ed25519 before inspecting source, lock or SBOM bytes."""
    try:
        signed = signatures.verify(archive, manifest, signature, version)
    except signatures.SignatureError as exc:
        raise InventoryError("Publisher signature failed") from exc
    if not isinstance(assets, Mapping) or assets.get("archive") != archive:
        raise InventoryError("Source differs from signed candidate")
    return signed, verify_bound_assets(signed, inventory, assets)
