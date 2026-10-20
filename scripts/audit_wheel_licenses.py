#!/usr/bin/env python3
"""Bounded, deterministic license-evidence inventory for verified native wheels.

This is a technical evidence gate, NOT an automated legal compatibility review.
The caller must first verify the authenticated wheelhouse digest and each wheel
SHA-256. No wheel code is executed and no ZIP member is extracted to disk.
"""
from __future__ import annotations

from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import re
import zipfile


class LicenseEvidenceError(ValueError):
    """Required wheel distribution or bounded rights metadata is invalid."""


MAX_METADATA = 1_000_000
MAX_LICENSE_FILES = 64
MAX_LICENSE_FILE_BYTES = 1_000_000


def audit_wheel(path: Path) -> dict:
    """Inspect only the authenticated wheel's distribution metadata and notices."""
    if not path.is_file() or path.is_symlink() or not path.name.endswith(".whl"):
        raise LicenseEvidenceError("Expected a regular verified wheel")
    try:
        with zipfile.ZipFile(path, "r") as wheel:
            entries = wheel.infolist()
            # Wheels such as setuptools vendor third-party packages whose
            # nested dist-info metadata must not be mistaken for the
            # top-level distribution being audited. Require one root entry.
            metadata = [entry for entry in entries
                        if entry.filename.endswith(".dist-info/METADATA")
                        and entry.filename.count("/") == 1]
            if len(metadata) != 1:
                raise LicenseEvidenceError("Wheel metadata count invalid: " + path.name)
            if metadata[0].file_size > MAX_METADATA:
                raise LicenseEvidenceError("Wheel metadata too large: " + path.name)
            folder = metadata[0].filename.removesuffix("METADATA")
            if not folder.endswith(".dist-info/"):
                raise LicenseEvidenceError("Invalid wheel metadata path")
            with wheel.open(metadata[0], "r") as raw:
                value = raw.read(MAX_METADATA + 1)
            if len(value) > MAX_METADATA:
                raise LicenseEvidenceError("Oversized wheel license metadata")
            headers = BytesParser().parsebytes(value, headersonly=True)
            name, version = headers.get("Name"), headers.get("Version")
            pieces = path.name.split("-")
            if not name or not version or len(pieces) < 5:
                raise LicenseEvidenceError("Invalid package identity or wheel name")
            normalize = lambda x: re.sub(r"[-_.]+", "-", x).lower()
            if normalize(name) != normalize(pieces[0]) or version != pieces[1]:
                raise LicenseEvidenceError("Wheel name and distribution metadata disagree")
            expr = (headers.get("License-Expression") or "").strip()
            legacy = (headers.get("License") or "").strip()
            classifiers = [item for item in headers.get_all("Classifier", [])
                           if item.startswith("License ::")]
            notices = [entry for entry in entries
                       if (entry.filename.startswith(folder + "licenses/") or
                           entry.filename.startswith(folder + "license_files/"))
                       and not entry.is_dir()]
            if len(notices) > MAX_LICENSE_FILES:
                raise LicenseEvidenceError("Too many wheel license notice files")
            if any(n.file_size > MAX_LICENSE_FILE_BYTES for n in notices):
                raise LicenseEvidenceError("Oversized wheel license notice")
            if not (expr or (legacy and legacy.upper() != "UNKNOWN")
                    or classifiers or notices):
                raise LicenseEvidenceError("Distribution lacks license review evidence")
            return {
                "name": name, "version": version,
                "wheel": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "license_expression": expr or None,
                "legacy_license": legacy if legacy and legacy.upper() != "UNKNOWN" else None,
                "license_classifiers": sorted(set(classifiers)),
                "notice_files": sorted(n.filename for n in notices),
                # Legal rights and obligations are not decided by parsing alone.
                "legal_compatibility": "NOT VERIFIED",
            }
    except (OSError, zipfile.BadZipFile, RuntimeError, UnicodeError, EOFError) as exc:
        raise LicenseEvidenceError("Invalid or unreadable wheel rights metadata") from exc


def inventory(wheels: list[Path]) -> dict:
    if not wheels or len(wheels) > 120:
        raise LicenseEvidenceError("Missing or excessive wheels for rights inventory")
    result = [audit_wheel(path) for path in wheels]
    if len({re.sub(r"[-_.]+", "-", r["name"]).lower() for r in result}) != len(result):
        raise LicenseEvidenceError("Duplicate wheel distribution in rights inventory")
    result.sort(key=lambda item: item["wheel"])
    return {"schema": 1, "source": "authenticated offline wheelhouse",
            "review_state": "NOT VERIFIED — human third-party rights approval pending",
            "components": result}


def format_inventory(wheels: list[Path]) -> str:
    return json.dumps(inventory(wheels), sort_keys=True, separators=(",", ":")) + "\n"
