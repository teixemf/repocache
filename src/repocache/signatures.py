"""Authenticate detached Ed25519 release manifests against host trust anchors.

The trust store must be independently provisioned by an administrator. Release
assets, GitHub tags, the same-origin .sha256, and a bundle-provided key are
NEVER considered trust anchors. No verification fallback exists.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

TRUST_DIR = Path("/etc/repocache/trust.d")
OPENSSL = "/usr/bin/openssl"
MAX_MANIFEST = 4096
MAX_SIGNATURE = 64
MAX_KEY = 4096
KEY_ID = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")
HEX40 = re.compile(r"^[a-f0-9]{40}$")
VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class SignatureError(RuntimeError):
    """Release authentication failed; no release code may be executed."""


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, content in pairs:
        if name in value:
            raise SignatureError("Duplicate signed manifest field")
        value[name] = content
    return value


def _parse(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAX_MANIFEST:
        raise SignatureError("Missing or oversized signed release manifest")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeError, ValueError) as exc:
        raise SignatureError("Invalid signed release manifest") from exc
    if not isinstance(document, dict):
        raise SignatureError("Invalid signed release manifest object")
    fields = {"schema", "key_id", "repository", "channel", "version",
              "commit", "archive", "archive_sha256", "policy_sha256",
              "wheelhouse_sha256", "issued_at", "expires_at"}
    if set(document) != fields or type(document["schema"]) is not int or document["schema"] != 1:
        raise SignatureError("Unsupported signed release manifest schema")
    if (not isinstance(document["key_id"], str)
            or KEY_ID.fullmatch(document["key_id"]) is None
            or document["repository"] != "teixemf/repocache"
            or document["channel"] != "stable"
            or not isinstance(document["version"], str)
            or VERSION.fullmatch(document["version"]) is None
            or not isinstance(document["commit"], str)
            or HEX40.fullmatch(document["commit"]) is None
            or document["archive"] != "repocache-v" + document["version"] + ".tar.gz"):
        raise SignatureError("Invalid signed release identity")
    for name in ("archive_sha256", "policy_sha256"):
        if not isinstance(document[name], str) or HEX64.fullmatch(document[name]) is None:
            raise SignatureError("Invalid signed release digest")
    wheel = document["wheelhouse_sha256"]
    if wheel is not None and (not isinstance(wheel, str) or HEX64.fullmatch(wheel) is None):
        raise SignatureError("Invalid signed dependency digest")
    if (type(document["issued_at"]) is not int or type(document["expires_at"]) is not int
            or document["issued_at"] < 0 or
            document["expires_at"] <= document["issued_at"]):
        raise SignatureError("Invalid signed release validity interval")
    return document


def _trusted_key(key_id: str) -> Path:
    """Reject symlinked/unowned/writable trust components before opening key."""
    if KEY_ID.fullmatch(key_id) is None:
        raise SignatureError("Invalid trusted key identifier")
    key = TRUST_DIR / (key_id + ".pem")
    for path in (TRUST_DIR.parent.parent, TRUST_DIR.parent, TRUST_DIR, key):
        try:
            info = path.lstat()
        except OSError as exc:
            raise SignatureError("Publisher trust anchor is not provisioned") from exc
        if (info.st_uid != 0 or info.st_mode & 0o022 or
                stat.S_ISLNK(info.st_mode)):
            raise SignatureError("Unsafe publisher trust anchor ownership or path")
        if path == key:
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_KEY:
                raise SignatureError("Invalid publisher public key")
        elif not stat.S_ISDIR(info.st_mode):
            raise SignatureError("Unsafe publisher trust anchor directory")
    return key


def verify(archive: bytes, manifest: bytes, signature: bytes, version: str) -> dict[str, Any]:
    """Verify signature BEFORE interpreting or extracting archive bytes."""
    if len(signature) != MAX_SIGNATURE:
        raise SignatureError("Missing or invalid Ed25519 signature")
    document = _parse(manifest)
    if document["version"] != version:
        raise SignatureError("Signed manifest version does not match selection")
    now = int(time.time())
    if now < document["issued_at"] or now >= document["expires_at"]:
        raise SignatureError("Signed release is not currently valid")
    key = _trusted_key(document["key_id"])
    # No bundled code is loaded. OpenSSL sees only the root-owned public key,
    # the raw signed manifest and the detached 64-byte Ed25519 signature.
    with tempfile.TemporaryDirectory(prefix="repocache-sig-") as temp:
        source = Path(temp) / "manifest"
        detached = Path(temp) / "signature"
        source.write_bytes(manifest)
        detached.write_bytes(signature)
        try:
            result = subprocess.run(
                [OPENSSL, "pkeyutl", "-verify", "-pubin", "-inkey",
                 str(key), "-rawin", "-in", str(source), "-sigfile", str(detached)],
                env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                text=True, capture_output=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SignatureError("Publisher signature verification unavailable") from exc
    if result.returncode != 0:
        raise SignatureError("Publisher release signature is invalid")
    if hashlib.sha256(archive).hexdigest() != document["archive_sha256"]:
        raise SignatureError("Authenticated release archive SHA-256 mismatch")
    return document
