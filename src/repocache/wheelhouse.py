"""Strictly verify prebuilt Python wheels with zero index/build resolution.

This is a #49 component, not yet wired to the release install path. The
authenticated #47 manifest must bind the exact wheelhouse tar digest before
this function receives untrusted data.
"""
from __future__ import annotations

import hashlib
import json
import io
import re
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path

MAX_WHEELHOUSE = 100_000_000
MAX_MEMBERS = 120
MAX_WHEEL = 25_000_000
MAX_UNPACKED = 200_000_000
HASH_LINE = re.compile(
    r"^\./wheels/([A-Za-z0-9_][A-Za-z0-9_.+-]{0,220}\.whl) --hash=sha256:([a-f0-9]{64})$"
)


class WheelhouseError(RuntimeError):
    """Offline wheel bundle cannot satisfy verified dependency requirements."""


def verified_extract(archive: bytes, digest: str, destination: Path) -> Path:
    """Materialize exactly hash-pinned wheel files and a lock, no symlinks."""
    if (not re.fullmatch(r"[a-f0-9]{64}", digest)
            or not archive or len(archive) > MAX_WHEELHOUSE
            or hashlib.sha256(archive).hexdigest() != digest):
        raise WheelhouseError("Signed wheelhouse archive digest mismatch")
    if destination.exists() or destination.is_symlink():
        raise WheelhouseError("Wheelhouse extraction destination must not exist")
    destination.mkdir(mode=0o700, parents=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as stream:
            files: dict[str, bytes] = {}
            total = 0
            for member in stream:
                name = member.name
                if (not member.isfile() or name in files or
                        name not in ("requirements.lock", "sbom.json") and (
                            not name.startswith("wheels/") or
                            HASH_LINE.fullmatch("./" + name + " --hash=sha256:" + "0" * 64) is None)
                        or member.size < 0 or member.size > MAX_WHEEL or
                        member.mode & 0o7000):
                    raise WheelhouseError("Unsafe wheelhouse archive entry")
                total += member.size
                if len(files) >= MAX_MEMBERS or total > MAX_UNPACKED:
                    raise WheelhouseError("Wheelhouse resource limits exceeded")
                file = stream.extractfile(member)
                if file is None:
                    raise WheelhouseError("Unreadable wheelhouse archive entry")
                value = file.read(member.size + 1)
                if len(value) != member.size:
                    raise WheelhouseError("Malformed wheelhouse archive entry")
                files[name] = value
        if "requirements.lock" not in files or "sbom.json" not in files:
            raise WheelhouseError("Missing locked wheel inventory or signed SBOM")
        try:
            text = files["requirements.lock"].decode("ascii")
        except UnicodeError as exc:
            raise WheelhouseError("Lockfile is not ASCII") from exc
        lines = text.splitlines()
        if not lines or len(lines) > MAX_MEMBERS:
            raise WheelhouseError("Empty/oversized dependency lock")
        inventory: dict[str, str] = {}
        for line in lines:
            match = HASH_LINE.fullmatch(line)
            if match is None:
                raise WheelhouseError("Unexpected lockfile syntax or index directive")
            name, wheel_digest = match.groups()
            if name in inventory:
                raise WheelhouseError("Duplicate wheel lock entry")
            inventory[name] = wheel_digest
        wheels = {name.removeprefix("wheels/") for name in files if name.startswith("wheels/")}
        if set(inventory) != wheels:
            raise WheelhouseError("Missing, extra or unpinned wheel")
        # Require a complete standard CycloneDX component inventory as part
        # of the already-authenticated wheelhouse byte stream.
        if len(files["sbom.json"]) > 131072:
            raise WheelhouseError("Dependency SBOM resource limit exceeded")
        try:
            sbom = json.loads(files["sbom.json"].decode("utf-8"))
            if (not isinstance(sbom, dict)
                    or sbom.get("bomFormat") != "CycloneDX"
                    or sbom.get("specVersion") != "1.5"
                    or sbom.get("version") != 1
                    or not isinstance(sbom.get("components"), list)):
                raise ValueError("invalid CycloneDX schema")
            declared = {}
            for component in sbom["components"]:
                if not isinstance(component, dict):
                    raise ValueError("invalid CycloneDX component")
                attrs = component.get("properties", [])
                if (not isinstance(attrs, list) or len(attrs) != 1
                        or attrs[0].get("name") != "repocache:wheel-file"):
                    raise ValueError("missing wheel identity in CycloneDX")
                filename = attrs[0].get("value")
                digests = component.get("hashes")
                if (not isinstance(filename, str) or filename in declared
                        or not isinstance(digests, list) or len(digests) != 1
                        or digests[0].get("alg") != "SHA-256"):
                    raise ValueError("invalid wheel hash in CycloneDX")
                declared[filename] = digests[0].get("content")
            if declared != inventory:
                raise ValueError("signed SBOM and wheel lock disagree")
        except (UnicodeError, ValueError, AttributeError, TypeError) as exc:
            raise WheelhouseError("Incomplete or inconsistent signed dependency SBOM") from exc
        for name, expected in inventory.items():
            if hashlib.sha256(files["wheels/" + name]).hexdigest() != expected:
                raise WheelhouseError("Pinned wheel SHA-256 mismatch")
        for name, value in files.items():
            target = destination / name
            target.parent.mkdir(exist_ok=True, mode=0o700)
            target.write_bytes(value)
            target.chmod(0o600)
        return destination / "requirements.lock"
    except (OSError, tarfile.TarError, EOFError) as exc:
        raise WheelhouseError("Malformed or inaccessible wheelhouse") from exc


def install_argv(python: Path, lock: Path) -> list[str]:
    """No PyPI, user pip config, dependency resolver or source builds allowed."""
    return [str(python), "-m", "pip", "install", "--no-index",
            "--no-deps", "--require-hashes", "--disable-pip-version-check",
            "--no-cache-dir", "--no-input", "-r", str(lock)]

def verify_application_wheel(lock: Path, version: str) -> None:
    """Require exactly one wheel whose package metadata matches the release.

    Wheels are not unpacked by this check. The signed digest and the complete
    SHA-256 inventory must already have been verified with verified_extract().
    """
    from pathlib import PurePosixPath
    name = "repocache_control-" + version + "-"
    selected = [x for x in (lock.parent / "wheels").glob("*.whl")
                if x.name.startswith(name)]
    if len(selected) != 1:
        raise WheelhouseError("Missing or ambiguous signed REPOCACHE application wheel")
    wheel = selected[0]
    try:
        with zipfile.ZipFile(wheel) as content:
            matches = [entry for entry in content.infolist()
                       if entry.filename.endswith(".dist-info/METADATA")
                       and entry.filename.count("/") == 1]
            if (len(matches) != 1 or matches[0].file_size > 65536 or
                    len(content.infolist()) > 2000):
                raise WheelhouseError("Invalid application wheel metadata")
            info = BytesParser().parsebytes(content.read(matches[0]))
            if info.get("Name", "").lower().replace("_", "-") != "repocache-control":
                raise WheelhouseError("Unexpected signed application wheel name")
            if info.get("Version") != version:
                raise WheelhouseError("Signed application wheel version mismatch")
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        raise WheelhouseError("Invalid signed application wheel ZIP format") from exc
