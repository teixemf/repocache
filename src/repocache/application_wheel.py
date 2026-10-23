"""Deterministic, pure-Python REPOCACHE application wheel from owned source.

Issue #84: build ONLY at trusted release preparation time, never on hosts.
Stdlib-only wheel authoring avoids executing setuptools/third-party build
backends. Verification deterministically re-derives ALL wheel bytes from
the independently owner-signed release source, before any pip execution.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import re
import tarfile
import tomllib
import zipfile


class ApplicationWheelError(RuntimeError):
    """First-party executable identity is missing or inconsistent."""


MAX_APP_WHEEL = 8_000_000
DIST = "repocache_control"
DATE = (1980, 1, 1, 0, 0, 0)
_FILENAME = re.compile(r"0|[1-9][0-9]*")
_MODULE = re.compile(r"src/repocache/[a-z_][a-z0-9_]*\.py\Z")


def filename(version: str) -> str:
    if (not isinstance(version, str)
            or re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", version) is None
            or any(_FILENAME.fullmatch(part) is None
                   for part in version.split("."))):
        raise ApplicationWheelError("Invalid first-party wheel version")
    return f"{DIST}-{version}-py3-none-any.whl"


def _sources(archive: bytes, version: str) -> tuple[dict[str, bytes], dict]:
    """Read bounded, uniquely named first-party modules from the source tar."""
    if not isinstance(archive, bytes) or len(archive) > 25_000_000:
        raise ApplicationWheelError("Oversized signed application source")
    members: dict[str, bytes] = {}
    prefix = f"repocache-v{version}/"
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
            for member in source:
                if (not member.isfile()
                        or not member.name.startswith(prefix) or member.size > 1_000_000):
                    raise ApplicationWheelError("Unexpected application source entry")
                path = member.name[len(prefix):]
                if not path or path in members or ".." in path.split("/") or "\\" in path:
                    raise ApplicationWheelError("Unsafe application source path")
                fp = source.extractfile(member)
                if fp is None:
                    raise ApplicationWheelError("Unreadable application source")
                members[path] = fp.read(member.size + 1)
                if len(members) > 100:
                    raise ApplicationWheelError("Too many application sources")
    except (OSError, tarfile.TarError, EOFError) as exc:
        raise ApplicationWheelError("Invalid signed application source") from exc
    pyproject = members.get("pyproject.toml")
    license_content = members.get("LICENSE")
    if not pyproject or not license_content or len(license_content) > 100_000:
        raise ApplicationWheelError("Missing first-party project/license metadata")
    try:
        config = tomllib.loads(pyproject.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ApplicationWheelError("Invalid source project metadata") from exc
    project = config.get("project")
    if (not isinstance(project, dict)
            or project.get("name") != "repocache-control"
            or project.get("version") != version
            or project.get("requires-python") != ">=3.12"
            or project.get("license") != "Apache-2.0"
            or project.get("scripts") != {"repocache": "repocache.cli:app"}
            or not isinstance(project.get("dependencies"), list)
            or not 1 <= len(project["dependencies"]) <= 20
            or any(not isinstance(x, str)
                   or len(x) > 200 or "\n" in x or "\r" in x
                   for x in project["dependencies"])):
        raise ApplicationWheelError("Unsupported first-party application metadata")
    modules = {
        path[len("src/"):]: value
        for path, value in members.items() if path.startswith("src/repocache/")
    }
    if (not modules or len(modules) > 65
            or not all(_MODULE.fullmatch("src/" + name) for name in modules)
            or "repocache/__init__.py" not in modules
            or "repocache/cli.py" not in modules
            or (f'__version__ = "{version}"').encode() not in modules["repocache/__init__.py"]):
        raise ApplicationWheelError("Application modules do not match original source")
    return modules, {"project": project, "license": license_content}


def build(archive: bytes, version: str) -> bytes:
    """Generate a deterministic PEP 427-compatible wheel without build hooks."""
    filename(version)
    modules, info = _sources(archive, version)
    project = info["project"]
    base = f"{DIST}-{version}.dist-info"
    lines = [
        "Metadata-Version: 2.4",
        "Name: repocache-control",
        f"Version: {version}",
        "Summary: REPOCACHE Linux package repository proxy management",
        "License-Expression: Apache-2.0",
        "Requires-Python: >=3.12",
    ]
    lines.extend("Requires-Dist: " + requirement for requirement in project["dependencies"])
    files = {
        **modules,
        base + "/METADATA": ("\n".join(lines) + "\n\n").encode("utf-8"),
        base + "/WHEEL": (
            "Wheel-Version: 1.0\nGenerator: repocache-owned-stdlib/1\n"
            "Root-Is-Purelib: true\nTag: py3-none-any\n").encode(),
        base + "/entry_points.txt": b"[console_scripts]\nrepocache = repocache.cli:app\n",
        base + "/licenses/LICENSE": info["license"],
    }
    if any(len(value) > 1_000_000 for value in files.values()):
        raise ApplicationWheelError("Oversized first-party source member")
    record = []
    for name, contents in sorted(files.items()):
        sha = base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).rstrip(b"=").decode()
        record.append((name, "sha256=" + sha, str(len(contents))))
    record_name = base + "/RECORD"
    record.append((record_name, "", ""))
    stream = io.StringIO(newline="")
    csv.writer(stream, lineterminator="\n").writerows(record)
    files[record_name] = stream.getvalue().encode("utf-8")
    result = io.BytesIO()
    with zipfile.ZipFile(result, mode="w", compression=zipfile.ZIP_STORED) as wheel:
        for name, contents in sorted(files.items()):
            item = zipfile.ZipInfo(name, DATE)
            item.compress_type = zipfile.ZIP_STORED
            item.create_system = 3
            item.external_attr = 0o100644 << 16
            wheel.writestr(item, contents)
    raw = result.getvalue()
    if len(raw) > MAX_APP_WHEEL:
        raise ApplicationWheelError("First-party wheel exceeds allowed size")
    return raw


def verify(wheel: bytes, archive: bytes, version: str) -> None:
    """Require canonical exact wheel bytes, never import or execute its code."""
    if (not isinstance(wheel, bytes) or len(wheel) > MAX_APP_WHEEL
            or wheel != build(archive, version)):
        raise ApplicationWheelError("First-party wheel differs from signed owned source")
