#!/usr/bin/env python3
"""Read-only preflight for supported operating systems and their native Python."""
from __future__ import annotations
import re
import sys
from pathlib import Path

SUPPORTED = {("debian", "13"): (3, 13), ("almalinux", "10"): (3, 12)}


class PlatformError(ValueError):
    """Unsupported host or interpreter."""


def validate(os_release: str, python_version: tuple[int, int]) -> None:
    values: dict[str, str] = {}
    for raw in os_release.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key not in {"ID", "VERSION_ID"}:
            continue
        if key in values:
            raise PlatformError(f"Duplicate {key} in /etc/os-release")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[key] = value
    version = values.get("VERSION_ID", "")
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", version):
        raise PlatformError("Missing or invalid VERSION_ID in /etc/os-release")
    distro = values.get("ID", "")
    expected = SUPPORTED.get((distro, version.split(".", 1)[0]))
    if expected is None:
        raise PlatformError(
            f"Unsupported OS: {distro or 'unknown'} {version}; "
            "supported: Debian 13 and AlmaLinux 10 only"
        )
    if tuple(python_version) != expected:
        raise PlatformError(
            f"Unsupported system Python: {python_version[0]}.{python_version[1]} "
            f"on {distro} {version}; expected {expected[0]}.{expected[1]} "
            "from /usr/bin/python3"
        )


def main() -> int:
    try:
        validate(Path("/etc/os-release").read_text(encoding="utf-8"),
                 (sys.version_info.major, sys.version_info.minor))
    except (OSError, PlatformError) as exc:
        print(f"REPOCACHE platform preflight failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
