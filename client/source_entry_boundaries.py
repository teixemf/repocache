"""Read-only APT/DNF entry boundaries for non-authoritative ownership candidates.

Only recognizes separable line/stanza/section boundaries. Parsing a boundary
does NOT prove safe syntax, package trust, or permission to edit the file.
All spans refer to exact original bytes; no rewriting/normalization occurs.
"""
from __future__ import annotations

import hashlib
import re

import source_preflight as pre
import source_structure_subset as subset


class EntryRefused(ValueError):
    """Ambiguous or malformed repository-entry boundaries."""


SECTION = re.compile(rb"^\[([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\][ \t]*(?:\n)?$")
KIND = {"list": "apt-list", "sources": "apt-deb822", "repo": "dnf-repo"}


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _lines(data: bytes):
    position = 0
    for line in data.splitlines(keepends=True):
        start, position = position, position + len(line)
        yield start, position, line


def _eligible(path: str, body: bytes) -> bool:
    try:
        result = subset.inspect_structure(path, body)
        return result["structure_subset_pass"] and not result["write_eligible"]
    except subset.StructureRefused:
        return False


def _item(path: str, ordinal: int, kind: str, begin: int,
          end: int, data: bytes, *, key: str = "") -> dict:
    return {
        "ordinal": ordinal, "kind": kind, "start": begin, "end": end,
        "sha256": _digest(data[begin:end]), "key": key,
        "structure_subset_pass": _eligible(path, data[begin:end]),
        "ownership_granted": False, "write_eligible": False,
    }


def boundaries(path: str, data: bytes) -> list[dict]:
    """Identify exact, unique entries without changing unrelated bytes.

    Malformed boundaries refuse the entire file. Recognized but unsupported
    sections may be inventoried, never selected as managed candidates.
    """
    if (not isinstance(path, str) or not pre.SOURCE_PATH.fullmatch(path)
            or path.startswith("etc/apt/mirrors/")
            or not isinstance(data, bytes) or len(data) > pre.MAX_SOURCE_BYTES
            or b"\0" in data or b"\r" in data):
        raise EntryRefused("Unsupported or untrusted source")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EntryRefused("Unsupported source encoding") from exc
    entries = []
    lines = list(_lines(data))
    if path == "etc/apt/sources.list" or path.endswith(".list"):
        for start, end, line in lines:
            body = line.strip()
            if not body or body.startswith(b"#"):
                continue
            if not (body.startswith(b"deb ") or body.startswith(b"deb-src ")):
                raise EntryRefused("Unrecognized APT source directive")
            entries.append(_item(path, len(entries) + 1, "apt-list",
                                 start, end, data))
    elif path.endswith(".sources"):
        begin = None
        for start, end, line in lines:
            if not line.strip():
                if begin is not None:
                    entries.append(_item(path, len(entries) + 1,
                                         "apt-deb822", begin, start, data))
                    begin = None
            else:
                if begin is None:
                    begin = start
                if b":" not in line and not line.lstrip().startswith(b"#"):
                    # Folded lines can be recognized but never candidates.
                    if not line.startswith((b" ", b"\t")):
                        raise EntryRefused("Unrecognized deb822 field boundary")
        if begin is not None:
            entries.append(_item(path, len(entries) + 1, "apt-deb822",
                                 begin, len(data), data))
    elif path.endswith(".repo"):
        begin, current = None, None
        seen = set()
        for start, end, line in lines:
            striped = line.strip()
            m = SECTION.fullmatch(line)
            if m:
                name = m.group(1).decode("ascii")
                if name in seen:
                    raise EntryRefused("Duplicate DNF section name")
                seen.add(name)
                if begin is not None:
                    entries.append(_item(path, len(entries) + 1,
                                         "dnf-repo", begin, start, data,
                                         key=current))
                begin, current = start, name
            elif striped.startswith(b"["):
                raise EntryRefused("Malformed DNF section header")
            elif begin is None and striped and not striped.startswith((b"#", b";")):
                raise EntryRefused("Untrusted DNF preamble")
        if begin is not None:
            entries.append(_item(path, len(entries) + 1, "dnf-repo",
                                 begin, len(data), data, key=current))
    else:
        raise EntryRefused("Unsupported source format")
    if len(entries) > 128:
        raise EntryRefused("Too many repository entries")
    # Duplicated byte-identical entries cannot be selected uniquely by hash.
    # A record may still be created for a distinct entry in that file, but
    # any ambiguous selected digest is always rejected by the registry.
    return entries
