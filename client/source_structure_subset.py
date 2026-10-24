"""Conservative syntax *subset* check for candidate managed APT/DNF files.

Pure, side-effect-free and deliberately incomplete. A PASS is not proof of
native package-manager grammar, signatures, enabled state, TLS or fallback.
Unrecognised forms are refused rather than silently declared compatible.
"""
from __future__ import annotations

import configparser
import re
from urllib.parse import urlsplit

MAX_BYTES = 1024 * 1024
APT_LINE = re.compile(
    r"^(deb|deb-src)\s+(?:\[([^\]\r\n]+)\]\s+)?(\S+)\s+(\S+)(?:\s+(.+))?$"
)
FIELD_NAME = re.compile(r"[A-Za-z][A-Za-z0-9-]*\Z")
APT_TYPES = {"deb", "deb-src"}


class StructureRefused(ValueError):
    """Source is outside this deliberately limited syntactic subset."""


def _tokens(value: str, *, minimum: int = 1) -> list[str]:
    tokens = value.split()
    if len(tokens) < minimum or any(any(ord(c) < 33 for c in part)
                                     for part in tokens):
        raise StructureRefused("Unsupported source field")
    return tokens


def _single_url(value: str) -> None:
    if len(value) > 2048 or any(x in value for x in ("\\", "\x00", "\r", "\n")):
        raise StructureRefused("Unsupported repository URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise StructureRefused("Invalid repository URL") from exc
    if (parsed.scheme not in ("https", "http") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment
            or (port is not None and port == 0)):
        raise StructureRefused("Repository URL is outside tested subset")


def _apt_list(body: str) -> int:
    entries = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Inline comment and continuation/quote behavior need full APT parsing:
        # do not guess their meaning.
        if "#" in line or "\\" in line or '"' in line or "'" in line:
            raise StructureRefused("APT line uses unreviewed syntax")
        match = APT_LINE.fullmatch(line)
        if not match:
            raise StructureRefused("Unsupported APT source line")
        kind, options, uri, suite, components = match.groups()
        _single_url(uri)
        if options:
            parsed = [item.split("=", 1) for item in options.split()]
            if (any(len(pair) != 2 or not pair[1] for pair in parsed)
                    or len({pair[0] for pair in parsed}) != len(parsed)
                    or any(pair[0] not in {"arch", "signed-by"} for pair in parsed)):
                raise StructureRefused("Unsupported APT source options")
            for key, val in parsed:
                if key == "arch" and not re.fullmatch(
                        r"[A-Za-z0-9_-]+(?:,[A-Za-z0-9_-]+)*", val):
                    raise StructureRefused("Unsupported architecture selector")
                if key == "signed-by" and not re.fullmatch(
                        r"/usr/share/keyrings/[A-Za-z0-9_.-]+\.gpg|"
                        r"/etc/apt/keyrings/[A-Za-z0-9_.-]+\.gpg", val):
                    raise StructureRefused("Unsupported keyring selector")
        if not re.fullmatch(r"[A-Za-z0-9._/+:-]+", suite):
            raise StructureRefused("Unsupported APT suite")
        if suite.endswith("/"):
            if components:
                raise StructureRefused("Exact path suite may not set components")
        elif not components or not all(
                re.fullmatch(r"[A-Za-z0-9._+-]+", item)
                for item in _tokens(components)):
            raise StructureRefused("Unsupported APT components")
        entries.append(kind)
    if len(entries) != 1:
        raise StructureRefused("Candidate must contain exactly one APT entry")
    return len(entries)


def _apt_deb822(body: str) -> int:
    fields: dict[str, str] = {}
    for raw in body.splitlines():
        if not raw.strip():
            raise StructureRefused("Only one deb822 stanza is supported")
        if raw.lstrip() != raw or ":" not in raw:
            raise StructureRefused("Folded or malformed deb822 fields are unsupported")
        key, value = raw.split(":", 1)
        key = key.strip()
        if not FIELD_NAME.fullmatch(key) or key in fields:
            raise StructureRefused("Duplicate or unsupported deb822 field")
        value = value.strip()
        if not value:
            raise StructureRefused("Empty deb822 field")
        fields[key] = value
    if not {"Types", "URIs", "Suites"}.issubset(fields):
        raise StructureRefused("Missing deb822 mandatory field")
    allowed = {"Types", "URIs", "Suites", "Components", "Architectures",
               "Signed-By", "Enabled"}
    if not set(fields).issubset(allowed):
        raise StructureRefused("Unsupported deb822 field")
    if fields.get("Enabled", "yes") != "yes":
        raise StructureRefused("Disabled deb822 entries are not managed")
    types = _tokens(fields["Types"])
    if len(types) != 1 or types[0] not in APT_TYPES:
        raise StructureRefused("Only one APT type is supported")
    urls = _tokens(fields["URIs"])
    if len(urls) != 1:
        raise StructureRefused("Multiple deb822 URLs require full validation")
    _single_url(urls[0])
    suites = _tokens(fields["Suites"])
    if len(suites) != 1 or not re.fullmatch(r"[A-Za-z0-9._/+:-]+", suites[0]):
        raise StructureRefused("Only one valid deb822 suite is supported")
    if suites[0].endswith("/"):
        if "Components" in fields:
            raise StructureRefused("Exact suite may not set components")
    elif "Components" not in fields or not all(
            re.fullmatch(r"[A-Za-z0-9._+-]+", x)
            for x in _tokens(fields["Components"])):
        raise StructureRefused("Missing or invalid deb822 components")
    if "Architectures" in fields and not all(
            re.fullmatch(r"[A-Za-z0-9_-]+", x)
            for x in _tokens(fields["Architectures"])):
        raise StructureRefused("Unsupported deb822 architectures")
    if "Signed-By" in fields and not re.fullmatch(
            r"/usr/share/keyrings/[A-Za-z0-9_.-]+\.gpg|"
            r"/etc/apt/keyrings/[A-Za-z0-9_.-]+\.gpg", fields["Signed-By"]):
        raise StructureRefused("Unverified keyring selector")
    return 1


def _dnf_repo(body: str) -> int:
    config = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        config.read_string(body)
    except configparser.Error as exc:
        raise StructureRefused("Malformed DNF repository configuration") from exc
    if config.defaults() or len(config.sections()) != 1:
        raise StructureRefused("Only one DNF repository section is supported")
    section_name = config.sections()[0]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", section_name):
        raise StructureRefused("Unsupported DNF repository identifier")
    section = config[section_name]
    allowed = {"name", "baseurl", "enabled", "gpgcheck", "repo_gpgcheck",
               "gpgkey", "metadata_expire"}
    if not set(section).issubset(allowed):
        raise StructureRefused("Unsupported DNF option")
    if section.get("enabled", "1") != "1" or section.get("gpgcheck") != "1":
        raise StructureRefused("Disabled or unsigned DNF sources are unsupported")
    if "repo_gpgcheck" in section and section["repo_gpgcheck"] != "1":
        raise StructureRefused("Explicit unsigned metadata is unsupported")
    if "baseurl" not in section or len(_tokens(section["baseurl"])) != 1:
        raise StructureRefused("Exactly one DNF baseurl is supported")
    _single_url(section["baseurl"].strip())
    if any(key in section for key in ("mirrorlist", "metalink")):
        raise StructureRefused("Mirrorlist/metalink needs native validation")
    return 1


def inspect_structure(relative: str, data: bytes) -> dict:
    """Check one intentionally small source shape; does not grant ownership."""
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise StructureRefused("Invalid source content")
    try:
        body = data.decode("utf-8")
    except UnicodeError as exc:
        raise StructureRefused("Source encoding is unsupported") from exc
    if "\x00" in body or "\r" in body:
        raise StructureRefused("Unsupported control character")
    if relative == "etc/apt/sources.list" or relative.endswith(".list"):
        family, count = "apt-list", _apt_list(body)
    elif relative.endswith(".sources"):
        family, count = "apt-deb822", _apt_deb822(body)
    elif relative.endswith(".repo"):
        family, count = "dnf-repo", _dnf_repo(body)
    else:
        raise StructureRefused("Unsupported source path")
    return {
        "format": family,
        "source_entries": count,
        "structure_subset_pass": True,
        "native_syntax_verified": False,
        "repository_signature_verified": False,
        "fallback_verified": False,
        "write_eligible": False,
    }
