"""Strict, side-effect-free input validation for the proposed server install v1 model.

This library is an initial provisioning preflight building block, not an
installer, privileged helper, repository authorization engine or NGINX renderer.
"""
from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlsplit
from typing import Any

MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_DEPTH = 16
MAX_INT = 2**63 - 1
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z", re.ASCII)
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z", re.ASCII)
LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z", re.ASCII)
OS_SUPPORTED = {"debian": ("13", (3, 13)), "almalinux": ("10", (3, 12))}


class InstallInputError(ValueError):
    """Rejected input; messages contain only static field names, never values."""


def _reject(message: str) -> None:
    raise InstallInputError(message)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject("Duplicate JSON object key")
        result[key] = value
    return result


def _depth(value: Any, level: int = 1) -> None:
    if level > MAX_DEPTH:
        _reject("JSON nesting exceeds 16 levels")
    if isinstance(value, dict):
        for key, nested in value.items():
            _string(key, "JSON field name", allow_empty=False)
            _depth(nested, level + 1)
    elif isinstance(value, list):
        for nested in value:
            _depth(nested, level + 1)


def _object(value: Any, name: str, required: set[str],
            optional: set[str] | None = None) -> dict[str, Any]:
    if type(value) is not dict:
        _reject(f"{name}: expected object")
    allowed = required | (optional or set())
    if not required.issubset(value) or set(value) - allowed:
        _reject(f"{name}: missing or unknown fields")
    return value


def _string(value: Any, name: str, *, allow_empty: bool = False,
            limit: int = 2048) -> str:
    if type(value) is not str:
        _reject(f"{name}: expected string")
    try:
        raw = value.encode("utf-8", errors="strict")
    except UnicodeError:
        _reject(f"{name}: invalid Unicode")
    if len(raw) > limit or (not allow_empty and not raw) or value != value.strip():
        _reject(f"{name}: invalid length or whitespace")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        _reject(f"{name}: control character")
    return value


def _integer(value: Any, name: str, low: int, high: int = MAX_INT) -> int:
    if type(value) is not int or not low <= value <= high:
        _reject(f"{name}: integer out of permitted range")
    return value


def _boolean(value: Any, name: str) -> bool:
    if type(value) is not bool:
        _reject(f"{name}: expected Boolean")
    return value


def _host(value: Any, name: str) -> str:
    value = _string(value, name, limit=253)
    if not value.isascii() or not 1 <= len(value) <= 253:
        _reject(f"{name}: invalid DNS name")
    if any(not LABEL.fullmatch(label) for label in value.split(".")):
        _reject(f"{name}: invalid DNS label")
    if len(value.split(".")) < 2:
        _reject(f"{name}: expected DNS hostname")
    # inet_aton/getaddrinfo may interpret legacy dotted octal/hex or
    # abbreviated numbers as IP literals even when ipaddress rejects them.
    numeric = re.compile(r"(?:[0-9]+|0[xX][0-9A-Fa-f]+)\Z", re.ASCII)
    if all(numeric.fullmatch(part) for part in value.split(".")):
        _reject(f"{name}: numeric IP-like host forbidden")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        _reject(f"{name}: IP literals are not permitted for upstream hosts")
    return value.lower()


def _path(value: Any, name: str) -> str:
    value = _string(value, name)
    if (not value.startswith("/") or "//" in value
            or any(piece in ("", ".", "..") for piece in value.split("/")[1:])
            or "\\" in value or value == "/"):
        _reject(f"{name}: noncanonical absolute path")
    return value


def _trust_ref(value: Any, name: str) -> str:
    value = _string(value, name)
    if not value.startswith("file:"):
        _reject(f"{name}: expected file reference")
    _path(value[5:], name)
    return value


def _token(value: Any, name: str) -> str:
    value = _string(value, name, limit=64)
    if not TOKEN.fullmatch(value) or value in (".", ".."):
        _reject(f"{name}: invalid repository token")
    return value


def _array(value: Any, name: str, validate, low: int = 1,
           high: int = 32) -> list[Any]:
    if type(value) is not list or not low <= len(value) <= high:
        _reject(f"{name}: invalid array size")
    validated = [validate(item, name) for item in value]
    if len(set(validated)) != len(validated):
        _reject(f"{name}: duplicate normalized entry")
    return validated


def _upstream(value: Any) -> str:
    value = _string(value, "upstream.base_url")
    if "\\" in value or "%" in value:
        # No encoded or ambiguous path syntax before an origin policy exists.
        _reject("upstream.base_url: ambiguous escaping")
    try:
        parsed = urlsplit(value)
        host = _host(parsed.hostname, "upstream.base_url host")
        port = parsed.port
    except ValueError:
        _reject("upstream.base_url: invalid URL")
    if (parsed.scheme != "https" or not parsed.netloc
            or parsed.netloc.endswith(":")
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or "?" in value or "#" in value):
        _reject("upstream.base_url: only credential-free HTTPS is permitted")
    if port is not None and not 1 <= port <= 65535:
        _reject("upstream.base_url: invalid port")
    path = parsed.path
    if any(ord(ch) < 33 or ord(ch) > 126 for ch in path):
        _reject("upstream.base_url: invalid or unescaped path characters")
    if (not path.startswith("/") or not path.endswith("/") or "//" in path
            or any(part in (".", "..") for part in path.split("/")[1:-1])):
        _reject("upstream.base_url: noncanonical slash-terminated path")
    return host


def _layout(kind: str, value: Any) -> None:
    if kind == "apt":
        obj = _object(value, "repositories.layout", {
            "suites", "components", "architectures", "release_key_refs"})
        for key in ("suites", "components", "architectures"):
            _array(obj[key], f"layout.{key}", _token)
        _array(obj["release_key_refs"], "layout.release_key_refs", _trust_ref)
    else:
        obj = _object(value, "repositories.layout", {
            "releasever", "basearch", "metadata_path", "gpg_key_refs"})
        _token(obj["releasever"], "layout.releasever")
        _token(obj["basearch"], "layout.basearch")
        path = _string(obj["metadata_path"], "layout.metadata_path", limit=512)
        if path.startswith("/") or "//" in path or "\\" in path:
            _reject("layout.metadata_path: invalid relative path")
        for segment in path.split("/"):
            _token(segment, "layout.metadata_path")
        _array(obj["gpg_key_refs"], "layout.gpg_key_refs", _trust_ref)


def validate_install_document(document: Any, *, for_apply: bool = False) -> dict:
    """Validate a decoded document without accessing the filesystem or network.

    for_apply enforces the mandatory optimistic-concurrency precondition, but
    never authorizes or executes an apply.
    """
    _depth(document)
    root = _object(document, "root", {"kind", "schema_version", "deployment",
                                      "repositories"}, {"expected_state_generation"})
    if root["kind"] != "repocache.server.install":
        _reject("kind: unsupported document kind")
    _integer(root["schema_version"], "schema_version", 1, 1)
    if for_apply and "expected_state_generation" not in root:
        _reject("expected_state_generation: required for mutation")
    if "expected_state_generation" in root:
        _integer(root["expected_state_generation"], "expected_state_generation", 0)
    dep = _object(root["deployment"], "deployment", {
        "listen", "tls", "native_packages", "nginx", "paths", "logging",
        "cache_policy"}, {"firewall"})
    listen = _object(dep["listen"], "deployment.listen", {
        "bind_address", "hostname", "https_port"})
    address = _string(listen["bind_address"], "deployment.listen.bind_address")
    try:
        if str(ipaddress.ip_address(address)) != address:
            _reject("deployment.listen.bind_address: noncanonical IP")
    except ValueError:
        _reject("deployment.listen.bind_address: invalid IP literal")
    _host(listen["hostname"], "deployment.listen.hostname")
    _integer(listen["https_port"], "deployment.listen.https_port", 1, 65535)

    tls = _object(dep["tls"], "deployment.tls", {
        "mode", "certificate_file", "private_key_file"})
    if tls["mode"] != "operator-provided":
        _reject("deployment.tls.mode: unsupported mode")
    for key in ("certificate_file", "private_key_file"):
        _path(tls[key], f"deployment.tls.{key}")
    if tls["certificate_file"] == tls["private_key_file"]:
        _reject("deployment.tls: certificate and private key paths must differ")

    pkg = _object(dep["native_packages"], "deployment.native_packages", {"policy"})
    if pkg["policy"] != "explicit-review":
        _reject("deployment.native_packages: unsupported package policy")
    nginx = _object(dep["nginx"], "deployment.nginx", {"ownership"})
    if nginx["ownership"] != "new-managed-only":
        _reject("deployment.nginx: external adoption forbidden")
    if "firewall" in dep:
        fw = _object(dep["firewall"], "deployment.firewall", {"modify"})
        _boolean(fw["modify"], "deployment.firewall.modify")

    paths = _object(dep["paths"], "deployment.paths", {
        "generated_include", "state_root", "cache_root", "log_root"})
    checked_paths = [_path(paths[key], f"deployment.paths.{key}")
                     for key in ("generated_include", "state_root",
                                 "cache_root", "log_root")]
    if len(set(checked_paths)) != len(checked_paths):
        _reject("deployment.paths: conflicting paths")
    logging = _object(dep["logging"], "deployment.logging",
                      {"retention_days"}, {"metrics_opt_in"})
    _integer(logging["retention_days"], "deployment.logging.retention_days",
             1, 3650)
    if "metrics_opt_in" in logging:
        _boolean(logging["metrics_opt_in"], "deployment.logging.metrics_opt_in")
    cache = _object(dep["cache_policy"], "deployment.cache_policy", {
        "engine", "global", "disk_pressure"})
    if cache["engine"] != "nginx-native":
        _reject("deployment.cache_policy: unsupported engine")
    glob = _object(cache["global"], "deployment.cache_policy.global", {
        "inactive_seconds", "max_size_bytes"})
    _integer(glob["inactive_seconds"], "global.inactive_seconds", 1, 2147483647)
    _integer(glob["max_size_bytes"], "global.max_size_bytes", 1)
    pressure = _object(cache["disk_pressure"], "deployment.cache_policy.disk_pressure", {
        "warning_free_bytes", "critical_free_bytes"})
    warning = _integer(pressure["warning_free_bytes"], "disk_pressure.warning_free_bytes", 1)
    critical = _integer(pressure["critical_free_bytes"], "disk_pressure.critical_free_bytes", 1)
    if warning < critical:
        _reject("disk_pressure: warning must be >= critical")

    repos = root["repositories"]
    if type(repos) is not list or len(repos) > 500:
        _reject("repositories: expected array of at most 500")
    identifiers: set[str] = set()
    identities: set[str] = set()
    for item in repos:
        repo = _object(item, "repositories[]", {
            "kind", "desired_state", "upstream", "layout"}, {
            "id", "cache_overrides"})
        if "id" in repo:
            identifier = _string(repo["id"], "repositories[].id", limit=48)
            if not ID.fullmatch(identifier) or identifier in identifiers:
                _reject("repositories[].id: invalid or duplicate ID")
            identifiers.add(identifier)
        if repo["kind"] not in ("apt", "dnf"):
            _reject("repositories[].kind: expected apt or dnf")
        if repo["desired_state"] not in ("active", "disabled"):
            _reject("repositories[].desired_state: invalid value")
        upstream = _object(repo["upstream"], "repositories[].upstream", {
            "base_url", "allowed_hosts"})
        hostname = _upstream(upstream["base_url"])
        hosts = _array(upstream["allowed_hosts"], "upstream.allowed_hosts", _host)
        if hostname not in hosts:
            _reject("upstream.allowed_hosts: missing base_url host")
        _layout(repo["kind"], repo["layout"])
        overrides = _object(repo.get("cache_overrides", {}),
                            "repositories[].cache_overrides", set(),
                            {"inactive_seconds", "max_size_bytes"})
        if "inactive_seconds" in overrides:
            _integer(overrides["inactive_seconds"], "cache_overrides.inactive_seconds",
                     1, 2147483647)
        if "max_size_bytes" in overrides:
            _integer(overrides["max_size_bytes"], "cache_overrides.max_size_bytes", 1)
        # A duplicate canonical upstream+layout is never a distinct repository.
        identity = json.dumps([repo["kind"], upstream["base_url"].lower(),
                               repo["layout"]], sort_keys=True, separators=(",", ":"))
        if identity in identities:
            _reject("repositories: duplicate canonical repository identity")
        identities.add(identity)
    return root


def parse_install_bytes(payload: bytes, *, for_apply: bool = False) -> dict:
    """Parse strict UTF-8 JSON and validate its closed v1 input schema."""
    if type(payload) is not bytes or len(payload) > MAX_DOCUMENT_BYTES:
        _reject("install document: expected bytes of at most 1 MiB")
    if payload.startswith(b"\xef\xbb\xbf"):
        _reject("install document: UTF-8 BOM forbidden")
    try:
        data = payload.decode("utf-8", "strict")
        document = json.loads(data, object_pairs_hook=_pairs,
                              parse_constant=lambda _v: _reject(
                                  "install document: nonfinite number"))
    except InstallInputError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError,
            OverflowError, ValueError):
        _reject("install document: invalid UTF-8 JSON")
    return validate_install_document(document, for_apply=for_apply)


def validate_os_identity(os_release: str, python_version: tuple[int, int]) -> str:
    """Read-only supported-OS identity gate; other host checks remain unimplemented.

    Do not use this gate alone to authorize native packages or service changes.
    """
    if type(os_release) is not str:
        _reject("os-release: expected text")
    values: dict[str, str] = {}
    for line in os_release.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            _reject("os-release: malformed record")
        key, value = line.split("=", 1)
        if key not in ("ID", "VERSION_ID"):
            continue
        if key in values:
            _reject("os-release: duplicate OS identity field")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[key] = value
    distro = values.get("ID", "")
    version = values.get("VERSION_ID", "")
    target = OS_SUPPORTED.get(distro)
    if (target is None or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", version)
            or version.split(".")[0] != target[0]):
        _reject("os-release: supported targets are Debian 13 and AlmaLinux 10")
    if (type(python_version) is not tuple or len(python_version) != 2
            or python_version != target[1]):
        _reject("os-release: unsupported distribution system Python")
    return distro
