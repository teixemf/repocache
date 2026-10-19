"""Opt-in local HTTP adapter for authenticated pending-only submissions.

No daemon is installed or started by importing this module. Network-facing
TLS and deployment require the separate issue #17 security acceptance gate.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import stat
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from repocache.submissions import SubmissionError, SubmissionQueue, validate_payload

ENDPOINT = "/v1/repository-submissions"


def canonical_request(timestamp: str, nonce: str, raw: bytes) -> bytes:
    return (f"repocache-v1\nPOST\n{ENDPOINT}\n{timestamp}\n{nonce}\n"
            f"{hashlib.sha256(raw).hexdigest()}").encode("ascii")


def _secret(encoded: str) -> bytes:
    if not isinstance(encoded, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded):
        raise SubmissionError("invalid_credentials", 503)
    try:
        value = base64.urlsafe_b64decode(encoded + "=")
    except (ValueError, TypeError) as exc:
        raise SubmissionError("invalid_credentials", 503) from exc
    if len(value) != 32 or base64.urlsafe_b64encode(value).decode("ascii").rstrip("=") != encoded:
        raise SubmissionError("invalid_credentials", 503)
    return value


def load_keyring(path: Path) -> dict[str, bytes]:
    """Read an operator-created protected keyring (never keys from requests)."""
    try:
        st = path.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077
                or st.st_uid not in {0, os.geteuid()} or st.st_size > 8192):
            raise SubmissionError("invalid_credentials", 503)
        if path.parent.lstat().st_mode & 0o022:
            raise SubmissionError("invalid_credentials", 503)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as file:
            data = file.read(8193)
        doc = json.loads(data.decode("utf-8"))
        if not isinstance(doc, dict) or set(doc) != {"keys"} or not isinstance(doc["keys"], list):
            raise SubmissionError("invalid_credentials", 503)
        result = {}
        for item in doc["keys"]:
            if not isinstance(item, dict) or set(item) != {"key_id", "secret"}:
                raise SubmissionError("invalid_credentials", 503)
            ident = item["key_id"]
            if (not isinstance(ident, str) or
                    not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", ident) or ident in result):
                raise SubmissionError("invalid_credentials", 503)
            result[ident] = _secret(item["secret"])
        if not 1 <= len(result) <= 32:
            raise SubmissionError("invalid_credentials", 503)
        return result
    except (OSError, UnicodeError, ValueError) as exc:
        if isinstance(exc, SubmissionError):
            raise
        raise SubmissionError("invalid_credentials", 503) from exc


class SubmissionIntake:
    def __init__(self, queue: SubmissionQueue, keys: dict[str, bytes]):
        if not keys or any(len(secret) != 32 for secret in keys.values()):
            raise SubmissionError("invalid_credentials", 503)
        self.queue, self.keys = queue, dict(keys)

    def handle(self, method: str, path: str, headers: dict[str, str], raw: bytes,
               *, now: int | None = None) -> tuple[int, dict, dict[str, str]]:
        """Return (HTTP status, sanitized JSON, extra response headers)."""
        extra = {"Cache-Control": "no-store"}
        try:
            if method != "POST" or path != ENDPOINT:
                raise SubmissionError("not_found", 404)
            if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                raise SubmissionError("unsupported_type", 415)
            if not isinstance(raw, bytes) or len(raw) > 65536 or not raw:
                raise SubmissionError("invalid_size", 413)
            key_id = headers.get("x-repocache-key-id", "")
            timestamp = headers.get("x-repocache-timestamp", "")
            nonce = headers.get("x-repocache-nonce", "")
            signature = headers.get("x-repocache-signature", "")
            if (not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key_id)
                    or not re.fullmatch(r"[0-9]{10,11}", timestamp)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{22}", nonce)
                    or not re.fullmatch(r"[a-f0-9]{64}", signature)):
                raise SubmissionError("unauthorized", 401)
            try:
                decoded = base64.urlsafe_b64decode(nonce + "==")
            except (ValueError, TypeError) as exc:
                raise SubmissionError("unauthorized", 401) from exc
            if len(decoded) != 16 or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != nonce:
                raise SubmissionError("unauthorized", 401)
            current = int(time.time()) if now is None else int(now)
            if abs(current - int(timestamp)) > 30:
                raise SubmissionError("unauthorized", 401)
            secret = self.keys.get(key_id)
            if secret is None:
                raise SubmissionError("unauthorized", 401)
            calculated = hmac.new(secret, canonical_request(timestamp, nonce, raw),
                                  hashlib.sha256).hexdigest()
            if not hmac.compare_digest(calculated, signature):
                raise SubmissionError("unauthorized", 401)
            payload = validate_payload(raw)
            ident = self.queue.enqueue(
                hashlib.sha256(key_id.encode()).hexdigest(), nonce,
                hashlib.sha256(raw).hexdigest(), payload, now=current)
            return 202, {"status": "pending", "proposal_id": ident}, extra
        except SubmissionError as exc:
            if exc.status == 429:
                extra["Retry-After"] = "60"
            return exc.status, {"error": exc.code}, extra
        except (OSError, ValueError):
            return 503, {"error": "store_unavailable"}, extra


class _LocalHandler(BaseHTTPRequestHandler):
    intake: SubmissionIntake

    def setup(self):
        super().setup()
        # Bound client slow-read attacks even on an explicitly enabled
        # loopback test listener. Deployment must enforce NGINX timeouts too.
        self.connection.settimeout(5)

    def do_POST(self):
        size = self.headers.get("Content-Length", "")
        if (self.headers.get("Transfer-Encoding") or not size.isdecimal()
                or len(size) > 6 or int(size) > 65536):
            self.close_connection = True
            self._reply(413, {"error": "invalid_size"}, {})
            return
        try:
            body = self.rfile.read(int(size))
        except (TimeoutError, OSError):
            self.close_connection = True
            return
        if len(body) != int(size):
            self.close_connection = True
            self._reply(400, {"error": "invalid_size"}, {})
            return
        header_names = ("content-type", "x-repocache-key-id", "x-repocache-timestamp",
                        "x-repocache-nonce", "x-repocache-signature")
        headers = {key: self.headers.get(key, "") for key in header_names}
        status, result, extra = self.intake.handle("POST", self.path, headers, body)
        self._reply(status, result, extra)

    def do_GET(self):
        self._reply(405, {"error": "method_not_allowed"}, {})

    def _reply(self, status: int, payload: dict, extra: dict) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        for key, value in extra.items():
            if key.lower() not in {"content-length", "content-type", "connection", "cache-control"}:
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def log_message(self, format, *args):
        # Never log remote payloads, request URLs, IP addresses or auth headers.
        return


def make_loopback_server(intake: SubmissionIntake, *, enabled: bool = False,
                         port: int = 0) -> HTTPServer:
    """Explicit local-only construction; no CLI, unit or import starts a server."""
    if not enabled:
        raise SubmissionError("listener_disabled", 403)
    if not isinstance(port, int) or port < 0 or port > 65535:
        raise SubmissionError("invalid_listener", 400)

    class Handler(_LocalHandler):
        pass

    Handler.intake = intake
    return HTTPServer(("127.0.0.1", port), Handler)
