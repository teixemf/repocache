"""Disposable TLS end-to-end and hostile HTTP integration tests for #17.

This exercises a loopback-only temporary server and generated test certificates.
It is NOT real NGINX, systemd, SELinux or a production deployment test.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import ssl
import subprocess
import threading
from http.client import HTTPConnection
from pathlib import Path

import pytest

from repocache.intake import SubmissionIntake, make_loopback_server
from repocache.submissions import SubmissionQueue


def _fixture(tmp_path):
    parent = tmp_path / "db"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    queue = SubmissionQueue(parent / "queue.db")
    return queue, SubmissionIntake(queue, {"test": b"c" * 32})


def test_http_body_length_and_method_fail_closed(tmp_path):
    queue, intake = _fixture(tmp_path)
    server = make_loopback_server(intake, enabled=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
        connection.request("GET", "/v1/repository-submissions")
        response = connection.getresponse()
        assert response.status == 405
        assert b"token" not in response.read()
        connection.close()
        connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
        connection.request("POST", "/v1/repository-submissions", body=b"x" * 65537,
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        assert response.status == 413
        response.read()
        connection.close()
        with queue._connect() as db:
            assert db.execute("SELECT COUNT(*) FROM proposals").fetchone()[0] == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_ephemeral_https_client_to_local_pending_server(tmp_path, monkeypatch):
    # Openssl is part of the disposable CI runner, never a runtime REPOCACHE
    # dependency; missing executable is a test failure, not a silent skip.
    assert shutil.which("openssl"), "Disposable HTTPS integration requires openssl"
    cert, key = tmp_path / "local-test.crt", tmp_path / "local-test.key"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "1",
        "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ], check=True, capture_output=True, timeout=20)
    key.chmod(0o600)
    queue, intake = _fixture(tmp_path)
    server = make_loopback_server(intake, enabled=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    spec = importlib.util.spec_from_file_location(
        "submission_tls_client", Path(__file__).resolve().parents[1] /
        "client/repocache_client.py")
    client = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(client)
    secret_dir = tmp_path / "credentials"
    secret_dir.mkdir(mode=0o700)
    secret_dir.chmod(0o700)
    credential = secret_dir / "secret.json"
    import base64
    credential.write_text(json.dumps({"key_id": "test", "secret":
        base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")}))
    credential.chmod(0o600)
    verify_context = ssl.create_default_context(cafile=str(cert))
    monkeypatch.setattr(client.ssl, "create_default_context",
                        lambda *args, **kwargs: verify_context)

    body = {"schema": 1, "os": {"id": "debian", "version": "13"},
            "repositories": [{"type": "apt-list",
                              "url": "https://mirror.example.org/debian/"}]}
    try:
        result = client._send_submission(
            f"https://127.0.0.1:{server.server_address[1]}", body, credential)
        assert result["ok"] is True
        ident = result["proposal_id"]
        # Only inert sanitized metadata persists; a live upstream request
        # must not occur during submission.
        with queue._connect() as db:
            row = db.execute("SELECT state,items FROM proposals WHERE id=?",
                             (ident,)).fetchone()
            assert row[0] == "PENDING"
            assert json.loads(row[1])[0]["url"] == "https://mirror.example.org/debian/"
        assert queue.path.stat().st_mode & 0o077 == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
