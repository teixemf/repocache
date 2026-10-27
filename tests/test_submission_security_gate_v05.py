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
from types import SimpleNamespace

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

    # Control only the client's nonce generator, not the intake's secrets.
    # The first two requests use the same nonce for an actual HTTPS replay.
    nonce_number = 0

    def next_nonce(size):
        nonlocal nonce_number
        nonce_number += 1
        value = 1 if nonce_number <= 2 else nonce_number - 1
        return value.to_bytes(size, "big")

    monkeypatch.setattr(client, "secrets", SimpleNamespace(token_bytes=next_nonce))

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

        # The same signed body and nonce must return the same pending proposal.
        replayed = client._send_submission(
            f"https://127.0.0.1:{server.server_address[1]}", body, credential)
        assert replayed["proposal_id"] == ident

        # The real TLS endpoint must refuse an otherwise well-formed request
        # signed with the wrong secret, without persisting it.
        wrong_credential = secret_dir / "wrong.json"
        wrong_credential.write_text(json.dumps({"key_id": "test", "secret":
            base64.urlsafe_b64encode(b"d" * 32).decode().rstrip("=")}))
        wrong_credential.chmod(0o600)
        with pytest.raises(client.RemoteSubmissionError) as unauthorized:
            client._send_submission(
                f"https://127.0.0.1:{server.server_address[1]}",
                body, wrong_credential)
        assert unauthorized.value.error_code == "AUTHENTICATION_REQUIRED"
        assert unauthorized.value.exit_code == 2

        with queue._connect() as db:
            assert db.execute("SELECT COUNT(*) FROM proposals").fetchone()[0] == 1

        # Nine additional unique valid nonces reach the per-key ten-request
        # quota. The eleventh must be rejected over TLS, not just by a mock.
        for _ in range(9):
            accepted = client._send_submission(
                f"https://127.0.0.1:{server.server_address[1]}", body, credential)
            assert accepted["status"] == "pending"
        with pytest.raises(client.RemoteSubmissionError) as limited:
            client._send_submission(
                f"https://127.0.0.1:{server.server_address[1]}", body, credential)
        assert limited.value.error_code == "RATE_LIMITED"
        assert limited.value.exit_code == 2
        with queue._connect() as db:
            assert db.execute("SELECT COUNT(*) FROM proposals").fetchone()[0] == 10
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()

    # The same real client against the now-closed HTTPS port must fail
    # predictably, without exposing endpoint details or credential material.
    with pytest.raises(client.RemoteSubmissionError) as unavailable:
        client._send_submission(
            f"https://127.0.0.1:{server.server_address[1]}", body, credential)
    assert unavailable.value.error_code == "OFFLINE"
    assert unavailable.value.exit_code == 2
    for value in (str(credential), "127.0.0.1", "c" * 32,
                  base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")):
        assert value not in str(unavailable.value)


def test_http_duplicate_content_length_is_refused(tmp_path):
    import socket

    queue, intake = _fixture(tmp_path)
    server = make_loopback_server(intake, enabled=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.create_connection(("127.0.0.1", server.server_address[1]),
                                      timeout=3) as stream:
            stream.sendall(
                b"POST /v1/repository-submissions HTTP/1.1\r\n"
                b"Host: localhost\r\nContent-Length: 2\r\nContent-Length: 2\r\n"
                b"Content-Type: application/json\r\n\r\n{}")
            answer = stream.recv(1024)
        assert b" 400 " in answer
        with queue._connect() as db:
            assert db.execute("SELECT COUNT(*) FROM proposals").fetchone()[0] == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
