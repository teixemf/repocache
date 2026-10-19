"""Issue #22: explicit, non-interactive, credential-safe client submissions."""
from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest

spec = importlib.util.spec_from_file_location(
    "client_v05", Path(__file__).resolve().parents[1] / "client/repocache_client.py")
client = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(client)


@pytest.fixture
def credential(tmp_path):
    directory = tmp_path / "keys"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "key.json"
    path.write_text(json.dumps({"key_id": "test",
        "secret": base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")}))
    path.chmod(0o600)
    return path


def _data():
    return {"schema": 1, "os": {"id": "debian", "version": "13"}, "repositories":
            [{"type": "apt-list", "url": "https://mirror.example.org/debian/"}]}


class Response:
    def __init__(self, status=202, result=None):
        self.status = status
        self.result = result or {"proposal_id": "a" * 32}
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def read(self, count):
        return json.dumps(self.result).encode()[:count]


def test_client_submits_explicitly_over_https_without_redirects(monkeypatch, credential):
    calls = []
    class FakeOpener:
        def open(self, request, timeout):
            calls.append((request, timeout))
            return Response()
    monkeypatch.setattr(client, "build_opener", lambda *handlers: FakeOpener())
    result = client._send_submission("https://cache.example.org", _data(), credential)
    assert result == {"ok": True, "status": "pending", "proposal_id": "a" * 32}
    request, timeout = calls[0]
    assert request.full_url == "https://cache.example.org/v1/repository-submissions"
    assert request.get_method() == "POST" and timeout == 8
    assert request.get_header("X-repocache-signature")
    assert not any("cccc" in str(v) for v in request.headers.values())
    assert client._RejectRedirects().redirect_request(None, None, 307, "", {},
                                                       "https://evil.example.net") is None


@pytest.mark.parametrize("status,expected", [(401, 4), (403, 4), (429, 5), (503, 6), (307, 6)])
def test_server_failure_codes_do_not_echo_remote_body(monkeypatch, credential, status, expected):
    class FakeOpener:
        def open(self, request, timeout):
            raise HTTPError(request.full_url, status,
                            "secret from attacker", {}, None)
    monkeypatch.setattr(client, "build_opener", lambda *handlers: FakeOpener())
    with pytest.raises(client.RemoteSubmissionError) as failure:
        client._send_submission("https://cache.example.org", _data(), credential)
    assert failure.value.exit_code == expected
    assert "secret" not in str(failure.value)
    assert "cache.example.org" not in str(failure.value)


def test_invalid_response_and_network_errors_are_redacted(monkeypatch, credential):
    class BadResponse:
        def open(self, request, timeout):
            return Response(result={"proposal_id": "not-a-valid-id"})
    monkeypatch.setattr(client, "build_opener", lambda *handlers: BadResponse())
    with pytest.raises(client.RemoteSubmissionError) as failure:
        client._send_submission("https://cache.example.org", _data(), credential)
    assert failure.value.exit_code == 6

    class NoNetwork:
        def open(self, request, timeout):
            raise URLError("unsafe internal address with token")
    monkeypatch.setattr(client, "build_opener", lambda *handlers: NoNetwork())
    with pytest.raises(client.RemoteSubmissionError) as failure:
        client._send_submission("https://cache.example.org", _data(), credential)
    assert "token" not in str(failure.value)


def test_credential_file_is_protected_and_not_a_symlink(credential):
    assert client._submission_credential(credential)[1] == b"c" * 32
    credential.chmod(0o644)
    with pytest.raises(client.ClientError):
        client._submission_credential(credential)
    credential.chmod(0o600)
    link = credential.parent / "link.json"
    link.symlink_to(credential)
    with pytest.raises(client.ClientError):
        client._submission_credential(link)


def test_send_does_not_allow_implicit_network_or_alter_sources(monkeypatch, credential, tmp_path):
    root = tmp_path / "host"
    (root / "etc/apt").mkdir(parents=True)
    (root / "etc/os-release").write_text('ID=debian\nVERSION_ID="13"\n')
    source = root / "etc/apt/sources.list"
    source.write_text("deb https://mirror.example.org/debian trixie main\n")
    assert client.run(["repos", "submit", "--token-file", str(credential)], root=root) == 2
    assert client.run(["repos", "submit", "--send", "--output", "/tmp/nope",
                       "--token-file", str(credential)], root=root) == 2
    before = source.read_bytes()
    monkeypatch.setattr(client, "_send_submission",
                        lambda *args: {"ok": True, "proposal_id": "b"*32})
    assert client.run(["--json", "repos", "submit", "--send",
                       "--token-file", str(credential)], root=root) == 0
    assert before == source.read_bytes()
