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


@pytest.mark.parametrize("status,expected", [(401, "AUTHENTICATION_REQUIRED"), (403, "AUTHENTICATION_REQUIRED"),
     (429, "RATE_LIMITED"), (503, "SUBMISSION_REJECTED"),
     (307, "SUBMISSION_REJECTED")])
def test_server_failure_codes_do_not_echo_remote_body(monkeypatch, credential, status, expected):
    class FakeOpener:
        def open(self, request, timeout):
            raise HTTPError(request.full_url, status,
                            "secret from attacker", {}, None)
    monkeypatch.setattr(client, "build_opener", lambda *handlers: FakeOpener())
    with pytest.raises(client.RemoteSubmissionError) as failure:
        client._send_submission("https://cache.example.org", _data(), credential)
    assert failure.value.exit_code == 2
    assert failure.value.error_code == expected
    assert "secret" not in str(failure.value)
    assert "cache.example.org" not in str(failure.value)


def test_invalid_response_and_network_errors_are_redacted(monkeypatch, credential):
    class BadResponse:
        def open(self, request, timeout):
            return Response(result={"proposal_id": "not-a-valid-id"})
    monkeypatch.setattr(client, "build_opener", lambda *handlers: BadResponse())
    with pytest.raises(client.RemoteSubmissionError) as failure:
        client._send_submission("https://cache.example.org", _data(), credential)
    assert failure.value.exit_code == 2
    assert failure.value.error_code == "SUBMISSION_REJECTED"

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


def test_credential_replacement_between_lstat_and_open_is_refused(
    monkeypatch, credential
):
    """A substituted safe-looking credential must not bypass inode checks."""
    original_open = client.os.open
    alternate = credential.parent / "alternate.json"
    alternate.write_text(json.dumps({
        "key_id": "attacker",
        "secret": base64.urlsafe_b64encode(b"x" * 32).decode().rstrip("="),
    }))
    alternate.chmod(0o600)
    invoked = []

    def replace_before_open(path, flags, *args, **kwargs):
        if Path(path) == credential and not invoked:
            invoked.append(True)
            credential.unlink()
            alternate.rename(credential)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(client.os, "open", replace_before_open)
    with pytest.raises(client.ClientError, match="changed or is unsafe"):
        client._submission_credential(credential)
    assert invoked


def test_credential_replacement_with_insecure_file_is_refused(
    monkeypatch, credential
):
    original_open = client.os.open
    replacement = credential.parent / "world-readable.json"
    replacement.write_text(credential.read_text())
    replacement.chmod(0o644)
    once = []

    def replace_before_open(path, flags, *args, **kwargs):
        if Path(path) == credential and not once:
            once.append(True)
            credential.unlink()
            replacement.rename(credential)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(client.os, "open", replace_before_open)
    with pytest.raises(client.ClientError, match="changed or is unsafe"):
        client._submission_credential(credential)
    assert once


@pytest.mark.parametrize("status,symbol", [
    (401, "AUTHENTICATION_REQUIRED"), (429, "RATE_LIMITED"),
    (503, "SUBMISSION_REJECTED"),
])
def test_remote_submission_cli_v1_exit_json_contract(
    monkeypatch, credential, tmp_path, capsys, status, symbol
):
    root = tmp_path / "host"
    (root / "etc/apt").mkdir(parents=True)
    (root / "etc/os-release").write_text('ID=debian\\nVERSION_ID="13"\\n')
    (root / "etc/apt/sources.list").write_text(
        "deb https://mirror.example.org/debian trixie main\\n"
    )

    def rejected(*_args):
        errors = {
            401: "Submission authentication failed",
            429: "Submission rate limit exceeded",
            503: "Submission endpoint rejected request",
        }
        raise client.RemoteSubmissionError(errors[status], symbol)

    monkeypatch.setattr(client, "_send_submission", rejected)
    result = client.run(["--json", "repos", "submit", "--send",
                         "--token-file", str(credential)], root=root)
    output = json.loads(capsys.readouterr().out)
    assert result == 2
    assert output["schema_version"] == 1
    assert output["ok"] is False
    assert output["exit_code"] == 2
    assert output["error"]["code"] == symbol
    assert isinstance(output["error"]["message"], str)
