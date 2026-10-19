"""Upstream probes are bounded, opt-in and never modify system settings."""
import socket
import ssl
import time
from repocache.core import probe_upstream


def _repository(url="https://deb.debian.org/debian/"):
    return {"name": "debian", "path": "/debian/", "upstream": url}


def test_credentialed_or_dynamic_upstream_never_triggers_network(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw:
                        (_ for _ in ()).throw(AssertionError("Unexpected DNS access")))
    unsafe = probe_upstream(_repository("http://guest:example@example.org/path"))
    assert unsafe["result"] == "WARN"
    assert unsafe["dns"] == "not checked"
    assert probe_upstream(_repository("http://$upstream"))["result"] == "WARN"


def test_failed_dns_reports_actual_failure(monkeypatch):
    def fail(*a, **k):
        raise socket.gaierror("test resolver failure")
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    output = probe_upstream(_repository())
    assert output["dns"] == "failed"
    assert output["connectivity"] == "not checked"
    assert output["result"] == "FAIL"


def test_dns_request_has_a_wallclock_deadline(monkeypatch):
    def slow(*a, **k):
        time.sleep(1.0)
        return []
    monkeypatch.setattr(socket, "getaddrinfo", slow)
    start = time.monotonic()
    output = probe_upstream(_repository(), timeout=0.3)
    assert time.monotonic() - start < 0.9
    assert output["dns"] == "timeout"


class SocketFixture:
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def settimeout(self, duration):
        assert 0 < duration <= 5
    def connect(self, address):
        pass


def test_non_tls_reachability_only_checks_tcp(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))])
    monkeypatch.setattr(socket, "socket", lambda *a: SocketFixture())
    output = probe_upstream(_repository("http://example.org/repo/"), timeout=2)
    assert output["result"] == "OK"
    assert output["tls"] == "not applicable (HTTP)"


def test_tls_certificate_failure_is_observable(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))])
    monkeypatch.setattr(socket, "socket", lambda *a: SocketFixture())
    class InvalidCertificate:
        def wrap_socket(self, connection, server_hostname):
            raise ssl.SSLError("bad certificate")
    monkeypatch.setattr(ssl, "create_default_context", lambda: InvalidCertificate())
    output = probe_upstream(_repository(), timeout=2)
    assert output["dns"] == "resolved"
    assert output["connectivity"] == "reachable"
    assert output["tls"] == "failed"
    assert output["result"] == "FAIL"
