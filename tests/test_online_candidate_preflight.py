"""Offline signed eight-asset v0.6 candidate gate; all fixtures use TEST keys.

These synthetic signatures do not constitute publisher-key release acceptance.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest
from repocache import online_generation, signatures


def _checker():
    source = Path(__file__).resolve().parents[1] / "scripts/verify_online_candidate.py"
    spec = importlib.util.spec_from_file_location("offline_candidate_checker", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def candidate(tmp_path, monkeypatch):
    # Reuse the separately exercised, real Ed25519 -> archive -> lock -> SBOM
    # synthetic fixture to prove the new entrypoint uses production validation.
    sample = Path(__file__).with_name("test_signed_dependency_staging.py")
    spec = importlib.util.spec_from_file_location("signed_dependency_test_fixture", sample)
    assert spec is not None and spec.loader is not None
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    secret = tmp_path / "secret.pem"
    public = tmp_path / "public.pem"
    subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "Ed25519",
                    "-out", str(secret)], check=True, capture_output=True)
    secret.chmod(0o600)
    subprocess.run(["/usr/bin/openssl", "pkey", "-in", str(secret),
                    "-pubout", "-out", str(public)], check=True, capture_output=True)
    monkeypatch.setattr(signatures, "_trusted_key", lambda key_id: public)
    parts = fixture._parts()
    signed = tmp_path / "candidate"
    signed.mkdir(mode=0o700)
    fixture._signed(signed, secret, parts)
    return signed


def test_valid_test_key_candidate_authenticates_both_profiles(candidate, capsys):
    checker = _checker()
    data, verdict = checker.verify_candidate(candidate, "0.6.0")
    assert len(data) == 8
    assert verdict["targets"] == {"debian13-py313": 1, "almalinux10-py312": 1}
    assert verdict["publisher_authenticated"] is True
    assert verdict["activation"] is False
    assert checker.main(["--assets-dir", str(candidate), "--version", "0.6.0"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "owner-signature-and-locks-verified-only"
    assert output["activation"] is False
    assert "rehearsal" not in output


@pytest.mark.parametrize("change", [
    "missing", "extra", "symlink", "writable", "corrupt", "signature", "directory-mode",
])
def test_untrusted_eight_asset_input_is_refused(candidate, tmp_path, monkeypatch,
                                              change, capsys):
    checker = _checker()
    names = checker._filenames("0.6.0")
    dependency = candidate / names["dependency_lock"]
    if change == "missing":
        dependency.unlink()
    elif change == "extra":
        (candidate / "unaccounted.whl").write_bytes(b"malicious")
    elif change == "symlink":
        dependency.unlink()
        dependency.symlink_to(tmp_path / "public.pem")
    elif change == "writable":
        dependency.chmod(0o666)
    elif change == "corrupt":
        dependency.write_bytes(dependency.read_bytes() + b"\n")
    elif change == "signature":
        (candidate / names["signature"]).write_bytes(b"\x00" * 64)
    else:
        candidate.chmod(0o777)

    assert checker.main(["--assets-dir", str(candidate), "--version", "0.6.0"]) == 1
    stderr = capsys.readouterr().err
    assert stderr.startswith("Candidate refused:")
    assert "secret.pem" not in stderr
    assert "https://" not in stderr


def test_wrong_trust_anchor_refuses_fixture_signature(candidate, tmp_path, monkeypatch):
    checker = _checker()
    another_secret = tmp_path / "different-key.pem"
    another_public = tmp_path / "different-public.pem"
    subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "Ed25519",
                    "-out", str(another_secret)], check=True, capture_output=True)
    subprocess.run(["/usr/bin/openssl", "pkey", "-in", str(another_secret),
                    "-pubout", "-out", str(another_public)], check=True,
                   capture_output=True)
    monkeypatch.setattr(signatures, "_trusted_key", lambda key_id: another_public)
    with pytest.raises(Exception, match="signature"):
        checker.verify_candidate(candidate, "0.6.0")


def test_no_network_or_candidate_rehearsal_before_signature(candidate, monkeypatch):
    checker = _checker()
    paths = checker._filenames("0.6.0")
    (candidate / paths["signature"]).write_bytes(b"\x00" * 64)
    monkeypatch.setattr(online_generation, "rehearse_signed_install",
                        lambda *args, **kwargs: pytest.fail("Unsigned candidate executed"))
    assert checker.main(["--assets-dir", str(candidate), "--version", "0.6.0",
                         "--rehearse", "--ca-file", "/etc/ssl/certs/ca-certificates.crt"]) == 1


def test_verified_only_can_invoke_nonactivating_rehearsal(candidate, monkeypatch,
                                                         capsys):
    checker = _checker()
    calls = []
    monkeypatch.setattr(online_generation, "_current_host_target",
                        lambda: "debian13-py313")

    def rehearsal(archive, manifest, signature, version, inventory, assets, target,
                  *, cafile):
        calls.append((version, target, cafile))
        assert set(assets) == {"archive", "checksum", "dependency_lock", "sbom",
                               "application_wheel"}
        return {"activated": False, "status": "tested-only"}

    monkeypatch.setattr(online_generation, "rehearse_signed_install", rehearsal)
    assert checker.main(["--assets-dir", str(candidate), "--version", "0.6.0",
                         "--rehearse", "--ca-file", "/etc/ssl/certs/ca-certificates.crt"]) == 0
    assert calls == [("0.6.0", "debian13-py313",
                      Path("/etc/ssl/certs/ca-certificates.crt"))]
    output = json.loads(capsys.readouterr().out)
    assert output["rehearsal"]["activated"] is False


def test_abnormal_rehearsal_activation_is_never_reported_as_success(candidate, monkeypatch):
    checker = _checker()
    monkeypatch.setattr(online_generation, "_current_host_target",
                        lambda: "debian13-py313")
    monkeypatch.setattr(online_generation, "rehearse_signed_install",
                        lambda *args, **kwargs: {"activated": True})
    assert checker.main(["--assets-dir", str(candidate), "--version", "0.6.0",
                         "--rehearse", "--ca-file", "/etc/ssl/certs/ca-certificates.crt"]) == 1


def test_rehearsal_cli_requires_explicit_ca_bundle(candidate):
    checker = _checker()
    with pytest.raises(SystemExit):
        checker.main(["--assets-dir", str(candidate), "--version", "0.6.0", "--rehearse"])
