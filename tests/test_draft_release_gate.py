"""Fail-closed regression cases for #76 read-only signed draft gate.

These are synthetic metadata/transport tests ONLY. They do not demonstrate a
real owner-signed v0.5.0 candidate or a successful prepublication upgrade.
"""
from __future__ import annotations

import ast
import hashlib
import io
import json
import sys
import urllib.error
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import draft_release_gate as gate  # noqa: E402


TAG = "v0.5.0"
SHA = "a" * 40
BASE = "repocache-v0.5.0.tar.gz"


def assets():
    names = (BASE + suffix for suffix in gate.SUFFIXES)
    return {name: {"id": i + 1, "size": 70,
                   "sha256": hashlib.sha256(name.encode()).hexdigest()}
            for i, name in enumerate(names)}


def draft():
    return {
        "id": 42, "tag_name": TAG, "target_commitish": SHA,
        "draft": True, "prerelease": False, "immutable": False,
        "published_at": None,
        "assets": [
            {"name": name, "id": value["id"], "size": value["size"],
             "digest": "sha256:" + value["sha256"], "state": "uploaded"}
            for name, value in assets().items()
        ],
    }


def record():
    return {"schema": 1, "repository": gate.REPO, "tag": TAG,
            "commit": SHA, "release_id": 42,
            "build_run_id": 99, "build_run_attempt": 1,
            "assets": assets()}


@pytest.mark.parametrize("tag", ("v0.4.0", "v0.3.1", "v0.5.1", "v0.6.0", "v0.5.0-rc1",
                                 "../v0.5.0", "v0.5.0/x", "v00.5.0"))
def test_reject_non_candidate_tag(tag):
    with pytest.raises(gate.Refused):
        gate.normal(tag, SHA, 42, 99, 1)


def test_strict_json_duplicate_fields():
    with pytest.raises(gate.Refused, match="Duplicate"):
        gate.document(b'{"tag":"v0.5.0","tag":"v0.6.0"}')


@pytest.mark.parametrize("field,value", (
    ("draft", False), ("immutable", True), ("published_at", "2026-10-21"),
    ("tag_name", "v0.5.1"), ("target_commitish", "b" * 40),
))
def test_wrong_draft_identity(monkeypatch, field, value):
    payload = draft()
    payload[field] = value
    monkeypatch.setattr(gate, "api", lambda *_: payload)
    with pytest.raises(gate.Refused):
        gate.inventory(42, TAG, SHA, "dummy")


def test_missing_extra_duplicate_draft_assets(monkeypatch):
    data = draft()
    data["assets"][1]["name"] = BASE
    monkeypatch.setattr(gate, "api", lambda *_: data)
    with pytest.raises(gate.Refused):
        gate.inventory(42, TAG, SHA, "dummy")


def test_changed_digest_or_size_fails_remote_identity(monkeypatch):
    original = draft()
    monkeypatch.setattr(gate, "api", lambda *_: original)
    verified = gate.inventory(42, TAG, SHA, "dummy")
    original["assets"][0]["digest"] = "sha256:" + "f" * 64
    assert gate.inventory(42, TAG, SHA, "dummy") != verified


def test_local_rejects_missing_and_symlink_assets(tmp_path):
    with pytest.raises(gate.Refused, match="Extra or missing"):
        gate.read_and_hash(tmp_path, assets())
    folder = tmp_path / "folder"
    folder.mkdir()
    (folder / BASE).symlink_to(tmp_path)
    with pytest.raises(gate.Refused):
        gate.read_and_hash(folder, assets())


def test_recheck_catches_draft_asset_swap(monkeypatch):
    monkeypatch.setattr(gate, "identity", lambda *_: None)
    monkeypatch.setattr(gate, "inventory", lambda *_: {"different": {}})
    with pytest.raises(gate.Refused, match="modified"):
        gate.recheck(record(), "dummy")


@pytest.mark.parametrize("run_status,run_result", (
    ("in_progress", None), ("completed", "failure"), ("completed", "cancelled"),
))
def test_guard_refuses_unfinished_or_failed_acceptance(
    monkeypatch, run_status, run_result
):
    rec = record() | {
        "acceptance_run_id": 500, "acceptance_run_attempt": 1,
        "acceptance_commit": "b" * 40,
    }
    monkeypatch.setattr(gate, "identity", lambda *_: None)
    monkeypatch.setattr(gate, "inventory", lambda *_: rec["assets"])
    monkeypatch.setattr(gate, "api", lambda path, token: {
        "event": "workflow_dispatch", "head_branch": "main",
        "head_sha": "b" * 40, "run_attempt": 1, "actor": {"login": "teixemf"},
        "status": run_status, "conclusion": run_result,
        "name": "Signed release candidate acceptance",
    })
    with pytest.raises(gate.Refused, match="not approved"):
        gate.guard(rec, "dummy")


def test_guard_refuses_missing_or_skipped_jobs(monkeypatch):
    rec = record() | {
        "acceptance_run_id": 500, "acceptance_run_attempt": 1,
        "acceptance_commit": "b" * 40,
    }
    monkeypatch.setattr(gate, "identity", lambda *_: None)
    monkeypatch.setattr(gate, "inventory", lambda *_: rec["assets"])

    def fake(path, token):
        if "/jobs" in path:
            return {"total_count": 1, "jobs": [
                {"name": "Signed draft publisher and asset identity",
                 "status": "completed", "conclusion": "success"}]}
        return {"event": "workflow_dispatch", "head_branch": "main",
                "head_sha": "b" * 40, "run_attempt": 1,
                "actor": {"login": "teixemf"}, "status": "completed",
                "conclusion": "success",
                "name": "Signed release candidate acceptance"}

    monkeypatch.setattr(gate, "api", fake)
    with pytest.raises(gate.Refused, match="jobs"):
        gate.guard(rec, "dummy")


def test_evidence_artifact_digest_refuses_forged_zip(monkeypatch):
    data = {"total_count": 1, "artifacts": [{
        "id": 300, "name": "signed-candidate-acceptance", "expired": False,
        "workflow_run": {"id": 500}, "size_in_bytes": 440,
        "digest": "sha256:" + "0" * 64,
    }]}
    monkeypatch.setattr(gate, "api", lambda path, tok: data)
    monkeypatch.setattr(gate, "request", lambda *args, **kwargs: b"imposter")
    with pytest.raises(gate.Refused, match="SHA-256"):
        gate.authenticated_ci_evidence(500, "dummy")


def test_token_is_only_sent_on_initial_github_api_origin(monkeypatch):
    calls = []

    class Reply:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def read(self, amount):
            return b"safe"

    class MockHTTPError(urllib.error.HTTPError):
        pass

    def redirect(req, timeout):
        calls.append((req.full_url, dict(req.header_items())))
        if len(calls) == 1:
            raise MockHTTPError(req.full_url, 302, "Found",
                                {"Location": "https://release-assets.githubusercontent.com/test"},
                                None)
        return Reply()

    monkeypatch.setattr(gate.OPENER, "open", redirect)
    result = gate.request(gate.API + "/releases/assets/1",
                          token="LOCAL-TEST-TOKEN", binary=True, maximum=20)
    assert result == b"safe"
    assert "Authorization" in calls[0][1]
    assert "Authorization" not in calls[1][1]
    assert calls[1][0].startswith("https://release-assets.githubusercontent.com/")


def test_denies_bearer_redirect_to_arbitrary_hostname(monkeypatch):
    def reject(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 302, "Moved",
                                     {"Location": "https://bad.example.org/token"},
                                     None)
    monkeypatch.setattr(gate.OPENER, "open", reject)
    with pytest.raises(gate.Refused, match="Off-host"):
        gate.request(gate.API + "/releases/assets/1", token="secret",
                     binary=True, maximum=20)


def test_canonical_frozen_evidence_roundtrip(tmp_path):
    output = tmp_path / "proof.json"
    gate.freeze(record(), 500, 1, "b" * 40, output)
    result = gate.from_file(output)
    assert result["acceptance_run_id"] == 500
    assert result["acceptance_commit"] == "b" * 40
    assert output.read_bytes() == gate.canonical(result)
    with pytest.raises(gate.Refused, match="already exist"):
        gate.freeze(record(), 500, 1, "b" * 40, output)

def test_disposable_native_harness_syntax_compiles():
    script = Path(__file__).resolve().parents[1] / "scripts/ci_signed_candidate_native.py"
    ast.parse(script.read_text(encoding="utf-8"), filename=str(script))


def test_reviewed_v050_identity_is_accepted():
    gate.normal("v0.5.0", SHA, 42, 99, 1)
