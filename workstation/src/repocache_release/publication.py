"""Owner-authorized draft staging / exact candidate acceptance and publication.

Release-side verification is *delegated* to the reviewed #76 implementation
(scripts/draft_release_gate.py). Until that code is merged into protected main,
both write paths fail closed before contacting a mutating GitHub endpoint.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import ssl
import stat
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPOSITORY = "teixemf/repocache"
API = "https://api.github.com/repos/" + REPOSITORY
MAX_REPLY = 2_000_000


def refuse(c, code: str, message: str):
    raise c.OperatorError(code, message)


def token(c) -> str:
    result = c.command(["gh", "auth", "token"]).decode("ascii", "strict").strip()
    if not result or len(result) > 4096 or any(x.isspace() for x in result):
        refuse(c, "AUTHORIZATION_REQUIRED", "Authenticated GitHub owner token unavailable")
    current = c.command(["gh", "api", "user"])
    if len(current) > MAX_REPLY:
        refuse(c, "AUTHORIZATION_REQUIRED", "GitHub account response exceeded limit")
    try:
        user = json.loads(current)
    except (TypeError, ValueError):
        refuse(c, "AUTHORIZATION_REQUIRED", "GitHub account identity was not verified")
    if not isinstance(user, dict) or user.get("login") != "teixemf":
        refuse(c, "AUTHORIZATION_REQUIRED", "Only the repository owner may stage or publish")
    return result


def reviewed_gate(c):
    """Load ONLY exact, clean, protected-main source; never from unsigned archive."""
    root = c.root_path()
    try:
        local = c.command(["git", "-C", str(root), "rev-parse", "HEAD"]).decode().strip()
        main = c.gh_json(f"repos/{REPOSITORY}/branches/main")
        if local != main.get("commit", {}).get("sha"):
            refuse(c, "GATE_NOT_AVAILABLE", "Use the exact current protected main checkout")
        relative = "scripts/draft_release_gate.py"
        file = root / relative
        if not file.is_file() or file.is_symlink():
            refuse(c, "GATE_NOT_AVAILABLE", "Reviewed signed-candidate gate has not been merged")
        clean = c.command(["git", "-C", str(root), "status", "--porcelain",
                           "--untracked-files=all", "--", relative])
        published = c.command(["git", "-C", str(root), "show", "HEAD:" + relative])
        if clean or published != file.read_bytes():
            refuse(c, "GATE_NOT_AVAILABLE", "Signed-candidate gate differs from approved main")
        spec = importlib.util.spec_from_file_location("repocache_verified_draft_gate", file)
        if spec is None or spec.loader is None:
            refuse(c, "GATE_NOT_AVAILABLE", "Signed-candidate verifier cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for name in ("normal", "identity", "authenticate", "inventory",
                     "authenticated_ci_evidence", "guard"):
            if not callable(getattr(module, name, None)):
                refuse(c, "GATE_NOT_AVAILABLE", "Incomplete reviewed candidate acceptance engine")
        return module
    except c.OperatorError:
        raise
    except (OSError, ValueError, UnicodeError, ImportError) as exc:
        refuse(c, "GATE_NOT_AVAILABLE", "Cannot prove protected candidate gate identity")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def release_metadata(c, version: str, bearer: str) -> dict[str, Any] | None:
    """Never follow token-bearing redirects and only interpret 404 as absent."""
    c.check_tag(version)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(
        API + "/releases/tags/" + version,
        headers={"Authorization": "Bearer " + bearer,
                 "Accept": "application/vnd.github+json",
                 "User-Agent": "repocache-release-operator/1",
                 "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with opener.open(request, timeout=30) as response:
            raw = response.read(MAX_REPLY + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        refuse(c, "REMOTE_UNAVAILABLE", "GitHub release metadata could not be authenticated")
    except (OSError, TimeoutError, ValueError) as exc:
        refuse(c, "REMOTE_UNAVAILABLE", "GitHub release metadata unavailable")
    if len(raw) == 0 or len(raw) > MAX_REPLY:
        refuse(c, "INVALID_RESPONSE", "GitHub returned missing or oversized release data")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError):
        refuse(c, "INVALID_RESPONSE", "GitHub release metadata is not valid JSON")
    if not isinstance(data, dict):
        refuse(c, "INVALID_RESPONSE", "GitHub release metadata has an invalid type")
    return data


def exact_signed_assets(c, version: str, record: dict[str, Any], gate):
    gate.normal(version, record["commit"], 1, record["run_id"], record["attempt"])
    folder = c.candidate_dir(version) / "assets"
    if record["phase"] not in ("signed", "staged"):
        refuse(c, "CANDIDATE_NOT_SIGNED", "A verified owner signature is required")
    c.verify_state(version, record)
    c.verify_checkout(version, record)
    expected = c.files_for(version, signed=True)
    if len(expected) != 8 or set(record["assets"]) != set(expected):
        refuse(c, "ASSET_DRIFT", "Signed candidate inventory does not match reviewed profile")
    result = {}
    for i, name in enumerate(expected):
        path = folder / name
        if path.is_symlink() or not path.is_file():
            refuse(c, "UNSAFE_ASSET", "Signed candidate contains unsafe assets")
        result[name] = {
            "id": i + 1, "size": path.stat().st_size,
            "sha256": c.digest(path),
        }
    return folder, result


def local_proof(c, gate, version: str, record: dict[str, Any], bearer: str):
    folder, expected = exact_signed_assets(c, version, record, gate)
    with contextlib.redirect_stdout(io.StringIO()):
        gate.identity(version, record["commit"], record["run_id"], record["attempt"], bearer)
        gate.authenticate(version, record["commit"], record["run_id"],
                          record["attempt"], expected, folder, bearer)
    return folder, expected


def fingerprint(c, record: dict[str, Any]) -> str:
    payload = json.dumps({
        "version": record["version"],
        "commit": record["commit"],
        "run_id": record["run_id"],
        "attempt": record["attempt"],
        "assets": record["assets"]},
        sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def remote_exact(c, gate, version: str, record: dict, bearer: str):
    release = release_metadata(c, version, bearer)
    if not release:
        refuse(c, "DRAFT_NOT_FOUND", "No staged Draft Release exists for these signed assets")
    release_id = release.get("id")
    if type(release_id) is not int or release_id <= 0:
        refuse(c, "INVALID_RESPONSE", "Draft Release identity is invalid")
    with contextlib.redirect_stdout(io.StringIO()):
        result = gate.inventory(release_id, version, record["commit"], bearer)
    if set(result) != set(record["assets"]):
        refuse(c, "ASSET_DRIFT", "Draft asset list differs from the local signed candidate")
    for name, item in result.items():
        if item["sha256"] != record["assets"][name]:
            refuse(c, "ASSET_DRIFT", "Draft asset digest differs from the owner-signed candidate")
    if "release_id" in record and release_id != record["release_id"]:
        refuse(c, "ASSET_DRIFT", "Draft release ID changed")
    return release_id, result


def stage(c, version: str):
    """Separate, explicit action; only after #76 gate is on reviewed main."""
    c.check_tag(version)
    if os.geteuid() == 0:
        refuse(c, "UNSAFE_PRIVILEGE", "Release management may not run as root")
    record = c.read_state(version)
    if record is None:
        refuse(c, "CANDIDATE_NOT_PREPARED", "Prepare and sign this version first")
    gate = reviewed_gate(c)
    bearer = token(c)
    local_proof(c, gate, version, record, bearer)
    if record["phase"] == "staged":
        release_id, _ = remote_exact(c, gate, version, record, bearer)
        return {"version": version, "phase": "staged",
                "release_id": release_id, "changed": False,
                "acceptance": "NOT VERIFIED"}
    existing = release_metadata(c, version, bearer)
    if existing is not None:
        if existing.get("draft") is not True:
            refuse(c, "DRAFT_CONFLICT", "Release already published; replacement is forbidden")
        # Safe interrupted-create replay: accept an existing Draft only
        # after *full* remote ID/size/SHA and owner-signature revalidation.
        release_id, _ = remote_exact(c, gate, version, record, bearer)
        updated = dict(record, phase="staged", release_id=release_id)
        c.save_state(version, updated)
        return {"version": version, "phase": "staged", "release_id": release_id,
                "changed": False, "acceptance": "NOT VERIFIED"}
    folder = c.candidate_dir(version) / "assets"
    names = c.files_for(version, signed=True)
    arguments = ["gh", "release", "create", version,
                 *(str(folder / name) for name in names),
                 "--repo", REPOSITORY, "--draft", "--verify-tag",
                 "--target", record["commit"], "--title",
                 "REPOCACHE " + version + " (signed candidate)",
                 "--notes", "Owner-signed candidate awaiting required native acceptance."]
    # No automatic retry: an interrupted publish may have created a partial
    # draft remotely. Always inspect it before another explicit invocation.
    c.command(arguments, timeout=300)
    release_id, _ = remote_exact(c, gate, version, record, bearer)
    updated = dict(record, phase="staged", release_id=release_id)
    c.save_state(version, updated)
    return {"version": version, "phase": "staged", "release_id": release_id,
            "changed": True, "acceptance": "NOT VERIFIED"}


def signed_acceptance(c, gate, version: str, record: dict, ci_run: int, bearer: str):
    if type(ci_run) is not int or ci_run <= 0:
        refuse(c, "INVALID_ARGUMENT", "Specify an approved signed-candidate acceptance run ID")
    release_id, inventory = remote_exact(c, gate, version, record, bearer)
    with contextlib.redirect_stdout(io.StringIO()):
        proof = gate.authenticated_ci_evidence(ci_run, bearer)
        if (proof.get("tag") != version or proof.get("commit") != record["commit"]
                or proof.get("release_id") != release_id
                or proof.get("build_run_id") != record["run_id"]
                or proof.get("build_run_attempt") != record["attempt"]
                or proof.get("assets") != inventory):
            refuse(c, "ACCEPTANCE_MISMATCH", "Accepted candidate identity or assets differ")
        gate.guard(proof, bearer)
    return {"acceptance_run_id": ci_run, "release_id": release_id, "assets": inventory}


def publish(c, version: str, ci_run: int, approved_fingerprint: str):
    """Manual single release transition, with fresh remote acceptance proof."""
    c.check_tag(version)
    if os.geteuid() == 0:
        refuse(c, "UNSAFE_PRIVILEGE", "Release publication may not run as root")
    record = c.read_state(version)
    if record is None or record.get("phase") != "staged":
        refuse(c, "CANDIDATE_NOT_STAGED", "Only an accepted signed Draft may be published")
    if approved_fingerprint != fingerprint(c, record):
        refuse(c, "APPROVAL_REQUIRED", "Owner must approve the exact current candidate fingerprint")
    gate = reviewed_gate(c)
    bearer = token(c)
    local_proof(c, gate, version, record, bearer)
    proof = signed_acceptance(c, gate, version, record, ci_run, bearer)
    # The operator's separate invocation and exact fingerprint approval
    # are NOT substitutes for GitHub policy or all #76 acceptance criteria.
    c.command(["gh", "release", "edit", version, "--repo", REPOSITORY,
               "--draft=false"], timeout=120)
    remote = release_metadata(c, version, bearer)
    if (not remote or remote.get("id") != proof["release_id"]
            or remote.get("tag_name") != version
            or remote.get("draft") is not False or remote.get("immutable") is not True):
        refuse(c, "POST_PUBLISH_UNVERIFIED",
               "Publication may have occurred but immutable identity could not be proven")
    entries = remote.get("assets")
    if not isinstance(entries, list) or len(entries) != len(proof["assets"]):
        refuse(c, "POST_PUBLISH_UNVERIFIED", "Published asset inventory was not verified")
    observed = {}
    for item in entries:
        if not isinstance(item, dict) or item.get("name") in observed:
            refuse(c, "POST_PUBLISH_UNVERIFIED", "Invalid published asset identity")
        value = item.get("digest", "")
        if not isinstance(value, str) or not value.startswith("sha256:"):
            refuse(c, "POST_PUBLISH_UNVERIFIED", "Published asset lacks SHA-256 identity")
        observed[item["name"]] = {"id": item.get("id"),
                                  "size": item.get("size"),
                                  "sha256": value[7:]}
    if observed != proof["assets"]:
        refuse(c, "POST_PUBLISH_UNVERIFIED",
               "Published assets are different from the accepted signed candidate")
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            gate.identity(version, record["commit"], record["run_id"],
                          record["attempt"], bearer)
    except (ValueError, KeyError, TypeError) as exc:
        refuse(c, "POST_PUBLISH_UNVERIFIED",
               "Protected release tag or original successful build changed")
    result = dict(record, phase="published",
                  acceptance_run_id=ci_run,
                  release_id=proof["release_id"])
    c.save_state(version, result)
    return {"version": version, "phase": "published", "changed": True,
            "release_id": proof["release_id"], "immutable": True,
            "acceptance": "PASS"}


def acceptance_status(c, version: str, record: dict | None, ci_run: int | None):
    if record is None:
        return {"version": version, "phase": "absent",
                "acceptance": "NOT VERIFIED", "ready_to_publish": False}
    c.verify_state(version, record)
    c.verify_checkout(version, record)
    base = {"version": version, "phase": record["phase"],
            "commit": record["commit"], "run_id": record["run_id"],
            "assets": dict(record["assets"]),
            "candidate_sha256": fingerprint(c, record),
            "acceptance": "NOT VERIFIED", "ready_to_publish": False}
    if record["phase"] not in ("staged",) or ci_run is None:
        return base
    try:
        gate = reviewed_gate(c)
    except c.OperatorError as exc:
        if exc.code == "GATE_NOT_AVAILABLE":
            base["reason"] = "Reviewed signed-candidate verifier is not installed on protected main"
            return base
        raise
    bearer = token(c)
    try:
        local_proof(c, gate, version, record, bearer)
        signed_acceptance(c, gate, version, record, ci_run, bearer)
    except c.OperatorError as exc:
        if exc.code in ("DRAFT_NOT_FOUND", "REMOTE_UNAVAILABLE",
                        "AUTHORIZATION_REQUIRED", "GATE_NOT_AVAILABLE"):
            base["reason"] = "Required signed-candidate evidence could not be obtained"
            return base
        base["acceptance"] = "FAIL"
        base["reason"] = "Signed candidate or acceptance identity verification failed"
        return base
    except (ValueError, KeyError, TypeError):
        base["acceptance"] = "FAIL"
        base["reason"] = "Signed candidate or acceptance proof rejected by trusted verifier"
        return base
    base.update({"acceptance": "PASS", "ready_to_publish": True,
                 "acceptance_run_id": ci_run})
    return base
