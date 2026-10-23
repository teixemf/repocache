#!/usr/bin/env python3
"""Fail-closed read-only prepublication validation for genuine owner-signed drafts.

The trusted logic runs from a reviewed protected-main checkout, NOT the draft
archive. GITHUB_TOKEN is used only on the original GitHub API origin. Drafts
are mutable: this tool never promotes/publishes a draft.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

REPO = "teixemf/repocache"
API = "https://api.github.com/repos/" + REPO
ROOT = Path(__file__).resolve().parents[1]
KEY = ROOT / "keys/repocache-2026-10.pem"
FINGERPRINT = "7bbf4b840f762a610da648869564a5b77669f24191d0c5c7af04c14c043dc0fb"
PREVIOUS = "v0.4.0"
SUFFIXES = ("", ".sha256", ".wheelhouse.tar.gz", ".wheelhouse.tar.gz.sha256",
            ".manifest.json", ".manifest.json.sig",
            ".provenance.json", ".provenance.json.sig")
CDN = frozenset(("release-assets.githubusercontent.com",
                 "objects.githubusercontent.com",
                 "github-releases.githubusercontent.com", "github.com"))
HEX = re.compile(r"[a-f0-9]{64}")
COMMIT = re.compile(r"[a-f0-9]{40}")
TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
MAX_API = 2_000_000
MAX_ASSET = 110_000_000


class Refused(ValueError):
    """Fail-closed candidate acceptance failure."""


def require(condition: bool, why: str) -> None:
    if not condition:
        raise Refused(why)


def strict_pairs(pairs):
    result = {}
    for k, v in pairs:
        require(k not in result, "Duplicate JSON field")
        result[k] = v
    return result


def document(raw: bytes) -> dict:
    parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs)
    require(isinstance(parsed, dict), "JSON object required")
    return parsed


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normal(tag: str, commit: str, release_id: int, run_id: int, attempt: int):
    # This initial gate is intentionally reviewed for one upgrade baseline:
    # actual public v0.4.0 -> signed v0.5.0. Refuse later versions until a
    # reviewed PR changes BOTH this trust policy and the public baseline.
    require(tag == "v0.5.0",
            "Unreviewed candidate: prior public release baseline must be updated")
    require(COMMIT.fullmatch(commit) is not None
            and type(release_id) is int and release_id > 0
            and type(run_id) is int and run_id > 0
            and type(attempt) is int and attempt > 0, "Invalid release identity")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), NoRedirect(),
    urllib.request.HTTPSHandler(context=ssl.create_default_context()))


def request(url: str, *, token: str, binary: bool = False, maximum: int = MAX_API) -> bytes:
    # GitHub API URLs are created internally; redirect targets are explicitly
    # checked and never receive the bearer token, cookies or forwarded headers.
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname == "api.github.com"
            and parsed.port in (None, 443) and not parsed.username
            and not parsed.password and not parsed.fragment, "Untrusted API origin")
    require(bool(token) and "\n" not in token, "Read-only GitHub token required")
    current = url
    for redirect in range(5):
        urlparts = urllib.parse.urlsplit(current)
        host = urlparts.hostname or ""
        api_origin = redirect == 0 and host == "api.github.com"
        if not api_origin:
            require(urlparts.scheme == "https" and
                    (host in CDN or host.endswith(".blob.core.windows.net"))
                    and urlparts.port in (None, 443)
                    and not urlparts.username and not urlparts.password
                    and not urlparts.fragment, "Off-host or insecure asset redirect")
        headers = {
            "User-Agent": "repocache-draft-gate/1",
            "Accept": "application/octet-stream" if binary else "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if api_origin:
            # Bearer credentials are NEVER sent to a CDN URL or passed on redirect.
            headers["Authorization"] = "Bearer " + token
        try:
            with OPENER.open(urllib.request.Request(current, headers=headers),
                             timeout=40) as response:
                data = response.read(maximum + 1)
                require(0 < len(data) <= maximum, "Missing/oversized GitHub response")
                return data
        except urllib.error.HTTPError as error:
            if error.code not in (301, 302, 303, 307, 308):
                raise Refused("GitHub API or asset request failed (HTTP " +
                              str(error.code) + ")") from error
            location = error.headers.get("Location", "")
            require(bool(location), "Missing asset redirect target")
            require(binary, "API metadata redirects not expected")
            current = urllib.parse.urljoin(current, location)
    raise Refused("Too many asset redirects")


def api(path: str, token: str) -> dict:
    return document(request(API + path, token=token))


def file_at_commit(path: str, commit: str, token: str) -> bytes:
    obj = api("/contents/" + path + "?ref=" + commit, token)
    require(obj.get("type") == "file" and obj.get("encoding") == "base64"
            and isinstance(obj.get("content"), str), "Unavailable reviewed Git blob")
    return base64.b64decode(obj["content"], validate=False)


def identity(tag: str, commit: str, run_id: int, attempt: int, token: str) -> None:
    ref = api("/git/ref/tags/" + tag, token)
    require(ref.get("ref") == "refs/tags/" + tag
            and ref.get("object", {}).get("sha") == commit
            and ref.get("object", {}).get("type") == "commit",
            "Candidate tag does not match reviewed commit")
    cmp = api("/compare/" + commit + "...main", token)
    require(cmp.get("status") in ("ahead", "identical")
            and cmp.get("base_commit", {}).get("sha") == commit,
            "Candidate commit is not on protected main ancestry")
    run = api("/actions/runs/" + str(run_id), token)
    require(run.get("path") == ".github/workflows/release.yml"
            and run.get("head_sha") == commit and run.get("head_branch") == tag
            and run.get("run_attempt") == attempt
            and run.get("actor", {}).get("login") == "teixemf"
            and run.get("event") == "workflow_dispatch"
            and run.get("status") == "completed"
            and run.get("conclusion") == "success",
            "Owner-approved unsigned build run not verified")
    jobs = api("/actions/runs/" + str(run_id) + "/jobs?per_page=100", token)
    values = jobs.get("jobs", [])
    require(isinstance(values, list) and len(values) >= 5
            and jobs.get("total_count") == len(values)
            and all(j.get("status") == "completed" and
                    j.get("conclusion") == "success" for j in values),
            "Incomplete, failed or skipped source release build")


def inventory(release_id: int, tag: str, commit: str, token: str) -> dict:
    r = api("/releases/" + str(release_id), token)
    require(r.get("id") == release_id and r.get("tag_name") == tag
            and r.get("draft") is True and r.get("published_at") is None
            and r.get("immutable") is False
            and r.get("prerelease") is False,
            "Release is not the exact unpublished candidate draft")
    require(r.get("target_commitish") in (commit, tag, "main"),
            "Draft release target changed")
    names = {"repocache-" + tag + ".tar.gz" + suffix for suffix in SUFFIXES}
    assets = r.get("assets")
    require(isinstance(assets, list) and len(assets) == 8
            and {x.get("name") for x in assets if isinstance(x, dict)} == names,
            "Draft does not contain exactly eight expected final assets")
    out = {}
    for a in assets:
        name = a["name"]
        digest = a.get("digest", "")
        require(a.get("state") == "uploaded" and type(a.get("id")) is int
                and type(a.get("size")) is int and 0 < a["size"] <= MAX_ASSET
                and digest.startswith("sha256:") and HEX.fullmatch(digest[7:]),
                "Draft asset does not have verified GitHub SHA-256 identity")
        out[name] = {"id": a["id"], "size": a["size"], "sha256": digest[7:]}
    require(len({x["id"] for x in out.values()}) == 8,
            "Duplicate draft asset IDs")
    return out


def read_and_hash(folder: Path, expected: dict) -> None:
    require(folder.is_dir() and not folder.is_symlink(),
            "Missing candidate asset directory")
    require({p.name for p in folder.iterdir()} == set(expected),
            "Extra or missing local candidate asset")
    for name, item in expected.items():
        path = folder / name
        require(path.is_file() and not path.is_symlink()
                and path.stat().st_size == item["size"]
                and sha(path.read_bytes()) == item["sha256"],
                "Draft asset bytes/hash mismatch: " + name)


def signature(doc: Path, detached: Path) -> None:
    require(KEY.is_file() and not KEY.is_symlink(), "No approved public key")
    actual = subprocess.run(["/usr/bin/openssl", "pkey", "-pubin", "-in",
                             str(KEY), "-outform", "DER"], check=True,
                            capture_output=True, timeout=15).stdout
    require(sha(actual) == FINGERPRINT, "Publisher trust anchor changed")
    require(detached.stat().st_size == 64, "Bad detached signature length")
    result = subprocess.run(["/usr/bin/openssl", "pkeyutl", "-verify", "-pubin",
                             "-inkey", str(KEY), "-rawin", "-in", str(doc),
                             "-sigfile", str(detached)], capture_output=True,
                            timeout=15, check=False)
    require(result.returncode == 0, "Owner Ed25519 signature invalid")


def canonical(doc: dict) -> bytes:
    return (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode()


def authenticate(tag: str, commit: str, run_id: int, attempt: int,
                 assets: dict, folder: Path, token: str | None = None) -> dict:
    """Authenticate all eight FINAL candidate bytes before any extraction."""
    read_and_hash(folder, assets)
    base = "repocache-" + tag + ".tar.gz"
    archive = folder / base
    manifest_file = folder / (base + ".manifest.json")
    provenance_file = folder / (base + ".provenance.json")
    signature(manifest_file, folder / (base + ".manifest.json.sig"))
    signature(provenance_file, folder / (base + ".provenance.json.sig"))
    manifest = document(manifest_file.read_bytes())
    require(canonical(manifest) == manifest_file.read_bytes()
            and set(manifest) == {"schema", "key_id", "repository", "channel",
                                  "version", "commit", "archive", "archive_sha256",
                                  "policy_sha256", "wheelhouse_sha256",
                                  "issued_at", "expires_at"},
            "Malformed signed publisher manifest")
    require(manifest["schema"] == 1 and manifest["key_id"] == "repocache-2026-10"
            and manifest["repository"] == REPO
            and manifest["channel"] == "stable"
            and manifest["version"] == tag[1:] and manifest["commit"] == commit
            and manifest["archive"] == base
            and manifest["archive_sha256"] == assets[base]["sha256"]
            and manifest["wheelhouse_sha256"] ==
            assets[base + ".wheelhouse.tar.gz"]["sha256"]
            and type(manifest["issued_at"]) is int
            and type(manifest["expires_at"]) is int
            and manifest["issued_at"] <= int(time.time()) < manifest["expires_at"],
            "Publisher manifest bound to unexpected source or expired")
    require((folder / (base + ".sha256")).read_bytes() ==
            (assets[base]["sha256"] + "  " + base + "\n").encode()
            and (folder / (base + ".wheelhouse.tar.gz.sha256")).read_text() ==
            assets[base + ".wheelhouse.tar.gz"]["sha256"],
            "Source or wheelhouse checksum file mismatch")
    prov = document(provenance_file.read_bytes())
    require(canonical(prov) == provenance_file.read_bytes()
            and set(prov) == {"schema", "repository", "tag", "commit",
                              "publisher_key_id", "build", "dependency_locks",
                              "artifacts"},
            "Malformed signed provenance")
    build = prov.get("build", {})
    require(prov["schema"] == 1 and prov["repository"] == REPO
            and prov["tag"] == tag and prov["commit"] == commit
            and prov["publisher_key_id"] == manifest["key_id"]
            and build.get("run_id") == run_id
            and build.get("run_attempt") == attempt
            and build.get("workflow_ref") ==
            REPO + "/.github/workflows/release.yml@refs/tags/" + tag,
            "Release provenance is not bound to approved review and owner run")
    art_names = (base, base + ".sha256", base + ".manifest.json",
                 base + ".manifest.json.sig", base + ".wheelhouse.tar.gz",
                 base + ".wheelhouse.tar.gz.sha256")
    require(prov["artifacts"] == {name: assets[name]["sha256"] for name in art_names},
            "Signed provenance artifact inventory mismatch")
    # Source code is not executed here. Source policy is inspected ONLY AFTER
    # the real owner's source-archive SHA and detached signatures verified.
    with tarfile.open(archive, "r:gz") as tar:
        prefix = "repocache-" + tag + "/"
        names = ("release-policy.json", "pyproject.toml",
                 "src/repocache/__init__.py")
        data = {}
        for name in names:
            item = tar.getmember(prefix + name)
            require(item.isfile() and 0 <= item.size <= 65536
                    and item.mode & 0o7000 == 0, "Unsafe authenticated policy item")
            f = tar.extractfile(item)
            require(f is not None, "Unreadable signed policy")
            data[name] = f.read(item.size + 1)
    require(sha(data["release-policy.json"]) == manifest["policy_sha256"],
            "Archive release policy hash mismatch")
    policy = document(data["release-policy.json"])
    require(policy.get("schema") == 1 and policy.get("version") == tag[1:]
            and {"id": "debian", "major": "13"} in policy.get("targets", [])
            and {"id": "almalinux", "major": "10"} in policy.get("targets", [])
            and isinstance(policy.get("compatible_from"), list)
            and "0.4.0" in policy["compatible_from"],
            "Signed candidate does not permit prior real public v0.4.0 upgrade")
    import tomllib
    require(tomllib.loads(data["pyproject.toml"].decode())["project"]["version"] == tag[1:]
            and ('__version__ = "' + tag[1:] + '"').encode()
            in data["src/repocache/__init__.py"],
            "Signed application and candidate version disagree")
    if token is not None:
        expected = {
            name: sha(file_at_commit(name, commit, token))
            for name in ("deps/runtime-wheels.lock", "deps/build-wheels.lock")
        }
        require(prov["dependency_locks"] == expected
                and build.get("workflow_sha256") ==
                sha(file_at_commit(".github/workflows/release.yml", commit, token)),
                "Signed source workflow or dependency locks differ from Git tag")
    print("PASS: genuine owner-signed draft, compatibility, provenance and all 8 asset hashes")
    return {"schema": 1, "repository": REPO, "tag": tag, "commit": commit,
            "build_run_id": run_id, "build_run_attempt": attempt, "assets": assets}


def fetch(release_id: int, tag: str, commit: str, run_id: int, attempt: int,
          folder: Path, token: str) -> dict:
    normal(tag, commit, release_id, run_id, attempt)
    identity(tag, commit, run_id, attempt, token)
    expected = inventory(release_id, tag, commit, token)
    require(not folder.exists(), "Candidate destination must not preexist")
    folder.mkdir(parents=True, mode=0o700)
    for name, item in sorted(expected.items()):
        raw = request(API + "/releases/assets/" + str(item["id"]),
                      token=token, binary=True, maximum=item["size"])
        require(len(raw) == item["size"] and sha(raw) == item["sha256"],
                "Draft downloaded bytes disagree with GitHub SHA-256")
        (folder / name).write_bytes(raw)
    record = authenticate(tag, commit, run_id, attempt, expected, folder, token)
    record["release_id"] = release_id
    return record


def recheck(report: dict, token: str) -> None:
    normal(report["tag"], report["commit"], report["release_id"],
           report["build_run_id"], report["build_run_attempt"])
    identity(report["tag"], report["commit"],
             report["build_run_id"], report["build_run_attempt"], token)
    require(inventory(report["release_id"], report["tag"],
                      report["commit"], token) == report["assets"],
            "Draft modified after original authenticated signed handoff")
    print("PASS: candidate draft inventory unchanged after native acceptance")


def authenticated_ci_evidence(run_id: int, token: str) -> dict:
    require(type(run_id) is int and run_id > 0, "Invalid accepted CI run")
    artifacts = api("/actions/runs/" + str(run_id) + "/artifacts?per_page=100", token)
    matches = [item for item in artifacts.get("artifacts", [])
               if item.get("name") == "signed-candidate-acceptance"]
    require(len(matches) == 1 and
            artifacts.get("total_count", 0) <= 30
            and not matches[0].get("expired") and
            matches[0].get("workflow_run", {}).get("id") == run_id,
            "Missing, ambiguous or expired immutable acceptance artifact")
    identity = matches[0]
    require(type(identity.get("id")) is int
            and identity.get("size_in_bytes", 0) <= 100_000
            and identity.get("digest", "").startswith("sha256:")
            and HEX.fullmatch(identity["digest"][7:]),
            "Acceptance proof artifact has no immutable GitHub digest")
    raw = request(API + "/actions/artifacts/" + str(identity["id"]) + "/zip",
                  token=token, binary=True, maximum=100_000)
    require(sha(raw) == identity["digest"][7:],
            "Downloaded CI acceptance artifact differs from stored SHA-256")
    with zipfile.ZipFile(io.BytesIO(raw)) as packaged:
        files = packaged.infolist()
        require(len(files) == 1 and
                files[0].filename == "publisher-candidate-acceptance.json" and
                0 < files[0].file_size < 20000,
                "Malformed acceptance artifact ZIP")
        return document(packaged.read(files[0]))


def from_file(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink()
            and 0 < path.stat().st_size < 20000, "Invalid evidence file")
    return document(path.read_bytes())


def freeze(record: dict, run_id: int, attempt: int, ci_commit: str, out: Path) -> None:
    require(COMMIT.fullmatch(ci_commit) is not None and run_id > 0 and attempt > 0,
            "Invalid gate execution identity")
    require(not out.exists(), "Evidence file must not already exist")
    result = dict(record, acceptance_run_id=run_id, acceptance_run_attempt=attempt,
                  acceptance_commit=ci_commit)
    out.write_bytes(canonical(result))
    print("PASS: frozen signed candidate asset inventory written")


def guard(report: dict, token: str) -> None:
    tag, commit = report.get("tag"), report.get("commit")
    release_id, run_id, attempt = (report.get("release_id"),
                                   report.get("build_run_id"),
                                   report.get("build_run_attempt"))
    normal(tag, commit, release_id, run_id, attempt)
    identity(tag, commit, run_id, attempt, token)
    require(inventory(release_id, tag, commit, token) == report.get("assets"),
            "Mutable draft changed after candidate acceptance")
    id_ci, try_no = report.get("acceptance_run_id"), report.get("acceptance_run_attempt")
    require(type(id_ci) is int and id_ci > 0 and type(try_no) is int and try_no > 0
            and COMMIT.fullmatch(report.get("acceptance_commit", "")),
            "Missing signed-candidate CI evidence")
    ci = api("/actions/runs/" + str(id_ci), token)
    require(ci.get("path") == ".github/workflows/signed-candidate-acceptance.yml"
            and ci.get("event") == "workflow_dispatch" and
            ci.get("head_branch") == "main" and
            ci.get("head_sha") == report["acceptance_commit"]
            and ci.get("run_attempt") == try_no
            and ci.get("actor", {}).get("login") == "teixemf"
            and ci.get("status") == "completed" and
            ci.get("conclusion") == "success" and
            ci.get("name") == "Signed release candidate acceptance",
            "Candidate acceptance workflow not approved and successful")
    jobs = api("/actions/runs/" + str(id_ci) + "/jobs?per_page=100", token)
    seen = {j["name"]: j for j in jobs.get("jobs", [])}
    required = ("Signed draft publisher and asset identity",
                "Upgrade signed candidate (debian13)",
                "Upgrade signed candidate (almalinux10)",
                "Freeze final candidate acceptance evidence")
    require(len(seen) == jobs.get("total_count") == len(required) and
            all(seen.get(name, {}).get("status") == "completed"
                and seen[name].get("conclusion") == "success" for name in required),
            "Missing/failed/skipped required signed-candidate gate jobs")
    print("PASS: candidate immutable-byte fingerprint and 4/4 successful acceptance jobs")
    print("PASS: operator may request SEPARATE public publication approval; no publish performed")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=("fetch", "verify-local", "recheck", "freeze", "guard"))
    p.add_argument("--release-id", type=int)
    p.add_argument("--tag")
    p.add_argument("--commit")
    p.add_argument("--run-id", type=int)
    p.add_argument("--run-attempt", type=int, default=1)
    p.add_argument("--dest", type=Path)
    p.add_argument("--inventory", type=Path)
    p.add_argument("--evidence", type=Path)
    p.add_argument("--ci-run-id", type=int)
    p.add_argument("--ci-attempt", type=int, default=1)
    p.add_argument("--ci-commit")
    args = p.parse_args()
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    if args.mode == "guard":
        guard(authenticated_ci_evidence(args.ci_run_id, token), token)
        return
    if args.mode == "recheck":
        require(args.inventory is not None, "Missing reviewed candidate inventory")
        recheck(from_file(args.inventory), token)
        return
    if args.mode == "freeze":
        require(args.inventory is not None and args.evidence is not None,
                "Missing prevalidated inventory or evidence destination")
        freeze(from_file(args.inventory), args.ci_run_id, args.ci_attempt,
               args.ci_commit, args.evidence)
        return
    require(args.dest is not None and args.tag is not None
            and args.commit is not None and args.release_id is not None
            and args.run_id is not None, "Missing required candidate identity")
    normal(args.tag, args.commit, args.release_id, args.run_id, args.run_attempt)
    if args.mode == "fetch":
        record = fetch(args.release_id, args.tag, args.commit, args.run_id,
                       args.run_attempt, args.dest, token)
        require(args.inventory is not None, "Missing output inventory path")
        require(not args.inventory.exists(), "Inventory output already exists")
        args.inventory.write_bytes(canonical(record))
    else:
        require(args.inventory is not None, "Missing reviewed draft inventory")
        record = from_file(args.inventory)
        require(record.get("release_id") == args.release_id
                and record.get("tag") == args.tag
                and record.get("commit") == args.commit
                and record.get("build_run_id") == args.run_id
                and record.get("build_run_attempt") == args.run_attempt,
                "Candidate inputs differ from authenticated draft inventory")
        authenticate(args.tag, args.commit, args.run_id, args.run_attempt,
                     record["assets"], args.dest)
    print("PASS: draft release candidate " + args.mode + " for " + args.tag)


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError, KeyError, TypeError, ValueError,
            subprocess.CalledProcessError, tarfile.TarError) as exc:
        print("FAIL: draft candidate acceptance: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
