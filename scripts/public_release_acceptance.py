#!/usr/bin/env python3
"""Verify an actual immutable PUBLIC GitHub Release before executing any asset.

No API tokens, source-tree fallbacks, disposable keys, or release-side trust anchors.
Use a separately code-reviewed pinned fingerprint/asset inventory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

REPO = "teixemf/repocache"
API = "https://api.github.com/repos/" + REPO
DOWNLOAD = "https://github.com/" + REPO + "/releases/download/"
ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "scripts/public_release_targets.json"
ALLOWED_HOSTS = frozenset((
    "api.github.com", "github.com", "release-assets.githubusercontent.com",
    "objects.githubusercontent.com", "github-releases.githubusercontent.com",
))
MAX_METADATA = 2_000_000


class AcceptanceError(ValueError):
    """The public release or trust proof does not match the reviewed target."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceError(message)


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def decode(raw: bytes) -> dict:
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs)
    require(isinstance(value, dict), "Non-object JSON document")
    return value


class StrictRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        require(parsed.scheme == "https" and parsed.hostname in ALLOWED_HOSTS
                and parsed.port in (None, 443) and not parsed.username
                and not parsed.password and not parsed.fragment,
                "Off-origin or insecure redirect refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url: str, limit: int) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname in ALLOWED_HOSTS
            and parsed.port in (None, 443) and not parsed.username
            and not parsed.password and not parsed.fragment,
            "Unexpected release URL")
    # Disable environment-provided proxies and the implicit cookie/auth handlers.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), StrictRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "repocache-public-acceptance/1",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with opener.open(request, timeout=30) as response:
        raw = response.read(limit + 1)
    require(0 < len(raw) <= limit, "Missing or oversized remote response")
    return raw


def target(tag: str) -> dict:
    require(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag) is not None,
            "Invalid release tag")
    reviewed = decode(TARGETS.read_bytes())
    require(reviewed.get("schema") == 1
            and tag in reviewed.get("releases", {}), "Unknown, unreviewed release target")
    data = reviewed["releases"][tag]
    require(isinstance(data, dict) and len(data["assets"]) == 8,
            "Invalid reviewed asset inventory")
    require(all(re.fullmatch(r"[a-f0-9]{64}", item["sha256"])
                for item in data["assets"].values()), "Invalid pinned SHA-256")
    return data


def assert_public_release(tag: str, pinned: dict) -> None:
    release = decode(download(API + "/releases/tags/" + tag, MAX_METADATA))
    require(release.get("id") == pinned["release_id"]
            and release.get("tag_name") == tag
            and release.get("draft") is False
            and release.get("prerelease") is False
            and release.get("immutable") is True
            and isinstance(release.get("published_at"), str)
            and release.get("html_url") == "https://github.com/" + REPO + "/releases/tag/" + tag,
            "Wrong, draft, mutable or unapproved public release")
    assets = release.get("assets")
    require(isinstance(assets, list) and
            {a.get("name") for a in assets if isinstance(a, dict)}
            == set(pinned["assets"]) and len(assets) == 8,
            "Unexpected published asset set")
    for asset in assets:
        item = pinned["assets"][asset["name"]]
        require(asset.get("id") == item["id"]
                and asset.get("size") == item["size"]
                and asset.get("digest") == "sha256:" + item["sha256"]
                and asset.get("state") == "uploaded"
                and asset.get("browser_download_url") ==
                DOWNLOAD + tag + "/" + asset["name"],
                "Published asset identity mismatch: " + asset["name"])
    reference = decode(download(API + "/git/ref/tags/" + tag, MAX_METADATA))
    require(reference.get("ref") == "refs/tags/" + tag
            and reference.get("object", {}).get("sha") == pinned["commit"]
            and reference.get("object", {}).get("type") == "commit",
            "Version tag moved away from reviewed source")
    # The signing run itself is read-only, public and directly bound to owner identity.
    run = decode(download(API + "/actions/runs/" + str(pinned["run_id"]), MAX_METADATA))
    require(run.get("head_sha") == pinned["commit"] and
            run.get("head_branch") == tag and run.get("run_attempt") == pinned["run_attempt"]
            and run.get("actor", {}).get("login") == "teixemf"
            and run.get("event") == "workflow_dispatch"
            and run.get("status") == "completed"
            and run.get("conclusion") == "success",
            "Unsigned build run does not match reviewed publisher provenance")
    print("PASS: anonymous immutable published release, tag, 8 assets and build-run identity")


def fingerprint(public: Path, pinned: dict) -> None:
    require(public.is_file() and not public.is_symlink(), "Publisher trust anchor absent")
    der = subprocess.run(["/usr/bin/openssl", "pkey", "-pubin", "-in", str(public),
                          "-outform", "DER"], capture_output=True, check=True).stdout
    require(sha(der) == pinned["publisher_der_sha256"],
            "Publisher public key fingerprint mismatch")


def verify_signature(public: Path, document: Path, signature: Path) -> None:
    require(signature.stat().st_size == 64, "Invalid detached Ed25519 signature length")
    subprocess.run(["/usr/bin/openssl", "pkeyutl", "-verify", "-pubin", "-inkey",
                    str(public), "-rawin", "-in", str(document),
                    "-sigfile", str(signature)],
                   capture_output=True, check=True, timeout=20)


def verify_files(tag: str, pinned: dict, folder: Path) -> None:
    for name, item in pinned["assets"].items():
        path = folder / name
        require(path.is_file() and not path.is_symlink()
                and path.stat().st_size == item["size"] and
                sha(path.read_bytes()) == item["sha256"],
                "Local published asset mismatch: " + name)
    public = ROOT / "keys/repocache-2026-10.pem"
    fingerprint(public, pinned)
    archive = "repocache-" + tag + ".tar.gz"
    manifest_file = folder / (archive + ".manifest.json")
    proof_file = folder / (archive + ".provenance.json")
    verify_signature(public, manifest_file,
                     folder / (archive + ".manifest.json.sig"))
    verify_signature(public, proof_file,
                     folder / (archive + ".provenance.json.sig"))
    manifest = decode(manifest_file.read_bytes())
    require(manifest.get("repository") == REPO
            and manifest.get("version") == tag[1:]
            and manifest.get("channel") == "stable"
            and manifest.get("key_id") == pinned["publisher_key_id"]
            and manifest.get("commit") == pinned["commit"]
            and manifest.get("archive") == archive
            and manifest.get("archive_sha256") == pinned["assets"][archive]["sha256"]
            and manifest.get("wheelhouse_sha256") ==
            pinned["assets"][archive + ".wheelhouse.tar.gz"]["sha256"],
            "Signed manifest identity mismatch")
    now = int(time.time())
    require(type(manifest.get("issued_at")) is int
            and type(manifest.get("expires_at")) is int
            and manifest["issued_at"] <= now < manifest["expires_at"],
            "Publisher signature validity interval expired or not started")
    checksum = (pinned["assets"][archive]["sha256"] + "  " + archive + "\n").encode()
    require((folder / (archive + ".sha256")).read_bytes() == checksum,
            "Source checksum record does not match archive")
    require((folder / (archive + ".wheelhouse.tar.gz.sha256")).read_text() ==
            pinned["assets"][archive + ".wheelhouse.tar.gz"]["sha256"],
            "Wheelhouse checksum record mismatch")
    proof = decode(proof_file.read_bytes())
    require(proof.get("repository") == REPO and proof.get("tag") == tag
            and proof.get("commit") == pinned["commit"]
            and proof.get("publisher_key_id") == pinned["publisher_key_id"]
            and proof.get("build", {}).get("run_id") == pinned["run_id"]
            and proof.get("build", {}).get("run_attempt") == pinned["run_attempt"]
            and proof.get("build", {}).get("workflow_ref") ==
            REPO + "/.github/workflows/release.yml@refs/tags/" + tag,
            "Signed provenance/source/run identity mismatch")
    expected = {name: pinned["assets"][name]["sha256"] for name in
                (archive, archive + ".sha256", archive + ".manifest.json",
                 archive + ".manifest.json.sig",
                 archive + ".wheelhouse.tar.gz",
                 archive + ".wheelhouse.tar.gz.sha256")}
    require(proof.get("artifacts") == expected,
            "Signed provenance asset inventory mismatch")
    print("PASS: 8 pinned hashes, publisher Ed25519 manifest and provenance")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=("fetch", "verify"))
    p.add_argument("--tag", default="v0.4.0")
    p.add_argument("--dest", required=True, type=Path)
    args = p.parse_args()
    reviewed = target(args.tag)
    if args.mode == "fetch":
        assert_public_release(args.tag, reviewed)
        args.dest.mkdir(parents=True, exist_ok=True)
        for name, item in sorted(reviewed["assets"].items()):
            require(not (args.dest / name).exists(), "Destination must be fresh")
            data = download(DOWNLOAD + args.tag + "/" + name, item["size"])
            require(len(data) == item["size"] and sha(data) == item["sha256"],
                    "Anonymous CDN download failed asset identity verification: " + name)
            (args.dest / name).write_bytes(data)
    verify_files(args.tag, reviewed, args.dest)
    print("PASS: actual owner-signed public " + args.tag + " release (" + args.mode + ")")


if __name__ == "__main__":
    try:
        main()
    except (AcceptanceError, OSError, ValueError, KeyError, TypeError,
            subprocess.CalledProcessError) as error:
        print("FAIL: public release acceptance: " + str(error), file=sys.stderr)
        raise SystemExit(1)
