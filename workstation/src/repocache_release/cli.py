"""Noninteractive maintainer release operator — CLI architecture v1 / #88.

Only read-only inspection, verified candidate preparation and explicit local
offline signing are currently exposed. Stage/publish are intentionally not
registered until authentic #76 signed-candidate acceptance is integrated.
Never imports or executes downloaded unsigned candidate content.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import zipfile
import os
import re
import shutil
import stat
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO = "teixemf/repocache"
OWNER = "teixemf"
TAG = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
HEX40 = re.compile(r"^[a-f0-9]{40}$")
EXPECTED_FINGERPRINT = "7bbf4b840f762a610da648869564a5b77669f24191d0c5c7af04c14c043dc0fb"
UNSIGNED_SUFFIXES = ("", ".sha256", ".wheelhouse.tar.gz", ".wheelhouse.tar.gz.sha256")
SIGNED_SUFFIXES = (".manifest.json", ".manifest.json.sig",
                   ".provenance.json", ".provenance.json.sig")
MAX_METADATA = 4_000_000
MAX_ASSET = 2_000_000_000
MAX_DOWNLOAD = 1_000_000_000


class OperatorError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class SyntaxErrorFromParser(Exception):
    pass


class SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise SyntaxErrorFromParser(message)


def command(argv: list[str], *, cwd: Path | None = None, timeout: int = 60) -> bytes:
    """Trusted binary/arguments only; never disclose gh stderr or credentials."""
    if not argv or argv[0] not in ("git", "gh", "/usr/bin/openssl"):
        raise OperatorError("INVALID_COMMAND", "Unapproved external executable")
    try:
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0",
                   GH_PROMPT_DISABLED="1", GCM_INTERACTIVE="Never")
        result = subprocess.run(argv, cwd=cwd, capture_output=True,
                                stdin=subprocess.DEVNULL, env=env,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OperatorError("TOOL_UNAVAILABLE", "Required local tool unavailable") from exc
    if result.returncode:
        raise OperatorError("OPERATION_FAILED", "Git, GitHub or OpenSSL validation failed")
    if len(result.stdout) > MAX_METADATA:
        raise OperatorError("OVERSIZED_RESPONSE", "Tool output exceeded supported size")
    return result.stdout


def gh_json(endpoint: str) -> dict[str, Any]:
    if not endpoint.startswith("repos/" + REPO + "/") or any(
            item in endpoint for item in ("\n", "\r", "\\", "..")):
        raise OperatorError("INVALID_ENDPOINT", "Unapproved GitHub API endpoint")
    raw = command(["gh", "api", endpoint])
    if len(raw) > MAX_METADATA:
        raise OperatorError("OVERSIZED_RESPONSE", "GitHub API response is too large")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise OperatorError("INVALID_RESPONSE", "GitHub API response is invalid") from exc
    if not isinstance(data, dict):
        raise OperatorError("INVALID_RESPONSE", "GitHub API returned a nonobject")
    return data


def digest(path: Path) -> str:
    """Hash the validated asset inode, not a path that can change before open."""
    try:
        # A symlink/FIFO substituted after a path precheck must not be followed
        # or allowed to block an offline release operation.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                     | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise OperatorError("UNSAFE_ASSET", "Asset cannot be opened safely") from exc
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ASSET
                or info.st_nlink != 1):
            raise OperatorError("UNSAFE_ASSET", "Asset inode is unsafe or oversized")
        h = hashlib.sha256()
        remaining = MAX_ASSET
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while True:
                chunk = stream.read(min(131072, remaining + 1))
                if not chunk:
                    break
                remaining -= len(chunk)
                if remaining < 0:
                    raise OperatorError("UNSAFE_ASSET", "Asset exceeded the size limit")
                h.update(chunk)
        return h.hexdigest()
    except OSError as exc:
        raise OperatorError("UNSAFE_ASSET", "Asset could not be read") from exc
    finally:
        os.close(fd)


def check_tag(version: str) -> str:
    if not TAG.fullmatch(version):
        raise OperatorError("INVALID_RELEASE", "Version must be an exact vX.Y.Z tag")
    return version


def root_path() -> Path:
    raw = command(["git", "rev-parse", "--show-toplevel"])
    path = Path(raw.decode("utf-8", "strict").strip())
    # The operator must be launched from its trusted source checkout.
    remote = command(["git", "-C", str(path), "remote", "get-url", "origin"]).decode().strip()
    if remote not in (
            "https://github.com/teixemf/repocache.git",
            "https://github.com/teixemf/repocache",
            "git@github.com:teixemf/repocache.git"):
        raise OperatorError("UNTRUSTED_REPOSITORY", "Checkout origin is not REPOCACHE")
    if not (path / "scripts/offline_sign_release.py").is_file():
        raise OperatorError("INVALID_WORKTREE", "REPOCACHE release scripts are missing")
    return path


def state_root() -> Path:
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local/state"
    if not base.is_absolute():
        raise OperatorError("UNSAFE_STATE", "State directory must be absolute")
    return base / "repocache-release"


def guard_state_dir(path: Path, *, create: bool = False) -> None:
    if path.is_symlink():
        raise OperatorError("UNSAFE_STATE", "Refusing symlinked state directory")
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077):
            raise OperatorError("UNSAFE_STATE", "State directory must be private and owned")


@contextlib.contextmanager
def candidate_lock(version: str):
    """Serialize local candidate mutations without deleting an active flock."""
    check_tag(version)
    base = state_root()
    guard_state_dir(base, create=True)
    path = base / (version + ".lock")
    fd = -1
    try:
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1):
            raise OperatorError("UNSAFE_STATE", "Candidate lock file is unsafe")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise OperatorError("BUSY", "Another release operation holds the candidate lock") from exc
        yield
    finally:
        if fd >= 0:
            os.close(fd)


def state_file(version: str) -> Path:
    return state_root() / (check_tag(version) + ".json")


def read_state(version: str) -> dict[str, Any] | None:
    base = state_root()
    guard_state_dir(base)
    path = state_file(version)
    if path.is_symlink():
        raise OperatorError("UNSAFE_STATE", "State file symlink refused")
    # Validate the opened inode, not a path inspected before open: an
    # interrupted or locally replaced record must never be followed through
    # a symlink or a hardlink to another owner file.
    try:
        # O_NONBLOCK prevents a replaced FIFO from stalling before fstat() can reject it.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                     | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise OperatorError("UNSAFE_STATE", "State file cannot be safely opened") from exc
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1
                or info.st_size > 65536):
            raise OperatorError("UNSAFE_STATE", "State file is not private, unique or is oversized")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(65537)
    except OSError as exc:
        raise OperatorError("INVALID_STATE", "Release state record could not be read") from exc
    finally:
        os.close(fd)
    if len(raw) > 65536:
        raise OperatorError("UNSAFE_STATE", "State file exceeded the size limit")
    try:
        record = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise OperatorError("INVALID_STATE", "Release state record corrupted") from exc
    if (not isinstance(record, dict) or record.get("schema") != 1
            or record.get("version") != version
            or not HEX40.fullmatch(str(record.get("commit", "")))
            or not isinstance(record.get("assets"), dict)
            or record.get("phase") not in ("prepared", "signed", "staged", "published")
            or type(record.get("run_id")) is not int or record["run_id"] < 1
            or type(record.get("attempt")) is not int or record["attempt"] < 1
            or set(record["assets"]) != set(files_for(version, record["phase"] in ("signed", "staged", "published")))
            or any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value)
                   for value in record["assets"].values())):
        raise OperatorError("INVALID_STATE", "Release state identity invalid")
    return record


def save_state(version: str, record: dict[str, Any]) -> None:
    base = state_root()
    guard_state_dir(base, create=True)
    fd, name = tempfile.mkstemp(prefix=".pending-", dir=base)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(record, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, state_file(version))
        dfd = os.open(base, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def candidate_dir(version: str) -> Path:
    return state_root() / check_tag(version)


def files_for(version: str, signed: bool = False) -> list[str]:
    name = "repocache-" + check_tag(version) + ".tar.gz"
    return [name + part for part in
            (*UNSIGNED_SUFFIXES, *(SIGNED_SUFFIXES if signed else ()))]


def observed_assets(version: str, record: dict[str, Any]) -> dict[str, str]:
    folder = candidate_dir(version) / "assets"
    expected = set(files_for(version, record.get("phase") in ("signed", "staged", "published")))
    if folder.is_symlink() or not folder.is_dir():
        raise OperatorError("UNSAFE_ASSET", "Prepared asset directory is missing")
    actual = {item.name for item in folder.iterdir()}
    if actual != expected:
        raise OperatorError("ASSET_DRIFT", "Candidate asset inventory changed")
    return {item: digest(folder / item) for item in sorted(expected)}


def verify_state(version: str, record: dict[str, Any]) -> dict[str, str]:
    observed = observed_assets(version, record)
    if observed != record["assets"]:
        raise OperatorError("ASSET_DRIFT", "Candidate bytes no longer match recorded digests")
    return observed


def approved_build(version: str) -> tuple[str, int, int]:
    tag = check_tag(version)
    ref = gh_json(f"repos/{REPO}/git/ref/tags/{tag}")
    if ref.get("ref") != "refs/tags/" + tag:
        raise OperatorError("UNREVIEWED_RELEASE", "Release tag identity mismatch")
    resolved = gh_json(f"repos/{REPO}/commits/{tag}")
    commit = resolved.get("sha")
    if (not isinstance(commit, str) or not HEX40.fullmatch(commit)
            or ref.get("object", {}).get("type") != "commit"
            or ref.get("object", {}).get("sha") != commit):
        raise OperatorError("UNREVIEWED_RELEASE", "Tag ref does not identify the reviewed commit")
    comparison = gh_json(f"repos/{REPO}/compare/{commit}...main")
    if (comparison.get("status") not in ("ahead", "identical")
            or comparison.get("base_commit", {}).get("sha") != commit):
        raise OperatorError("UNREVIEWED_RELEASE", "Release is not contained in reviewed main")
    runs = gh_json(f"repos/{REPO}/actions/workflows/release.yml/runs?event=workflow_dispatch&per_page=100")
    entries = runs.get("workflow_runs")
    if (not isinstance(entries, list) or type(runs.get("total_count")) is not int
            or runs["total_count"] > 100 or len(entries) != runs["total_count"]):
        raise OperatorError("INVALID_RESPONSE", "Release run listing is missing or incomplete")
    matches = [r for r in entries if
               isinstance(r, dict) and r.get("head_sha") == commit
               and r.get("head_branch") == tag
               and r.get("event") == "workflow_dispatch"
               and r.get("status") == "completed"
               and r.get("conclusion") == "success"
               and isinstance(r.get("actor"), dict)
               and r["actor"].get("login") == OWNER]
    if len(matches) != 1:
        raise OperatorError("BUILD_NOT_VERIFIED", "Expected exactly one approved successful candidate run")
    run = matches[0]
    rid, attempt = run.get("id"), run.get("run_attempt")
    if (type(rid) is not int or rid < 1 or type(attempt) is not int
            or attempt < 1):
        raise OperatorError("BUILD_NOT_VERIFIED", "Invalid Actions run identity")
    jobs = gh_json(f"repos/{REPO}/actions/runs/{rid}/jobs?per_page=100")
    listed = jobs.get("jobs")
    if (not isinstance(listed, list)
            or type(jobs.get("total_count")) is not int
            or not 5 <= len(listed) == jobs["total_count"] <= 100
            or any(not isinstance(j, dict) or j.get("status") != "completed"
                   or j.get("conclusion") != "success" for j in listed)):
        raise OperatorError("BUILD_NOT_VERIFIED", "Release build has failed, skipped or incomplete jobs")
    return commit, rid, attempt


def environment() -> dict[str, Any]:
    if os.geteuid() == 0:
        raise OperatorError("UNSAFE_PRIVILEGE", "Release operator must run as a normal user")
    repo = root_path()
    for tool in ("git", "gh", "/usr/bin/openssl"):
        command([tool, "version"] if tool == "/usr/bin/openssl" else [tool, "--version"])
    command(["gh", "auth", "status"])
    try:
        user = json.loads(command(["gh", "api", "user"]))
    except (ValueError, TypeError) as exc:
        raise OperatorError("AUTHORIZATION_REQUIRED", "Cannot verify GitHub account identity") from exc
    if not isinstance(user, dict) or user.get("login") != OWNER:
        raise OperatorError("AUTHORIZATION_REQUIRED", "Release operator requires the official owner account")
    info = gh_json(f"repos/{REPO}/actions/workflows/release.yml")
    if info.get("path") != ".github/workflows/release.yml":
        raise OperatorError("UNTRUSTED_REPOSITORY", "Release workflow is not readable or mismatched")
    pub = repo / "keys/repocache-2026-10.pem"
    trusted = command(["/usr/bin/openssl", "pkey", "-pubin", "-in", str(pub),
                       "-outform", "DER"])
    if hashlib.sha256(trusted).hexdigest() != EXPECTED_FINGERPRINT:
        raise OperatorError("UNTRUSTED_SIGNER", "Publisher public key fingerprint mismatch")
    guard_state_dir(state_root())
    private = Path.home() / "repocache-signing/repocache-release-private.pem"
    if private.exists():
        if (private.is_symlink() or private.stat().st_uid != os.getuid()
                or private.stat().st_mode & 0o077 or not private.is_file()):
            raise OperatorError("UNSAFE_SIGNER", "Signing key must be owner-only mode 0600")
    return {"repository": REPO, "public_fingerprint": EXPECTED_FINGERPRINT,
            "private_key_present": private.is_file(),
            "status": "ready" if private.is_file() else "signer_missing"}


def extract_candidate_zip(archive: Path, assets: Path, version: str) -> None:
    """Only the four exact expected files; no traversal, symlinks or extras."""
    expected = set(files_for(version))
    if assets.is_symlink() or not assets.is_dir() or list(assets.iterdir()):
        raise OperatorError("UNSAFE_ASSET", "Candidate staging must be a new empty directory")
    if archive.is_symlink() or archive.stat().st_size > MAX_DOWNLOAD:
        raise OperatorError("UNSAFE_ASSET", "Downloaded artifact is unsafe or oversized")
    try:
        with zipfile.ZipFile(archive) as zipped:
            infos = zipped.infolist()
            if len(infos) != len(expected) or {x.filename for x in infos} != expected:
                raise OperatorError("UNSAFE_ASSET", "Downloaded ZIP has unexpected member paths")
            if any((i.file_size == 0 or i.file_size > MAX_ASSET
                    or i.compress_size == 0
                    or i.file_size > i.compress_size * 1000
                    or stat.S_ISLNK((i.external_attr >> 16) & 0xFFFF)
                    or i.is_dir()) for i in infos):
                raise OperatorError("UNSAFE_ASSET", "Downloaded ZIP has unsafe member metadata")
            for item in infos:
                # The validated name is one of exactly four constant leaf names.
                dest = assets / item.filename
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as stream, zipped.open(item) as source:
                    total = 0
                    while True:
                        part = source.read(131072)
                        if not part:
                            break
                        total += len(part)
                        if total > item.file_size or total > MAX_ASSET:
                            raise OperatorError("UNSAFE_ASSET", "ZIP expansion exceeds declared size")
                        stream.write(part)
                    if total != item.file_size:
                        raise OperatorError("UNSAFE_ASSET", "ZIP member is truncated")
                    stream.flush()
                    os.fsync(stream.fileno())
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        raise OperatorError("UNSAFE_ASSET", "Downloaded ZIP failed strict verification") from exc


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def download_unsigned(run_id: int, assets: Path, version: str) -> None:
    """Verify official Actions ZIP digest and never forward auth to the CDN.

    The unsigned archive is never executed; independent deterministic source
    and pinned dependency verification follows strict ZIP member extraction.
    """
    listing = gh_json(f"repos/{REPO}/actions/runs/{run_id}/artifacts?per_page=100")
    items = listing.get("artifacts")
    if (not isinstance(items, list) or type(listing.get("total_count")) is not int
            or listing["total_count"] != len(items) or len(items) > 100):
        raise OperatorError("INVALID_RESPONSE", "Incomplete GitHub artifact listing")
    matches = [item for item in items if isinstance(item, dict)
               and item.get("name") == "unsigned-release-candidate"
               and item.get("expired") is False
               and isinstance(item.get("workflow_run"), dict)
               and item["workflow_run"].get("id") == run_id]
    if len(matches) != 1:
        raise OperatorError("BUILD_NOT_VERIFIED", "Missing or ambiguous authorized Actions artifact")
    entry = matches[0]
    artifact_id, size, remote_sha = (entry.get("id"), entry.get("size_in_bytes"),
                                     entry.get("digest"))
    if (type(artifact_id) is not int or artifact_id < 1
            or type(size) is not int or size < 1 or size > MAX_DOWNLOAD
            or not isinstance(remote_sha, str)
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", remote_sha)):
        raise OperatorError("UNSAFE_ASSET", "Actions artifact lacks reviewed size and SHA-256 identity")
    token = command(["gh", "auth", "token"]).decode("ascii", "strict").strip()
    if not token or len(token) > 4096 or any(character.isspace() for character in token):
        raise OperatorError("AUTHORIZATION_REQUIRED", "GitHub authentication unavailable")
    endpoint = f"https://api.github.com/repos/{REPO}/actions/artifacts/{artifact_id}/zip"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    fd, temporary = tempfile.mkstemp(prefix=".actions-", suffix=".zip", dir=assets.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            url = endpoint
            for attempt in range(5):
                parsed = urllib.parse.urlsplit(url)
                initial = attempt == 0
                host = parsed.hostname or ""
                if initial:
                    if host != "api.github.com":
                        raise OperatorError("UNSAFE_REDIRECT", "Unexpected source for authenticated request")
                elif not (host in {"github.com", "release-assets.githubusercontent.com",
                                   "objects.githubusercontent.com",
                                   "github-releases.githubusercontent.com"}
                          or host.endswith(".blob.core.windows.net")):
                    raise OperatorError("UNSAFE_REDIRECT", "Unapproved release CDN origin")
                if (parsed.scheme != "https" or parsed.port not in (None, 443)
                        or parsed.username or parsed.password or parsed.fragment):
                    raise OperatorError("UNSAFE_REDIRECT", "Insecure GitHub artifact URL")
                headers = {"User-Agent": "repocache-release-operator/1",
                           "Accept": "application/octet-stream",
                           "X-GitHub-Api-Version": "2022-11-28"}
                if initial:
                    headers["Authorization"] = "Bearer " + token
                request = urllib.request.Request(url, headers=headers)
                try:
                    response = opener.open(request, timeout=60)
                except urllib.error.HTTPError as exc:
                    if exc.code not in (301, 302, 303, 307, 308):
                        raise OperatorError("REMOTE_UNAVAILABLE",
                                            "GitHub artifact download failed") from exc
                    redirect = exc.headers.get("Location", "")
                    if not redirect:
                        raise OperatorError("UNSAFE_REDIRECT", "Missing GitHub artifact redirect")
                    url = urllib.parse.urljoin(url, redirect)
                    continue
                with response:
                    total = 0
                    h = hashlib.sha256()
                    while True:
                        block = response.read(131072)
                        if not block:
                            break
                        total += len(block)
                        if total > MAX_DOWNLOAD:
                            raise OperatorError("UNSAFE_ASSET", "Downloaded ZIP is oversized")
                        h.update(block)
                        output.write(block)
                if total != size or h.hexdigest() != remote_sha[7:]:
                    raise OperatorError("ASSET_DRIFT", "GitHub Actions ZIP digest/size mismatch")
                output.flush()
                os.fsync(output.fileno())
                extract_candidate_zip(Path(temporary), assets, version)
                return
            raise OperatorError("UNSAFE_REDIRECT", "Too many authenticated artifact redirects")
    except (OSError, TimeoutError) as exc:
        raise OperatorError("REMOTE_UNAVAILABLE", "Cannot verify downloaded Actions artifact") from exc
    finally:
        os.unlink(temporary)


def verify_checkout(version: str, record: dict[str, Any]) -> Path:
    checkout = candidate_dir(version) / "checkout"
    if checkout.is_symlink() or not checkout.is_dir():
        raise OperatorError("UNSAFE_STATE", "Candidate checkout is missing")
    local = command(["git", "-C", str(checkout), "rev-parse", "HEAD"]).decode().strip()
    if local != record["commit"]:
        raise OperatorError("ASSET_DRIFT", "Candidate worktree commit changed")
    if command(["git", "-C", str(checkout), "status", "--porcelain",
                "--untracked-files=all"]):
        raise OperatorError("ASSET_DRIFT", "Candidate worktree has unreviewed files or modifications")
    return checkout


def verify_unsigned(worktree: Path, assets: Path, version: str) -> None:
    expected = set(files_for(version))
    actual = {f.name for f in assets.iterdir()}
    if actual != expected:
        raise OperatorError("UNSAFE_ASSET", "Unexpected or missing unsigned candidate files")
    for name in expected:
        digest(assets / name)
    base = "repocache-" + version + ".tar.gz"
    for suffix in ("", ".wheelhouse.tar.gz"):
        name = base + suffix
        sha_path = assets / (name + ".sha256")
        claimed = sha_path.read_text("ascii")
        if claimed != digest(assets / name) + "  " + name + "\n":
            raise OperatorError("ASSET_DRIFT", "Unsigned checksum differs from downloaded asset")
    script = worktree / "scripts/verify_release_candidate.py"
    result = subprocess.run([sys.executable, str(script), str(assets)],
                            cwd=worktree, capture_output=True, timeout=180,
                            check=False)
    if result.returncode:
        raise OperatorError("BUILD_NOT_VERIFIED", "Source rebuild or signed dependency-lock verification failed")


def prepare(version: str) -> dict[str, Any]:
    if os.geteuid() == 0:
        raise OperatorError("UNSAFE_PRIVILEGE", "Release operator cannot run as root")
    repo = root_path()
    commit, rid, attempt = approved_build(version)
    old = read_state(version)
    if old:
        if (old["commit"], old["run_id"], old["attempt"]) != (commit, rid, attempt):
            raise OperatorError("CANDIDATE_CONFLICT", "A different build is already prepared")
        verify_state(version, old)
        verify_checkout(version, old)
        return {"version": version, "changed": False, "phase": old["phase"],
                "run_id": rid, "commit": commit}
    base = state_root()
    guard_state_dir(base, create=True)
    folder = candidate_dir(version)
    if folder.exists() or folder.is_symlink():
        raise OperatorError("UNSAFE_STATE", "Interrupted candidate exists; inspect before retry")
    folder.mkdir(mode=0o700)
    guard_state_dir(folder)
    checkout, staging = folder / "checkout", folder / "staging"
    try:
        command(["git", "-C", str(repo), "fetch", "--no-tags", "origin",
                 f"refs/tags/{version}:refs/tags/{version}"], timeout=120)
        local_sha = command(["git", "-C", str(repo), "rev-parse",
                             f"refs/tags/{version}^{{commit}}"]).decode().strip()
        if local_sha != commit:
            raise OperatorError("UNREVIEWED_RELEASE", "Local tag differs from reviewed commit")
        command(["git", "-C", str(repo), "worktree", "add", "--detach",
                 str(checkout), commit], timeout=120)
        # Restrict extraction to an empty, owner-only staging folder.
        staging.mkdir(mode=0o700)
        download_unsigned(rid, staging, version)
        verify_unsigned(checkout, staging, version)
        os.replace(staging, folder / "assets")
        record = {"schema": 1, "version": version, "commit": commit,
                  "run_id": rid, "attempt": attempt, "phase": "prepared",
                  "assets": {name: digest(folder / "assets" / name)
                             for name in sorted(files_for(version))}}
        save_state(version, record)
        return {"version": version, "changed": True, "phase": "prepared",
                "run_id": rid, "commit": commit}
    except Exception:
        # Intentional fail-closed quarantine: never erase possible altered
        # files or a checked-out worktree after a partial operation.
        raise


def read_passphrase(fd: int) -> bytes:
    if fd < 3:
        raise OperatorError("INVALID_SECRET_FD", "Protected passphrase descriptor must be >= 3")
    try:
        data = os.read(fd, 4097)
        extra = os.read(fd, 1) if len(data) == 4097 else b""
    except OSError as exc:
        raise OperatorError("INVALID_SECRET_FD", "Protected passphrase descriptor cannot be read") from exc
    if (not data or len(data) > 4096 or extra or b"\x00" in data):
        raise OperatorError("INVALID_SECRET_FD", "Missing or oversized signer passphrase")
    if data.endswith(b"\n"):
        data = data[:-1]
    if not data or b"\r" in data or b"\n" in data:
        raise OperatorError("INVALID_SECRET_FD", "Invalid passphrase encoding")
    return data


def sign(version: str, fd: int) -> dict[str, Any]:
    if os.geteuid() == 0:
        raise OperatorError("UNSAFE_PRIVILEGE", "Release signer cannot run as root")
    record = read_state(version)
    if record is None:
        raise OperatorError("CANDIDATE_NOT_PREPARED", "Prepare and verify candidate first")
    if record["phase"] != "prepared":
        raise OperatorError("ALREADY_SIGNED", "Signing requires a fresh explicit prepared candidate")
    verify_state(version, record)
    private = Path.home() / "repocache-signing/repocache-release-private.pem"
    if (private.is_symlink() or not private.is_file()
            or private.stat().st_uid != os.getuid()
            or private.stat().st_mode & 0o077):
        raise OperatorError("UNSAFE_SIGNER", "Owner Ed25519 key must be private and mode 0600")
    checkout = verify_checkout(version, record)
    password = read_passphrase(fd)
    scripts = checkout / "scripts"
    # Load the approved exact-commit signer, not executable bytes from a
    # downloaded unsigned tarball.
    sys.path.insert(0, str(scripts))
    try:
        spec = importlib.util.spec_from_file_location("repocache_offline_sign", scripts / "offline_sign_release.py")
        if not spec or not spec.loader:
            raise OperatorError("TOOL_UNAVAILABLE", "Reviewed signing module unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with contextlib.redirect_stdout(io.StringIO()):
            module.sign_candidate(
                candidate_dir(version) / "assets" / files_for(version)[0],
                private, commit=record["commit"], run_id=str(record["run_id"]),
                attempt=str(record["attempt"]), password=password)
    except OperatorError:
        raise
    except (ValueError, RuntimeError, OSError) as exc:
        raise OperatorError("SIGNATURE_FAILED", "Offline signing refused or verification failed") from exc
    finally:
        sys.path.remove(str(scripts))
        del password
    signed = dict(record)
    signed["phase"] = "signed"
    signed["assets"] = observed_assets(version, signed)
    save_state(version, signed)
    return {"version": version, "phase": "signed", "changed": True,
            "publisher_key_id": "repocache-2026-10"}


def status(version: str, acceptance_run_id: int | None = None) -> dict[str, Any]:
    # Import only this project's workstation adapter, never a candidate archive.
    from repocache_release import publication
    return publication.acceptance_status(sys.modules[__name__], version,
                                         read_state(version), acceptance_run_id)


def stage(version: str) -> dict[str, Any]:
    from repocache_release import publication
    return publication.stage(sys.modules[__name__], version)


def publish(version: str, acceptance_run_id: int, approve_sha256: str) -> dict[str, Any]:
    from repocache_release import publication
    return publication.publish(sys.modules[__name__], version, acceptance_run_id,
                               approve_sha256)


def build_parser() -> SafeParser:
    root = SafeParser(prog="repocache-release",
                      description="Workstation-only owner-held release operator")
    root.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    objects = root.add_subparsers(dest="object", parser_class=SafeParser)
    env = objects.add_parser("environment", help="Read-only local prerequisites")
    env.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    ea = env.add_subparsers(dest="action", parser_class=SafeParser)
    ec = ea.add_parser("check", help="Check tools, trust anchor and signer path")
    ec.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    candidate = objects.add_parser("candidate", help="Prepare and sign a reviewed candidate")
    candidate.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    actions = candidate.add_subparsers(dest="action", parser_class=SafeParser)
    for action in ("prepare", "sign", "stage", "status", "publish"):
        p = actions.add_parser(action, help={
            "prepare": "Fetch and verify exact unsigned release candidate",
            "sign": "Offline Ed25519 signing; explicit protected passphrase FD",
            "stage": "Create an owner-signed Draft Release (requires merged #76 gate)",
            "status": "Inspect signed draft acceptance and detect asset drift",
            "publish": "Publish only an owner-approved, CI-accepted unchanged Draft",
        }[action])
        p.add_argument("version")
        if action == "sign":
            p.add_argument("--passphrase-fd", required=True, type=int)
        if action == "status":
            p.add_argument("--acceptance-run-id", type=int)
        if action == "publish":
            p.add_argument("--acceptance-run-id", required=True, type=int)
            p.add_argument("--approve-sha256", required=True)
        p.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    return root


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    json_mode = "--json" in args
    parser = build_parser()
    try:
        values = parser.parse_args(args)
        if values.object is None:
            parser.print_help()
            return 0
        if values.action is None:
            for action in parser._actions:
                if isinstance(action, argparse._SubParsersAction):
                    action.choices[values.object].print_help()
                    break
            return 0
        if values.object == "environment":
            data = environment()
        elif values.action in ("prepare", "sign", "stage", "publish"):
            with candidate_lock(values.version):
                if values.action == "prepare":
                    data = prepare(values.version)
                elif values.action == "sign":
                    data = sign(values.version, values.passphrase_fd)
                elif values.action == "stage":
                    data = stage(values.version)
                else:
                    data = publish(values.version, values.acceptance_run_id,
                                   values.approve_sha256)
        else:
            data = status(values.version, values.acceptance_run_id)
        payload = {"schema_version": 1, "ok": True, "result": data}
        if json_mode:
            print(json.dumps(payload, sort_keys=True))
        else:
            print(json.dumps(data, indent=2, sort_keys=True))
        return 0
    except SystemExit as exc:
        # argparse --help is side-effect-free and exits 0.
        return int(exc.code or 0)
    except SyntaxErrorFromParser as exc:
        err = OperatorError("INVALID_ARGUMENT", "Invalid command arguments: " + str(exc))
        rc = 2
    except OperatorError as exc:
        err = exc
        rc = 1
    except (OSError, ValueError, UnicodeError, TypeError, KeyError, AttributeError) as exc:
        err = OperatorError("OPERATION_FAILED", "Release operator could not verify its inputs")
        rc = 1
    if json_mode:
        print(json.dumps({"schema_version": 1, "ok": False,
                          "error": {"code": err.code, "message": str(err)}},
                         sort_keys=True))
    else:
        print(f"{err.code}: {err}", file=sys.stderr)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
