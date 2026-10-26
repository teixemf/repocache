"""Explicit operator-issued HMAC keyring with no credentials on stdout.

Issuing keys writes an offline client credential file and a server keyring.
There is no automatic service reload, networking or client provisioning.
"""
from __future__ import annotations

import base64
import fcntl
import json
import os
import pwd
import re
import secrets
import stat
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from repocache.intake import (_secret, _keyring_file_valid,
                              _keyring_directory_valid)
from repocache.submissions import SubmissionError

KEY_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
SERVICE_USER = "repocache-intake"
MAX_KEYS = 32
_KEYRING_LOCK_TIMEOUT = 10.0


class _KeyringPublicationUncertain(OSError):
    """Keyring rename may be visible while directory durability is unknown."""


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                 getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _verify_keyring_lock(fd: int) -> None:
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
        raise SubmissionError("unsafe_keyring_lock", 403)


@contextmanager
def _exclusive_keyring_lock(directory: Path):
    """Serialize full read-modify-publish transactions between root operators."""
    path = directory / ".keyring.lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR |
                 getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        _verify_keyring_lock(fd)
        deadline = time.monotonic() + _KEYRING_LOCK_TIMEOUT
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise SubmissionError("credential_busy", 409) from exc
                time.sleep(0.025)
        try:
            # Never trust a swapped pathname after acquiring the inode lock.
            inode = path.lstat()
            actual = os.fstat(fd)
            if ((inode.st_dev, inode.st_ino) !=
                    (actual.st_dev, actual.st_ino) or
                    not stat.S_ISREG(inode.st_mode)):
                raise SubmissionError("unsafe_keyring_lock", 403)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)



def _root_only() -> None:
    if os.geteuid() != 0:
        raise SubmissionError("operator_required", 403)


def _service_gid() -> int:
    try:
        account = pwd.getpwnam(SERVICE_USER)
    except KeyError as exc:
        raise SubmissionError("service_account_missing", 503) from exc
    if account.pw_uid <= 0 or account.pw_gid <= 0:
        raise SubmissionError("unsafe_service_identity", 503)
    return account.pw_gid


def _set_keyring_ownership(fd: int, group: int) -> None:
    # Root owns each newly created staging inode. Group read permission is
    # enabled only after the full credential set is durably written.
    os.fchown(fd, 0, group)
    os.fchmod(fd, 0o600)


def _trusted_directory(path: Path, *, for_client: bool) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
        raise SubmissionError("unsafe_credentials_directory", 403)
    if for_client:
        if info.st_mode & 0o077:
            raise SubmissionError("unsafe_credentials_directory", 403)
    elif not _keyring_directory_valid(info, _service_gid()):
        raise SubmissionError("unsafe_credentials_directory", 403)
    # A root-owned immediate directory is not enough: a caller-controlled
    # ancestor could rename the directory between checking and writing an
    # operator-issued client secret or replacing the service keyring.
    for ancestor in path.parents:
        try:
            trusted = ancestor.lstat()
        except OSError as exc:
            raise SubmissionError("unsafe_credentials_directory", 403) from exc
        if (not stat.S_ISDIR(trusted.st_mode) or trusted.st_uid != 0 or
                (trusted.st_mode & 0o022 and not trusted.st_mode & stat.S_ISVTX)):
            raise SubmissionError("unsafe_credentials_directory", 403)


def _load(path: Path, service_gid: int) -> list[dict]:
    if not path.exists() and not path.is_symlink():
        return []
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        details = os.fstat(descriptor)
        if not _keyring_file_valid(details, service_gid):
            raise SubmissionError("unsafe_keyring", 403)
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            doc = json.loads(stream.read(8193).decode("utf-8"))
    finally:
        os.close(descriptor)
    if (not isinstance(doc, dict) or set(doc) != {"keys"} or
            not isinstance(doc["keys"], list) or len(doc["keys"]) > MAX_KEYS):
        raise SubmissionError("invalid_keyring", 422)
    seen = set()
    for item in doc["keys"]:
        if not isinstance(item, dict) or set(item) != {"key_id", "secret"}:
            raise SubmissionError("invalid_keyring", 422)
        if (not isinstance(item["key_id"], str) or
                not KEY_ID.fullmatch(item["key_id"]) or item["key_id"] in seen):
            raise SubmissionError("invalid_keyring", 422)
        _secret(item["secret"])
        seen.add(item["key_id"])
    return doc["keys"]


def _write_keyring(path: Path, service_gid: int, keys: list[dict]) -> None:
    fd, name = tempfile.mkstemp(prefix=".keyring-", dir=path.parent)
    try:
        _set_keyring_ownership(fd, service_gid)
        payload = (json.dumps({"keys": keys}, separators=(",", ":")) + "\n").encode("ascii")
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            # The intake process can only read a complete, immutable-to-it
            # group-readable file after root has written the full payload.
            os.fchmod(stream.fileno(), 0o640)
            os.fsync(stream.fileno())
        # After entering the rename boundary the on-disk state is not
        # safely reversible on an I/O error or crash. The caller must retain
        # the confidential client handoff for explicit reconciliation.
        try:
            os.replace(name, path)
            _fsync_directory(path.parent)
        except OSError as exc:
            raise _KeyringPublicationUncertain("keyring publication uncertain") from exc
    finally:
        if os.path.exists(name):
            os.unlink(name)


def issue_key(keyring: Path, client_output: Path, key_id: str, *,
              approved: bool = False) -> None:
    """Generate new key; never print or return the plaintext secret."""
    _root_only()
    if not approved:
        raise SubmissionError("operator_approval_required", 403)
    if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id):
        raise SubmissionError("invalid_key_id", 422)
    keyring, client_output = Path(keyring), Path(client_output)
    _trusted_directory(keyring.parent, for_client=False)
    _trusted_directory(client_output.parent, for_client=True)
    service_gid = _service_gid()
    try:
        with _exclusive_keyring_lock(keyring.parent):
            keys = _load(keyring, service_gid)
            if len(keys) >= MAX_KEYS or any(item["key_id"] == key_id for item in keys):
                raise SubmissionError("duplicate_or_full_keyring", 409)
            secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
            # The confidential client handoff must be durable before the
            # server key becomes active. Both stay under root-controlled dirs.
            fd = os.open(client_output,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write((json.dumps({"key_id": key_id, "secret": secret}) +
                                  "\n").encode("ascii"))
                    stream.flush()
                    os.fsync(stream.fileno())
                _fsync_directory(client_output.parent)
                _write_keyring(keyring, service_gid,
                               keys + [{"key_id": key_id, "secret": secret}])
            except _KeyringPublicationUncertain as exc:
                # Never discard the only client copy when its key may
                # already be published. The operator must reconcile offline.
                raise SubmissionError("credential_publication_uncertain", 503) from exc
            except BaseException:
                # No keyring publication was attempted or the write failed
                # before the rename boundary. Remove the uncommitted handoff.
                client_output.unlink(missing_ok=True)
                _fsync_directory(client_output.parent)
                raise
    except SubmissionError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise SubmissionError("credential_write_unavailable", 503) from exc


def revoke_key(keyring: Path, key_id: str, *, approved: bool = False) -> None:
    """Remove an old credential; never revoke the last operational key."""
    _root_only()
    if not approved:
        raise SubmissionError("operator_approval_required", 403)
    if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id):
        raise SubmissionError("invalid_key_id", 422)
    keyring = Path(keyring)
    _trusted_directory(keyring.parent, for_client=False)
    service_gid = _service_gid()
    try:
        with _exclusive_keyring_lock(keyring.parent):
            keys = _load(keyring, service_gid)
            retained = [key for key in keys if key["key_id"] != key_id]
            if len(retained) == len(keys):
                raise SubmissionError("key_not_found", 404)
            if not retained:
                raise SubmissionError("last_key_refused", 409)
            try:
                _write_keyring(keyring, service_gid, retained)
            except _KeyringPublicationUncertain as exc:
                raise SubmissionError("credential_publication_uncertain", 503) from exc
    except SubmissionError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise SubmissionError("credential_write_unavailable", 503) from exc


def main(argv: list[str] | None = None) -> int:
    """Script-friendly offline key generation and revocation; no secret output."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="repocache-submissions-keys")
    sub = parser.add_subparsers(dest="operation", required=True)
    add = sub.add_parser("issue")
    add.add_argument("--id", required=True)
    add.add_argument("--client-output", type=Path, required=True)
    add.add_argument("--approve", action="store_true", required=True)
    remove = sub.add_parser("revoke")
    remove.add_argument("--id", required=True)
    remove.add_argument("--approve", action="store_true", required=True)
    args = parser.parse_args(argv)
    keyring = Path("/etc/repocache-intake/keyring.json")
    try:
        if args.operation == "issue":
            issue_key(keyring, args.client_output, args.id, approved=args.approve)
            print("Key issued; protected client credential written. Restart service after approved change.")
        else:
            revoke_key(keyring, args.id, approved=args.approve)
            print("Key revoked in persisted keyring. Restart service after approved change.")
        return 0
    except (SubmissionError, OSError) as exc:
        status = exc.code if isinstance(exc, SubmissionError) else "credential_write_unavailable"
        print("ERROR: " + status, file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
