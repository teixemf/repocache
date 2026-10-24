"""EXPERIMENTAL atomic APT/DNF file replacement with interrupted-write rollback.

Sandbox ONLY: never import from installed client, never operate on / or /etc.
No permission to use this with privileges, real sources or deployment.
Depends on transaction_stage from the parent staging PR (#131).

A private intent journal is durable before os.replace; recovery trusts both
the source digest AND the expected target inode. A foreign replacement, even
with identical content, is a conflict and must not be overwritten.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import json
import os
import stat

import source_metadata_lab as attributes
from pathlib import Path

import transaction_stage as staging


MARKER = ".repocache-atomic-lab"
MAGIC = b"REPOCACHE_SANDBOX_ONLY_V1\n"
PHASES = {"install-intent", "installed", "restore-intent", "restored"}
JOURNAL = "atomic-lab-journal.json"


def _sandbox(root: Path) -> Path:
    # Refuse the live filesystem root before any ownership-dependent check.
    if Path(root) == Path("/"):
        raise staging.StageError("Atomic test writer is restricted to /tmp sandbox roots")
    root = staging._root(root)
    if (root == Path("/tmp") or
            root == Path("/var/tmp") or
            not any(parent in (Path("/tmp"), Path("/var/tmp"))
                    for parent in root.parents) or root.resolve() != root):
        raise staging.StageError("Atomic test writer is restricted to /tmp sandbox roots")
    marker = root / MARKER
    if staging._read_private(marker, max_size=80) != MAGIC:
        raise staging.StageError("Missing verified atomic-write sandbox marker")
    return root


def _phase(directory: Path) -> dict | None:
    allowed = {"manifest.json", "original.bin", "proposed.bin", JOURNAL,
               "original-attributes.json"}
    if {entry.name for entry in directory.iterdir()} - allowed:
        raise staging.StageError("Unknown transaction file; manual review required")
    path = directory / JOURNAL
    if not path.exists() and not path.is_symlink():
        return None
    raw = staging._read_private(path, max_size=1024)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise staging.StageError("Invalid atomic intent journal") from exc
    if (type(data) is not dict or set(data) !=
            {"schema", "phase", "device", "inode",
             "from_device", "from_inode"} or data.get("schema") != 1
            or data.get("phase") not in PHASES
            or type(data.get("device")) is not int or data["device"] < 0
            or type(data.get("inode")) is not int or data["inode"] < 1
            or type(data.get("from_device")) is not int or data["from_device"] < 0
            or type(data.get("from_inode")) is not int or data["from_inode"] < 1):
        raise staging.StageError("Invalid atomic intent journal")
    return data


def _protected_attributes(directory: Path, record: dict) -> tuple[tuple[str, bytes], ...]:
    """Validate original xattrs bound to the stage's protected source hash/inode."""
    path = directory / "original-attributes.json"
    if not path.exists() and not path.is_symlink():
        return ()
    raw = staging._read_private(path, max_size=128 * 1024)
    try:
        obj = json.loads(raw.decode("utf-8"))
        if (type(obj) is not dict or set(obj) != {
                "schema", "original_sha256", "original_device",
                "original_inode", "attributes"
            } or type(obj["schema"]) is not int or obj["schema"] != 1
                or obj["original_sha256"] != record["before_sha256"]
                or obj["original_device"] != record["metadata"]["device"]
                or obj["original_inode"] != record["metadata"]["inode"]
                or type(obj["attributes"]) is not list
                or len(obj["attributes"]) > attributes.MAX_ATTRS):
            raise ValueError("Invalid attribute snapshot")
        parsed = []
        total = 0
        for item in obj["attributes"]:
            if (type(item) is not list or len(item) != 2 or
                    type(item[0]) is not str or type(item[1]) is not str
                    or not attributes._allowed_attribute(item[0])):
                raise ValueError("Unsupported attribute")
            value = base64.b64decode(item[1], validate=True)
            total += len(value)
            if (len(value) > attributes.MAX_ATTRIBUTE_BYTES
                    or total > attributes.MAX_TOTAL_ATTRIBUTE_BYTES):
                raise ValueError("Oversized attribute")
            parsed.append((item[0], value))
        if parsed != sorted(set(parsed), key=lambda pair: pair[0]):
            raise ValueError("Duplicate or unordered attributes")
        return tuple(parsed)
    except (ValueError, KeyError, TypeError, UnicodeError, binascii.Error) as exc:
        raise staging.StageError("Invalid protected original metadata snapshot") from exc


def _check_attributes(fd: int, expected: tuple[tuple[str, bytes], ...]) -> None:
    # Missing a snapshot must never authorize silently dropping xattrs.
    _, actual = attributes._metadata(fd)
    if actual != expected:
        if not expected:
            raise staging.StageError("Source has unhandled extended attributes")
        raise staging.StageError("External source attribute drift")


def _write_phase(directory: Path, phase: str, identity: tuple[int, int],
                 from_identity: tuple[int, int]) -> None:
    if phase not in PHASES:
        raise staging.StageError("Unsupported transaction phase")
    path = directory / JOURNAL
    # The old journal must not be a symlink or an unexpected inode type.
    if path.exists() or path.is_symlink():
        staging._read_private(path, max_size=1024)
    payload = json.dumps({
        "schema": 1, "phase": phase,
        "device": identity[0], "inode": identity[1],
        "from_device": from_identity[0], "from_inode": from_identity[1],
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    temp = directory / ".atomic-lab-journal.tmp"
    staging._write_private(temp, payload)
    try:
        os.replace(temp, path)
        staging._fsync_dir(directory)
    finally:
        if temp.exists() and not temp.is_symlink():
            temp.unlink()


@contextlib.contextmanager
def _source_directory(root: Path, relative: str):
    # The source allowlist in #131 is mandatory but by itself not enough.
    if not staging.SOURCE_RULE.fullmatch(relative):
        raise staging.StageError("Unapproved repository source pathname")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY |
                 os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for component in relative.split("/")[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            meta = os.fstat(child)
            if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.geteuid()
                    or stat.S_IMODE(meta.st_mode) & 0o022):
                os.close(child)
                raise staging.StageError("Unsafe source directory")
            os.close(fd)
            fd = child
        yield fd, relative.rsplit("/", 1)[-1]
    except OSError as exc:
        raise staging.StageError("Unsafe repository source pathname") from exc
    finally:
        os.close(fd)


def _target_state(directory_fd: int, leaf: str,
                  expected_attrs: tuple[tuple[str, bytes], ...] = ()) -> tuple[bytes, dict]:
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=directory_fd)
    except OSError as exc:
        raise staging.StageError("Repository source missing or replaced") from exc
    try:
        info = os.fstat(fd)
        at_path = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o022
                or info.st_size > staging.MAX_SOURCE_BYTES
                or (info.st_dev, info.st_ino) !=
                (at_path.st_dev, at_path.st_ino)):
            raise staging.StageError("Untrusted or replaced source inode")
        _check_attributes(fd, expected_attrs)
        content = os.read(fd, staging.MAX_SOURCE_BYTES + 1)
        after = os.fstat(fd)
        if (len(content) > staging.MAX_SOURCE_BYTES
                or (info.st_mtime_ns, info.st_ctime_ns, info.st_size) !=
                   (after.st_mtime_ns, after.st_ctime_ns, after.st_size)):
            raise staging.StageError("Repository source changed during read")
        _check_attributes(fd, expected_attrs)
        return content, {
            "device": after.st_dev, "inode": after.st_ino,
            "mode": stat.S_IMODE(after.st_mode), "uid": after.st_uid,
            "gid": after.st_gid,
            "mtime_ns": after.st_mtime_ns, "ctime_ns": after.st_ctime_ns,
        }
    finally:
        os.close(fd)


def _matches(payload: bytes, metadata: dict, expected: bytes,
             identity: tuple[int, int]) -> bool:
    return (payload == expected and
            (metadata["device"], metadata["inode"]) == identity)


def _write_new(directory_fd: int, leaf: str, ident: str,
               data: bytes, metadata: dict,
               expected_attrs: tuple[tuple[str, bytes], ...] = ()) -> tuple[str, tuple[int, int]]:
    # Deterministic private temp names make ambiguous abandoned writes visible
    # and unambiguously fail closed rather than being silently deleted.
    temp = ".repocache-atomic-%s" % ident
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
    except OSError as exc:
        raise staging.StageError("Pending source temporary file needs review") from exc
    try:
        if (metadata["uid"] != os.geteuid()
                or metadata["gid"] != os.getegid()):
            raise staging.StageError("Source owner/group preservation is unavailable")
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
        os.fchmod(fd, metadata["mode"])
        try:
            for name, value in expected_attrs:
                if name != "system.posix_acl_access":
                    os.setxattr(fd, name, value)
            for name, value in expected_attrs:
                if name == "system.posix_acl_access":
                    os.setxattr(fd, name, value)
        except OSError as exc:
            raise staging.StageError("Cannot preserve approved source metadata") from exc
        _check_attributes(fd, expected_attrs)
        if stat.S_IMODE(os.fstat(fd).st_mode) != metadata["mode"]:
            raise staging.StageError("New source mode differs after ACL installation")
        os.fsync(fd)
        info = os.fstat(fd)
        return temp, (info.st_dev, info.st_ino)
    finally:
        os.close(fd)


def _replace(directory_fd: int, temp: str, leaf: str,
             expected: tuple[int, int]) -> None:
    # Compare at the last practical moment under a trusted directory fd.
    # Concurrent edits by another writer with equal privilege are NOT solved
    # by this check; therefore no production use is permitted.
    observed = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
    if (observed.st_dev, observed.st_ino) != expected:
        raise staging.StageError("Source inode changed immediately before replace")
    os.replace(temp, leaf, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    os.fsync(directory_fd)


def _pending_file(directory_fd: int, ident: str,
                  expected_identity: tuple[int, int] | None,
                  expected_payload: bytes,
                  expected_attrs: tuple[tuple[str, bytes], ...]) -> str | None:
    """Read a pending temporary file ONLY when a journal proves its identity.

    A missing temp is distinct from a malicious symlink, foreign inode or
    unknown content. Never delete or overwrite an unverified file.
    """
    name = ".repocache-atomic-%s" % ident
    try:
        observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if expected_identity is None:
        raise staging.StageError("Unjournalled source temporary file requires review")
    contents, metadata = _target_state(directory_fd, name, expected_attrs)
    if not _matches(contents, metadata, expected_payload, expected_identity):
        raise staging.StageError("Foreign or modified source temporary file")
    if (observed.st_dev, observed.st_ino) != expected_identity:
        raise staging.StageError("Pending source temporary inode changed")
    return name


def _precheck(root: Path, ident: str):
    root = _sandbox(root)
    if not isinstance(ident, str) or not staging.STAGE_ID.fullmatch(ident):
        raise staging.StageError("Invalid stage ID")
    state = staging._state(root, create=False)
    return root, state


def _prepare(root: Path, ident: str, state: Path) -> tuple[Path, dict]:
    records = staging._records(state)
    if ident not in records:
        raise staging.StageError("Unknown stage ID")
    directory = state / ident
    _phase(directory)  # Validate unknown partial journals before any mutation.
    attrs = _protected_attributes(directory, records[ident])
    return directory, records[ident], attrs


def _change(root: Path, ident: str, *, rollback: bool):
    root, state = _precheck(root, ident)
    with staging._locked(state):
        directory, record, expected_attrs = _prepare(root, ident, state)
        prior = staging._read_private(directory / "original.bin",
                                      max_size=staging.MAX_SOURCE_BYTES)
        proposed = staging._read_private(directory / "proposed.bin",
                                         max_size=staging.MAX_SOURCE_BYTES)
        journal = _phase(directory)
        if rollback and (journal is None or journal["phase"] != "installed"):
            raise staging.StageError("No verified installed stage to roll back")
        if not rollback and journal is not None:
            raise staging.StageError("Stage already modified or needs recovery")
        with _source_directory(root, record["source"]) as (parent_fd, leaf):
            current, meta = _target_state(parent_fd, leaf, expected_attrs)
            if rollback:
                expected_identity = (journal["device"], journal["inode"])
                expected_payload = proposed
                target = prior
                intent, completed = "restore-intent", "restored"
            else:
                expected_identity = (record["metadata"]["device"],
                                     record["metadata"]["inode"])
                expected_payload = prior
                target = proposed
                intent, completed = "install-intent", "installed"
                if any(meta[key] != record["metadata"][key]
                       for key in ("mode", "uid", "gid", "mtime_ns", "ctime_ns")):
                    raise staging.StageError("Source metadata drift")
            if (not _matches(current, meta, expected_payload, expected_identity)
                    or any(meta[key] != record["metadata"][key]
                           for key in ("mode", "uid", "gid"))):
                raise staging.StageError("External source drift; no replacement attempted")
            temp, new_identity = _write_new(parent_fd, leaf, ident, target, meta,
                                            expected_attrs)
            _write_phase(directory, intent, new_identity, expected_identity)
            _replace(parent_fd, temp, leaf, expected_identity)
            _write_phase(directory, completed, new_identity, expected_identity)
            return {"status": completed, "source": record["source"], "id": ident}


def apply_sandbox(root: Path, ident: str) -> dict:
    """Atomic file replacement for explicitly-marked temporary sandboxes only."""
    return _change(root, ident, rollback=False)


def rollback_sandbox(root: Path, ident: str) -> dict:
    """Rollback a clean installed sandbox stage if no external drift occurred."""
    return _change(root, ident, rollback=True)


def recover_sandbox(root: Path, ident: str) -> dict:
    """Fail closed on ambiguity; undo a provable interrupted install only."""
    root, state = _precheck(root, ident)
    with staging._locked(state):
        directory, record, expected_attrs = _prepare(root, ident, state)
        journal = _phase(directory)
        if journal is None:
            with _source_directory(root, record["source"]) as (parent_fd, _):
                _pending_file(parent_fd, ident, None, b"", expected_attrs)
            return {"status": "no-intent", "id": ident}
        phase = journal["phase"]
        prior = staging._read_private(directory / "original.bin",
                                      max_size=staging.MAX_SOURCE_BYTES)
        proposed = staging._read_private(directory / "proposed.bin",
                                         max_size=staging.MAX_SOURCE_BYTES)
        with _source_directory(root, record["source"]) as (parent_fd, leaf):
            current, meta = _target_state(parent_fd, leaf, expected_attrs)
            if any(meta[key] != record["metadata"][key]
                   for key in ("mode", "uid", "gid")):
                raise staging.StageError("External source metadata drift during recovery")
            intended_identity = (journal["device"], journal["inode"])
            from_identity = (journal["from_device"], journal["from_inode"])
            if phase in ("installed", "restored"):
                expected = proposed if phase == "installed" else prior
                if not _matches(current, meta, expected, intended_identity):
                    raise staging.StageError("Committed source changed externally")
                _pending_file(parent_fd, ident, None, b"", expected_attrs)
                return {"status": phase, "id": ident}
            if phase == "install-intent":
                if _matches(current, meta, prior, from_identity):
                    pending = _pending_file(parent_fd, ident, intended_identity,
                                            proposed, expected_attrs)
                    if pending is not None:
                        # Only remove the still-identical journalled inode.
                        observed = os.stat(pending, dir_fd=parent_fd,
                                           follow_symlinks=False)
                        if (observed.st_dev, observed.st_ino) != intended_identity:
                            raise staging.StageError("Pending source inode changed")
                        os.unlink(pending, dir_fd=parent_fd)
                        os.fsync(parent_fd)
                    _write_phase(directory, "restored", from_identity, from_identity)
                    return {"status": "not-applied", "id": ident}
                if not _matches(current, meta, proposed, intended_identity):
                    raise staging.StageError("External drift during interrupted apply")
                # The install temp should have been consumed in this phase.
                # If it still exists, an unknown actor or crash window has
                # created an ambiguous state: do not overwrite it.
                _pending_file(parent_fd, ident, None, b"", expected_attrs)
            elif phase == "restore-intent":
                if _matches(current, meta, prior, intended_identity):
                    _pending_file(parent_fd, ident, None, b"", expected_attrs)
                    _write_phase(directory, "restored", intended_identity, from_identity)
                    return {"status": "restored", "id": ident}
                if not _matches(current, meta, proposed, from_identity):
                    raise staging.StageError("External drift during interrupted rollback")
                # Resume the verified exact rollback intent rather than
                # creating a second temp and failing with EEXIST.
                pending = _pending_file(parent_fd, ident, intended_identity,
                                        prior, expected_attrs)
                if pending is None:
                    raise staging.StageError("Missing journalled rollback temporary file")
                _replace(parent_fd, pending, leaf, from_identity)
                _write_phase(directory, "restored", intended_identity, from_identity)
                return {"status": "restored", "id": ident}
            else:
                raise staging.StageError("Invalid recovery state")
            temp, new_identity = _write_new(parent_fd, leaf, ident, prior, meta,
                                            expected_attrs)
            active_identity = (meta["device"], meta["inode"])
            _write_phase(directory, "restore-intent", new_identity, active_identity)
            _replace(parent_fd, temp, leaf, active_identity)
            _write_phase(directory, "restored", new_identity, active_identity)
            return {"status": "restored", "id": ident}
