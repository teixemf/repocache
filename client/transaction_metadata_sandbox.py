"""Protected metadata snapshot for sandbox-only APT/DNF transaction experiments.

This bridges #131/#132 protected staging and #133/#134 Linux ACL/xattr
inspection. NOT a privileged writer, owner registry, SELinux implementation
or production transaction. Never import from installed client CLI.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import source_metadata_lab as attributes
import transaction_atomic_lab as atomic
import transaction_stage as stage


SNAPSHOT = "original-attributes.json"
SCHEMA = 1


def snapshot_sandbox(root: Path, ident: str) -> dict:
    """Bind supported original xattrs to a protected stage before any apply.

    An interrupted snapshot leaves an explicit partial entry which blocks
    subsequent atomic writes; it must not be auto-discarded after SIGKILL.
    """
    root = atomic._sandbox(root)
    if not isinstance(ident, str) or not stage.STAGE_ID.fullmatch(ident):
        raise stage.StageError("Invalid transaction ID")
    state = stage._state(root, create=False)
    with stage._locked(state):
        records = stage._records(state)
        if ident not in records:
            raise stage.StageError("Unknown transaction ID")
        record = records[ident]
        folder = state / ident
        if atomic._phase(folder) is not None:
            raise stage.StageError("Cannot snapshot metadata after apply intent")
        if (folder / SNAPSHOT).exists() or (folder / SNAPSHOT).is_symlink():
            raise stage.StageError("Original metadata snapshot already exists")
        with atomic._source_directory(root, record["source"]) as (parent, leaf):
            fd = os.open(leaf, atomic.FLAGS_FILE if hasattr(atomic, "FLAGS_FILE") else (
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            ), dir_fd=parent)
            try:
                observed, values = attributes._metadata(fd)
                expected = record["metadata"]
                if any(observed[key] != expected[key] for key in (
                        "device", "inode", "mode", "uid", "gid",
                        "mtime_ns", "ctime_ns")):
                    raise stage.StageError("Original source changed before metadata snapshot")
                data = os.read(fd, stage.MAX_SOURCE_BYTES + 1)
                if hashlib.sha256(data).hexdigest() != record["before_sha256"]:
                    raise stage.StageError("Original source content changed before snapshot")
                final, final_values = attributes._metadata(fd)
                if final != observed or final_values != values:
                    raise stage.StageError("Source metadata changed during snapshot")
                inode = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                if (inode.st_dev, inode.st_ino) != (
                        observed["device"], observed["inode"]):
                    raise stage.StageError("Original source pathname changed")
            finally:
                os.close(fd)
        snapshot = {
            "schema": SCHEMA,
            "original_sha256": record["before_sha256"],
            "original_device": expected["device"],
            "original_inode": expected["inode"],
            "attributes": [[name, base64.b64encode(value).decode("ascii")]
                           for name, value in values],
        }
        payload = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")
        temp = folder / ".original-attributes.partial"
        stage._write_private(temp, payload)
        # On crash, a partial file remains detectable by the transaction
        # verifier and must not be removed automatically.
        os.replace(temp, folder / SNAPSHOT)
        stage._fsync_dir(folder)
        return {"status": "snapshotted", "id": ident,
                "attribute_count": len(values), "apply_eligible": False}
