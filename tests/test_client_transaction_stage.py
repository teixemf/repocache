"""Security-focused sandbox tests for non-applying client transaction staging.

No test creates or modifies real /etc/apt or /etc/yum.repos.d files.
"""
from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
import re
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "client" / "transaction_stage.py"
spec = importlib.util.spec_from_file_location("client_transaction_stage_under_test", MODULE)
stage = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(stage)

SOURCE = "etc/apt/sources.list.d/repocache.list"
BEFORE = b"deb https://deb.debian.org/debian trixie main\n"
PROPOSED = b"deb mirror+file:/etc/apt/mirrors/repocache.txt trixie main\n"


@pytest.fixture
def host(tmp_path):
    tmp_path.chmod(0o700)
    (tmp_path / "var/lib").mkdir(parents=True)
    (tmp_path / "etc/apt/sources.list.d").mkdir(parents=True)
    (tmp_path / "etc/apt/mirrors").mkdir(parents=True)
    (tmp_path / "etc/yum.repos.d").mkdir(parents=True)
    (tmp_path / SOURCE).write_bytes(BEFORE)
    return tmp_path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def snapshot_source(host):
    file = host / SOURCE
    return file.read_bytes(), file.stat().st_mode, file.stat().st_ino


def test_stage_creates_private_fsynced_artifacts_but_never_edits_sources(host):
    before = snapshot_source(host)
    result = stage.stage(host, SOURCE, digest(BEFORE), PROPOSED)
    assert result["status"] == "prepared"
    assert re.fullmatch("[0-9a-f]{32}", result["id"])
    assert snapshot_source(host) == before
    assert stage.inspect(host, result["id"])["status"] == "prepared"

    directory = host / "var/lib/repocache-client/staging" / result["id"]
    for component in (directory, directory.parent, directory.parent.parent):
        assert stat.S_IMODE(component.stat().st_mode) == 0o700
    for name, data in (("original.bin", BEFORE), ("proposed.bin", PROPOSED)):
        item = directory / name
        assert item.read_bytes() == data
        assert stat.S_IMODE(item.stat().st_mode) == 0o600
    manifest = directory / "manifest.json"
    document = json.loads(manifest.read_text())
    assert document["source"] == SOURCE
    assert document["before_sha256"] == digest(BEFORE)
    assert document["proposed_sha256"] == digest(PROPOSED)
    assert stat.S_IMODE(manifest.stat().st_mode) == 0o600
    assert not list(directory.parent.glob("*.partial"))
    assert snapshot_source(host) == before


def test_identical_payload_is_a_true_no_op_without_state_creation(host):
    result = stage.stage(host, SOURCE, digest(BEFORE), BEFORE)
    assert result == {"status": "unchanged", "source": SOURCE}
    assert not (host / "var/lib/repocache-client").exists()


def test_repeated_staging_refuses_to_replace_original_snapshot(host):
    first = stage.stage(host, SOURCE, digest(BEFORE), PROPOSED)
    original = host / "var/lib/repocache-client/staging" / first["id"] / "original.bin"
    with pytest.raises(stage.StageError, match="pending stage"):
        stage.stage(host, SOURCE, digest(BEFORE), b"new proposal")
    assert original.read_bytes() == BEFORE
    assert stage.inspect(host, first["id"])["status"] == "prepared"


def test_drift_detects_source_replacement_even_when_bytes_match(host):
    ident = stage.stage(host, SOURCE, digest(BEFORE), PROPOSED)["id"]
    file = host / SOURCE
    substitute = file.with_suffix(".replacement")
    substitute.write_bytes(BEFORE)
    os.replace(substitute, file)
    assert stage.inspect(host, ident)["status"] == "drift"
    assert file.read_bytes() == BEFORE


@pytest.mark.parametrize("mutation", ("content", "mode", "missing", "symlink", "hardlink"))
def test_drift_detects_external_changes_and_never_repairs_them(host, mutation):
    ident = stage.stage(host, SOURCE, digest(BEFORE), PROPOSED)["id"]
    file = host / SOURCE
    if mutation == "content":
        file.write_bytes(b"edited by ansible\n")
    elif mutation == "mode":
        file.chmod(0o600)
    elif mutation == "missing":
        file.unlink()
    elif mutation == "symlink":
        file.unlink()
        file.symlink_to(host / "etc/os-release")
    else:
        os.link(file, file.parent / "second-link.list")
    assert stage.inspect(host, ident)["status"] == "drift"


def test_wrong_original_digest_fails_before_any_state_write(host):
    before = snapshot_source(host)
    with pytest.raises(stage.StageError, match="differs"):
        stage.stage(host, SOURCE, "0" * 64, PROPOSED)
    assert snapshot_source(host) == before
    assert not (host / "var/lib/repocache-client").exists()


@pytest.mark.parametrize("source", (
    "/etc/apt/sources.list",
    "etc/apt/../yum.repos.d/repo.repo",
    "etc/apt/sources.list.d/.hidden.list",
    "etc/apt/sources.list.d/file.conf",
    "etc/yum.repos.d/../../etc/shadow",
    "etc/repocache-client/config.json",
    "home/user/.ssh/authorized_keys",
    "etc/apt/mirrors/../sources.list",
))
def test_untrusted_source_path_is_rejected(host, source):
    with pytest.raises(stage.StageError, match="outside approved"):
        stage.stage(host, source, digest(BEFORE), PROPOSED)
    assert not (host / "var/lib/repocache-client").exists()


def test_parent_symlink_is_rejected_before_writes(host):
    source_dir = host / "etc/apt/sources.list.d"
    source_dir.rename(host / "etc/apt/real-sources")
    source_dir.symlink_to(host / "etc/apt/real-sources", target_is_directory=True)
    with pytest.raises(stage.StageError):
        stage.stage(host, SOURCE, digest(BEFORE), PROPOSED)
    assert not (host / "var/lib/repocache-client").exists()


def test_hardlinked_source_is_rejected(host):
    file = host / SOURCE
    os.link(file, file.parent / "linked.list")
    with pytest.raises(stage.StageError, match="Unsafe repository source"):
        stage.stage(host, SOURCE, digest(BEFORE), PROPOSED)


def test_world_writable_source_is_rejected(host):
    (host / SOURCE).chmod(0o666)
    with pytest.raises(stage.StageError, match="Unsafe repository source"):
        stage.stage(host, SOURCE, digest(BEFORE), PROPOSED)


def test_proposed_size_is_bounded_without_state_creation(host):
    with pytest.raises(stage.StageError, match="Invalid or oversized"):
        stage.stage(host, SOURCE, digest(BEFORE),
                    b"x" * (stage.MAX_SOURCE_BYTES + 1))
    assert not (host / "var/lib/repocache-client").exists()


def test_corrupt_private_payload_fails_closed(host):
    ident = stage.stage(host, SOURCE, digest(BEFORE), PROPOSED)["id"]
    path = host / "var/lib/repocache-client/staging" / ident / "proposed.bin"
    path.write_bytes(b"tampered")
    with pytest.raises(stage.StageError, match="checksum mismatch"):
        stage.inspect(host, ident)
    assert (host / SOURCE).read_bytes() == BEFORE


def test_symlinked_manifest_fails_closed(host):
    ident = stage.stage(host, SOURCE, digest(BEFORE), PROPOSED)["id"]
    path = host / "var/lib/repocache-client/staging" / ident / "manifest.json"
    path.unlink()
    path.symlink_to(host / SOURCE)
    with pytest.raises(stage.StageError):
        stage.inspect(host, ident)
    assert (host / SOURCE).read_bytes() == BEFORE


def test_incomplete_transaction_blocks_further_staging_and_inspection(host):
    first = stage.stage(host, SOURCE, digest(BEFORE), PROPOSED)["id"]
    staging = host / "var/lib/repocache-client/staging"
    (staging / ".deadbeef.partial").mkdir(mode=0o700)
    with pytest.raises(stage.StageError, match="Incomplete"):
        stage.inspect(host, first)
    (host / "etc/yum.repos.d/other.repo").write_bytes(b"[repo]\nenabled=0\n")
    with pytest.raises(stage.StageError, match="Incomplete"):
        stage.stage(host, "etc/yum.repos.d/other.repo",
                    digest(b"[repo]\nenabled=0\n"), b"[repo]\nenabled=1\n")


def test_nonblocking_lock_refuses_concurrent_staging(host):
    staging = stage._state(host, create=True)
    with stage._locked(staging):
        with pytest.raises(stage.StageBusy):
            stage.stage(host, SOURCE, digest(BEFORE), PROPOSED)
    assert (host / SOURCE).read_bytes() == BEFORE


def test_unsafe_lock_file_refuses_operation(host):
    staging = stage._state(host, create=True)
    lock = staging / ".stage.lock"
    lock.symlink_to(host / SOURCE)
    with pytest.raises(stage.StageError, match="lock"):
        stage.stage(host, SOURCE, digest(BEFORE), PROPOSED)
    assert (host / SOURCE).read_bytes() == BEFORE


def test_unsafe_state_permissions_refuse_stage(host):
    state = host / "var/lib/repocache-client"
    state.mkdir(mode=0o700)
    state.chmod(0o755)
    with pytest.raises(stage.StageError, match="private"):
        stage.stage(host, SOURCE, digest(BEFORE), PROPOSED)


def test_private_original_snapshot_is_never_exposed_through_cli(host):
    from importlib.util import spec_from_file_location, module_from_spec
    path = ROOT / "client/repocache_client.py"
    spec = spec_from_file_location("client_no_apply_test", path)
    client = module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(client)
    assert client.run(["--server", "https://cache.example.org",
                       "repos", "sync", "--apply"], root=host) == 2
    assert not (host / "var/lib/repocache-client").exists()
