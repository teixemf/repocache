"""Bounded Linux fixed-path lock + manifest reconciliation tests (#31)."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from repocache.server_locked_manifest_reconcile_v1 import (
    LockedManifestInspectionError,
    _inspect_locked_under_root,
    _match_manifest,
    _candidate_action,
    preview_proposed_v2_state_transition,
    _preview_recovery_under_root,
    preview_current_namespace_locked_candidate,
)
from repocache.server_protected_state_store_v1 import (
    JOURNAL_NAME, JOURNAL_TMP_NAME, LOCK_NAME, STAGE_NAME, STATE_NAME,
    ProtectedStateStoreError, _commit_under_root, _recover_under_root, _locked,
)


@pytest.fixture
def layout(tmp_path):
    root = tmp_path / "fixture"
    root.mkdir(mode=0o700)
    current = root
    for name in ("var", "lib", "repocache", "server"):
        current = current / name
        current.mkdir(mode=0o700)
    state_dir = current
    (state_dir / LOCK_NAME).write_bytes(b"")
    (state_dir / LOCK_NAME).chmod(0o600)

    include_dir = root
    for name in ("etc", "nginx", "conf.d"):
        include_dir = include_dir / name
        include_dir.mkdir(mode=0o700)
    rootfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield rootfd, state_dir, include_dir, os.geteuid()
    finally:
        os.close(rootfd)


def inspect(layout, generation=0):
    fd, _, _, owner = layout
    return _inspect_locked_under_root(
        fd, owner_uid=owner, expected_generation=generation
    )


def state(generation=1):
    return {
        "state_schema_version": 1,
        "state_generation": generation,
        "configuration_sha256": "a" * 64,
        "repositories": [],
        "ownership_manifest": [],
    }


def persist(layout, value, expected=0):
    fd, _, _, owner = layout
    return _commit_under_root(
        fd, value, expected_generation=expected, owner_uid=owner
    )


def include(layout, data=b"# managed test\n"):
    name = layout[2] / "repocache-managed.conf"
    name.write_bytes(data)
    name.chmod(0o640)
    return name


def test_empty_layout_inert_and_no_disk_effect(layout):
    _, state_dir, include_dir, _ = layout
    before = sorted(p.name for p in state_dir.iterdir())
    report = inspect(layout)
    assert report["status"] == "LOCKED_READ_ONLY_RECONCILIATION"
    assert report["include_status"] == "NO_MANAGED_INCLUDE"
    assert report["state_generation"] == 0
    assert report["exclusive_state_lock_held_during_inspection"] is True
    assert report["authorizes_write"] is False
    assert report["authorizes_nginx_reload"] is False
    assert report["authorizes_catalog_publication"] is False
    assert report["operator_authorization_verified"] is False
    assert report["protected_manifest_provenance_verified"] is False
    assert report["nginx_syntax_verified"] is False
    assert sorted(p.name for p in state_dir.iterdir()) == before
    assert list(include_dir.iterdir()) == []
    assert inspect(layout) == report


def test_existing_inert_protected_state_uses_actual_generation(layout):
    persist(layout, state())
    _, state_dir, _, _ = layout
    before = (state_dir / "state-v1.json").read_bytes()
    result = inspect(layout, 1)
    assert result["state_generation"] == 1
    assert result["manifest_entry_present"] is False
    assert (state_dir / "state-v1.json").read_bytes() == before
    with pytest.raises(LockedManifestInspectionError, match="GENERATION_STALE"):
        inspect(layout, 0)


@pytest.mark.parametrize("invalid", [-1, True, 2**63, None, "0"])
def test_generation_invalid_without_effects(layout, invalid):
    _, folder, _, _ = layout
    with pytest.raises(LockedManifestInspectionError, match="ARGUMENT_INVALID"):
        inspect(layout, invalid)
    assert sorted(p.name for p in folder.iterdir()) == [LOCK_NAME]


def test_existing_file_without_manifest_refused_even_if_safe(layout):
    path = include(layout)
    previous = path.read_bytes()
    with pytest.raises(LockedManifestInspectionError, match="FOREIGN"):
        inspect(layout)
    assert path.read_bytes() == previous


def test_existing_state_does_not_adopt_foreign_include(layout):
    persist(layout, state())
    path = include(layout)
    with pytest.raises(LockedManifestInspectionError, match="FOREIGN"):
        inspect(layout, 1)
    assert path.is_file()


@pytest.mark.parametrize("kind", ["symlink", "dangling", "hardlink", "fifo"])
def test_unsafe_managed_include_refused_and_not_modified(layout, kind, tmp_path):
    path = layout[2] / "repocache-managed.conf"
    if kind in ("symlink", "dangling"):
        path.symlink_to(
            tmp_path / "external" if kind == "dangling" else "/etc/hosts"
        )
    elif kind == "hardlink":
        source = tmp_path / "outside"
        source.write_bytes(b"foreign")
        os.link(source, path)
    else:
        os.mkfifo(path, mode=0o600)
    with pytest.raises(ValueError):
        inspect(layout)
    assert path.is_symlink() if kind in ("symlink", "dangling") else path.exists()


def test_generation_and_lock_stay_together(layout):
    fd, _, _, owner = layout
    with _locked(fd, owner):
        with pytest.raises(ProtectedStateStoreError, match="LOCK_UNAVAILABLE"):
            inspect(layout)


def test_pending_transaction_requires_explicit_recovery(layout):
    fd, state_dir, _, owner = layout

    def crash(phase):
        if phase == "journal_durable":
            raise RuntimeError("interrupted")

    with pytest.raises(RuntimeError):
        _commit_under_root(
            fd, state(), expected_generation=0,
            owner_uid=owner, inject_fault=crash
        )
    before = (state_dir / JOURNAL_NAME).read_bytes()
    with pytest.raises(LockedManifestInspectionError, match="RECOVERY_REQUIRED"):
        inspect(layout, 0)
    assert (state_dir / JOURNAL_NAME).read_bytes() == before
    assert not (state_dir / "state-v1.json").exists()


def test_orphan_pending_temp_refused_without_cleanup(layout):
    _, state_dir, _, _ = layout
    temp = state_dir / JOURNAL_TMP_NAME
    temp.write_bytes(b"partial journal")
    temp.chmod(0o600)
    with pytest.raises(LockedManifestInspectionError, match="RECOVERY_REQUIRED"):
        inspect(layout)
    assert temp.read_bytes() == b"partial journal"


def test_orphan_stage_refused_without_cleanup(layout):
    _, state_dir, _, _ = layout
    temp = state_dir / STAGE_NAME
    temp.write_bytes(b"unfinished")
    temp.chmod(0o600)
    with pytest.raises(LockedManifestInspectionError, match="RECOVERY_REQUIRED"):
        inspect(layout)
    assert temp.read_bytes() == b"unfinished"


def test_unsafe_state_directory_refused(layout):
    _, state_dir, _, _ = layout
    state_dir.chmod(0o777)
    with pytest.raises(ValueError):
        inspect(layout)


def test_untrusted_root_fd_or_uid_refused(layout):
    fd, _, _, owner = layout
    with pytest.raises(LockedManifestInspectionError):
        _inspect_locked_under_root(
            fd, owner_uid=owner, expected_generation=False
        )
    with pytest.raises(ValueError):
        _inspect_locked_under_root(
            fd, owner_uid=owner + 1, expected_generation=0
        )


def manifest_record(uid=0):
    return {
        "schema_version": 1, "generation": 1,
        "path": "/etc/nginx/conf.d/repocache-managed.conf",
        "sha256": hashlib.sha256(b"# managed test\n").hexdigest(),
        "uid": uid, "gid": 0, "mode": 0o640, "dev": 12, "ino": 34,
    }


def observed(uid=0):
    m = manifest_record(uid)
    return {
        "kind": "regular", "sha256": m["sha256"],
        "uid": m["uid"], "gid": m["gid"], "mode": m["mode"],
        "dev": m["dev"], "ino": m["ino"], "nlink": 1,
    }


def test_pure_metadata_match_does_not_infer_authorization():
    assert _match_manifest(
        [manifest_record()], observed(), expected_owner_uid=0
    ) == "MANIFEST_MATCHES_OBSERVED_INCLUDE"


@pytest.mark.parametrize("field", ["sha256", "uid", "gid", "mode", "dev", "ino"])
def test_every_owned_inode_field_must_match(field):
    obs = observed()
    obs[field] = ("f" * 64) if field == "sha256" else obs[field] + 1
    with pytest.raises(LockedManifestInspectionError):
        _match_manifest([manifest_record()], obs, expected_owner_uid=0)


def test_manifest_missing_and_foreign_paths_fail_closed():
    with pytest.raises(LockedManifestInspectionError, match="MISSING"):
        _match_manifest([manifest_record()], None, expected_owner_uid=0)
    with pytest.raises(LockedManifestInspectionError, match="FOREIGN"):
        _match_manifest([], observed(), expected_owner_uid=0)


def test_observed_hardlink_or_special_kind_refused():
    obs = observed()
    obs["nlink"] = 2
    with pytest.raises(LockedManifestInspectionError, match="UNSAFE"):
        _match_manifest([manifest_record()], obs, expected_owner_uid=0)
    obs = observed()
    obs["kind"] = "symlink"
    with pytest.raises(LockedManifestInspectionError, match="UNSAFE"):
        _match_manifest([manifest_record()], obs, expected_owner_uid=0)


def test_no_network_service_or_subprocess_side_effects(layout, monkeypatch):
    import socket
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected external operation")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert inspect(layout)["authorizes_write"] is False


def test_errors_never_echo_sensitive_bytes(layout):
    payload = b"private-token-will-not-be-shown"
    include(layout, payload)
    with pytest.raises(ValueError) as err:
        inspect(layout)
    assert payload.decode() not in str(err.value)
    assert str(layout[2]) not in str(err.value)


def test_current_namespace_root_entry_rejects_unprivileged_without_open(
    monkeypatch,
):
    import repocache.server_locked_manifest_reconcile_v1 as module
    monkeypatch.setattr(module.os, "geteuid", lambda: 1001)

    def unexpected(*args, **kwargs):
        raise AssertionError("must not open any host path")
    monkeypatch.setattr(module.os, "open", unexpected)
    with pytest.raises(
        LockedManifestInspectionError, match="ROOT_PRIVILEGE_REQUIRED"
    ):
        module.inspect_current_namespace_locked_manifest(expected_generation=0)


@pytest.mark.parametrize("bad", [True, -1, None, "1", 2**63])
def test_current_namespace_root_entry_validates_generation_before_open(
    monkeypatch, bad,
):
    import repocache.server_locked_manifest_reconcile_v1 as module
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    with pytest.raises(
        LockedManifestInspectionError, match="ARGUMENT_INVALID"
    ):
        module.inspect_current_namespace_locked_manifest(expected_generation=bad)


def test_current_namespace_root_entry_pins_real_root_before_and_after(
    monkeypatch,
):
    import repocache.server_locked_manifest_reconcile_v1 as module
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    visited = []

    def observe(fd, *, owner_uid, expected_generation):
        assert owner_uid == 0
        assert expected_generation == 6
        assert os.fstat(fd).st_ino == os.stat("/").st_ino
        visited.append(os.fstat(fd).st_ino)
        return {
            "authorizes_write": False,
            "authorizes_nginx_reload": False,
            "authorizes_catalog_publication": False,
        }
    monkeypatch.setattr(module, "_inspect_locked_under_root", observe)
    report = module.inspect_current_namespace_locked_manifest(
        expected_generation=6
    )
    assert report["current_namespace_root_path_verified"] is True
    assert report["authorizes_write"] is False
    assert report["authorizes_nginx_reload"] is False
    assert report["authorizes_catalog_publication"] is False
    assert len(visited) == 1


def test_current_namespace_root_entry_rejects_caller_root_substitution(
    layout, monkeypatch,
):
    import repocache.server_locked_manifest_reconcile_v1 as module
    fd, _, _, _ = layout
    real_open = os.open
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)

    def substitute(path, flags, *args, **kwargs):
        if path == "/":
            return os.dup(fd)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", substitute)
    with pytest.raises(
        LockedManifestInspectionError,
        match="ROOT_(CHANGED|UNVERIFIED)",
    ):
        module.inspect_current_namespace_locked_manifest(
            expected_generation=0
        )


def test_current_namespace_root_fd_is_not_a_fixture_authorization(layout):
    import repocache.server_locked_manifest_reconcile_v1 as module
    fd, _, _, _ = layout
    with pytest.raises(LockedManifestInspectionError):
        module._verify_current_root_fd(fd)


def preview(layout, content, generation=0):
    fd, _, _, uid = layout
    return _inspect_locked_under_root(
        fd, owner_uid=uid, expected_generation=generation,
        candidate_bytes=content,
    )


def test_locked_candidate_preview_idempotent_and_read_only(layout):
    _, state_dir, include_dir, _ = layout
    before = sorted(p.name for p in state_dir.iterdir())
    report = preview(layout, b"# candidate\n")
    assert preview(layout, b"# candidate\n") == report
    assert report["candidate_action"] == "WOULD_CREATE"
    assert report["candidate_preview_only"] is True
    for flag in ("authorizes_write", "authorizes_nginx_reload",
                 "authorizes_catalog_publication", "nginx_syntax_verified",
                 "operator_authorization_verified"):
        assert report[flag] is False
    assert sorted(p.name for p in state_dir.iterdir()) == before
    assert list(include_dir.iterdir()) == []


def test_candidate_actions_compare_digest_but_do_not_expose_it():
    assert _candidate_action(b"# managed test\n", observed()) == "UNCHANGED"
    assert _candidate_action(b"# revised\n", observed()) == "WOULD_REPLACE"
    assert _candidate_action(b"# new\n", None) == "WOULD_CREATE"


@pytest.mark.parametrize("bad", [
    b"", b"\x00", b"a" * (256 * 1024 + 1), b"\xff",
    "text", bytearray(b"text"), True,
])
def test_invalid_candidates_refused_without_disk_access(layout, bad):
    _, state_dir, include_dir, _ = layout
    before = sorted(p.name for p in state_dir.iterdir())
    with pytest.raises(LockedManifestInspectionError, match="MANAGED_CANDIDATE"):
        preview(layout, bad)
    assert sorted(p.name for p in state_dir.iterdir()) == before
    assert list(include_dir.iterdir()) == []


def test_preflight_refuses_foreign_file_without_replacement(layout):
    path = include(layout, b"external owner config")
    with pytest.raises(LockedManifestInspectionError, match="FOREIGN"):
        preview(layout, b"# replacement\n")
    assert path.read_bytes() == b"external owner config"


def test_preflight_refuses_stale_generation(layout):
    persist(layout, state())
    with pytest.raises(LockedManifestInspectionError, match="GENERATION_STALE"):
        preview(layout, b"# candidate\n", generation=0)


def test_preflight_refuses_lock_contention(layout):
    fd, _, _, uid = layout
    with _locked(fd, uid):
        with pytest.raises(ProtectedStateStoreError, match="LOCK_UNAVAILABLE"):
            preview(layout, b"# candidate\n")


def test_preflight_refuses_interrupted_state_transaction(layout):
    fd, folder, _, uid = layout

    def interrupt(phase):
        if phase == "journal_durable":
            raise RuntimeError("synthetic interruption")

    with pytest.raises(RuntimeError):
        _commit_under_root(fd, state(), expected_generation=0,
                           owner_uid=uid, inject_fault=interrupt)
    journal = (folder / JOURNAL_NAME).read_bytes()
    with pytest.raises(LockedManifestInspectionError, match="RECOVERY_REQUIRED"):
        preview(layout, b"# candidate\n")
    assert (folder / JOURNAL_NAME).read_bytes() == journal


def test_preflight_refuses_symlink_without_changes(layout, tmp_path):
    path = layout[2] / "repocache-managed.conf"
    path.symlink_to(tmp_path / "external")
    with pytest.raises(ValueError):
        preview(layout, b"# candidate\n")
    assert path.is_symlink()


def test_public_candidate_preflight_refuses_nonroot_before_open(monkeypatch):
    import repocache.server_locked_manifest_reconcile_v1 as module
    monkeypatch.setattr(module.os, "geteuid", lambda: 1001)

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected host access")

    monkeypatch.setattr(module.os, "open", forbidden)
    with pytest.raises(LockedManifestInspectionError, match="PRIVILEGE_REQUIRED"):
        preview_current_namespace_locked_candidate(
            expected_generation=0, candidate_bytes=b"# candidate\n",
        )


def test_public_candidate_preflight_rejects_bad_bytes_before_open(monkeypatch):
    import repocache.server_locked_manifest_reconcile_v1 as module

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected host access")

    monkeypatch.setattr(module.os, "open", forbidden)
    with pytest.raises(LockedManifestInspectionError, match="CANDIDATE_INVALID"):
        preview_current_namespace_locked_candidate(
            expected_generation=0, candidate_bytes=b"\x00",
        )


def test_candidate_preview_refuses_include_observation_change_without_mutation(
    layout, monkeypatch,
):
    import repocache.server_locked_manifest_reconcile_v1 as module
    # Model a hostile writer that does not honor the protected-state flock.
    # In production, this could be an external root actor racing in-place.
    actual = module.observe_managed_include_at
    calls = 0

    def substituted(parent_fd):
        nonlocal calls
        calls += 1
        snapshot = actual(parent_fd)
        if calls == 2:
            return {**snapshot, "observation": {
                "kind": "regular", "sha256": "e" * 64, "uid": 0,
                "gid": 0, "mode": 0o640, "dev": 1, "ino": 1,
                "nlink": 1,
            }}
        return snapshot

    monkeypatch.setattr(module, "observe_managed_include_at", substituted)
    with pytest.raises(
        LockedManifestInspectionError,
        match="MANAGED_INCLUDE_CHANGED_DURING_INSPECTION",
    ):
        preview(layout, b"# candidate\n")
    assert calls == 2
    assert not (layout[2] / "repocache-managed.conf").exists()


def test_candidate_preview_rechecks_absent_include_without_mutation(
    layout, monkeypatch,
):
    import repocache.server_locked_manifest_reconcile_v1 as module
    actual = module.observe_managed_include_at
    observations = []

    def record(parent_fd):
        observation = actual(parent_fd)
        observations.append(observation)
        return observation

    monkeypatch.setattr(module, "observe_managed_include_at", record)
    result = preview(layout, b"# candidate\n")
    assert result["candidate_action"] == "WOULD_CREATE"
    assert len(observations) == 2
    assert observations[0] == observations[1]
    assert not (layout[2] / "repocache-managed.conf").exists()


def recovery_preview(layout):
    fd, _, _, uid = layout
    return _preview_recovery_under_root(fd, owner_uid=uid)


def test_recovery_preview_clean_is_repeatable_and_read_only(layout):
    _, folder, includes, _ = layout
    before = sorted(p.name for p in folder.iterdir())
    report = recovery_preview(layout)
    assert recovery_preview(layout) == report
    assert report["recovery_action"] == "CLEAN"
    assert report["recovery_required"] is False
    assert report["observed_state_generation"] == 0
    for flag in (
        "recovery_executed", "authorizes_state_mutation",
        "authorizes_nginx_reload", "authorizes_catalog_publication",
        "operator_authorization_verified", "nginx_syntax_verified",
    ):
        assert report[flag] is False
    assert sorted(p.name for p in folder.iterdir()) == before
    assert list(includes.iterdir()) == []


@pytest.mark.parametrize(
    ("phase", "expected", "journal_file"),
    [
        ("journal_tmp_durable", "DISCARD_UNPUBLISHED_JOURNAL", JOURNAL_TMP_NAME),
        ("journal_durable", "ROLLBACK_PENDING_STATE", JOURNAL_NAME),
        ("stage_durable", "ROLLBACK_PENDING_STATE", JOURNAL_NAME),
        ("replace_durable", "ROLLBACK_PENDING_STATE", JOURNAL_NAME),
    ],
)
def test_recovery_preview_classifies_crashes_without_mutating(
    layout, phase, expected, journal_file,
):
    root, directory, _, uid = layout

    def crash(at):
        if at == phase:
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError, match="simulated crash"):
        _commit_under_root(
            root, state(), owner_uid=uid,
            expected_generation=0, inject_fault=crash,
        )
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    report = recovery_preview(layout)
    assert report["recovery_action"] == expected
    assert report["recovery_required"] is True
    assert report["recovery_executed"] is False
    assert journal_file in before
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == before
    assert recovery_preview(layout) == report

    # The separate, private fixture-only recovery still works afterwards.
    _recover_under_root(root, owner_uid=uid)
    assert recovery_preview(layout)["recovery_action"] == "CLEAN"


def test_recovery_preview_rejects_valid_but_unjournalled_state_drift(layout):
    root, directory, _, uid = layout

    def crash(phase):
        if phase == "replace_durable":
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError):
        _commit_under_root(
            root, state(), owner_uid=uid,
            expected_generation=0, inject_fault=crash,
        )
    previous = (directory / STATE_NAME).read_bytes()
    altered = previous.replace(b"a" * 64, b"b" * 64)
    assert altered != previous
    (directory / STATE_NAME).write_bytes(altered)
    with pytest.raises(LockedManifestInspectionError, match="RECOVERY_DRIFT"):
        recovery_preview(layout)
    assert (directory / STATE_NAME).read_bytes() == altered
    assert (directory / JOURNAL_NAME).is_file()


def test_recovery_preview_refuses_orphan_stage_without_cleanup(layout):
    _, directory, _, _ = layout
    stage = directory / STAGE_NAME
    stage.write_bytes(b"unfinished")
    stage.chmod(0o600)
    with pytest.raises(LockedManifestInspectionError, match="ORPHAN_STAGE"):
        recovery_preview(layout)
    assert stage.read_bytes() == b"unfinished"


def test_recovery_preview_refuses_lock_contention(layout):
    root, _, _, uid = layout
    with _locked(root, uid):
        with pytest.raises(ProtectedStateStoreError, match="LOCK_UNAVAILABLE"):
            recovery_preview(layout)


def test_recovery_preview_rechecks_pending_journal(layout, monkeypatch):
    import repocache.server_locked_manifest_reconcile_v1 as module
    root, directory, _, uid = layout

    def crash(phase):
        if phase == "journal_durable":
            raise RuntimeError("simulated crash")

    with pytest.raises(RuntimeError):
        _commit_under_root(
            root, state(), owner_uid=uid,
            expected_generation=0, inject_fault=crash,
        )
    actual = module._read_journal
    calls = 0

    def changed_read(fd, owner):
        nonlocal calls
        calls += 1
        value = actual(fd, owner)
        if calls == 2:
            assert value is not None
            old, _, original = value
            return old, "f" * 64, original
        return value

    monkeypatch.setattr(module, "_read_journal", changed_read)
    with pytest.raises(LockedManifestInspectionError, match="RECOVERY_INPUT_CHANGED"):
        recovery_preview(layout)
    assert calls == 2
    assert (directory / JOURNAL_NAME).is_file()


@pytest.mark.parametrize("bad", [True, -1, None, "0"])
def test_recovery_preview_rejects_invalid_fixture_root_without_fs_access(
    layout, bad,
):
    _, directory, _, uid = layout
    with pytest.raises(
        LockedManifestInspectionError, match="RECOVERY_PREVIEW_ARGUMENT_INVALID"
    ):
        _preview_recovery_under_root(bad, owner_uid=uid)
    assert sorted(p.name for p in directory.iterdir()) == [LOCK_NAME]



def test_public_recovery_preview_rejects_nonroot_before_open(monkeypatch):
    import repocache.server_locked_manifest_reconcile_v1 as module
    monkeypatch.setattr(module.os, "geteuid", lambda: 1001)

    def forbidden(*args, **kwargs):
        raise AssertionError("unprivileged caller accessed host path")

    monkeypatch.setattr(module.os, "open", forbidden)
    with pytest.raises(
        LockedManifestInspectionError, match="ROOT_PRIVILEGE_REQUIRED"
    ):
        module.inspect_current_namespace_locked_recovery()


def test_public_recovery_preview_pins_current_root_before_and_after(
    monkeypatch,
):
    import repocache.server_locked_manifest_reconcile_v1 as module
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    root_checks = []
    observed_fd = []
    original_verify = module._verify_current_root_fd

    def verified(fd):
        original_verify(fd)
        root_checks.append(os.fstat(fd).st_ino)

    def inspect(fd, *, owner_uid):
        assert owner_uid == 0
        assert os.fstat(fd).st_ino == os.stat("/").st_ino
        observed_fd.append(fd)
        return {
            "status": "LOCKED_READ_ONLY_RECOVERY_PREVIEW",
            "recovery_action": "CLEAN",
            "recovery_executed": False,
            "authorizes_state_mutation": False,
            "authorizes_nginx_reload": False,
            "authorizes_catalog_publication": False,
        }

    monkeypatch.setattr(module, "_verify_current_root_fd", verified)
    monkeypatch.setattr(module, "_preview_recovery_under_root", inspect)
    result = module.inspect_current_namespace_locked_recovery()
    assert len(root_checks) == 2
    assert len(observed_fd) == 1
    assert result["current_namespace_root_path_verified"] is True
    assert result["recovery_action"] == "CLEAN"
    assert result["recovery_executed"] is False
    assert result["authorizes_state_mutation"] is False
    assert result["authorizes_nginx_reload"] is False
    assert result["authorizes_catalog_publication"] is False
    with pytest.raises(OSError):
        os.fstat(observed_fd[0])


def test_public_recovery_preview_rejects_substituted_fixture_root(
    layout, monkeypatch,
):
    import repocache.server_locked_manifest_reconcile_v1 as module
    fixture_fd, _, _, _ = layout
    actual_open = os.open
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)

    def replaced(path, flags, *args, **kwargs):
        if path == "/":
            return os.dup(fixture_fd)
        return actual_open(path, flags, *args, **kwargs)

    def forbidden(*args, **kwargs):
        raise AssertionError("recovery preview must not inspect substitute")

    monkeypatch.setattr(module.os, "open", replaced)
    monkeypatch.setattr(module, "_preview_recovery_under_root", forbidden)
    with pytest.raises(LockedManifestInspectionError, match="ROOT_(CHANGED|UNVERIFIED)"):
        module.inspect_current_namespace_locked_recovery()


def test_public_recovery_preview_closes_root_after_refusal(monkeypatch):
    import repocache.server_locked_manifest_reconcile_v1 as module
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    visited = []

    def refused(fd, *, owner_uid):
        assert owner_uid == 0
        visited.append(fd)
        raise LockedManifestInspectionError("SYNTHETIC_RECOVERY_REFUSAL")

    monkeypatch.setattr(module, "_preview_recovery_under_root", refused)
    with pytest.raises(
        LockedManifestInspectionError, match="SYNTHETIC_RECOVERY_REFUSAL"
    ):
        module.inspect_current_namespace_locked_recovery()
    assert len(visited) == 1
    with pytest.raises(OSError):
        os.fstat(visited[0])



def v2_install_document(count=2, *, generation=1):
    example = (Path(__file__).resolve().parents[1] /
               "docs/examples/server-install-v1.json")
    document = json.loads(example.read_text(encoding="utf-8"))
    document["expected_state_generation"] = generation
    template = document["repositories"][0]
    repos = []
    for index in range(count):
        item = copy.deepcopy(template)
        item["id"] = f"repo-{index}"
        item["upstream"]["base_url"] = (
            f"https://mirror{index}.example.invalid/debian/"
        )
        item["upstream"]["allowed_hosts"] = [
            f"mirror{index}.example.invalid"
        ]
        repos.append(item)
    document["repositories"] = repos
    return document


def proposed_v2_state(document, *, generation, prior=None):
    from repocache.server_repository_plan_v1 import _canonical_identity
    doc = copy.deepcopy(document)
    doc["expected_state_generation"] = generation
    raw = json.dumps(
        doc, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    records = []
    for repo in doc["repositories"]:
        records.append({
            "id": repo["id"],
            "canonical_identity_sha256": hashlib.sha256(
                _canonical_identity(repo).encode("utf-8")
            ).hexdigest(),
            "desired_state": repo["desired_state"],
            "observed_state": "not-activated",
        })
    reservations = [{
        "id": item["id"],
        "canonical_identity_sha256": item["canonical_identity_sha256"],
        "status": "allocated",
    } for item in records]
    if prior is not None:
        existing = {row["id"]: row for row in reservations}
        for item in prior["id_reservations"]:
            if item["id"] not in existing:
                reservations.append({
                    **item,
                    "status": "retired",
                })
    return {
        "state_schema_version": 2,
        "state_generation": generation,
        "configuration_base64": base64.b64encode(raw).decode("ascii"),
        "configuration_sha256": hashlib.sha256(raw).hexdigest(),
        "repository_records": records,
        "id_reservations": reservations,
        "approval_reference": {
            "source": "operator",
            "decision_sha256": "d" * 64,
            "configuration_sha256": hashlib.sha256(raw).hexdigest(),
            "expected_generation": generation - 1,
        },
    }


def v2_preview(candidate, *, expected=0, previous=None):
    return preview_proposed_v2_state_transition(
        candidate, expected_generation=expected,
        previous_snapshot=previous,
    )


@pytest.mark.parametrize("count", [0, 2, 32, 33, 500])
def test_proposed_v2_contract_scales_without_changing_store_v1(count):
    doc = v2_install_document(count)
    snapshot = proposed_v2_state(doc, generation=1)
    report = v2_preview(snapshot)
    assert report["status"] == "PROPOSED_UNTRUSTED_V2_CONTRACT_ONLY"
    assert report["repository_count"] == count
    assert report["reserved_id_count"] == count
    assert report["configuration_digest_matches_canonical_payload"] is True
    for flag in (
        "operator_authorization_verified",
        "protected_snapshot_provenance_verified",
        "reservation_history_authoritative",
        "observed_nginx_exposure_verified",
        "native_transaction_verified",
        "authorizes_write",
        "authorizes_nginx_reload",
        "authorizes_catalog_publication",
        "authorizes_cache_cleanup",
    ):
        assert report[flag] is False
    from repocache.server_protected_state_store_v1 import (
        ProtectedStateStoreError, validate_protected_state,
    )
    # A proposed v2 snapshot is never silently treated as v1 persisted state.
    with pytest.raises(ProtectedStateStoreError):
        validate_protected_state(snapshot)


def test_proposed_v2_retirement_preserves_id_and_identity():
    original = v2_install_document()
    prev = proposed_v2_state(original, generation=1)
    next_doc = copy.deepcopy(original)
    next_doc["repositories"] = next_doc["repositories"][:1]
    next_state = proposed_v2_state(next_doc, generation=2, prior=prev)
    report = v2_preview(next_state, expected=1, previous=prev)
    assert report["removed_repository_count"] == 1
    assert report["repository_count"] == 1
    assert report["reserved_id_count"] == 2
    assert next_state["id_reservations"][-1]["status"] == "retired"
    # An id that was ever retired cannot be silently made active again.
    resurrected = copy.deepcopy(next_state)
    resurrected["id_reservations"][-1]["status"] = "allocated"
    with pytest.raises(LockedManifestInspectionError, match="RESERVATION"):
        v2_preview(resurrected, expected=1, previous=prev)


def test_proposed_v2_retired_id_cannot_reappear_in_later_generation():
    start = proposed_v2_state(v2_install_document(), generation=1)
    reduced = v2_install_document(1)
    removed = proposed_v2_state(reduced, generation=2, prior=start)
    readded = proposed_v2_state(v2_install_document(), generation=3)
    with pytest.raises(LockedManifestInspectionError, match="RESERVATION"):
        v2_preview(readded, expected=2, previous=removed)


@pytest.mark.parametrize("mutation", [
    "digest", "payload", "schema", "intent", "identity", "reservation",
    "approval", "generation", "unknown", "observed", "uncanonical",
])
def test_proposed_v2_rejects_untrusted_or_inconsistent_inputs(mutation):
    snapshot = proposed_v2_state(v2_install_document(), generation=1)
    if mutation == "digest":
        snapshot["configuration_sha256"] = "b" * 64
    elif mutation == "payload":
        snapshot["configuration_base64"] = base64.b64encode(
            b'{"private-token":"no"}'
        ).decode("ascii")
    elif mutation == "schema":
        snapshot["state_schema_version"] = 1
    elif mutation == "intent":
        snapshot["repository_records"][0]["desired_state"] = "active"
    elif mutation == "identity":
        snapshot["repository_records"][0]["canonical_identity_sha256"] = "f" * 64
    elif mutation == "reservation":
        snapshot["id_reservations"].pop()
    elif mutation == "approval":
        snapshot["approval_reference"]["configuration_sha256"] = "a" * 64
    elif mutation == "generation":
        snapshot["state_generation"] = 2
    elif mutation == "unknown":
        snapshot["new_permission"] = True
    elif mutation == "observed":
        snapshot["repository_records"][0]["observed_state"] = "verified-active"
    else:
        raw = base64.b64decode(snapshot["configuration_base64"])
        snapshot["configuration_base64"] = base64.b64encode(
            raw + b" "
        ).decode("ascii")
        snapshot["configuration_sha256"] = hashlib.sha256(
            raw + b" "
        ).hexdigest()
        snapshot["approval_reference"]["configuration_sha256"] = (
            snapshot["configuration_sha256"]
        )
    with pytest.raises(LockedManifestInspectionError, match="PROPOSED_V2_"):
        v2_preview(snapshot)


def test_proposed_v2_fail_closed_on_501_repositories():
    snapshot = proposed_v2_state(v2_install_document(501), generation=1)
    with pytest.raises(LockedManifestInspectionError, match="PROPOSED_V2_"):
        v2_preview(snapshot)


def test_proposed_v2_rejects_disappeared_tombstone_and_changed_identity():
    old = proposed_v2_state(v2_install_document(2), generation=1)
    same = proposed_v2_state(v2_install_document(2), generation=2, prior=old)
    same["id_reservations"] = same["id_reservations"][:-1]
    with pytest.raises(LockedManifestInspectionError, match="RESERVATION"):
        v2_preview(same, expected=1, previous=old)
    changed = proposed_v2_state(v2_install_document(2), generation=2)
    changed["id_reservations"][0]["canonical_identity_sha256"] = "e" * 64
    with pytest.raises(LockedManifestInspectionError, match="RESERVATION"):
        v2_preview(changed, expected=1, previous=old)


@pytest.mark.parametrize("bad", [None, True, -1, 2**63, "0"])
def test_proposed_v2_rejects_invalid_expected_generation(bad):
    state = proposed_v2_state(v2_install_document(), generation=1)
    with pytest.raises(LockedManifestInspectionError, match="EXPECTED_GENERATION"):
        v2_preview(state, expected=bad)


def test_proposed_v2_does_not_touch_host_or_mutate_caller(monkeypatch):
    import socket
    import subprocess
    original = proposed_v2_state(v2_install_document(), generation=1)
    before = copy.deepcopy(original)

    def forbidden(*args, **kwargs):
        raise AssertionError("side effect in pure v2 contract check")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(os, "replace", forbidden)
    assert v2_preview(original)["authorizes_write"] is False
    assert original == before
