"""Linux FD fixture-only v2 durability, crash and legacy-migration refusals."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from repocache.server_repository_plan_v1 import _canonical_identity
from repocache.server_protected_state_store_v1 import (
    JOURNAL_NAME as LEGACY_JOURNAL,
    LOCK_NAME,
    ProtectedStateStoreError,
    _commit_under_root as commit_legacy,
    _recover_under_root as recover_legacy,
    _locked,
)
from repocache.server_proposed_state_v2_store import (
    MAX_V2_STATE_BYTES, V2_JOURNAL, V2_JOURNAL_TMP, V2_ROLLBACK,
    V2_STAGE, V2_STATE,
    ProposedV2PersistenceError,
    _commit_proposed_v2_under_root as commit,
    _recover_proposed_v2_under_root as recover,
    _preview_persisted_v2_nginx_candidate_under_root as render_persisted,
)


@pytest.fixture
def fixture_root(tmp_path):
    root = tmp_path / "mock-root"
    root.mkdir(mode=0o700)
    folder = root
    for segment in ("var", "lib", "repocache", "server"):
        folder = folder / segment
        folder.mkdir(mode=0o700)
    (folder / LOCK_NAME).write_bytes(b"")
    (folder / LOCK_NAME).chmod(0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield fd, folder, os.geteuid()
    finally:
        os.close(fd)


def document(count=2, *, generation=1):
    example = (Path(__file__).resolve().parents[1] /
               "docs/examples/server-install-v1.json")
    source = json.loads(example.read_text(encoding="utf-8"))
    source["expected_state_generation"] = generation
    original = source["repositories"][0]
    repos = []
    for index in range(count):
        row = copy.deepcopy(original)
        row["id"] = f"repo-{index}"
        row["upstream"]["base_url"] = (
            f"https://mirror{index}.example.invalid/debian/"
        )
        row["upstream"]["allowed_hosts"] = [
            f"mirror{index}.example.invalid"
        ]
        repos.append(row)
    source["repositories"] = repos
    return source


def snapshot(count=2, *, generation=1, previous=None, doc=None):
    config = copy.deepcopy(doc if doc is not None else document(count))
    config["expected_state_generation"] = generation
    raw = json.dumps(
        config, sort_keys=True, ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    records = [{
        "id": row["id"],
        "canonical_identity_sha256": hashlib.sha256(
            _canonical_identity(row).encode("utf-8")
        ).hexdigest(),
        "desired_state": row["desired_state"],
        "observed_state": "not-activated",
    } for row in config["repositories"]]
    reserved = [{
        "id": rec["id"],
        "canonical_identity_sha256": rec["canonical_identity_sha256"],
        "status": "allocated",
    } for rec in records]
    if previous is not None:
        existing = {rec["id"] for rec in reserved}
        for row in previous["id_reservations"]:
            if row["id"] not in existing:
                reserved.append({**row, "status": "retired"})
    sha = hashlib.sha256(raw).hexdigest()
    return {
        "state_schema_version": 2,
        "state_generation": generation,
        "configuration_base64": base64.b64encode(raw).decode("ascii"),
        "configuration_sha256": sha,
        "repository_records": records,
        "id_reservations": reserved,
        "approval_reference": {
            "source": "operator",
            "decision_sha256": "d" * 64,
            "configuration_sha256": sha,
            "expected_generation": generation - 1,
        },
    }


def apply(layout, candidate, expected=0, inject=None):
    fd, _, uid = layout
    return commit(
        fd, candidate, expected_generation=expected,
        owner_uid=uid, inject_fault=inject,
    )


def rollback(layout):
    fd, _, uid = layout
    return recover(fd, owner_uid=uid)


def assert_no_authority(report):
    for field in (
        "operator_authorization_verified",
        "host_root_provenance_verified",
        "authorizes_installation",
        "authorizes_nginx_reload",
        "authorizes_catalog_publication",
        "authorizes_cache_cleanup",
    ):
        assert report[field] is False


def test_v2_bootstrap_reads_exact_canonical_bytes_and_recovers_clean(fixture_root):
    _, folder, _ = fixture_root
    requested = snapshot(33)
    report = apply(fixture_root, requested)
    assert report["status"] == "COMMITTED_INERT_V2"
    assert report["state_generation"] == 1
    assert_no_authority(report)
    raw = (folder / V2_STATE).read_bytes()
    assert json.loads(raw) == requested
    assert (folder / V2_STATE).stat().st_mode & 0o777 == 0o600
    assert not (folder / V2_JOURNAL).exists()
    assert not (folder / V2_STAGE).exists()
    assert rollback(fixture_root)["status"] == "CLEAN"
    assert (folder / V2_STATE).read_bytes() == raw


def test_v2_noop_does_not_create_generation_or_change_inode(fixture_root):
    _, folder, _ = fixture_root
    first = snapshot(2)
    apply(fixture_root, first)
    before = (folder / V2_STATE).stat()
    second = snapshot(2, generation=2, previous=first)
    status = apply(fixture_root, second, expected=1)
    assert status["status"] == "NO_CHANGE_INERT_V2"
    assert status["state_generation"] == 1
    assert (folder / V2_STATE).stat().st_ino == before.st_ino
    assert not (folder / V2_JOURNAL).exists()
    assert rollback(fixture_root)["state_generation"] == 1


def test_v2_retirement_durable_and_stale_cas_refused(fixture_root):
    _, folder, _ = fixture_root
    first = snapshot()
    apply(fixture_root, first)
    reduced = document(1)
    later = snapshot(generation=2, previous=first, doc=reduced)
    assert apply(fixture_root, later, expected=1)["state_generation"] == 2
    saved = json.loads((folder / V2_STATE).read_bytes())
    assert len(saved["repository_records"]) == 1
    assert len(saved["id_reservations"]) == 2
    assert saved["id_reservations"][-1]["status"] == "retired"
    with pytest.raises(ProposedV2PersistenceError, match="STALE_GENERATION"):
        apply(fixture_root, snapshot(generation=2), expected=1)
    assert json.loads((folder / V2_STATE).read_bytes()) == saved


@pytest.mark.parametrize(
    "phase",
    ["journal_tmp_durable", "journal_durable", "stage_durable", "replace_durable"],
)
@pytest.mark.parametrize("bootstrap", [True, False])
def test_v2_crash_recovery_restores_exact_previous_bytes(
    fixture_root, phase, bootstrap,
):
    _, folder, _ = fixture_root
    previous = None
    baseline = None
    generation = 0
    if not bootstrap:
        previous = snapshot()
        apply(fixture_root, previous)
        baseline = (folder / V2_STATE).read_bytes()
        generation = 1
    candidate = snapshot(
        count=1, generation=generation + 1,
        previous=previous,
    )
    def interrupt(point):
        if point == phase:
            raise RuntimeError("synthetic crash")

    with pytest.raises(RuntimeError, match="synthetic crash"):
        apply(fixture_root, candidate, expected=generation, inject=interrupt)
    journal_file = (V2_JOURNAL_TMP if phase == "journal_tmp_durable"
                    else V2_JOURNAL)
    assert (folder / journal_file).exists()
    with pytest.raises(ProposedV2PersistenceError, match="RECOVERY_REQUIRED"):
        apply(fixture_root, candidate, expected=generation)
    report = rollback(fixture_root)
    assert report["status"] in (
        "DISCARDED_UNPUBLISHED_V2_JOURNAL", "ROLLED_BACK_INERT_V2"
    )
    assert report["state_generation"] == generation
    assert_no_authority(report)
    assert not (folder / V2_JOURNAL).exists()
    assert not (folder / V2_JOURNAL_TMP).exists()
    assert not (folder / V2_STAGE).exists()
    if baseline is None:
        assert not (folder / V2_STATE).exists()
    else:
        assert (folder / V2_STATE).read_bytes() == baseline
    assert rollback(fixture_root)["status"] == "CLEAN"
    assert apply(fixture_root, candidate, expected=generation)["status"] == (
        "COMMITTED_INERT_V2"
    )


def test_v2_recovery_refuses_changed_authoritative_bytes(fixture_root):
    _, folder, _ = fixture_root
    start = snapshot()
    apply(fixture_root, start)
    future = snapshot(count=1, generation=2, previous=start)
    def crash(point):
        if point == "replace_durable":
            raise RuntimeError("crash")
    with pytest.raises(RuntimeError):
        apply(fixture_root, future, expected=1, inject=crash)
    altered = (folder / V2_STATE).read_bytes().replace(
        b'"state_schema_version":2', b'"state_schema_version":9'
    )
    assert altered != (folder / V2_STATE).read_bytes()
    (folder / V2_STATE).write_bytes(altered)
    with pytest.raises(ProposedV2PersistenceError, match="STATE_DRIFT"):
        rollback(fixture_root)
    assert (folder / V2_STATE).read_bytes() == altered
    assert (folder / V2_JOURNAL).is_file()


def test_v2_recovery_retry_after_simulated_rename_failure(
    fixture_root, monkeypatch,
):
    import repocache.server_proposed_state_v2_store as module
    _, folder, _ = fixture_root
    first = snapshot()
    apply(fixture_root, first)
    raw = (folder / V2_STATE).read_bytes()
    next_state = snapshot(count=1, generation=2, previous=first)

    def crash(phase):
        if phase == "replace_durable":
            raise RuntimeError("crash")

    with pytest.raises(RuntimeError):
        apply(fixture_root, next_state, expected=1, inject=crash)
    original = os.replace

    def fail_rollback(src, dst, *args, **kwargs):
        if src == V2_ROLLBACK:
            raise OSError("synthetic rename refusal")
        return original(src, dst, *args, **kwargs)

    monkeypatch.setattr(module.os, "replace", fail_rollback)
    with pytest.raises(ProposedV2PersistenceError, match="ROLLBACK_IO_REFUSED"):
        rollback(fixture_root)
    assert (folder / V2_JOURNAL).exists()
    monkeypatch.setattr(module.os, "replace", original)
    assert rollback(fixture_root)["status"] == "ROLLED_BACK_INERT_V2"
    assert (folder / V2_STATE).read_bytes() == raw
    assert rollback(fixture_root)["status"] == "CLEAN"


def test_v2_orphan_stage_refused_without_deletion(fixture_root):
    _, folder, _ = fixture_root
    (folder / V2_STAGE).write_bytes(b"unexpected")
    (folder / V2_STAGE).chmod(0o600)
    with pytest.raises(ProposedV2PersistenceError, match="ORPHAN"):
        rollback(fixture_root)
    assert (folder / V2_STAGE).read_bytes() == b"unexpected"


def test_v2_symlink_and_lock_contention_refused(fixture_root, tmp_path):
    fd, folder, uid = fixture_root
    (folder / V2_STATE).symlink_to(tmp_path / "external")
    with pytest.raises(ProtectedStateStoreError):
        rollback(fixture_root)
    (folder / V2_STATE).unlink()
    with _locked(fd, uid):
        with pytest.raises(ProtectedStateStoreError, match="LOCK_UNAVAILABLE"):
            apply(fixture_root, snapshot())


def test_v2_never_adopts_existing_v1_state(fixture_root):
    fd, folder, uid = fixture_root
    legacy = {
        "state_schema_version": 1, "state_generation": 1,
        "configuration_sha256": "a" * 64,
        "repositories": [], "ownership_manifest": [],
    }
    commit_legacy(
        fd, legacy, owner_uid=uid, expected_generation=0
    )
    initial = (folder / "state-v1.json").read_bytes()
    with pytest.raises(ProposedV2PersistenceError, match="LEGACY_MIGRATION_REQUIRED"):
        apply(fixture_root, snapshot())
    with pytest.raises(ProposedV2PersistenceError, match="LEGACY_MIGRATION_REQUIRED"):
        rollback(fixture_root)
    assert (folder / "state-v1.json").read_bytes() == initial
    assert not (folder / V2_STATE).exists()


def test_v2_never_adopts_unfinished_v1_journal(fixture_root):
    fd, folder, uid = fixture_root
    legacy = {
        "state_schema_version": 1, "state_generation": 1,
        "configuration_sha256": "a" * 64,
        "repositories": [], "ownership_manifest": [],
    }

    def interrupted(phase):
        if phase == "journal_durable":
            raise RuntimeError("crash")

    with pytest.raises(RuntimeError):
        commit_legacy(
            fd, legacy, owner_uid=uid, expected_generation=0,
            inject_fault=interrupted,
        )
    assert (folder / LEGACY_JOURNAL).is_file()
    with pytest.raises(ProposedV2PersistenceError, match="LEGACY_RECOVERY_REQUIRED"):
        apply(fixture_root, snapshot())
    assert (folder / LEGACY_JOURNAL).is_file()
    assert not (folder / V2_STATE).exists()


def test_v2_full_500_repository_snapshot_is_durable(fixture_root):
    _, folder, _ = fixture_root
    candidate = snapshot(500)
    report = apply(fixture_root, candidate)
    assert report["state_generation"] == 1
    raw = (folder / V2_STATE).read_bytes()
    assert 1_000_000 > len(raw) > 90_000
    assert json.loads(raw)["repository_records"][499]["id"] == "repo-499"
    assert rollback(fixture_root)["status"] == "CLEAN"


def test_v2_large_retired_ledger_fits_separate_bounds(fixture_root):
    _, folder, _ = fixture_root
    candidate = snapshot(2)
    for i in range(2, 10_000):
        candidate["id_reservations"].append({
            "id": f"retired-{i}",
            "canonical_identity_sha256": hashlib.sha256(
                f"history-{i}".encode()
            ).hexdigest(),
            "status": "retired",
        })
    report = apply(fixture_root, candidate)
    assert report["status"] == "COMMITTED_INERT_V2"
    raw = (folder / V2_STATE).read_bytes()
    assert 1_000_000 < len(raw) < MAX_V2_STATE_BYTES
    assert rollback(fixture_root)["status"] == "CLEAN"


def test_v2_invalid_candidate_causes_no_disk_effect(fixture_root):
    _, folder, _ = fixture_root
    bad = snapshot()
    bad["configuration_sha256"] = "0" * 64
    before = sorted(p.name for p in folder.iterdir())
    with pytest.raises(ProposedV2PersistenceError, match="SNAPSHOT_INVALID"):
        apply(fixture_root, bad)
    assert sorted(p.name for p in folder.iterdir()) == before



def test_legacy_writer_and_reader_refuse_existing_v2_state(fixture_root):
    from repocache.server_locked_manifest_reconcile_v1 import (
        _inspect_locked_under_root,
    )
    fd, folder, uid = fixture_root
    proposed = snapshot()
    apply(fixture_root, proposed)
    v2_bytes = (folder / V2_STATE).read_bytes()
    legacy = {
        "state_schema_version": 1, "state_generation": 1,
        "configuration_sha256": "a" * 64,
        "repositories": [], "ownership_manifest": [],
    }
    with pytest.raises(ProtectedStateStoreError, match="V2_COHABITATION_REFUSED"):
        commit_legacy(fd, legacy, expected_generation=0, owner_uid=uid)
    with pytest.raises(ProtectedStateStoreError, match="V2_COHABITATION_REFUSED"):
        recover_legacy(fd, owner_uid=uid)
    with pytest.raises(ProtectedStateStoreError, match="V2_COHABITATION_REFUSED"):
        _inspect_locked_under_root(
            fd, owner_uid=uid, expected_generation=0,
        )
    assert not (folder / "state-v1.json").exists()
    assert (folder / V2_STATE).read_bytes() == v2_bytes


def test_legacy_writer_refuses_interrupted_v2_journal(fixture_root):
    fd, folder, uid = fixture_root
    legacy = {
        "state_schema_version": 1, "state_generation": 1,
        "configuration_sha256": "a" * 64,
        "repositories": [], "ownership_manifest": [],
    }

    def crash(phase):
        if phase == "journal_durable":
            raise RuntimeError("crash")

    with pytest.raises(RuntimeError):
        apply(fixture_root, snapshot(), inject=crash)
    pending = (folder / V2_JOURNAL).read_bytes()
    with pytest.raises(ProtectedStateStoreError, match="V2_COHABITATION_REFUSED"):
        commit_legacy(fd, legacy, expected_generation=0, owner_uid=uid)
    with pytest.raises(ProtectedStateStoreError, match="V2_COHABITATION_REFUSED"):
        recover_legacy(fd, owner_uid=uid)
    assert (folder / V2_JOURNAL).read_bytes() == pending
    assert not (folder / "state-v1.json").exists()
    assert rollback(fixture_root)["status"] == "ROLLED_BACK_INERT_V2"


def test_legacy_writer_refuses_dangling_v2_symlink(fixture_root):
    fd, folder, uid = fixture_root
    link = folder / V2_STATE
    link.symlink_to(folder / "missing-target")
    legacy = {
        "state_schema_version": 1, "state_generation": 1,
        "configuration_sha256": "a" * 64,
        "repositories": [], "ownership_manifest": [],
    }
    with pytest.raises(ProtectedStateStoreError, match="V2_COHABITATION_REFUSED"):
        commit_legacy(fd, legacy, expected_generation=0, owner_uid=uid)
    assert link.is_symlink()
    assert not (folder / "state-v1.json").exists()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires Linux fork")
@pytest.mark.parametrize(
    "phase",
    ["journal_tmp_durable", "journal_durable", "stage_durable", "replace_durable"],
)
@pytest.mark.parametrize("upgrade", [False, True])
def test_real_process_exit_and_recovery_in_second_process(
    fixture_root, phase, upgrade,
):
    """A child exits without Python cleanup after fsync; new PID recovers."""
    _, folder, _ = fixture_root
    old = snapshot() if upgrade else None
    generation = 1 if upgrade else 0
    old_bytes = None
    if upgrade:
        apply(fixture_root, old)
        old_bytes = (folder / V2_STATE).read_bytes()
    proposal = snapshot(count=1, generation=generation + 1, previous=old)

    pid = os.fork()
    if pid == 0:
        def stop(point):
            if point == phase:
                os._exit(73)
        try:
            apply(fixture_root, proposal, expected=generation, inject=stop)
        except BaseException:
            os._exit(74)
        os._exit(75)

    waited, status = os.waitpid(pid, 0)
    assert waited == pid and os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 73
    pending = V2_JOURNAL_TMP if phase == "journal_tmp_durable" else V2_JOURNAL
    assert (folder / pending).is_file()
    with pytest.raises(ProposedV2PersistenceError, match="RECOVERY_REQUIRED"):
        apply(fixture_root, proposal, expected=generation)

    other = os.fork()
    if other == 0:
        try:
            report = rollback(fixture_root)
            assert report["state_generation"] == generation
            assert report["status"] in (
                "DISCARDED_UNPUBLISHED_V2_JOURNAL", "ROLLED_BACK_INERT_V2",
            )
            assert_no_authority(report)
        except BaseException:
            os._exit(76)
        os._exit(0)

    waited, status = os.waitpid(other, 0)
    assert waited == other and os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 0
    assert not (folder / V2_JOURNAL).exists()
    assert not (folder / V2_JOURNAL_TMP).exists()
    assert not (folder / V2_STAGE).exists()
    if old_bytes is None:
        assert not (folder / V2_STATE).exists()
    else:
        assert (folder / V2_STATE).read_bytes() == old_bytes
    assert rollback(fixture_root)["status"] == "CLEAN"
    assert apply(fixture_root, proposal, expected=generation)["status"] == (
        "COMMITTED_INERT_V2"
    )



def two_layout_active_snapshot():
    source = (Path(__file__).resolve().parents[1] /
              "docs/examples/server-install-v1.json")
    doc = json.loads(source.read_text(encoding="utf-8"))
    doc["expected_state_generation"] = 1
    doc["repositories"][1]["id"] = "almalinux-baseos"
    for repository in doc["repositories"]:
        repository["desired_state"] = "active"
    return snapshot(generation=1, doc=doc)


def pinned_two_layouts():
    return {
        name: {"mirror.example.invalid": ["8.8.8.8", "2001:4860:4860::8888"]}
        for name in ("debian-trixie-main", "almalinux-baseos")
    }


def persisted_render(layout, *, generation=1, pins=None):
    fd, _, uid = layout
    return render_persisted(
        fd, owner_uid=uid, expected_generation=generation,
        candidate_pins_by_repository=(
            pinned_two_layouts() if pins is None else pins
        ),
        ca_bundle_path="/etc/ssl/certs/ca-certificates.crt",
    )


def test_locked_persisted_v2_produces_only_non_authorizing_nginx_candidate(
    fixture_root,
):
    _, folder, _ = fixture_root
    state = two_layout_active_snapshot()
    apply(fixture_root, state)
    before = (folder / V2_STATE).read_bytes()
    result = persisted_render(fixture_root)
    assert result["status"] == "LOCKED_FIXTURE_V2_NGINX_CANDIDATE_ONLY"
    assert result["proposed_repository_ids"] == [
        "almalinux-baseos", "debian-trixie-main",
    ]
    assert "proxy_ssl_verify on;" in result["server_location_fragment"]
    assert "proxy_ssl_server_name on;" in result["server_location_fragment"]
    assert "proxy_pass https://" in result["server_location_fragment"]
    assert "proxy_pass http://" not in result["server_location_fragment"]
    assert result["persisted_config_bytes_and_digest_consistent"] is True
    assert result["exclusive_state_lock_held_during_preview"] is True
    for key in (
        "trusted_host_root_verified", "operator_authorization_verified",
        "live_include_manifest_verified", "nginx_syntax_verified",
        "active_exposure_verified", "authorizes_nginx_activation",
        "authorizes_catalog_publication",
    ):
        assert result[key] is False
    assert (folder / V2_STATE).read_bytes() == before
    assert not (folder / V2_JOURNAL).exists()


@pytest.mark.parametrize("bad", [
    {}, {"debian-trixie-main": {"mirror.example.invalid": ["8.8.8.8"]}},
    {**pinned_two_layouts(), "unknown-repo": {"mirror.example.invalid": ["8.8.8.8"]}},
    {**pinned_two_layouts(), "almalinux-baseos": {
        "mirror.example.invalid": ["169.254.169.254"],
    }},
    {**pinned_two_layouts(), "almalinux-baseos": {
        "wrong.example.invalid": ["8.8.8.8"],
    }},
])
def test_locked_persisted_v2_refuses_missing_extra_unsafe_pins(
    fixture_root, bad,
):
    _, folder, _ = fixture_root
    apply(fixture_root, two_layout_active_snapshot())
    original = (folder / V2_STATE).read_bytes()
    with pytest.raises(ProposedV2PersistenceError, match="NGINX_CANDIDATE_REFUSED"):
        persisted_render(fixture_root, pins=bad)
    assert (folder / V2_STATE).read_bytes() == original
    assert not (folder / V2_JOURNAL).exists()


def test_locked_persisted_v2_refuses_stale_and_uncommitted_state(fixture_root):
    fd, folder, uid = fixture_root
    with pytest.raises(ProposedV2PersistenceError, match="STATE_ABSENT"):
        persisted_render(fixture_root)
    old = two_layout_active_snapshot()
    apply(fixture_root, old)
    with pytest.raises(ProposedV2PersistenceError, match="STALE_GENERATION"):
        persisted_render(fixture_root, generation=2)

    updated = snapshot(count=1, generation=2, previous=old)
    def stop(phase):
        if phase == "journal_durable":
            raise RuntimeError("interrupt")

    with pytest.raises(RuntimeError):
        apply(fixture_root, updated, expected=1, inject=stop)
    with pytest.raises(ProposedV2PersistenceError, match="RECOVERY_REQUIRED"):
        persisted_render(fixture_root)
    assert rollback(fixture_root)["state_generation"] == 1
    assert persisted_render(fixture_root)["proposed_repository_ids"] == [
        "almalinux-baseos", "debian-trixie-main",
    ]


def test_locked_persisted_v2_renderer_refuses_lock_contention(fixture_root):
    fd, _, uid = fixture_root
    apply(fixture_root, two_layout_active_snapshot())
    with _locked(fd, uid):
        with pytest.raises(ProtectedStateStoreError, match="LOCK_UNAVAILABLE"):
            persisted_render(fixture_root)


@pytest.mark.skipif(
    shutil.which("nginx") is None,
    reason="disposable distro-packaged nginx unavailable",
)
def test_persisted_v2_nginx_t_succeeds_without_touching_live_config(
    fixture_root, tmp_path,
):
    ca = next((
        p for p in (
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
        ) if Path(p).is_file()
    ), None)
    if ca is None:
        pytest.skip("disposable container CA bundle unavailable")
    state = two_layout_active_snapshot()
    apply(fixture_root, state)
    fd, folder, uid = fixture_root
    pinned = render_persisted(
        fd, owner_uid=uid, expected_generation=1,
        candidate_pins_by_repository=pinned_two_layouts(),
        ca_bundle_path=ca,
    )
    assert pinned["nginx_syntax_verified"] is False
    before = (folder / V2_STATE).read_bytes()
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        f"pid {tmp_path / 'nginx.pid'};\n"
        f"error_log {tmp_path / 'nginx-error.log'} notice;\n"
        "events {}\nhttp { access_log off;\n"
        + pinned["http_upstream_fragment"]
        + "server { listen 127.0.0.1:19991;\n"
        + pinned["server_location_fragment"]
        + "}\n}\n",
        encoding="utf-8",
    )
    finished = subprocess.run(
        [shutil.which("nginx"), "-t", "-c", str(conf), "-p", str(tmp_path)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert finished.returncode == 0, finished.stderr
    assert (folder / V2_STATE).read_bytes() == before
    assert not (folder / V2_JOURNAL).exists()
