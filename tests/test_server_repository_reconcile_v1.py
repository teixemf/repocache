"""No-effect v1 declarative reconciliation tests for #95 / #18."""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from repocache.server_install_v1 import InstallInputError
from repocache.server_repository_plan_v1 import _canonical_identity
from repocache.server_repository_reconcile_v1 import (
    ReconciliationPlanError,
    plan_declarative_reconciliation,
    preview_declarative_state_alignment,
    plan_inert_persistence_transition,
    preview_declarative_nginx_candidate,
    preview_repository_lifecycle_nginx_candidate,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"


def document() -> dict:
    data = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    data["repositories"][1]["id"] = "almalinux-baseos"
    return data


def preview(current: dict, proposed: dict) -> dict:
    return plan_declarative_reconciliation(
        current, proposed, current_generation=0
    )


def test_empty_submission_preserves_repositories_and_does_not_write():
    current = document()
    proposed = copy.deepcopy(current)
    proposed["repositories"] = []
    old_current, old_proposed = copy.deepcopy(current), copy.deepcopy(proposed)
    result = preview(current, proposed)
    assert result["status"] == "PLAN_ONLY"
    assert result["authorizes_installation"] is False
    assert result["changed"] is False
    assert result["candidate_document"] == current
    assert result["preserved_ids"] == ["almalinux-baseos", "debian-trixie-main"]
    assert result["implicit_policy_ids"] == []
    assert current == old_current
    assert proposed == old_proposed


def test_global_policy_change_affects_omitted_repositories():
    current = document()
    proposed = copy.deepcopy(current)
    proposed["repositories"] = []
    old_max = current["deployment"]["cache_policy"]["global"]["max_size_bytes"]
    proposed["deployment"]["cache_policy"]["global"]["max_size_bytes"] = old_max + 1024
    result = preview(current, proposed)
    assert result["changed"] is True
    assert result["explicit_changed_ids"] == []
    assert result["implicit_policy_ids"] == ["almalinux-baseos", "debian-trixie-main"]
    for change in result["effective_policy_changes"]:
        assert change["fields"] == ["max_size_bytes"]
        assert change["before"]["max_size_bytes"]["value"] == old_max
        assert change["after"]["max_size_bytes"]["value"] == old_max + 1024
        assert change["explicitly_listed"] is False
    assert result["candidate_document"]["repositories"] == current["repositories"]
    assert current["deployment"]["cache_policy"]["global"]["max_size_bytes"] == old_max


def test_per_repository_override_prevents_inherited_implicit_change():
    current = document()
    current["repositories"][0]["cache_overrides"] = {"max_size_bytes": 12345}
    proposed = copy.deepcopy(current)
    proposed["repositories"] = []
    proposed["deployment"]["cache_policy"]["global"]["max_size_bytes"] += 1024
    result = preview(current, proposed)
    assert result["implicit_policy_ids"] == ["almalinux-baseos"]
    assert result["candidate_document"]["repositories"][0]["cache_overrides"] == {
        "max_size_bytes": 12345
    }


def test_explicit_update_preserves_other_repository_and_identity():
    current = document()
    proposed = copy.deepcopy(current)
    proposed["repositories"] = [copy.deepcopy(current["repositories"][0])]
    proposed["repositories"][0]["desired_state"] = "active"
    result = preview(current, proposed)
    assert result["explicit_changed_ids"] == ["debian-trixie-main"]
    assert result["preserved_ids"] == ["almalinux-baseos"]
    assert result["candidate_document"]["repositories"][1] == current["repositories"][1]
    assert result["authorizes_installation"] is False
    assert result["status"] == "PLAN_ONLY"


def test_new_repository_and_missing_durable_ids_refused():
    current = document()
    proposed = copy.deepcopy(current)
    proposed["repositories"][0]["id"] = "new-identifier"
    with pytest.raises(ReconciliationPlanError, match="reservation"):
        preview(current, proposed)
    del current["repositories"][0]["id"]
    with pytest.raises(ReconciliationPlanError, match="durable IDs"):
        preview(current, copy.deepcopy(current))


@pytest.mark.parametrize("generation", [None, True, -1, 1, 2**63, "0"])
def test_generation_must_match_both_documents(generation):
    current = document()
    proposed = copy.deepcopy(current)
    with pytest.raises(ReconciliationPlanError):
        plan_declarative_reconciliation(
            current, proposed, current_generation=generation
        )
    proposed["expected_state_generation"] = 1
    with pytest.raises(ReconciliationPlanError, match="stale"):
        preview(current, proposed)


def test_partial_submission_cannot_collide_with_preserved_identity():
    current = document()
    proposed = copy.deepcopy(current)
    duplicate = copy.deepcopy(current["repositories"][0])
    duplicate["id"] = "almalinux-baseos"
    proposed["repositories"] = [duplicate]
    with pytest.raises(InstallInputError, match="duplicate canonical"):
        preview(current, proposed)


def test_invalid_nested_policy_is_refused_before_preview():
    current = document()
    proposed = copy.deepcopy(current)
    proposed["repositories"] = []
    proposed["deployment"]["cache_policy"]["global"]["extra"] = "private-token"
    with pytest.raises(InstallInputError) as exc:
        preview(current, proposed)
    assert "private-token" not in str(exc.value)


def test_no_network_process_or_host_writes(monkeypatch):
    import os
    import socket
    import subprocess
    def forbidden(*_args, **_kwargs):
        raise AssertionError("no external effects permitted")
    monkeypatch.setattr(os, "replace", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    current = document()
    proposed = copy.deepcopy(current)
    proposed["repositories"] = []
    result = preview(current, proposed)
    assert result["status"] == "PLAN_ONLY"


def test_semantically_equivalent_list_order_is_a_true_noop():
    """Unordered lists cannot trigger generation churn or policy changes."""
    current = document()
    repo = current["repositories"][0]
    repo["layout"]["suites"] = ["trixie", "bookworm"]
    repo["layout"]["components"] = ["main", "contrib"]
    repo["upstream"]["allowed_hosts"] = [
        "mirror.example.invalid", "backup.example.invalid"
    ]
    repo["layout"]["release_key_refs"] = [
        "file:/etc/repocache/keys/a.gpg",
        "file:/etc/repocache/keys/b.gpg",
    ]
    proposed = copy.deepcopy(current)
    proposed["repositories"] = [copy.deepcopy(repo)]
    for key in ("suites", "components", "release_key_refs"):
        proposed["repositories"][0]["layout"][key].reverse()
    proposed["repositories"][0]["upstream"]["allowed_hosts"].reverse()
    del proposed["repositories"][0]["cache_overrides"]
    result = preview(current, proposed)
    assert result["changed"] is False
    assert result["explicit_changed_ids"] == []
    assert result["implicit_policy_ids"] == []
    assert result["candidate_document"] == current


def test_explicit_change_of_trust_policy_is_not_silenced_by_identity():
    current = document()
    proposed = copy.deepcopy(current)
    proposed["repositories"] = [copy.deepcopy(current["repositories"][0])]
    proposed["repositories"][0]["layout"]["release_key_refs"] = [
        "file:/etc/repocache/keys/other.gpg"
    ]
    result = preview(current, proposed)
    assert result["changed"] is True
    assert result["explicit_changed_ids"] == ["debian-trixie-main"]
    assert result["candidate_document"]["repositories"][0]["layout"]["release_key_refs"] == [
        "file:/etc/repocache/keys/other.gpg"
    ]


def _inert_state_snapshot(config: dict, *, generation: int = 1) -> dict:
    return {
        "state_schema_version": 1,
        "state_generation": generation,
        # The inert state schema only checks the digest's shape. There is NO
        # accepted config-byte binding or provenance in this pure preview.
        "configuration_sha256": "a" * 64,
        "repositories": [
            {
                "id": repo["id"],
                "canonical_identity_sha256": hashlib.sha256(
                    _canonical_identity(repo).encode("utf-8")
                ).hexdigest(),
                "approval": {"source": "operator", "decision_sha256": "b" * 64},
                "desired_state": repo["desired_state"],
                "observed_state": "not-activated",
            }
            for repo in config["repositories"]
        ],
        "ownership_manifest": [],
    }


def test_untrusted_state_alignment_is_never_authorization():
    config = document()
    config["expected_state_generation"] = 1
    config["repositories"][0]["desired_state"] = "active"
    state = _inert_state_snapshot(config)
    before = copy.deepcopy(state)
    result = preview_declarative_state_alignment(
        config, state, current_generation=1
    )
    assert result["status"] == "UNTRUSTED_ALIGNMENT_ONLY"
    assert result["aligned_repository_ids"] == [
        "almalinux-baseos", "debian-trixie-main"
    ]
    assert result["requires_trusted_locked_recheck"] is True
    for field in (
        "configuration_digest_verified", "approval_provenance_verified",
        "observed_exposure_verified", "reservation_history_verified",
        "authorizes_installation", "authorizes_nginx_reload",
        "authorizes_catalog_publication", "authorizes_cache_cleanup",
    ):
        assert result[field] is False
    assert state == before


@pytest.mark.parametrize("which", [
    "missing", "extra", "duplicate", "identity", "intent", "invalid_schema",
])
def test_untrusted_state_alignment_refuses_drift(which):
    config = document()
    config["expected_state_generation"] = 1
    state = _inert_state_snapshot(config)
    if which == "missing":
        state["repositories"].pop()
    elif which == "extra":
        state["repositories"].append({
            **copy.deepcopy(state["repositories"][0]), "id": "extraneous"
        })
    elif which == "duplicate":
        state["repositories"][1]["id"] = state["repositories"][0]["id"]
    elif which == "identity":
        state["repositories"][0]["canonical_identity_sha256"] = "f" * 64
    elif which == "intent":
        state["repositories"][0]["desired_state"] = "active"
    else:
        state["repositories"][0]["observed_state"] = "active"
    with pytest.raises(ReconciliationPlanError, match="state alignment"):
        preview_declarative_state_alignment(
            config, state, current_generation=1
        )


@pytest.mark.parametrize("generation", [-1, 0, True, "1", 2**63])
def test_untrusted_state_alignment_refuses_invalid_generation(generation):
    config = document()
    config["expected_state_generation"] = 1
    with pytest.raises(ReconciliationPlanError):
        preview_declarative_state_alignment(
            config, _inert_state_snapshot(config), current_generation=generation
        )


def test_untrusted_state_alignment_detects_stale_snapshots_and_missing_ids():
    config = document()
    config["expected_state_generation"] = 1
    state = _inert_state_snapshot(config)
    state["state_generation"] = 2
    with pytest.raises(ReconciliationPlanError, match="stale state"):
        preview_declarative_state_alignment(config, state, current_generation=1)
    state["state_generation"] = 1
    config["expected_state_generation"] = 2
    with pytest.raises(ReconciliationPlanError, match="stale configuration"):
        preview_declarative_state_alignment(config, state, current_generation=1)
    config["expected_state_generation"] = 1
    del config["repositories"][0]["id"]
    with pytest.raises(ReconciliationPlanError, match="durable IDs"):
        preview_declarative_state_alignment(config, state, current_generation=1)


def test_untrusted_state_alignment_never_promises_a_config_digest():
    config = document()
    config["expected_state_generation"] = 1
    state = _inert_state_snapshot(config)
    # An untrusted shape-valid digest is not evidence of the actual config.
    state["configuration_sha256"] = "f" * 64
    result = preview_declarative_state_alignment(
        config, state, current_generation=1
    )
    assert result["configuration_digest_verified"] is False
    assert result["authorizes_catalog_publication"] is False


def test_untrusted_state_alignment_is_immutable_and_has_no_host_effects(monkeypatch):
    import os
    import socket
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("host effects are forbidden")

    monkeypatch.setattr(os, "replace", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    config = document()
    config["expected_state_generation"] = 1
    state = _inert_state_snapshot(config)
    old_config = copy.deepcopy(config)
    old_state = copy.deepcopy(state)
    preview_declarative_state_alignment(config, state, current_generation=1)
    assert config == old_config
    assert state == old_state


def test_inert_persistence_intent_for_one_explicit_state_change():
    config = document()
    config["expected_state_generation"] = 1
    proposed = copy.deepcopy(config)
    proposed["repositories"] = [copy.deepcopy(config["repositories"][0])]
    proposed["repositories"][0]["desired_state"] = "active"
    state = _inert_state_snapshot(config)
    original = copy.deepcopy(state)

    result = plan_inert_persistence_transition(
        config, proposed, state, current_generation=1
    )
    assert result["status"] == "PLAN_ONLY"
    assert result["changed"] is True
    assert result["expected_state_generation"] == 1
    assert result["proposed_state_generation"] == 2
    assert result["fresh_approval_required_ids"] == ["debian-trixie-main"]
    assert result["deployment_approval_required"] is False
    assert {item["id"] for item in result["repository_intents"]} == {
        "debian-trixie-main", "almalinux-baseos"
    }
    assert result["repository_intents"][1]["desired_state"] == "active"
    assert result["repository_intents"][1]["observed_state"] == "not-activated"
    for field in (
        "authorizes_state_commit", "authorizes_nginx_reload",
        "authorizes_catalog_publication", "authorizes_cache_cleanup",
        "configuration_digest_binding_verified",
        "reservation_history_verified", "approval_provenance_verified",
    ):
        assert result[field] is False
    assert result["requires_trusted_locked_recheck"] is True
    assert state == original
    assert config["repositories"][0]["desired_state"] == "disabled"
    # This preview is NOT a complete candidate accepted by #31's writer.
    from repocache.server_protected_state_store_v1 import (
        ProtectedStateStoreError, validate_protected_state,
    )
    with pytest.raises(ProtectedStateStoreError):
        validate_protected_state(result)


def test_inert_persistence_preserves_unmentioned_and_noop_generation():
    config = document()
    config["expected_state_generation"] = 1
    proposed = copy.deepcopy(config)
    proposed["repositories"] = []
    result = plan_inert_persistence_transition(
        config, proposed, _inert_state_snapshot(config), current_generation=1
    )
    assert not result["changed"]
    assert result["proposed_state_generation"] == 1
    assert result["fresh_approval_required_ids"] == []
    assert len(result["repository_intents"]) == 2


def test_inert_persistence_global_policy_change_requires_broad_approval():
    config = document()
    config["expected_state_generation"] = 1
    proposed = copy.deepcopy(config)
    proposed["repositories"] = []
    proposed["deployment"]["cache_policy"]["global"]["max_size_bytes"] += 1024
    result = plan_inert_persistence_transition(
        config, proposed, _inert_state_snapshot(config), current_generation=1
    )
    assert result["deployment_approval_required"] is True
    assert result["fresh_approval_required_ids"] == [
        "almalinux-baseos", "debian-trixie-main"
    ]
    assert result["authorizes_state_commit"] is False


@pytest.mark.parametrize("mutation", ["host", "path", "layout"])
def test_inert_persistence_refuses_reassigning_stable_identity(mutation):
    config = document()
    config["expected_state_generation"] = 1
    proposed = copy.deepcopy(config)
    proposed["repositories"] = [copy.deepcopy(config["repositories"][0])]
    repo = proposed["repositories"][0]
    if mutation == "host":
        repo["upstream"]["base_url"] = "https://new.example.invalid/debian/"
        repo["upstream"]["allowed_hosts"] = ["new.example.invalid"]
    elif mutation == "path":
        repo["upstream"]["base_url"] = "https://mirror.example.invalid/other/"
    else:
        repo["layout"]["suites"] = ["bookworm"]
    with pytest.raises(ReconciliationPlanError, match="identity reassignment"):
        plan_inert_persistence_transition(
            config, proposed, _inert_state_snapshot(config), current_generation=1
        )


def test_inert_persistence_detects_drift_before_persisting_anything():
    config = document()
    config["expected_state_generation"] = 1
    proposed = copy.deepcopy(config)
    state = _inert_state_snapshot(config)
    state["repositories"][0]["desired_state"] = "active"
    with pytest.raises(ReconciliationPlanError, match="identity or intent mismatch"):
        plan_inert_persistence_transition(
            config, proposed, state, current_generation=1
        )


def test_inert_persistence_rejects_exhausted_generation():
    config = document()
    config["expected_state_generation"] = (2**63 - 1)
    with pytest.raises(ReconciliationPlanError, match="generation exhausted"):
        plan_inert_persistence_transition(
            config, copy.deepcopy(config),
            _inert_state_snapshot(config, generation=2**63 - 1),
            current_generation=2**63 - 1,
        )


def test_inert_persistence_fixture_only_transaction_and_stale_cas(tmp_path):
    """Prove interoperability with #31's PRIVATE fixture writer only.

    A test explicitly invents approval/config-hash values; these are not
    authenticated, safe production provenance or an operator permission API.
    """
    import os
    from repocache.server_protected_state_store_v1 import (
        LOCK_NAME, STATE_NAME, ProtectedStateStoreError,
        _commit_under_root, _recover_under_root,
    )
    root = tmp_path / "mock-root"
    root.mkdir(mode=0o700)
    folder = root
    for part in ("var", "lib", "repocache", "server"):
        folder = folder / part
        folder.mkdir(mode=0o700)
    (folder / LOCK_NAME).write_bytes(b"")
    (folder / LOCK_NAME).chmod(0o600)

    config = document()
    config["expected_state_generation"] = 1
    proposed = copy.deepcopy(config)
    proposed["repositories"] = [copy.deepcopy(config["repositories"][0])]
    proposed["repositories"][0]["desired_state"] = "active"
    initial = _inert_state_snapshot(config)
    intent = plan_inert_persistence_transition(
        config, proposed, initial, current_generation=1
    )
    # Fixture-only synthetic provenance, NOT supplied by this module/API.
    candidate = copy.deepcopy(initial)
    candidate["state_generation"] = 2
    candidate["configuration_sha256"] = "c" * 64
    for projection in intent["repository_intents"]:
        row = next(r for r in candidate["repositories"] if r["id"] == projection["id"])
        row["desired_state"] = projection["desired_state"]
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        uid = os.geteuid()
        assert _commit_under_root(
            fd, initial, expected_generation=0, owner_uid=uid
        )["status"] == "COMMITTED_INERT_STATE"
        assert _commit_under_root(
            fd, candidate, expected_generation=1, owner_uid=uid
        )["status"] == "COMMITTED_INERT_STATE"
        saved = json.loads((folder / STATE_NAME).read_bytes())
        assert saved == candidate
        assert (folder / STATE_NAME).stat().st_mode & 0o777 == 0o600
        assert _recover_under_root(fd, owner_uid=uid)["status"] == "CLEAN"
        with pytest.raises(ProtectedStateStoreError, match="STALE_GENERATION"):
            _commit_under_root(
                fd, candidate, expected_generation=1, owner_uid=uid
            )
    finally:
        os.close(fd)


def test_inert_persistence_preview_does_not_call_writer(monkeypatch):
    import repocache.server_protected_state_store_v1 as store
    def forbidden(*args, **kwargs):
        raise AssertionError("fixture writer must never be invoked by a preview")
    monkeypatch.setattr(store, "_commit_under_root", forbidden)
    config = document()
    config["expected_state_generation"] = 1
    result = plan_inert_persistence_transition(
        config, copy.deepcopy(config),
        _inert_state_snapshot(config), current_generation=1,
    )
    assert result["authorizes_state_commit"] is False


# #95 + merged #28 candidate integration: pure preview, never a live route.


_CA = "/etc/ssl/certs/ca-certificates.crt"
_HOST = "mirror.example.invalid"
_PUBLIC_PINS = {_HOST: ["8.8.8.8", "2001:4860:4860::8888"]}


def _nginx_preview(current, proposed, *, state=None, pins=None, ca=_CA):
    if state is None:
        state = _inert_state_snapshot(current)
    if pins is None:
        pins = {
            row["id"]: copy.deepcopy(_PUBLIC_PINS)
            for row in proposed["repositories"]
            if row["desired_state"] == "active"
        }
    return preview_declarative_nginx_candidate(
        current, proposed, state, current_generation=1,
        candidate_pins_by_repository=pins, ca_bundle_path=ca,
    )


def test_declarative_enable_generates_pinned_nginx_candidate_without_authority():
    current = document()
    current["expected_state_generation"] = 1
    proposed = copy.deepcopy(current)
    proposed["repositories"] = [copy.deepcopy(current["repositories"][0])]
    proposed["repositories"][0]["desired_state"] = "active"
    before = copy.deepcopy(current), copy.deepcopy(proposed)
    result = _nginx_preview(current, proposed)
    assert result["status"] == "UNTRUSTED_NGINX_CANDIDATE_ONLY"
    assert result["declarative_change_requested"] is True
    assert result["expected_state_generation"] == 1
    assert result["proposed_state_generation"] == 2
    assert result["fresh_approval_required_ids"] == ["debian-trixie-main"]
    assert result["desired_new_route_ids"] == ["debian-trixie-main"]
    assert result["desired_withdraw_route_ids"] == []
    assert result["desired_retained_route_ids"] == []
    assert result["proposed_repository_ids"] == ["debian-trixie-main"]
    assert result["pin_count"] == 2
    assert "upstream repocache_pin_debian_trixie_main" in result["http_upstream_fragment"]
    assert "server 8.8.8.8:443;" in result["http_upstream_fragment"]
    assert "server mirror.example.invalid:" not in result["http_upstream_fragment"]
    assert "location ^~ /__repocache/repos/" in result["server_location_fragment"]
    assert "proxy_ssl_verify on;" in result["server_location_fragment"]
    assert "proxy_ssl_server_name on;" in result["server_location_fragment"]
    assert "proxy_pass $" not in result["server_location_fragment"]
    assert "catalog_artifact" not in result
    assert "discovery" not in result
    assert result["requires_nginx_t_and_activation"] is True
    assert result["requires_trusted_locked_recheck"] is True
    for field in (
        "trusted_state_provenance_verified", "operator_approval_verified",
        "active_exposure_verified", "configuration_digest_binding_verified",
        "reservation_history_verified", "authorizes_state_commit",
        "authorizes_nginx_activation", "authorizes_catalog_publication",
        "authorizes_cache_cleanup",
    ):
        assert result[field] is False
    assert (current, proposed) == before


def test_declarative_disable_withdraws_only_desired_route_and_retains_cache():
    current = document()
    current["expected_state_generation"] = 1
    current["repositories"][0]["desired_state"] = "active"
    proposed = copy.deepcopy(current)
    proposed["repositories"] = [copy.deepcopy(current["repositories"][0])]
    proposed["repositories"][0]["desired_state"] = "disabled"
    result = _nginx_preview(current, proposed, pins={})
    assert result["desired_withdraw_route_ids"] == ["debian-trixie-main"]
    assert result["desired_new_route_ids"] == []
    assert result["proposed_repository_ids"] == []
    assert result["http_upstream_fragment"] == ""
    assert result["server_location_fragment"] == ""
    assert result["authorizes_cache_cleanup"] is False
    assert result["authorizes_catalog_publication"] is False


def test_declarative_preview_preserves_omitted_active_repository():
    current = document()
    current["expected_state_generation"] = 1
    current["repositories"][0]["desired_state"] = "active"
    proposed = copy.deepcopy(current)
    proposed["repositories"] = []
    result = _nginx_preview(
        current, proposed,
        pins={"debian-trixie-main": copy.deepcopy(_PUBLIC_PINS)},
    )
    assert result["declarative_change_requested"] is False
    assert result["proposed_state_generation"] == 1
    assert result["desired_retained_route_ids"] == ["debian-trixie-main"]
    assert result["proposed_repository_ids"] == ["debian-trixie-main"]


def test_declarative_preview_renders_both_supported_layouts_deterministically():
    current = document()
    current["expected_state_generation"] = 1
    proposed = copy.deepcopy(current)
    for repo in proposed["repositories"]:
        repo["desired_state"] = "active"
    both = {
        "debian-trixie-main": copy.deepcopy(_PUBLIC_PINS),
        "almalinux-baseos": copy.deepcopy(_PUBLIC_PINS),
    }
    first = _nginx_preview(current, proposed, pins=both)
    assert first["proposed_repository_ids"] == [
        "almalinux-baseos", "debian-trixie-main",
    ]
    assert first["server_location_fragment"].count("location ^~ /__repocache/repos/") == 2
    reversed_current = copy.deepcopy(current)
    reversed_current["repositories"].reverse()
    reversed_proposed = copy.deepcopy(proposed)
    reversed_proposed["repositories"].reverse()
    flipped = {
        k: {_HOST: list(reversed(v[_HOST]))}
        for k, v in reversed(list(both.items()))
    }
    second = _nginx_preview(reversed_current, reversed_proposed, pins=flipped)
    # Only the generated, sorted NGINX candidate matters, not input order.
    assert first["http_upstream_fragment"] == second["http_upstream_fragment"]
    assert first["server_location_fragment"] == second["server_location_fragment"]


@pytest.mark.parametrize("bad", [
    {},
    {"debian-trixie-main": copy.deepcopy(_PUBLIC_PINS),
     "almalinux-baseos": copy.deepcopy(_PUBLIC_PINS)},
    {"debian-trixie-main": {_HOST: ["127.0.0.1"]}},
    {"debian-trixie-main": {_HOST: ["8.8.8.8", "169.254.169.254"]}},
    {"debian-trixie-main": {"private.example.invalid": ["8.8.8.8"]}},
    [],
])
def test_declarative_nginx_preview_refuses_incomplete_foreign_unsafe_pins(bad):
    current = document()
    current["expected_state_generation"] = 1
    proposed = copy.deepcopy(current)
    proposed["repositories"][0]["desired_state"] = "active"
    with pytest.raises(ReconciliationPlanError, match="nginx preview: unsafe candidate") as exc:
        _nginx_preview(current, proposed, pins=bad)
    assert "169.254.169.254" not in str(exc.value)
    assert "private.example.invalid" not in str(exc.value)


def test_declarative_nginx_preview_checks_ca_even_without_routes():
    current = document()
    current["expected_state_generation"] = 1
    with pytest.raises(ReconciliationPlanError, match="nginx preview: unsafe candidate"):
        _nginx_preview(current, copy.deepcopy(current), ca="../not-a-ca")


def test_declarative_nginx_preview_refuses_protected_state_drift():
    current = document()
    current["expected_state_generation"] = 1
    proposed = copy.deepcopy(current)
    state = _inert_state_snapshot(current)
    state["repositories"][0]["canonical_identity_sha256"] = "0" * 64
    with pytest.raises(ReconciliationPlanError, match="state alignment"):
        _nginx_preview(current, proposed, state=state, pins={})


def test_declarative_nginx_preview_rejects_identity_reassignment():
    current = document()
    current["expected_state_generation"] = 1
    proposed = copy.deepcopy(current)
    proposed["repositories"][0]["upstream"]["base_url"] = (
        "https://other.example.invalid/debian/"
    )
    proposed["repositories"][0]["upstream"]["allowed_hosts"] = [
        "other.example.invalid"
    ]
    with pytest.raises(ReconciliationPlanError, match="identity reassignment"):
        _nginx_preview(current, proposed, pins={})


def test_declarative_nginx_preview_has_no_network_subprocess_or_file_write(monkeypatch):
    import os
    import socket
    import subprocess
    import repocache.server_protected_state_store_v1 as state_store

    def denied(*args, **kwargs):
        raise AssertionError("preview must not access the host")
    monkeypatch.setattr(os, "replace", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(subprocess, "run", denied)
    monkeypatch.setattr(state_store, "_commit_under_root", denied)
    current = document()
    current["expected_state_generation"] = 1
    proposed = copy.deepcopy(current)
    proposed["repositories"][0]["desired_state"] = "active"
    result = _nginx_preview(current, proposed, pins={
        "debian-trixie-main": copy.deepcopy(_PUBLIC_PINS),
    })
    assert result["authorizes_state_commit"] is False
    assert result["authorizes_nginx_activation"] is False
    assert result["active_exposure_verified"] is False


@pytest.mark.skipif(shutil.which("nginx") is None, reason="packaged nginx unavailable")
def test_declarative_lifecycle_candidate_passes_disposable_packaged_nginx_t(tmp_path):
    """Only parse a generated candidate in an isolated fixture, never reload."""
    import subprocess

    native_ca = next((path for path in (
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
    ) if Path(path).is_file()), None)
    if native_ca is None:
        pytest.skip("packaged CA bundle unavailable")
    current = document()
    current["expected_state_generation"] = 1
    proposed = copy.deepcopy(current)
    for repo in proposed["repositories"]:
        repo["desired_state"] = "active"
    pins = {
        repo["id"]: copy.deepcopy(_PUBLIC_PINS)
        for repo in proposed["repositories"]
    }
    rendered = _nginx_preview(current, proposed, pins=pins, ca=native_ca)
    assert rendered["proposed_repository_ids"] == [
        "almalinux-baseos", "debian-trixie-main",
    ]
    config = tmp_path / "nginx.conf"
    config.write_text(
        f"pid {tmp_path / 'nginx.pid'};\n"
        f"error_log {tmp_path / 'error.log'} notice;\n"
        "events {}\nhttp { access_log off;\n"
        + rendered["http_upstream_fragment"]
        + "server { listen 127.0.0.1:19991;\n"
        + rendered["server_location_fragment"]
        + "}\n}\n",
        encoding="utf-8",
    )
    process = subprocess.run(
        [shutil.which("nginx"), "-t", "-c", str(config), "-p", str(tmp_path)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert process.returncode == 0, process.stderr
    assert rendered["authorizes_nginx_activation"] is False
    assert rendered["authorizes_catalog_publication"] is False


# Whole-operation previews reuse the existing #95 operation planner, then #28
# NGINX candidate rendering. No operation grants privileged authority.


def _lifecycle_preview(config, operation, *, repo_id=None, proposal=None,
                       reservations=None, pins=None, state=None):
    if state is None:
        state = _inert_state_snapshot(config)
    if pins is None:
        pins = {}
    return preview_repository_lifecycle_nginx_candidate(
        config, state, current_generation=1, operation=operation,
        repository_id=repo_id, proposed_repository=proposal,
        reserved_ids=reservations, candidate_pins_by_repository=pins,
        ca_bundle_path=_CA,
    )


def test_lifecycle_explicit_add_uses_untrusted_reservations_and_pinned_route():
    current = document()
    current["expected_state_generation"] = 1
    proposal = copy.deepcopy(current["repositories"][0])
    proposal["id"] = "custom-new-apt"
    proposal["desired_state"] = "active"
    proposal["upstream"]["base_url"] = "https://mirror.example.invalid/new-apt/"
    before = copy.deepcopy(current), copy.deepcopy(proposal)
    result = _lifecycle_preview(
        current, "add", proposal=proposal,
        reservations={"debian-trixie-main", "almalinux-baseos"},
        pins={"custom-new-apt": copy.deepcopy(_PUBLIC_PINS)},
    )
    assert result["status"] == "UNTRUSTED_LIFECYCLE_NGINX_CANDIDATE_ONLY"
    assert result["changed"] is True
    assert result["new_repository_ids"] == ["custom-new-apt"]
    assert result["removed_repository_ids"] == []
    assert result["desired_new_route_ids"] == ["custom-new-apt"]
    assert result["proposed_repository_ids"] == ["custom-new-apt"]
    assert result["fresh_approval_required_ids"] == ["custom-new-apt"]
    assert result["id_eligibility"] == "CALLER_SNAPSHOT_ONLY"
    assert result["proposed_state_generation"] == 2
    assert "proxy_ssl_verify on;" in result["server_location_fragment"]
    assert result["cache_retention_required_ids"] == []
    for field in (
        "trusted_id_ledger_verified", "approval_provenance_verified",
        "configuration_digest_binding_verified", "active_exposure_verified",
        "cache_ownership_verified", "authorizes_state_commit",
        "authorizes_nginx_activation", "authorizes_catalog_publication",
        "authorizes_cache_cleanup",
    ):
        assert result[field] is False
    assert (current, proposal) == before


def test_lifecycle_remove_active_withdraws_desired_route_and_preserves_cache():
    current = document()
    current["expected_state_generation"] = 1
    current["repositories"][0]["desired_state"] = "active"
    old = copy.deepcopy(current)
    result = _lifecycle_preview(
        current, "remove", repo_id="debian-trixie-main",
    )
    assert result["changed"] is True
    assert result["removed_repository_ids"] == ["debian-trixie-main"]
    assert result["tombstone_required_ids"] == ["debian-trixie-main"]
    assert result["cache_retention_required_ids"] == ["debian-trixie-main"]
    assert result["desired_withdraw_route_ids"] == ["debian-trixie-main"]
    assert result["proposed_repository_ids"] == []
    assert result["server_location_fragment"] == ""
    assert result["authorizes_catalog_publication"] is False
    assert result["authorizes_cache_cleanup"] is False
    assert current == old


def test_lifecycle_enable_disable_update_and_idempotent_remove():
    current = document()
    current["expected_state_generation"] = 1
    enabled = _lifecycle_preview(
        current, "enable", repo_id="debian-trixie-main",
        pins={"debian-trixie-main": copy.deepcopy(_PUBLIC_PINS)},
    )
    assert enabled["desired_new_route_ids"] == ["debian-trixie-main"]
    assert enabled["new_repository_ids"] == []
    active = copy.deepcopy(current)
    active["repositories"][0]["desired_state"] = "active"
    disabled = _lifecycle_preview(
        active, "disable", repo_id="debian-trixie-main",
    )
    assert disabled["desired_withdraw_route_ids"] == ["debian-trixie-main"]

    updated = copy.deepcopy(current["repositories"][0])
    updated["layout"]["release_key_refs"] = [
        "file:/etc/repocache/keys/rotated.gpg"
    ]
    update = _lifecycle_preview(
        current, "update", repo_id="debian-trixie-main",
        proposal=updated,
    )
    assert update["changed"] is True
    assert update["desired_new_route_ids"] == []
    assert update["fresh_approval_required_ids"] == ["debian-trixie-main"]

    noop = _lifecycle_preview(
        current, "remove", repo_id="not-present",
    )
    assert noop["changed"] is False
    assert noop["proposed_state_generation"] == 1
    assert noop["tombstone_required_ids"] == []
    assert noop["fresh_approval_required_ids"] == []


def test_lifecycle_add_requires_reservations_and_refuses_tombstone_reuse():
    current = document()
    current["expected_state_generation"] = 1
    new = copy.deepcopy(current["repositories"][0])
    new["id"] = "previously-removed"
    new["upstream"]["base_url"] = "https://mirror.example.invalid/new/"
    for reservations in (None, {"debian-trixie-main", "almalinux-baseos",
                                "previously-removed"}):
        with pytest.raises(ReconciliationPlanError, match="unreserved"):
            _lifecycle_preview(
                current, "add", proposal=new, reservations=reservations,
            )


def test_lifecycle_update_refuses_identity_reassignment():
    current = document()
    current["expected_state_generation"] = 1
    repo = copy.deepcopy(current["repositories"][0])
    repo["upstream"]["base_url"] = "https://mirror.example.invalid/reassigned/"
    with pytest.raises(ReconciliationPlanError, match="identity reassignment"):
        _lifecycle_preview(
            current, "update", repo_id="debian-trixie-main", proposal=repo,
        )


def test_lifecycle_rejects_stale_protected_state_before_render():
    current = document()
    current["expected_state_generation"] = 1
    state = _inert_state_snapshot(current)
    state["state_generation"] = 2
    with pytest.raises(ReconciliationPlanError, match="stale state"):
        _lifecycle_preview(
            current, "disable", repo_id="debian-trixie-main", state=state,
        )


def test_lifecycle_refuses_unsafe_new_route_pin_and_false_catalog():
    current = document()
    current["expected_state_generation"] = 1
    with pytest.raises(ReconciliationPlanError, match="unsafe nginx"):
        _lifecycle_preview(
            current, "enable", repo_id="debian-trixie-main",
            pins={"debian-trixie-main": {_HOST: ["169.254.169.254"]}},
        )


def test_lifecycle_preview_never_writes_or_executes(monkeypatch):
    import os
    import socket
    import subprocess
    import repocache.server_protected_state_store_v1 as store

    def denied(*args, **kwargs):
        raise AssertionError("lifecycle preview cannot perform host effects")

    monkeypatch.setattr(os, "replace", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(subprocess, "run", denied)
    monkeypatch.setattr(store, "_commit_under_root", denied)
    current = document()
    current["expected_state_generation"] = 1
    result = _lifecycle_preview(current, "disable", repo_id="debian-trixie-main")
    assert result["authorizes_state_commit"] is False
    assert result["authorizes_nginx_activation"] is False
    assert result["authorizes_catalog_publication"] is False
    assert result["authorizes_cache_cleanup"] is False


# A route that remains desired-active may have changed trust/policy: it is NOT
# safe to infer that it can remain exposed without renewed native validation.


def test_partial_active_trust_change_requires_route_configuration_revalidation():
    current = document()
    current["expected_state_generation"] = 1
    current["repositories"][0]["desired_state"] = "active"
    proposed = copy.deepcopy(current)
    proposed["repositories"] = [copy.deepcopy(current["repositories"][0])]
    proposed["repositories"][0]["layout"]["release_key_refs"] = [
        "file:/etc/repocache/keys/rotated-archive.gpg"
    ]
    out = _nginx_preview(
        current, proposed,
        pins={"debian-trixie-main": copy.deepcopy(_PUBLIC_PINS)},
    )
    assert out["desired_retained_route_ids"] == ["debian-trixie-main"]
    assert out["desired_config_revalidation_ids"] == ["debian-trixie-main"]
    assert out["authorizes_nginx_activation"] is False
    assert out["authorizes_catalog_publication"] is False


def test_omitted_active_route_requires_revalidation_on_global_configuration_change():
    current = document()
    current["expected_state_generation"] = 1
    current["repositories"][0]["desired_state"] = "active"
    proposed = copy.deepcopy(current)
    proposed["repositories"] = []
    proposed["deployment"]["cache_policy"]["global"]["max_size_bytes"] += 1024
    out = _nginx_preview(
        current, proposed,
        pins={"debian-trixie-main": copy.deepcopy(_PUBLIC_PINS)},
    )
    assert out["desired_retained_route_ids"] == ["debian-trixie-main"]
    assert out["desired_config_revalidation_ids"] == ["debian-trixie-main"]
    assert out["deployment_approval_required"] is True
    assert out["authorizes_nginx_activation"] is False


def test_unchanged_active_route_has_no_detected_config_revalidation_not_proof():
    current = document()
    current["expected_state_generation"] = 1
    current["repositories"][0]["desired_state"] = "active"
    proposed = copy.deepcopy(current)
    proposed["repositories"] = []
    result = _nginx_preview(
        current, proposed,
        pins={"debian-trixie-main": copy.deepcopy(_PUBLIC_PINS)},
    )
    assert result["desired_retained_route_ids"] == ["debian-trixie-main"]
    assert result["desired_config_revalidation_ids"] == []
    # A blank *known config delta* never proves current DNS pins, live
    # NGINX exposure, TLS validity or administrator authorization.
    assert result["requires_trusted_locked_recheck"] is True
    assert result["active_exposure_verified"] is False
    assert result["authorizes_nginx_activation"] is False


def test_explicit_active_repository_trust_update_flags_revalidation():
    current = document()
    current["expected_state_generation"] = 1
    current["repositories"][0]["desired_state"] = "active"
    updated = copy.deepcopy(current["repositories"][0])
    updated["layout"]["release_key_refs"] = [
        "file:/etc/repocache/keys/rotated-archive.gpg"
    ]
    result = _lifecycle_preview(
        current, "update", repo_id="debian-trixie-main", proposal=updated,
        pins={"debian-trixie-main": copy.deepcopy(_PUBLIC_PINS)},
    )
    assert result["changed"] is True
    assert result["desired_retained_route_ids"] == ["debian-trixie-main"]
    assert result["desired_config_revalidation_ids"] == ["debian-trixie-main"]
    assert result["fresh_approval_required_ids"] == ["debian-trixie-main"]
    assert result["authorizes_catalog_publication"] is False


def test_explicit_disable_or_unrelated_disabled_add_does_not_revalidate_retained_route():
    current = document()
    current["expected_state_generation"] = 1
    current["repositories"][0]["desired_state"] = "active"
    disable = _lifecycle_preview(
        current, "disable", repo_id="debian-trixie-main",
    )
    assert disable["desired_withdraw_route_ids"] == ["debian-trixie-main"]
    assert disable["desired_config_revalidation_ids"] == []

    new_repo = copy.deepcopy(current["repositories"][0])
    new_repo["id"] = "additional-disabled"
    new_repo["desired_state"] = "disabled"
    new_repo["upstream"]["base_url"] = (
        "https://mirror.example.invalid/other-archive/"
    )
    add = _lifecycle_preview(
        current, "add", proposal=new_repo,
        reservations={"debian-trixie-main", "almalinux-baseos"},
        pins={"debian-trixie-main": copy.deepcopy(_PUBLIC_PINS)},
    )
    assert add["changed"] is True
    assert add["desired_retained_route_ids"] == ["debian-trixie-main"]
    assert add["desired_config_revalidation_ids"] == []
    assert add["authorizes_nginx_activation"] is False


# Proposed #31 v2 handoff requires a *complete* next-generation install
# document, not the old-generation untrusted candidate or a write token.


def test_explicit_lifecycle_next_generation_document_is_non_authoritative():
    from repocache.server_install_v1 import validate_install_document

    current = document()
    current["expected_state_generation"] = 1
    original = copy.deepcopy(current)
    result = _lifecycle_preview(
        current, "enable", repo_id="debian-trixie-main",
        pins={"debian-trixie-main": copy.deepcopy(_PUBLIC_PINS)},
    )
    rebased = result["next_generation_configuration_preview"]
    assert result["candidate_document"]["expected_state_generation"] == 1
    assert result["expected_state_generation"] == 1
    assert result["proposed_state_generation"] == 2
    assert rebased["expected_state_generation"] == 2
    assert rebased["repositories"] == result["candidate_document"]["repositories"]
    assert rebased["deployment"] == result["candidate_document"]["deployment"]
    assert validate_install_document(rebased, for_apply=True) == rebased
    assert current == original
    for k in (
        "trusted_id_ledger_verified", "approval_provenance_verified",
        "configuration_digest_binding_verified", "active_exposure_verified",
        "authorizes_state_commit", "authorizes_nginx_activation",
        "authorizes_catalog_publication", "authorizes_cache_cleanup",
    ):
        assert result[k] is False


def test_remove_next_generation_preserves_retained_state_and_not_ledger():
    current = document()
    current["expected_state_generation"] = 1
    current["repositories"][0]["desired_state"] = "active"
    result = _lifecycle_preview(
        current, "remove", repo_id="debian-trixie-main",
    )
    rebased = result["next_generation_configuration_preview"]
    assert rebased["expected_state_generation"] == 2
    assert {row["id"] for row in rebased["repositories"]} == {
        "almalinux-baseos",
    }
    assert result["tombstone_required_ids"] == ["debian-trixie-main"]
    assert result["cache_retention_required_ids"] == ["debian-trixie-main"]
    assert "id_reservations" not in rebased
    assert "approval_reference" not in rebased
    assert result["trusted_id_ledger_verified"] is False
    assert result["authorizes_cache_cleanup"] is False


def test_explicit_idempotent_remove_does_not_advance_generation():
    current = document()
    current["expected_state_generation"] = 1
    result = _lifecycle_preview(
        current, "remove", repo_id="absent-identifier",
    )
    assert result["changed"] is False
    assert result["proposed_state_generation"] == 1
    assert result["next_generation_configuration_preview"] is None
    assert result["authorizes_state_commit"] is False


def test_partial_lifecycle_next_generation_preserves_omitted_repositories():
    from repocache.server_install_v1 import validate_install_document

    current = document()
    current["expected_state_generation"] = 1
    proposed = copy.deepcopy(current)
    proposed["repositories"] = [copy.deepcopy(current["repositories"][0])]
    proposed["repositories"][0]["desired_state"] = "active"
    result = _nginx_preview(
        current, proposed,
        pins={"debian-trixie-main": copy.deepcopy(_PUBLIC_PINS)},
    )
    candidate = result["next_generation_configuration_preview"]
    assert result["proposed_state_generation"] == 2
    assert candidate["expected_state_generation"] == 2
    assert {row["id"] for row in candidate["repositories"]} == {
        "almalinux-baseos", "debian-trixie-main",
    }
    assert validate_install_document(candidate, for_apply=True) == candidate
    assert result["trusted_state_provenance_verified"] is False
    assert result["authorizes_state_commit"] is False


def test_partial_noop_has_no_next_generation_configuration():
    current = document()
    current["expected_state_generation"] = 1
    proposed = copy.deepcopy(current)
    proposed["repositories"] = []
    result = _nginx_preview(current, proposed, pins={})
    assert result["declarative_change_requested"] is False
    assert result["proposed_state_generation"] == 1
    assert result["next_generation_configuration_preview"] is None


def test_explicit_generation_exhaustion_never_returns_commit_candidate():
    current = document()
    current["expected_state_generation"] = 2**63 - 1
    state = _inert_state_snapshot(current, generation=2**63 - 1)
    with pytest.raises(ReconciliationPlanError, match="generation exhausted"):
        preview_repository_lifecycle_nginx_candidate(
            current, state, current_generation=2**63 - 1,
            operation="enable", repository_id="debian-trixie-main",
            candidate_pins_by_repository={
                "debian-trixie-main": copy.deepcopy(_PUBLIC_PINS),
            }, ca_bundle_path=_CA,
        )
