"""Read-only reconciliation preview for the proposed server installation v1 schema.

This pure planner is NOT a trusted state reader, authorization mechanism, NGINX
renderer or commit engine. No caller-provided JSON, expected generation or
preview may authorize a file write, service reload or catalog publication.
The future #95/#28/#31 owner must re-read protected state under the native
transaction lock, verify provenance/ownership and repeat validation.
"""
from __future__ import annotations

import copy
import hashlib
from typing import Any

from repocache.server_install_v1 import (
    MAX_INT, validate_install_document,
)
from repocache.server_repository_plan_v1 import (
    RepositoryPlanError, _canonical_identity, _effective_configuration,
    plan_repository_change,
)
from repocache.server_protected_state_store_v1 import (
    ProtectedStateStoreError, validate_protected_state,
)
from repocache.server_nginx_repository_bundle_v1 import (
    NginxRepositoryBundleError, render_repository_nginx_bundle_candidate,
)


class ReconciliationPlanError(ValueError):
    """Reject an unsupported preview without echoing input values."""


_POLICY_FIELDS = ("inactive_seconds", "max_size_bytes")


def _effective_policy(repo: dict[str, Any], global_policy: dict[str, Any]) -> dict[str, Any]:
    overrides = repo.get("cache_overrides", {})
    return {
        field: {
            "value": overrides.get(field, global_policy[field]),
            "source": "repository" if field in overrides else "global",
        }
        for field in _POLICY_FIELDS
    }


def _desired_config_revalidation_ids(
    current: dict[str, Any], candidate: dict[str, Any],
) -> list[str]:
    """Known config changes affecting already desired-active route candidates.

    This is only an intent comparison, NOT a list of all routes requiring
    revalidation. Even an empty result says nothing about changed DNS pins,
    the live NGINX include, current TLS trust, owner provenance or exposure.
    Every actual activation must independently verify all routes under the
    authenticated transaction lock, regardless of this field.
    """
    before = {
        row["id"]: row for row in current["repositories"]
        if row["desired_state"] == "active"
    }
    after = {
        row["id"]: row for row in candidate["repositories"]
        if row["desired_state"] == "active"
    }
    deployment_changed = current["deployment"] != candidate["deployment"]
    return sorted(
        identifier for identifier in before.keys() & after.keys()
        if deployment_changed
        or _effective_configuration(before[identifier])
           != _effective_configuration(after[identifier])
    )


def _next_generation_configuration_preview(
    candidate: dict[str, Any], *, generation: int, changed: bool,
) -> dict[str, Any] | None:
    """Return a pure next-generation install-v1 candidate, never a v2 state.

    The existing plan/NGINX candidate uses the *current* generation so it
    can be validated against the current untrusted state. The proposed #31
    v2 contract instead needs a complete install document bearing the next
    generation before its independently authenticated canonical encoding.
    We neither encode that durable v2 payload here nor compute/authorize
    its digest, reservation history, approvals or protected-state commit.
    """
    if not changed:
        return None
    if generation == MAX_INT:
        raise ReconciliationPlanError("next generation: exhausted")
    rebased = copy.deepcopy(candidate)
    rebased["expected_state_generation"] = generation + 1
    return validate_install_document(rebased, for_apply=True)


def plan_declarative_reconciliation(
    current_document: dict[str, Any],
    proposed_document: dict[str, Any],
    *,
    current_generation: int,
) -> dict[str, Any]:
    """Preview an explicit update, preserving EVERY omitted repository.

    Both documents are untrusted snapshots. New IDs are intentionally refused:
    allocation and tombstone reservations require the future authoritative
    locked state engine, not guesswork by this pure planner. Omitted entries
    survive even when the submitted repositories array is empty. Global
    defaults are applied to *all* stored entries, including omitted entries.
    """
    if type(current_generation) is not int or not 0 <= current_generation <= MAX_INT:
        raise ReconciliationPlanError("current_generation: invalid")
    current = validate_install_document(current_document, for_apply=True)
    proposed = validate_install_document(proposed_document, for_apply=True)

    if (current["expected_state_generation"] != current_generation
            or proposed["expected_state_generation"] != current_generation):
        raise ReconciliationPlanError("expected_state_generation: stale preview")

    existing = current["repositories"]
    incoming = proposed["repositories"]
    if any("id" not in repo for repo in existing + incoming):
        raise ReconciliationPlanError("repositories: durable IDs required")
    by_id = {repo["id"]: repo for repo in existing}
    updates = {repo["id"]: repo for repo in incoming}
    if set(updates) - set(by_id):
        raise ReconciliationPlanError(
            "repositories: new IDs require the authoritative reservation engine"
        )

    # A submitted document is not a replace-all request. It cannot remove,
    # disable or silently reauthorize any repository absent from its list.
    candidate = copy.deepcopy(current)
    candidate["deployment"] = copy.deepcopy(proposed["deployment"])
    candidate["repositories"] = [
        (copy.deepcopy(repo)
         if repo["id"] not in updates
         or _effective_configuration(updates[repo["id"]])
            == _effective_configuration(repo)
         else copy.deepcopy(updates[repo["id"]]))
        for repo in existing
    ]
    # Validate the combined result: an individually valid partial document
    # may collide with a preserved repository's canonical upstream identity.
    candidate = validate_install_document(candidate, for_apply=True)
    final_by_id = {repo["id"]: repo for repo in candidate["repositories"]}

    old_global = current["deployment"]["cache_policy"]["global"]
    new_global = candidate["deployment"]["cache_policy"]["global"]
    changes = []
    implicit_policy_ids = []
    explicit_changed_ids = []
    preserved_ids = sorted(set(by_id) - set(updates))

    for identifier in sorted(by_id):
        before = by_id[identifier]
        after = final_by_id[identifier]
        before_policy = _effective_policy(before, old_global)
        after_policy = _effective_policy(after, new_global)
        changed_fields = [
            key for key in _POLICY_FIELDS if before_policy[key] != after_policy[key]
        ]
        if identifier in updates and before != after:
            explicit_changed_ids.append(identifier)
        if changed_fields:
            changes.append({
                "repository_id": identifier,
                "fields": changed_fields,
                "before": {key: before_policy[key] for key in changed_fields},
                "after": {key: after_policy[key] for key in changed_fields},
                "explicitly_listed": identifier in updates,
            })
            if identifier not in updates:
                implicit_policy_ids.append(identifier)

    return {
        "schema_version": 1,
        "status": "PLAN_ONLY",
        "authorizes_installation": False,
        "state_generation": current_generation,
        "changed": candidate != current,
        "explicit_changed_ids": sorted(explicit_changed_ids),
        "preserved_ids": preserved_ids,
        "implicit_policy_ids": sorted(implicit_policy_ids),
        "effective_policy_changes": changes,
        "candidate_document": candidate,
    }

def preview_declarative_state_alignment(
    current_document: dict[str, Any],
    protected_snapshot: dict[str, Any],
    *,
    current_generation: int,
) -> dict[str, Any]:
    """Compare two UNTRUSTED snapshots, never authenticate persistent state.

    This checks only the narrow schema/generation/ID/identity/desired-state
    intersection between #18 and the inert #31 state v1. It cannot verify
    the configuration digest, reservation tombstones, approval provenance,
    actual NGINX exposure, privileged root/lock ownership or cache identity.
    The future privileged owner MUST independently read and verify state
    under the exclusive transaction lock and revalidate everything at commit.
    """
    if type(current_generation) is not int or not 1 <= current_generation <= MAX_INT:
        raise ReconciliationPlanError("state alignment: invalid generation")
    current = validate_install_document(current_document, for_apply=True)
    if current["expected_state_generation"] != current_generation:
        raise ReconciliationPlanError("state alignment: stale configuration")
    try:
        state = validate_protected_state(protected_snapshot)
    except ProtectedStateStoreError:
        raise ReconciliationPlanError("state alignment: invalid state snapshot") from None
    if state["state_generation"] != current_generation:
        raise ReconciliationPlanError("state alignment: stale state snapshot")

    installed = state["repositories"]
    declared = current["repositories"]
    if any("id" not in repo for repo in declared):
        raise ReconciliationPlanError("state alignment: durable IDs required")
    if len(installed) != len(declared):
        raise ReconciliationPlanError("state alignment: repository set mismatch")
    by_id = {row["id"]: row for row in installed}
    if set(by_id) != {repo["id"] for repo in declared}:
        raise ReconciliationPlanError("state alignment: repository set mismatch")

    for repo in declared:
        row = by_id[repo["id"]]
        identity_sha256 = hashlib.sha256(
            _canonical_identity(repo).encode("utf-8")
        ).hexdigest()
        if (row["canonical_identity_sha256"] != identity_sha256
                or row["desired_state"] != repo["desired_state"]):
            raise ReconciliationPlanError("state alignment: identity or intent mismatch")

    return {
        "schema_version": 1,
        "status": "UNTRUSTED_ALIGNMENT_ONLY",
        "state_generation": current_generation,
        "aligned_repository_ids": sorted(by_id),
        "configuration_digest_verified": False,
        "approval_provenance_verified": False,
        "observed_exposure_verified": False,
        "reservation_history_verified": False,
        "requires_trusted_locked_recheck": True,
        "authorizes_installation": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
        "authorizes_cache_cleanup": False,
    }


def plan_inert_persistence_transition(
    current_document: dict[str, Any],
    proposed_document: dict[str, Any],
    protected_snapshot: dict[str, Any],
    *,
    current_generation: int,
) -> dict[str, Any]:
    """Produce a non-committable transition intent for the inert #31 store.

    The #31 v1 protected format has no durable install-document payload,
    tombstone ledger, activation state or authenticated operator approval.
    Even a matching caller-supplied snapshot MUST NOT grant permission to
    invoke its private fixture-only writer. The returned intent intentionally
    omits the approval and configuration digest fields required by that writer.

    Existing canonical identities must stay stable: #31 forbids identity
    reassignment and removal. A different upstream/layout identity needs a
    future authenticated migration/reallocation transaction, not overwrite.
    """
    aligned = preview_declarative_state_alignment(
        current_document, protected_snapshot, current_generation=current_generation
    )
    if current_generation == MAX_INT:
        raise ReconciliationPlanError("persistence: state generation exhausted")

    plan = plan_declarative_reconciliation(
        current_document, proposed_document, current_generation=current_generation
    )
    current = validate_install_document(current_document, for_apply=True)
    candidate = plan["candidate_document"]
    before = {repo["id"]: repo for repo in current["repositories"]}
    after = {repo["id"]: repo for repo in candidate["repositories"]}
    if set(before) != set(after):
        raise ReconciliationPlanError("persistence: repository set change unsupported")

    projections = []
    changed_ids = []
    for identifier in sorted(after):
        old, new = before[identifier], after[identifier]
        digest = hashlib.sha256(_canonical_identity(new).encode("utf-8")).hexdigest()
        if digest != hashlib.sha256(_canonical_identity(old).encode("utf-8")).hexdigest():
            raise ReconciliationPlanError("persistence: identity reassignment unsupported")
        if _effective_configuration(old) != _effective_configuration(new):
            changed_ids.append(identifier)
        projections.append({
            "id": identifier,
            "canonical_identity_sha256": digest,
            "desired_state": new["desired_state"],
            "observed_state": "not-activated",
        })
    deployment_changed = current["deployment"] != candidate["deployment"]
    # Approval records are deliberately absent: only a separately reviewed
    # privileged owner can authenticate the exact deployment/repo decision.
    reapproval = sorted(after) if deployment_changed else changed_ids
    return {
        "schema_version": 1,
        "status": "PLAN_ONLY",
        "state_schema_version": 1,
        "expected_state_generation": current_generation,
        "proposed_state_generation": current_generation + int(plan["changed"]),
        "changed": plan["changed"],
        "repository_intents": projections,
        "fresh_approval_required_ids": reapproval,
        "deployment_approval_required": deployment_changed,
        "candidate_document": candidate,
        "state_alignment": aligned["status"],
        "authorizes_state_commit": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
        "authorizes_cache_cleanup": False,
        "requires_trusted_locked_recheck": True,
        "configuration_digest_binding_verified": False,
        "reservation_history_verified": False,
        "approval_provenance_verified": False,
    }


def preview_declarative_nginx_candidate(
    current_document: dict[str, Any],
    proposed_document: dict[str, Any],
    protected_snapshot: dict[str, Any],
    *,
    current_generation: int,
    candidate_pins_by_repository: dict[str, dict[str, list[str]]],
    ca_bundle_path: str,
) -> dict[str, Any]:
    """Compose a #95 lifecycle intent with #28's inert NGINX renderer.

    All input, including a caller-provided protected snapshot and DNS pins,
    is UNTRUSTED. A desired-active route is not proof of an approved, installed
    or exposed repository. The output is deliberately not a complete NGINX
    include, commit request, activated route list, or discovery catalog.
    A future privileged owner MUST reauthenticate and validate the complete
    exact generation, approval, DNS, CA, managed ownership and rollback state
    under its native transaction lock.
    """
    # First freeze the untrusted declarative inputs into validated copies.
    # A caller mutating their dict later cannot silently change the preview.
    current = validate_install_document(current_document, for_apply=True)
    proposed = validate_install_document(proposed_document, for_apply=True)
    transition = plan_inert_persistence_transition(
        current, proposed, protected_snapshot,
        current_generation=current_generation,
    )
    candidate = transition["candidate_document"]
    try:
        bundle = render_repository_nginx_bundle_candidate(
            candidate,
            expected_state_generation=current_generation,
            candidate_pins_by_repository=candidate_pins_by_repository,
            ca_bundle_path=ca_bundle_path,
        )
    except NginxRepositoryBundleError:
        # Error codes deliberately omit rejected hostnames, IPs, secret paths.
        raise ReconciliationPlanError("nginx preview: unsafe candidate") from None

    current_active = {
        repo["id"] for repo in current["repositories"]
        if repo["desired_state"] == "active"
    }
    candidate_active = {
        repo["id"] for repo in candidate["repositories"]
        if repo["desired_state"] == "active"
    }
    if bundle["proposed_repository_ids"] != sorted(candidate_active):
        raise ReconciliationPlanError("nginx preview: inconsistent candidate")

    return {
        "schema_version": 1,
        "status": "UNTRUSTED_NGINX_CANDIDATE_ONLY",
        "expected_state_generation": current_generation,
        "proposed_state_generation": transition["proposed_state_generation"],
        "next_generation_configuration_preview": _next_generation_configuration_preview(
            candidate, generation=current_generation, changed=transition["changed"],
        ),
        "declarative_change_requested": transition["changed"],
        "fresh_approval_required_ids": transition["fresh_approval_required_ids"],
        "deployment_approval_required": transition["deployment_approval_required"],
        "desired_new_route_ids": sorted(candidate_active - current_active),
        "desired_withdraw_route_ids": sorted(current_active - candidate_active),
        "desired_retained_route_ids": sorted(current_active & candidate_active),
        "desired_config_revalidation_ids": _desired_config_revalidation_ids(
            current, candidate,
        ),
        "proposed_repository_ids": bundle["proposed_repository_ids"],
        "pin_count": bundle["pin_count"],
        "http_upstream_fragment": bundle["http_upstream_fragment"],
        "server_location_fragment": bundle["server_location_fragment"],
        "requires_nginx_t_and_activation": True,
        "requires_trusted_locked_recheck": True,
        "trusted_state_provenance_verified": False,
        "operator_approval_verified": False,
        "active_exposure_verified": False,
        "configuration_digest_binding_verified": False,
        "reservation_history_verified": False,
        "authorizes_state_commit": False,
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
        "authorizes_cache_cleanup": False,
    }


def preview_repository_lifecycle_nginx_candidate(
    current_document: dict[str, Any],
    protected_snapshot: dict[str, Any],
    *,
    current_generation: int,
    operation: str,
    repository_id: str | None = None,
    proposed_repository: dict[str, Any] | None = None,
    reserved_ids: set[str] | frozenset[str] | None = None,
    candidate_pins_by_repository: dict[str, dict[str, list[str]]],
    ca_bundle_path: str,
) -> dict[str, Any]:
    """Preview add/update/enable/disable/remove via existing #95/#28 planners.

    This is a *non-authorizing* composition of untrusted input snapshots.
    Unlike partial reconciliation, an explicit remove changes the candidate
    repository set. Removal never implies cache deletion; a future protected
    state store must persist an all-time ID tombstone and authoritatively
    withdraw routes/catalog under its own lock. The caller's reserved-ID
    snapshot is not a trusted ledger, even when validation succeeds.
    """
    current = validate_install_document(current_document, for_apply=True)
    preview_declarative_state_alignment(
        current, protected_snapshot, current_generation=current_generation
    )
    try:
        intent = plan_repository_change(
            current,
            current_generation=current_generation,
            operation=operation,
            repository_id=repository_id,
            proposed_repository=proposed_repository,
            reserved_ids=reserved_ids,
        )
    except RepositoryPlanError:
        raise ReconciliationPlanError("lifecycle: invalid or unreserved operation") from None

    candidate = intent["candidate_document"]
    original = {repo["id"]: repo for repo in current["repositories"]}
    proposed = {repo["id"]: repo for repo in candidate["repositories"]}

    # The v1 state store cannot safely remap a durable ID to a new identity.
    for identifier in original.keys() & proposed.keys():
        if _canonical_identity(original[identifier]) != _canonical_identity(
            proposed[identifier]
        ):
            raise ReconciliationPlanError("lifecycle: identity reassignment unsupported")

    if intent["changed"] and current_generation == MAX_INT:
        raise ReconciliationPlanError("lifecycle: generation exhausted")

    try:
        bundle = render_repository_nginx_bundle_candidate(
            candidate,
            expected_state_generation=current_generation,
            candidate_pins_by_repository=candidate_pins_by_repository,
            ca_bundle_path=ca_bundle_path,
        )
    except NginxRepositoryBundleError:
        raise ReconciliationPlanError("lifecycle: unsafe nginx candidate") from None

    old_active = {
        repo_id for repo_id, repo in original.items()
        if repo["desired_state"] == "active"
    }
    new_active = {
        repo_id for repo_id, repo in proposed.items()
        if repo["desired_state"] == "active"
    }
    if bundle["proposed_repository_ids"] != sorted(new_active):
        raise ReconciliationPlanError("lifecycle: inconsistent nginx candidate")

    removed = sorted(original.keys() - proposed.keys())
    added = sorted(proposed.keys() - original.keys())
    affected = [intent["repository_id"]] if intent["changed"] else []
    return {
        "schema_version": 1,
        "status": "UNTRUSTED_LIFECYCLE_NGINX_CANDIDATE_ONLY",
        "operation": intent["operation"],
        "repository_id": intent["repository_id"],
        "changed": intent["changed"],
        "expected_state_generation": current_generation,
        "proposed_state_generation": (
            current_generation + int(intent["changed"])
        ),
        "next_generation_configuration_preview": _next_generation_configuration_preview(
            candidate, generation=current_generation, changed=intent["changed"],
        ),
        "new_repository_ids": added,
        "removed_repository_ids": removed,
        "tombstone_required_ids": removed,
        "cache_retention_required_ids": removed,
        "fresh_approval_required_ids": affected,
        "desired_new_route_ids": sorted(new_active - old_active),
        "desired_withdraw_route_ids": sorted(old_active - new_active),
        "desired_retained_route_ids": sorted(old_active & new_active),
        "desired_config_revalidation_ids": _desired_config_revalidation_ids(
            current, candidate,
        ),
        "proposed_repository_ids": bundle["proposed_repository_ids"],
        "pin_count": bundle["pin_count"],
        "http_upstream_fragment": bundle["http_upstream_fragment"],
        "server_location_fragment": bundle["server_location_fragment"],
        "candidate_document": candidate,
        "id_eligibility": (
            "CALLER_SNAPSHOT_ONLY" if operation == "add" else "NOT_APPLICABLE"
        ),
        "requires_trusted_locked_recheck": True,
        "requires_nginx_t_and_activation": True,
        "trusted_id_ledger_verified": False,
        "approval_provenance_verified": False,
        "configuration_digest_binding_verified": False,
        "active_exposure_verified": False,
        "cache_ownership_verified": False,
        "authorizes_state_commit": False,
        "authorizes_nginx_activation": False,
        "authorizes_catalog_publication": False,
        "authorizes_cache_cleanup": False,
    }
