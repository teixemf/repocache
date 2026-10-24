"""Adapter: prepare (not apply) an approved, byte-preserving entry plan.

Sandbox-only bridge to the protected stage() function from unmerged #131.
The transaction staging implementation is intentionally NOT copied or
vendored here: it is an explicit versioned dependency, tested with #131's
immutable commit in the dedicated native CI workflow.

No source file replacement, privileged helper or real /etc access.
"""
from __future__ import annotations

from pathlib import Path

import entry_approval_plan_sandbox as approval


def stage_entry_change_sandbox(root: Path, candidate_id: str,
                               new_https_url: str) -> dict:
    """Stage exact original/proposed shared-file bytes; NEVER apply them."""
    root = Path(root)
    # This call verifies the private /tmp fixture, explicit UID-0 approval,
    # whole-file inode/hash/metadata baseline, target uniqueness and intact
    # sibling bytes BEFORE invoking any potentially writing staging code.
    plan = approval._build_plan(root, candidate_id, new_https_url)
    try:
        import transaction_stage
    except ImportError as exc:
        raise approval.ApprovalRefused(
            "Protected transaction staging dependency is not integrated") from exc
    # transaction_stage.stage writes only protected state and performs its
    # own file-baseline preconditions. It is NOT an apply engine.
    staged = transaction_stage.stage(root, plan["source"],
                                      plan["original_sha256"],
                                      plan["proposed"])
    if staged.get("status") != "prepared":
        raise approval.ApprovalRefused("Unexpected protected staging result")
    # A process can change a shared file after staging. Never silently
    # rebaseline or continue if source evidence no longer matches.
    try:
        candidate = approval._candidate(root, candidate_id)
        approval._snapshot(root, candidate)
    except approval.ApprovalRefused:
        # Preserve the staged evidence for explicit operator recovery; do not
        # silently discard a transaction after a concurrent external change.
        raise
    return {
        "stage_id": staged["id"],
        "candidate_id": candidate_id,
        "state": "prepared",
        "shared_source_sha256": plan["original_sha256"],
        "staged_source_sha256": plan["proposed_sha256"],
        "siblings_byte_preserved": plan["other_entries_preserved"],
        "source_modified": False,
        "production_write_eligible": False,
        "native_syntax_verified": False,
        "package_signatures_verified": False,
        "upstream_fallback_verified": False,
    }
