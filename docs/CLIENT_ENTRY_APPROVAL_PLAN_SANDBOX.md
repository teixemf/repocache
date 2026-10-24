# Explicit sandbox approval and byte-preserving entry plan

**Issue:** [#24](https://github.com/teixemf/repocache/issues/24).  
**Immediate parent:** [#141](https://github.com/teixemf/repocache/pull/141), itself stacked on #140/#138/#133.  
**Transaction dependency:** [#131](https://github.com/teixemf/repocache/pull/131), tested at immutable commit `ddb0ab522e31a91c4026fb9a7c839c86fd25d78b`.  
**Status:** private, non-production /tmp laboratory. No installed helper, no public administrative CLI, no source-file writes.

## Authorization model

Approval to implement the feature is **not** authorization to modify any installed host repository. In this experiment:

1. An entry candidate must already exist under the protected #141 namespace, explicitly marked `ownership_granted=false` and `write_eligible=false`.
2. `approve_entry_plan_sandbox(root, candidate_id, expected_file_sha256, expected_entry_sha256)` requires the **actual effective UID 0**, a private marked temporary root and both independently supplied digests matching the complete file and exact selected entry.
3. The whole source is re-read and checked against its prior digest, inode, mode, UID/GID, timestamps, xattr presence, selected entry digest and byte span before a separate private `approval-<candidate_id>.json` record is written.
4. The approval record is `0600` under a `0700` directory; it records the explicit decision `approve-entry-plan` by UID 0, scope `sandbox-only`, original file/entry SHA-256 and `production_write_eligible=false`. No source contents, URL, key, secret or xattr value appear in that record.
5. Approval record creation uses a fsynced private temporary file and a **no-replace hard-link publication**. Duplicate records, corrupt or partial state, or altered approval scope/UID flag fail closed. Non-root processes cannot create a valid positive approval on native roots or within test fixtures.

This intentionally is not a production authorization registry, cryptographic signature, or tamper-proof root actor boundary. A root actor can still alter test state. Future deployment needs audited root-only installation/ACL/SELinux policies, explicit administrator confirmation outside untrusted catalogs, revocation/expiration and durable audit.

## Byte-preserving change previews

`preview_entry_change_sandbox(root, candidate_id, new_https_url)` checks the explicit sandbox approval, the unchanged entire file and one uniquely selected eligible entry. It replaces **only one URL token** in an in-memory copy, preserving the original line/stanza/section's key, suite, signature-related options and the **exact untouched bytes** of every other entry and comment. The proposed URL must be a simple explicit HTTPS URL without embedded credentials, queries, fragments, encoded traversal, control characters or shell-like quoting.

The in-memory planner reparses the proposed whole file and independently verifies the selected entry's kind/key remains stable, all unselected entry digests remain the same, the entry count remains unchanged and the original source file still matches its preflight baseline. It returns only a redacted plan summary with before/after hashes and the number of preserved siblings, always `production_write_eligible=false`.

**No actual upstream fallback, native parser validity, package metadata integrity or signing-key trust is proven by this structural subset.** `https://` is not sufficient to prove the cache is safe to use.

## Stage-only transaction adapter

`client/entry_transaction_stage_sandbox.py` exposes `stage_entry_change_sandbox(root, candidate_id, new_https_url)`. After revalidating the approved candidate, it calls the independent **protected stage-only** `transaction_stage.stage` from [#131](https://github.com/teixemf/repocache/pull/131) with:

- The **entire original shared-file** SHA-256;
- Exact full-file bytes with only the approved entry's URL replaced;
- The same private temporary fixture root.

The stage captures private original/proposed snapshots but **does not activate changes**. The adapter rechecks the file after staging and refuses externally changed input; the protected stage remains available for explicit diagnostic/recovery if a race occurs. It never invokes the atomic sandbox apply module from #132 and is not imported by installed REPOCACHE client commands.

The [native workflow](../.github/workflows/client-entry-approval-plan.yml) checks out the **immutable exact SHA** of unmerged #131 into an isolated dependency directory, then tests stage-only integration using OS Python in Debian 13/AlmaLinux 10 disposable containers. This is *dependency pinning for integration tests*, not merging or bundling #131 code.

## Acceptance and blockers

Unit and native tests cover real-root approval vs actual non-root UID/GID denial, exact source and entry preconditions, separate 0600 approval state, APT `.list` and deb822 `.sources`, DNF `.repo`, untouched sibling bytes, URL-option preservation, malicious URLs, conflicts after external edits, staging idempotency/conflicts and no active repository file mutation.

**NOT VERIFIED for production:** root helper installation/authorization, revocation and audit; real APT/DNF trust and metadata signature checks; catalog URL validation; upstream fallback; SELinux enforcing context preservation; protected shared-file backup retention for files containing other administrators' secrets; multi-file transactions; native APT/DNF locks; real package source patching; concurrent hostile actors, full crash recovery and clean install/upgrade/uninstall.

**SELinux enforcing:** skip the unsuitable GitHub Actions container test, but retain **NOT VERIFIED** until tested on a booted AlmaLinux 10 VM or host. Unknown security namespaces must fail closed.

No merge/release or `repocache-client repos sync --apply` enablement follows from any laboratory approval. Merge requires explicit maintainer authorization after exact-head CI, linked acceptance-evidence mapping, reviews and dependency reconciliation.
