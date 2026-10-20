# v0.5.0 — Gate A acceptance review (pre-integration)

**Date:** 2026-10-20. **Overall result: FAIL / NOT VERIFIED. DO NOT MERGE.**
This is a developer-led security review, **not an independent audit**.
The maintainer has approved separating code acceptance (#17) from operational
activation (#49), not weakening either requirement.

## Verified repository state and boundary

- The **v0.4.0 first-public bootstrap PR #2 is still draft and unmerged**.
  Its candidate `chore/bootstrap-public-v0.4.0` has moved since the
  v0.5.0 stack was branched, including changes to `cli.py` and the updater.
- The v0.5.0 draft dependency stack is #43 -> #45 -> #46 -> #47 -> #48 ->
  #51 -> #52 -> #56; #42 metrics is a sibling whose code was reconciled in
  #52. The listed arrows denote code bases, not authorization to merge.
- The metrics and protocol sibling PRs #42 and #43 currently have integration
  conflicts against the moving v0.4.0 branch. **Do not rebase or retarget
  prematurely**, and do not integrate #56 into `main` or `release/v0.4.0`.
- No branch has permission to enable the intake listener, change NGINX or
  install/modify APT/DNF sources as part of this work.

## Gate A exact-criterion matrix

The status below applies to the scope **actually exercised**, not to
untested native production environments. All seven #17 criteria must PASS
on the final reviewed integrated head before explicit merge approval.

| # | Criterion | Status | Evidence and remaining limitation |
| --- | --- | --- | --- |
| A1 | Fail-closed HMAC, nonce/replay, rate limits, negative input, TLS client/HTTP tests | **PASS — scoped automated tests** | `test_submissions_v05.py`, `test_submission_security_gate_v05.py`, `test_submission_json_depth_gate_v05.py`; strict JSON nesting cap; Python 3.12/3.13 CI on #56 (record exact final run) |
| A2 | No intake DNS/SSRF, no untrusted NGINX/APT/DNF mutation | **PASS — scoped implementation/tests** | No outgoing upstream resolution from `submissions.py`/`intake.py`; `test_bad_urls_rejected_without_dns_or_queue_changes`; no catalog publisher in intake. Future active upstream validation is not covered |
| A3 | SQLite safe quotas, retention, backup, restore and interruption/rollback | **PASS synthetic / NOT VERIFIED in full** | `test_submission_restore_v05.py`, `test_submission_retention_backup_v05.py` (privilege ownership simulated). Need final combined review of trust assumptions, interrupted multi-writer state and backup consistency; native recovery belongs to #49 |
| A4 | Disabled-by-default deployment example, least-privilege key/service boundary, redaction | **PASS scoped static / NOT VERIFIED in full** | `test_submission_keys_service_v05.py`, example-only unit/NGINX files, no enabled service. Installed executable paths, actual key rotation and NGINX syntax are not validated; operational activation remains blocked by #49 |
| A5 | Combined #14 metrics and #23 root-only TUI regression, redaction | **PASS — scoped automated tests** | `test_metrics_history_tui_v05.py`, `test_submission_tui_v05.py`, `test_submission_tui_corrupt_v05.py`, recent-event redaction tests. Still reconcile with the new v0.4.0 CLI baseline |
| A6 | Adversarial code-security review with no unresolved material security issue | **FAIL** | A root-only decision record is currently held in a state store writable by the intake service identity. An authoritative independent admin audit boundary is not established. **Issue #57** documents the required design/fix; do not label the present SQLite audit tamper-proof or immutable. |
| A7 | Exact-head CI, reviews, final diff acceptance, explicit merge approval | **NOT VERIFIED** | Automated CI may pass on #56 while the parent v0.4.0 candidate continues changing. Check current GitHub PR heads/targets and rules, resolve #57, obtain explicit maintainer merge approval after all mandatory A criteria PASS. |

## Adversarial finding addressed by #56

**Untrusted JSON recursion and persisted-record trust:** even a signed body
below the 64 KiB cap could contain thousands of nested objects/arrays.
Relying solely on the Python decoder's recursion limit is runtime-dependent.
The shared parser now enforces a deterministic limit of 32 nested JSON
containers before decoding, without treating braces/brackets **inside JSON
string literals** as nesting. A signed request that exceeds the limit must
return sanitized HTTP 400 and create no proposal. Corrupted stored JSON must
return a stable privileged-store error rather than crashing the TUI.

The following targeted tests were added (and must run successfully on both
supported Python versions):

- `test_nested_remote_json_is_sanitized_without_queue_mutation`
- `test_privileged_pending_reader_rejects_deep_stored_metadata`
- `test_privileged_pending_reader_rejects_invalid_stored_shapes`
- `test_brackets_inside_json_string_do_not_count_as_structure`

Other residual risks requiring separate evidence include native service-user
permissions, SELinux, log redaction in real NGINX, key revocation after a
controlled restart, filesystem crash consistency and the operational policy
for backups and retention; these belong to Gate B #49 unless they expose a
fundamental defect in the Gate A code.

## Integration plan while v0.4.0 remains unfinished

1. Keep every v0.5.0 PR **draft**, and keep `release/v0.4.0`/public `main`
   unchanged. Do not claim the v0.5.0 stack is ready to merge.
2. Complete the authoritative administrative audit boundary in #57 using
   independent root-controlled evidence and executed negative tests.
3. Record source/CLI and updater overlap between the old v0.4.0 base and
   the moving v0.4.0 PR #2, without cherry-picking unfinished release fixes.
4. Once v0.4.0 is explicitly accepted/integrated, rebuild or rebase the
   **v0.5.0-only** delta onto that final head with reviewed diffs. Avoid
   duplicate #14 source changes and prove the approved client CLI contract.
5. Run **all** required CI on the new exact integrated head, document PASS /
   FAIL / NOT VERIFIED per issue and obtain **separate explicit merge
   approval**. Production activation still additionally requires #49.

**Review disposition: BLOCKED.** Passing tests provide scoped confidence,
not a security audit, an approved merge or permission to expose the intake.
