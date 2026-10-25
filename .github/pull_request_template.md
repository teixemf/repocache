## Summary

Explain the change and the user-facing impact in English.

## Linked Issue and milestone

Replace `#N` with the primary **same-repository issue** for this PR. If multiple issues belong to different milestones, request maintainer review and assign the PR milestone manually.

Primary issue: #N

Closes #

## Implementation notes

Describe design choices, API/CLI compatibility, and any changes to NGINX, repository sources or stored metrics.

## Verification

- [ ] `PYTHONPATH=src python -m pytest -q` passes.
- [ ] Tested on supported Python versions or documented what could not be tested.
- [ ] Release-bundle/installer tests were run where applicable.
- [ ] English documentation and user-facing text were updated as needed.
- [ ] PR milestone matches the primary issue's planned release (not an acceptance claim).

**Test evidence:**

## Safety and rollout

- [ ] The default behaviour remains read-only/non-destructive, unless explicitly reviewed.
- [ ] No tokens, keys, private hostnames, logs or client identifiers are included.
- [ ] Changes to privileged configuration have a documented rollout and rollback plan, if applicable.
- [ ] Existing stable commands/JSON consumers remain compatible, or migrations are described.

**Deployment plan:**

**Rollback plan:**

## Independent review and acceptance (required)

Follow [PR review and acceptance policy](https://github.com/teixemf/repocache/blob/main/docs/PR_REVIEW_GOVERNANCE.md) (effective only after separately authorized merge into protected `main`). Do not call an AI-assisted report a human GitHub approval.

- [ ] Every applicable primary-issue/PR acceptance criterion is PASS with a reproducible executed test or verified review/manual procedure.
- [ ] Exact PR HEAD, protected target SHA, ancestry, merge method, milestone, and all nine required GitHub Actions contexts checked.
- [ ] Security/compatibility/install/upgrade/rollback/documentation impacts reviewed and outstanding FAIL/NOT VERIFIED gates classified.
- [ ] Independent review evidence recorded with the actual reviewer type, scope and exact SHA.
- [ ] If an AI-assisted technical second opinion is accepted as an allowed alternative to the **project-level review evidence criterion**, authenticated **PR-/exact-HEAD-specific maintainer approval** of that amendment is linked (or NOT VERIFIED); separately required human reviews are not waived.
- [ ] GitHub human review count, blocking discussions, and current protection/mergeability checked without bypass.
- [ ] **Separate explicit maintainer authorization for this merge** recorded after all applicable gates PASS.

**Review source and exact SHA:**

**Actual submitted human GitHub approvals:**

**PR-specific review criterion amendment (owner link, or NONE):**

**Acceptance criterion | PASS / FAIL / NOT VERIFIED | evidence:**

**Tests executed (run IDs/logs); tests not executed:**

**Blocking findings and remaining native/release/production gates:**

**Explicit merge permission (owner link, or NOT VERIFIED):**

## Reviewer notes

List known limitations, follow-up issues, and maintainer decisions. No merge is authorized by a clean CI status or completion of this template alone.
