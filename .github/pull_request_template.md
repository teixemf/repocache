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

## Independent review and acceptance record

Review policy proposal: [#176](https://github.com/teixemf/repocache/issues/176);
[proposed process](https://github.com/teixemf/repocache/blob/main/docs/PR_INDEPENDENT_REVIEW_POLICY.md).
Choice B and Choice C decisions in #176 currently conflict; this template does **not** authorize a standing exception or make either policy ACTIVE.

- **Exact HEAD/base SHAs and tested merge revision:**
- **Evidence matrix:** criterion | PASS / FAIL / NOT VERIFIED | test/log/review URL | residual risk
- **Risk classification and trust boundary:** ELEVATED / ROUTINE / UNCERTAIN; reasons and affected permissions, identities, source/release integrity, installer/update authority.
- **Review evidence:** eligible independent human GitHub review URL / external technical assessment URL / NOT VERIFIED
- **Proposed Choice C elevated gate:** eligible independent HUMAN GitHub APPROVED review REQUIRED; external technical evidence is supplemental only, never a replacement.
- **Proposed Choice C routine gate:** external assessment only after an explicitly accepted PR-specific, exact-HEAD substitution; no automatic waiver.
- **PR-specific substitution authorized by maintainer?** link to explicit decision, or NOT VERIFIED
- **Blocking findings / native platform limits / acceptance stage:**
- **Explicit separate merge authorization:** link or NOT VERIFIED
- **Intended merge method, ancestry requirements and post-merge verification:**

Never call external AI technical evidence a human GitHub APPROVED review.
Do not merge on a missing project review decision, any applicable FAIL /
NOT VERIFIED criterion, missing exact-head CI, or missing owner authorization.

## Reviewer notes

List known limitations, follow-up Issues and any maintainer decision needed. Do not merge until approved.
