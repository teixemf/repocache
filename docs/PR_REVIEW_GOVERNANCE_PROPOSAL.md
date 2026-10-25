# PR review and independent security acceptance — proposed policy

> **Status: PROPOSED / NOT YET APPROVED.** Tracking: [#176](https://github.com/teixemf/repocache/issues/176). This is a decision draft for the sole maintainer, not a repository-wide change to existing review requirements or a GitHub ruleset update. Do not treat this text or passing CI as a review-policy exemption.

## Existing enforceable protections (verified 2026-10-25)

- Protected `main` and `release/*` branches use [ruleset #25436501](https://github.com/teixemf/repocache/rules/25436501); protected `integration/*` branches use [ruleset #25793496](https://github.com/teixemf/repocache/rules/25793496).
- Both active branch rulesets require pull requests, strict success of nine stable GitHub Actions contexts, resolved discussions, and prohibit force pushes/deletion with no bypass actors. The `main`/release ruleset additionally requires linear history. Do not weaken these controls for convenience.
- Both rulesets currently have `required_approving_review_count: 0`. GitHub may therefore show `mergeable=true` with **zero** GitHub reviews. This is a platform setting, **not** evidence that a separate project-level independent review criterion has passed.
- The maintainer must explicitly authorize each merge only after a traceable acceptance-criterion report shows every applicable criterion PASS. Any FAIL, NOT VERIFIED, material security finding, unresolved required check/review or untested required native/release gate blocks that merge.

## Review evidence and identity

A **formal GitHub approval** is a submitted `APPROVED` review from an eligible, independent human (and must meet the effective branch rules). PR conversation comments, AI-authored reports, author self-review, green tests, and GitHub mergeability are **not** formal approvals.

An **independent technical second opinion** can be a separate-session or separately commissioned evidence-led security/code review, with current-head SHA, actual patches, trust boundaries, threat assumptions, reproducible CI evidence, risk findings, and explicit coverage gaps. If AI-assisted, identify it accurately as AI-assisted; it is not a human review, audit certification, or evidence of running tests it did not execute.

Existing one-off maintainer decisions to accept external technical review for PRs [#158](https://github.com/teixemf/repocache/pull/158), [#170](https://github.com/teixemf/repocache/pull/170), and [#171](https://github.com/teixemf/repocache/pull/171) were **each explicitly approved for that specific PR** and do not transfer to new changes, updated heads, or future releases.

## Proposed decision for a solo-maintainer workflow

**Option A — Independent eligible human (highest confidence):** recruit a qualified reviewer and configure `>=1` required approvals only after confirming the identity, review permissions, self-approval restrictions and that normal maintenance PRs can still merge. Otherwise a sole maintainer may face a permanent deadlock. Never add an administrative bypass or fabricate review events.

**Option B — Documented project-level review gate, zero GitHub approvals (recommended for now, subject to explicit owner decision):** preserve the current rulesets and add an auditable review process to every PR. Prefer an eligible independent human review for privilege-boundary, signing, updater, installer, trust anchor or sensitive external-service changes. If none is available, a narrowly scoped technical second opinion **may be proposed** as an exception, but requires a fresh, explicit maintainer decision accepting that form of evidence **for the exact PR and HEAD**. No standing AI-only waiver is implied. Do not silently change original issue acceptance criteria, especially where a genuine external security or native-host test is explicitly required. A change to an agreed criterion must be recorded in the issue/PR before treating it as PASS.

For either option, meaningful Critical/High vulnerabilities are hard merge blockers until corrected and retested. Affected Medium findings require remediation or a separately recorded, issue-authorized scope/risk decision only if the underlying acceptance/security requirements allow it. A reviewer may not waive failed tests, branch protection or release-publisher key custody.

**Maintainer decision required for #176:** choose Option A or B, or document another workable, GitHub-compatible option. Until that decision is explicitly made, the existing project-level independent-review policy remains unchanged.

## Proposed per-PR acceptance procedure

1. **Scope:** read the primary issue, specifications, security dependencies, planned base, migration/upgrade impacts, and measurable acceptance criteria. Confirm whether a requirement is pre-merge, post-merge, post-release, or production-specific; never shift the gate merely to make CI green.
2. **Code and threat review:** inspect the complete diff against the current target and confirm expected Git ancestry; examine untrusted input, root/service UID separation, filesystem and temp-file safety, network/TLS and credentials, GitHub Actions trust boundaries, APT/DNF/NGINX effects, rollback and compatibility. Record discovered vulnerabilities and negative tests.
3. **Independent evidence:** request an eligible review; record reviewer identity and PR/commit scope. For any proposed alternative, attach its complete technical findings and the **explicit owner approval of a single-PR acceptance amendment**. Do not call that a human GitHub approval.
4. **Executed test traceability:** enumerate every issue/PR criterion, label PASS/FAIL/NOT VERIFIED with exact command, CI run/job, log, source reference or reproducible manual proof. Test existence alone is NOT VERIFIED. Distinguish disposable GitHub containers from booted Debian 13/AlmaLinux 10 with native systemd and SELinux.
5. **Last-minute gate:** reread live PR HEAD/base, reviews/threads, branch protection, required nine contexts from the expected GitHub Actions app and full workflow status, milestone policy, mergeability and any blocking findings. Revalidate if head/base/code changed. No `--force`, protections bypass, unauthorized squash/rebase or unsigned release.
6. **Authorization:** obtain explicit maintainer approval for this specific merge after all *applicable* criteria are PASS. Record review criterion amendments with reason, scope and residual risk; merges do not implicitly authorize tags, signing, releases, listener enablement or production changes.
7. **After merge:** verify target SHA and required `push` checks for the updated branch where applicable; preserve evidence. Keep issues open while their real operational or release criteria are pending.

### Minimum PR evidence template

```text
Primary issue: #NN
Target / current base SHA:
Current PR head SHA:
Scope, dependencies and threat boundary:
Review source: eligible human / technical audit / NOT VERIFIED
GitHub approval count: N (actual)
PR-specific review amendment: owner link + exact scope, or NONE
Criterion | PASS / FAIL / NOT VERIFIED | exact evidence
Tests executed / not executed:
Unresolved vulnerabilities and blockers:
Required checks: names, app source, SHA and conclusions
Merge method / ancestry reasoning:
Explicit merge authorization: link or NOT VERIFIED
Post-merge or release gates not claimed:
```

## Scope and non-goals

This proposal does not make a GitHub comment an enforceable independent-review check. Formal reviewer enforcement needs GitHub ruleset administration and eligible humans. The external technical-audit alternative is a *human owner acceptance process* and cannot honestly be represented as a native GitHub approval. If the maintainer wants a stronger automated governance check, commission a separately reviewed, minimally privileged GitHub App/CI implementation with authenticated decision records; do not trust arbitrary PR-comment text as authorization.

Never use synthetic Ed25519 signing fixtures as proof of owner-signed assets, or rootless containers as proof of native enforcing SELinux, booted systemd, physical recovery, or the real signed v0.4.0-to-v0.5.0 migration. Specific gates [#17](https://github.com/teixemf/repocache/issues/17), [#49](https://github.com/teixemf/repocache/issues/49), and [#76](https://github.com/teixemf/repocache/issues/76) remain independently binding.

The accepted two-lane integration infrastructure in [#157](https://github.com/teixemf/repocache/issues/157) stays complete; the future-version workflow trigger enhancement is [#175](https://github.com/teixemf/repocache/issues/175). Nothing in this governance draft authorizes a merge, tag, release, signer access, ruleset mutation or live service activation.
