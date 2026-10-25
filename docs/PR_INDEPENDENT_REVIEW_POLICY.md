# Independent pull request review — proposed policy

**Status: PROPOSED / NOT ADOPTED.** Tracking: [#176](https://github.com/teixemf/repocache/issues/176).
This is a decision document for the maintainer, not an amendment of the live rulesets
or a standing waiver. Until a choice is expressly approved and implemented, use
the existing project acceptance gate and obtain explicit approval for each merge.

## Existing enforcement and scope

Applies to proposed changes targeting protected `main`, `release/*` and
`integration/*` branches. At the 2026-10-25 snapshot, main/release ruleset
`25436501` and integration ruleset `25793496` are active. They require a
pull request, nine strict GitHub Actions contexts, resolved review threads,
and prohibit protected-branch force pushes and deletion. Both currently set
`required_approving_review_count: 0`. Main also has milestone ruleset
`25791816`. Re-read all relevant live rules before each merge.

**GitHub mergeability is not the project's independent-review acceptance gate.**
GitHub does not prove that an external independent assessment occurred. A
`pull_request_target` milestone check is not a code-security review. Neither
an AI report nor a maintainer-written comment constitutes a GitHub human
`APPROVED` review.

## Decision required from the maintainer

Choose and record ONE enforceable policy, specifying whether it applies to
main, release and integration branches equally, and how exceptional PRs work:

| Choice | Model | Benefit | Cost / failure mode |
| --- | --- | --- | --- |
| A — eligible human review | Require at least one *eligible* independent human approval in each applicable ruleset | GitHub-enforced independent human review | May block sole-maintainer PRs indefinitely until an eligible reviewer exists; cannot be bypassed or self-approved |
| B — evidence-based solo-maintainer procedure | Keep zero required GitHub approvals, but require an independently prepared technical assessment, a traceable PR-specific acceptance record and explicit owner approval for each merge | Works with a sole maintainer and existing rules without spoofed reviews | **Process-only enforcement**: GitHub may show mergeable before project acceptance; cannot claim formal human scrutiny |
| C — risk-tiered hybrid (**proposal**) | Prefer eligible human approval for all; require eligible human review for trust-root/signing, credentials, privileged installation, APT/DNF source writes, critical security or branch-protection changes; use B for other scoped changes **only** after an explicit PR-specific owner decision | Stronger assurance for sensitive boundaries, realistic routine maintenance | Sensitive PRs may remain blocked until another eligible reviewer is available; judgment and manual process remain necessary |

**Proposed choice C is not authorized simply because this document is merged.**
Issue #176 requires an explicit maintainer decision identifying the selected
model, applicable branch families, exceptional review eligibility and exact
policy effective date. Changing a ruleset requires its own authorization,
live verification and a pilot. If the decision is different, revise this
proposal through a reviewed PR before claiming adoption.

No solution may rely on fabricated human approvals, self-review represented
as independent, bot impersonation, force pushes, branch-protection bypass,
ignored failing checks or lowered security acceptance criteria.

## Review evidence and eligibility (proposed invariant)

1. A **human GitHub reviewer** must be an eligible independent contributor
   capable of submitting a genuine `APPROVED` review under repository policy;
   an author or their own automation is not independent. Record review URLs
   and check that the review applies to the tested HEAD.
2. An **external technical second opinion**, including one assisted by AI,
   must disclose its provenance, scope, access limitations, examined exact
   HEAD/base and independent evidence (diff, code, CI/job logs, rulesets).
   An isolated session is not proof of human independence. Do not invent
   reviewer identity, quote it as a human APPROVED review or call it a full
   security audit.
3. For any substitute accepted in an individual PR, the owner must expressly
   identify the PR number, the review criterion being amended, the assessment
   accepted, why substitution is proportionate, retained security/CI gates
   and remaining risks. This decision does not automatically approve the
   merge. A **separate, explicit merge authorization** is still required.
4. A prior exception never transfers. Documented exceptions for
   [#158](https://github.com/teixemf/repocache/pull/158),
   [#170](https://github.com/teixemf/repocache/pull/170) and
   [#171](https://github.com/teixemf/repocache/pull/171)
   are strictly historical, PR-specific decisions, not precedent granting a
   blanket waiver.

### Proposed risk classification

- **Elevated review:** cryptographic trust anchors, owner signing/candidate
  provenance, update authority, privilege/root helpers, sandbox escapes,
  network credential handling, persistence or package-manager configuration,
  release publishing, and changing required CI/rulesets/reviewer requirements.
  Independent eligible human security review is the **recommended default**.
  Without such a reviewer, mark that review gate `NOT VERIFIED` and keep
  the PR unmerged unless the maintainer explicitly approves a separately
  documented policy change for that specific scope after reviewing risks.
- **Routine scoped review:** documentation, non-privileged tests and narrow
  CI trigger maintenance may qualify for an explicitly approved PR-specific
  external technical-assessment substitute when there is no material trust
  change. Never infer a low-risk label from the filenames alone.
- **Any confirmed critical or high security defect**, applicable failed test,
  unverified mandatory negative case, unresolved blocking review or changed
  untested HEAD remains a merge blocker regardless of reviewer type.

## Required per-PR acceptance record

In the PR conversation, record **before** merge:

- Primary issue, milestone, protected target, head/base SHA, ancestry and
  complete changed-file list; disclose substantive AI assistance.
- Individual issue/specification criteria, each `PASS`, `FAIL` or
  `NOT VERIFIED`, with exact executed test/CI run and log or reproducible
  code/manual review proof, including negative cases, compatibility, security,
  upgrade, rollback, documentation and source-integrity as applicable.
- Every applicable required status context and app identity, up-to-date strict
  CI results, missing/skipped tests and separate native platform limitations.
  Merely writing a test does not count as running it.
- Review method and its evidence link: genuine eligible human GitHub approval
  OR a PR-specific owner-approved project-criterion substitute, **never both
  conflated**. Record any findings and residual risks.
- Owner's **explicit permission for this merge**, intended method (squash,
  merge or rebase according to approved ancestry), and final re-check of
  actual HEAD/base, exact-head checks, rulesets, reviews and thread state.

Any applicable `FAIL` or `NOT VERIFIED`, material security issue, failed
required check, stale tested revision, unapproved review substitution or
missing merge permission blocks merge. Do not relabel missing evidence as
`PASS`. A pre-merge gate cannot be waived merely because a post-merge
operational test is chronologically impossible; track that operational gate
separately as `NOT VERIFIED` until its real branch `push` proves success.

Following an **authorized** merge, compare the protected branch commit,
reviewed tree and ancestry, obtain actual `event=push` results when required,
and record all mandatory contexts on the exact merged SHA. PR CI is not a
substitute for branch-push CI. Do not close the issue while applicable
post-merge criteria remain unverified.

## Release and security boundaries

A CI-green PR does not authorize tags, Ed25519 owner signing, GitHub Releases,
APT/DNF source mutation, production deployment, native booted systemd/SELinux
acceptance or release promotion. Those have separate criteria, evidence and
operator authorization. Never place private signing keys in Actions, and do
not publish security-sensitive findings or credentials in PR discussion.

## Enforceability and rollout

This proposed process does **not** add a privileged `pull_request_target`
workflow or claim to make external reviews machine-verifiable. With zero
GitHub-required approvals, a manual project gate remains **human/owner
enforced** until an explicitly reviewed enforcement mechanism exists.
An optional future evidence-only check must not execute untrusted PR code with
write permissions or convert AI output into a fabricated `APPROVED` event.

To adopt: obtain the #176 maintainer decision; revise this document to
`ACTIVE` with effective date, chosen policy per branch family and its limits;
verify current ruleset state; apply only separately approved ruleset changes;
test a real PR/approval or documented solo path; record actual CI results and
approval links; then request separate merge permission for the implementation.
If the elected design cannot be enforced or tested, record `NOT VERIFIED`
and keep #176 OPEN.

See also [milestone governance](PR_MILESTONE_GOVERNANCE.md),
[release integration](RELEASE_INTEGRATION_BRANCHES.md),
[release acceptance](RELEASE_ACCEPTANCE_POLICY.md), and
[contribution rules](../CONTRIBUTING.md).
