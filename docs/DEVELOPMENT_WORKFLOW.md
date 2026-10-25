# Development workflow — coordinated AI-assisted contributions

**Purpose:** deterministic handoff between parallel AI sessions without losing GitHub provenance, growing milestones automatically or relaxing acceptance. See [AGENTS.md](../AGENTS.md) for the mandatory entry point. This document complements, rather than supersedes, [CONTRIBUTING.md](../CONTRIBUTING.md), [TESTING.md](TESTING.md), [release acceptance](RELEASE_ACCEPTANCE_POLICY.md), [PR milestone governance](PR_MILESTONE_GOVERNANCE.md) and the [CLI contract](architecture/CLI_ARCHITECTURE.md).

## 1. Intake: establish the authoritative state

For any requested implementation, release work, issue closure or independent review:

1. Identify `owner/repo`, current protected `main` SHA, affected issue(s), milestone, target branch and user authorization. Inspect *live* GitHub, not cached discussion.
2. Read the **current issue/specification acceptance criteria** and explicit amendments/owner decisions. If an agreed criterion is ambiguous, propose measurable evidence before declaring it passed; do not silently rewrite it.
3. Inspect recent changes to affected files, all open PRs touching them, merged fixes, historical stacked bases and the actual implementation. Distinguish `planned`, `approved`, `implemented`, `tested`, `reviewed` and `merged`.
4. Review relevant docs for security, CLI, dependencies, installation and release. Note any stale document or conflict between issue/PR claims and protected-branch code.
5. Publish a short execution scope: intended issue/branch, unchanged contracts, overlap, tests, manual requirements and expected finish condition.

When access is missing, report the exact missing source/evidence. For read-only requests, stop at an evidence-backed assessment without modifying GitHub.

## 2. Work intake and scope control

Use the smallest independently verifiable increment of an **existing** issue. Prefer one focused PR and a checklist in that issue over serial child issues, parallel alternate implementations or a new issue for each acceptance test.

Create a separate issue only after confirming it is not a duplicate and that it has a separate deliverable, owner/dependency boundary or unavoidable independent acceptance. Propose justification, measurable criteria, release effect and alternatives before assigning a frozen release milestone. A discovered enhancement defaults to later backlog, not the active release. Confirm explicit owner agreement for release-scope changes; preserve the original criteria and historical evidence.

If a required test can only occur *after* a merge or on the real owner workstation/target host, record that as an acceptance stage or external blocker. Only split an issue if circular dependencies genuinely require separate change ownership; do not manufacture a false passing result or weaken the release gate.

If an issue's parents refer to another release (e.g. future online dependency activation), document the cross-release dependency for maintainer triage. Never silently move an issue, treat a PR title's version as authoritative or conflate optional production activation with code acceptance.

## 3. Implementation and integration

- Use a dedicated feature/docs/test/fix branch from a verified base. Respect protected `main`, `release/*` and `integration/*` branches, PR-only routing, strict checks and no force/deletion bypass.
- Never bulk retarget or merge a stacked PR chain: review ancestry, transferred changes and exact current-base diff. Prefer narrow reconciliation where original changes have already been integrated.
- Preserve functional and security boundaries: Debian 13 and AlmaLinux 10 only, approved client/CLI contracts, APT/DNF failover, safe NGINX/systemd/SELinux operation, secrets isolation, signed metadata and recovery.
- Add relevant unit, integration, CLI, installation, upgrade, negative-path, failure-injection, regression and security tests. Update English documentation and migration notes in the same PR as code that changes behavior.
- Limit parallel work on shared files. If another session owns an overlapping PR, coordinate in that existing PR rather than generating a competing branch.
- A finished PR is not necessarily an accepted parent issue or a publishable release.

## 4. Evidence and acceptance gate

Map **every original applicable criterion** to one of the following statuses:

| Status | Meaning | Required record |
| --- | --- | --- |
| PASS | Criterion demonstrated on the appropriate exact code/artifact/configuration | Test command or reviewed manual procedure, result, SHA, environment and run/log reference |
| FAIL | Verified negative outcome or security/regression defect | Exact reproduction, evidence and blocking owner |
| NOT VERIFIED | Test absent, inaccessible, wrong environment, stale SHA, missing review or ambiguous criterion | Missing evidence and the smallest next step |

Execute available checks and inspect actual outcomes, not only green workflow badges. Tests **added but not executed** remain NOT VERIFIED. Differentiate GitHub-hosted distro containers from native booted systemd/SELinux, synthetic signatures from owner-key signatures, and prepublication candidate acceptance from postpublication smoke.

Before any merge, re-check PR head/base, diff, scope, dependency ancestry, required job contexts, review eligibility, unresolved threads, issues and material findings. Any applicable FAIL/NOT VERIFIED, blocked review, missing required check or security defect is a merge blocker. Apply the independent-review policy **actually effective on the protected branch**; competing drafts #177/#178 cannot be adopted by assumption. A human GitHub approval and an AI-assisted technical assessment are distinct. Any alternative requires an explicit, traceable PR-specific owner decision when the operative policy permits it.

**No merge without separate explicit maintainer authorization.** Similarly require distinct authorization for release signing, tagging, Draft staging, publication, production service activation, protected ruleset changes and destructive actions. Preserve [signed candidate acceptance](SIGNED_CANDIDATE_ACCEPTANCE.md) and [release gates](RELEASE_ACCEPTANCE_POLICY.md).

## 5. Continuity: leave the repository ready for another session

At the end of authorized implementation work, update the existing issue or PR with a short English checkpoint using this form:

```text
Checkpoint (UTC): YYYY-MM-DD
Primary issue / milestone:
Authoritative branch / HEAD / target base:
Scope completed and files changed:
Acceptance: criterion -> PASS | FAIL | NOT VERIFIED -> exact evidence
Tests executed: command, environment, results, CI run / SHA
Tests added but not run:
Security / compatibility / rollback impact:
Overlapping or superseded PRs (do not close without authorization):
Remaining blockers / required owner decisions:
Next minimal action:
Merge / sign / publish / deploy authorization: NOT GRANTED unless explicit
```

Do not present a prior session's assertions as independently verified. A new session must re-fetch GitHub state and review changes since the checkpoint. Avoid repeated narrative comments unless evidence or state changed materially.

## 6. Minimizing process overhead

Do not create a new issue to document the same test, a new PR to restate a completed acceptance report, or an AI-specific history that competes with GitHub. Use the issue checklist, current PR and canonical release scope ledger. Keep the short [AGENTS.md](../AGENTS.md) stable; put detailed engineering requirements in their existing canonical documents.

**Do not merge this workflow into a release simply to raise a milestone completion percentage.** Publication readiness is determined by all applicable substantive and release acceptance criteria, not the number of closed tracking issues.
