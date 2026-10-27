# Pull request milestone governance

Tracking: [#145](https://github.com/teixemf/repocache/issues/145).

Every PR should be assigned to the **release milestone of its primary deliverable**, not necessarily the milestone of every upstream dependency it mentions. The milestone indicates intended delivery, **not** acceptance, test completion or merge eligibility.

## Authoring and manual triage

The pull request template asks for a same-repository issue reference in the form:

```text
Primary issue: #145
```

The milestone workflow also understands a conventional, standalone `Closes #145`, `Fixes #145`, or `Resolves #145` line and trailing PR title issue references such as `(#145)` or `(#83 #85)`. Ordinary prose, quoted PR links, issue numbers in branch names and arbitrary numeric tokens do not count as authoritative references.

- If the PR already has a milestone, the workflow **preserves** it; maintainers own deliberate overrides.
- If the PR has no milestone, only real, same-repository **issues with assigned milestones** qualify. All identified issues must agree on the milestone, even when an explicit primary issue is provided.
- If two explicitly linked issues belong to different milestones, the workflow **fails closed**. A maintainer must decide the correct delivery milestone and set it manually. Do not mutate issue milestones just to bypass this rule.
- If no eligible issue reference exists, or a referenced issue lacks a milestone, the workflow fails with an actionable message. This includes Dependabot maintenance PRs without a linked issue. Assign a milestone manually after review, or link an appropriate already-planned maintenance issue.
- A PR with only an experimental or test-only contribution should use the milestone of the functionality/release gate it materially serves. Associating a milestone does not make sandbox experiments production-ready.

The check is **not a substitute** for the project's functional, regression, security, compatibility, installation, upgrade, documentation or [independent review and acceptance policy](PR_REVIEW_GOVERNANCE.md). The maintainer-approved Option B process keeps GitHub's zero required formal approvals but requires documented independent technical evidence and any individually authorized review-criterion substitution, plus separate merge permission. A milestone or green CI never supplies those decisions.

## Execution and security

`.github/workflows/pr-milestone.yml` uses `pull_request_target` to grant narrowly scoped GitHub issue-metadata updates (`pull-requests: write`, `issues: read` and `contents: read`). It checks out only code from the protected repository **default branch**, pins the reviewed first-party checkout SHA and sets `persist-credentials: false`. It never checks out the PR head or executes PR-supplied code. Untrusted PR title/body are parsed as text and only same-repository numeric issue references are resolved via GitHub's API.

Runs on PR opened/reopened/**synchronize** (new head commits)/edited/ready-for-review and milestone-attachment/removal events. It verifies live PR metadata, is idempotent for existing milestones, and checks the GitHub response after assigning a new milestone. Transient GitHub API errors produce a non-passing check rather than an inferred milestone.

Status-check enforcement is configured separately from the workflow in branch protection/rulesets by the maintainer. **Current observed policy (2026-10-25):** the active [main-only milestone ruleset #25791816](https://github.com/teixemf/repocache/rules/25791816) requires the GitHub Actions context `Require milestone or unambiguous primary issue` on `main`; it is **not** a required milestone context for `release/*` or `integration/*`. The earlier advisory-only state and initial live pilot were superseded by an explicitly authorized required-check activation and negative test documented in [issue #148](https://github.com/teixemf/repocache/issues/148#issuecomment-6387956306). The nine existing strict mandatory contexts remain separate and unchanged. Always recheck the actual effective rulesets and live milestone behavior rather than treating this snapshot as permanent.

## GitHub token permissions: live integration finding (#148)

The first live pilot on GitHub Actions proved that `issues: write` alone is
insufficient to PATCH a **pull request** via `/repos/{owner}/{repo}/issues/{number}`:
the workflow returned **HTTP 403** on automatic milestone assignment despite
being able to read issue metadata. GitHub's PR-specific authorization boundary
requires `pull-requests: write`. Use `issues: read` only to inspect linked
issue milestones; keep `contents: read` for trusted default-branch checkout.

This token scope still grants more power than the one PATCH operation. Treat
all PR metadata as untrusted text; never execute PR code or expand PR content
into a shell command. The workflow uses pinned checkout, disabled credential
persistence, the trusted default branch and fixed GitHub API URLs. A static
permission test protects this configuration against accidental changes.

**Historical pilot guidance (superseded for `main`):** before the live assignment
and negative-case pilot, the owner required the milestone check to remain
advisory. The [#148 live pilot](https://github.com/teixemf/repocache/issues/148#issuecomment-6387751895)
and subsequent [main-only enforcement decision](https://github.com/teixemf/repocache/issues/148#issuecomment-6387956306)
completed those prerequisites. Ruleset #25791816 is now active for `main` only.
Preserve the original nine mandatory contexts on `main` and `release/*`; do not
extend the milestone rule to other protected branches or modify rulesets without
separate, explicit maintainer approval.

## Testing

Run the offline logic tests with:

```console
python -m pytest -q tests/test_pr_milestone_policy.py
```

The standard Python test matrix includes this test file when merged. Running local tests does **not** establish live GitHub Actions event or permission behavior. A post-merge pilot PR with an issue in the same milestone, another PR with conflicting milestones and a PR with a manually assigned milestone should be checked before claiming the automation is fully operational.
