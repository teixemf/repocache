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

The check is **not a substitute** for the project's functional, regression, security, compatibility, installation, upgrade, documentation or human merge acceptance gates.

## Execution and security

`.github/workflows/pr-milestone.yml` uses `pull_request_target` to grant narrowly scoped GitHub issue-metadata updates (`issues: write` and `contents: read`). It checks out only code from the protected repository **default branch**, pins the reviewed first-party checkout SHA and sets `persist-credentials: false`. It never checks out the PR head or executes PR-supplied code. Untrusted PR title/body are parsed as text and only same-repository numeric issue references are resolved via GitHub's API.

Runs on PR opened/reopened/edited/ready-for-review and milestone-attachment/removal events. It verifies live PR metadata, is idempotent for existing milestones, and checks the GitHub response after assigning a new milestone. Transient GitHub API errors produce a non-passing check rather than an inferred milestone.

A required status check must be configured separately in branch protection/rulesets by the maintainer. Until that is done, this workflow is advisory despite being able to fail its own job. The workflow is not operationally verified until a **post-merge** GitHub Actions `pull_request_target` run proves its token scope, event behavior, and assignment on the live repository.

## Testing

Run the offline logic tests with:

```console
python -m pytest -q tests/test_pr_milestone_policy.py
```

The standard Python test matrix includes this test file when merged. Running local tests does **not** establish live GitHub Actions event or permission behavior. A post-merge pilot PR with an issue in the same milestone, another PR with conflicting milestones and a PR with a manually assigned milestone should be checked before claiming the automation is fully operational.

## Live HTTP 403 diagnostics (issue #148)

The initial default-branch integration smoke ran under a GitHub Actions token which the runner reported as `Contents: read` and `Issues: write`. An automatic PR milestone PATCH still returned HTTP 403, so assignment is **NOT VERIFIED / FAIL** despite passing offline tests. See [issue #148](https://github.com/teixemf/repocache/issues/148) and [pilot #159](https://github.com/teixemf/repocache/pull/159).

A denied GitHub API request now includes only syntactically validated `X-GitHub-Request-Id` and `X-Accepted-GitHub-Permissions` headers if available. It never prints the response body, token, Authorization header, or arbitrary remote response text. These diagnostics are for administrator investigation, not permission to broaden the workflow token or relax branch policy. The new script will run in `pull_request_target` only after a separately reviewed and authorized merge to the protected default branch.

Keep the milestone status check **advisory** until real auto-assignment succeeds. Maintainers must explicitly decide whether to make this check required and validate enforcement independently.
