# Node.js 24-native GitHub Actions migration (#74)

## Scope and security boundary

The v0.5.0 workflow migration replaces Node.js 20-based upstream
GitHub Actions with pinned Node.js 24-native released commits.
It does **not** modify the published immutable v0.4.0 assets, the offline
Ed25519 signer, release authorization, branch rulesets or package dependency
resolution. Only the public `teixemf/repocache` repository is in scope.

Reviewed official upstream tag references and `action.yml` `runs.using`
on 2026-10-23:

| Action | Reviewed tag | Exact pinned commit | Runtime |
| --- | --- | --- | --- |
| actions/checkout | v5.0.1 | `93cb6efe18208431cddfb8368fd83d5badbf9bfd` | node24 |
| actions/setup-python | v6.0.0 | `e797f83bcb11b83ae66e0230d6156d7c80228e7c` | node24 |
| actions/upload-artifact | v6.0.0 | `b7c566a772e6b6bfb58ed0dc250532a479d7789f` | node24 |
| actions/download-artifact (future #77) | v7.0.0 | `37930b1c2abaa49bbe596cd826c3c89aef350131` | node24 |

The tags above resolved to Git commit objects (not a floating branch),
and each action manifest was inspected at its versioned upstream tag.
Source: `https://github.com/actions/<action>/releases` and
`https://raw.githubusercontent.com/actions/<action>/<tag>/action.yml`.

The official Node.js 24 actions require **Actions Runner v2.327.1 or newer**.
GitHub-hosted `ubuntu-latest` is used for all current workflows. Self-hosted
runners are not automatically supported; their versions must be checked first.
Do not use floating `@v*` refs. Review new SHA pins and transitive action
changes before any update.

## Required invariants

- `permissions: contents: read` stays the default, with scoped `issues:
  write` only for the existing label sync job.
- Every checkout explicitly uses `persist-credentials: false`.
- The existing nine required test contexts and their names must remain
  present, across unit tests, bundle integrity, offline wheels and native
  synthetic upgrade rehearsal.
- `release.yml` remains an explicit owner-triggered `workflow_dispatch`
  on an approved version tag, checks tag-to-main ancestry, and only
  **uploads unsigned candidate assets**. It never signs or publishes them.
- Prepublication owner-signed acceptance (#76/#78), immutable publication,
  and postpublication checks remain independent gates.

## Verification and operational procedure

1. Run `python -m pytest -q tests/test_actions_node24_contract.py`
   and the complete existing test suite on the PR exact head.
2. Require all nine protected CI contexts to finish **SUCCESS** at the
   exact head, including Debian 13 and AlmaLinux 10 disposable tests.
   A queued, skipped, cancelled or missing check is not a PASS.
3. The `tests.yml` bundle-integrity matrix uploads short-lived
   `node24-rehearsal-*` artifacts for a nonpublishing v0.5.0 PR.
   Review the jobs and verify GitHub exposes an artifact with its expected
   source workflow and run ID. This tests the selected Node24 uploader
   but does **not** replace the release-workflow acceptance requirement.
4. On an approved, nonpublishing synthetic release rehearsal, validate
   the gated `release.yml` upload, retrieve its ZIP through the GitHub
   Actions artifact API, and compare the source SHA, expected archive
   names and hashes. No private signer material in CI.
5. Recheck PR reviews, exact-head branch protection, Node24 action
   manifest identity and failure logs before merge. Review and merge
   remain distinct from owner approval to sign, tag or publish.

## Remaining evidence and rollback

**NOT VERIFIED until independently executed:** actual protected-branch
integrated CI, the owner-triggered release-workflow artifact retrieval on
a safe synthetic candidate, and final human review of the exact diff.
These are not waived by a static contract test.

If an official action update fails before publication, revert the
migration PR with a separately reviewed revert, rerun the nine required
checks and investigate the runtime compatibility. Do not alter signed
v0.4.0 release assets or bypass the required release acceptance gate.
Do not silently downgrade to vulnerable Node.js 20 actions in a future
release; any exception needs explicit risk acceptance and a documented
time-bounded remediation.

The draft signed-candidate acceptance workflow in PR #77 is independently
updated to this Node24 set before integration. Its owner-signed native
acceptance criteria remain unaffected and NOT VERIFIED until executed.
