# Release integration lanes — v0.5.0 and v0.6.0

**Status (2026-10-24):** both integration branches exist, but the CI extension
is still under review in PR #158. Its `push` triggers are NOT active on
`main` until merged; a green PR check is NOT a live integration-branch push.
Tracking issue: #157. Do not interpret an integration branch as a signed or
production-ready release.

## Canonical branches and provenance

| Branch | Initial base / purpose |
| --- | --- |
| `main` | Reviewed primary history; original v0.4.0 release remains immutable |
| `integration/v0.5.0` | Created 2026-10-24 from `main` SHA `bba3286be209eee85e3b7d8702edaa10af1bfe57`; v0.5.x consolidation |
| `integration/v0.6.0` | Created from `integration/v0.5.0` at the SAME baseline SHA; future online profile |
| `release/v0.4.0` | Historical protected release reference; do not rewrite |
| `integration/v0.5.0-governed-submissions-gate-a`, `integration/v0.5.0-metrics-submissions-tui` | Existing **feature-specific** experimental branches. Not release integration; do not bulk merge or delete |

Both new integration lanes initially contain **zero release-specific feature
commits**. The source still identifies itself as v0.4.0 until a real,
approved version transition is implemented. Branch names are NOT signed
version assertions.

## Direction and dependency rules

1. Changes originate in focused `feat/`, `fix/`, `test/`, `ci/` or
   `docs/` branches, with an issue reference, a draft/reviewable PR and
   measurable acceptance criteria.
2. Route only v0.5-target changes to `integration/v0.5.0` after reviewing
   issue milestone, stack ancestry and overlap with work already merged into
   `main`. **A green CI run alone does not authorize integration.** Each
   acceptance criterion must be PASS, with executed evidence; any FAIL or NOT
   VERIFIED blocks merge. Explicit maintainer approval is mandatory.
3. v0.6 may incorporate **approved, stable** v0.5 integration state through a
   dedicated reviewed synchronization PR
   `integration/v0.5.0` → `integration/v0.6.0`. Do not automatically
   propagate unaccepted v0.5 work, and do not directly merge feature-level
   0.5 integration branches into 0.6.
4. Route v0.6-target PRs to `integration/v0.6.0` only after reconciling their
   parent PRs, signature/lock contracts and the main-vs-integration diff.
   Avoid mass PR base retargeting: the current #99 → #151 chain is stacked,
   and blindly changing a child base exposes unexpected changes.
5. Before release stabilization, reconcile changes accepted into `main`
   against both lanes via an explicitly reviewed update, not force pushes.
   Final release PRs target `main` and require actual signed acceptance,
   native-system testing, security review and a distinct explicit merge
   authorization. Signing, tagging and publication are **separately
   authorized** operations.

## Initial PR and issue routing snapshot (2026-10-24)

| Work / issue | Release lane | Status / next action |
| --- | --- | --- |
| Signed-candidate infrastructure PR #77 (parent #76); bridge #82 / PR #98; CLI #107 / PR #114 | Already in `main` | **Those PRs merged**; parent signed v0.5.0 candidate acceptance #76 remains OPEN. Compare against current main; do not re-merge or infer release acceptance |
| Metrics #14 / governed submission #15/#16/#17/#22/#23/#57, with integration/security #125/#127 | v0.5.0 candidates | #125 and #127 are already CLOSED; remaining issues and overlapping draft series require reconciliation with main and individual security/acceptance gates before retargeting |
| Client repository sync #24, per-entry approval, ACL/xattr and rollback | v0.6.0 issue milestone; candidate only after dependency review | Overlapping clean/replacement branches and test-only sandbox work; confirm each PR's actual milestone and dependency before any retargeting |
| Online source-only release #84 and installer #83 / PRs #99–#104 | **v0.7.0** issue milestones (NOT v0.6.0) | Stacked DRAFT series; DO NOT route to `integration/v0.6.0` by historical version assumptions. Resolve roadmap/milestone discrepancy with maintainer first; trust, signing, activation and review still NOT VERIFIED |
| CLI/TUI regression #85 / PR #106; sandbox #112 / PR #113; signed candidate preflight #84 / PR #151 | **v0.7.0** issue milestones (NOT v0.6.0) | Stacked DRAFT security chain; do not change milestone or target branch without an explicit roadmap decision and verified dependent acceptance |
| Real PyPI compatibility PR #143 (related #83/#85) | Already in `main` | **PR merged**, parent issues #83/#85 are OPEN at **v0.7.0**; upstream-wheel CI evidence is not full installer/release acceptance |
| PR milestone policy #145 / PR #147 and live gate #148 / PR #163 | Shared repo governance | **Completed and merged where applicable**; keep the current trusted-default-branch privilege model; milestone check remains advisory until a separately approved ruleset change |

This table is a **routing shortlist**, not an authorization or a complete
inventory of open PRs. GitHub currently assigns #83/#84/#85/#112 to v0.7.0,
while earlier design descriptions call parts of the profile "v0.6". The
**current issue milestone takes precedence for routing**, and any proposed
change to that roadmap needs a separate explicit maintainer decision. Recheck
GitHub immediately before each change; never infer the release from a PR title.

## Continuous integration

The CI PR for #157 adds nonprivileged `push` triggers for both integration
branches to FOUR existing workflows, preserving the full original nine
mandatory unfiltered contexts plus a separate path-filtered compatibility check:

- `.github/workflows/tests.yml`: four jobs for Python 3.12/3.13 unit, CLI v1,
  mandatory security tests and Debian/Alma source bundle integrity.
- `.github/workflows/offline-wheelhouse.yml`: three jobs for signed legacy
  offline wheelchain and artifact verification.
- `.github/workflows/upgrade-distros.yml`: two jobs for rootless legacy
  upgrade and rollback on the supported distro userspaces.
- `.github/workflows/native-upstream-wheels.yml`: separate read-only,
  disposable upstream pinned-PyPI compatibility on changed runtime paths.

Existing `pull_request` triggers remain unchanged. The fourth workflow is
path-filtered: a successful `push` without relevant changes may have
**no run**, which must NOT be misrepresented as a passed check. Other
legacy/offline/rollback and platform-specific jobs must continue to be
required during appropriate PR/release gates; review their actual workflow
branch filters before declaring complete `push` coverage.

CI in GitHub-hosted containers is not actual booted native-kernel/SELinux,
owner-signed candidate acceptance, release publication or production
installation.

## Branch protection — pending explicit settings validation

The GitHub connector for this work can create branches and author PRs but
does not expose repository ruleset/branch-protection modification. An
administrator must configure and independently verify on **both** branches:

- Require PR-based changes, at least the review policy used on `main`,
  no force pushes or deletions, and no bypass of blocking reviews.
- Require stable exact check-context names after the CI workflow is merged
  and at least one live run confirms their names. Avoid requiring a
  path-filtered check that may never run for an ordinary PR.
- Require an up-to-date branch, appropriate signed-release security gates,
  and a strict approach to administrator bypass. Do not claim that this
  document enforces the rule.
- Keep GitHub Actions permissions least-privileged and never make a CI
  workflow a release-signing authority.

## Checklist before promoting integration to `main`

Record EACH original issue acceptance criterion with PASS/FAIL/NOT VERIFIED,
exact code revision, CI run and manual evidence, negative/rollback/security
results, approvals, target release compatibility and changed config/upgrade
impact. Reject promotion if any mandatory criterion, review, branch rule or
publisher-signature/native acceptance is NOT VERIFIED or FAIL.

Do not merge release integration branches merely to keep GitHub green.
