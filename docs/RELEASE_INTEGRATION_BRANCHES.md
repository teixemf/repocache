# Release integration lanes — v0.5.0 and v0.6.0

**Status:** branch baseline established; workflow changes are proposed in a
separate CI pull request and are NOT effective on `main` until merged.
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
| Signed legacy bootstrap #76 / PR #77; compatibility bridge #82 / PR #98; CLI #107 / PR #114 | Already in `main` | **Merged**; compare against current main before any forward-port; do not re-merge |
| Metrics #14 / governed submission #15/#16/#17/#22/#23/#57 and integration/security #125/#127 | v0.5.0 candidates | Multiple partially overlapping stacked DRAFT series; reconcile against main and enforce individual security/acceptance gates before retargeting |
| Client repository sync #24, per-entry approval, ACL/xattr and rollback | Check target milestone and dependency | Overlapping clean/replacement branches and test-only sandbox work; decide supported scope and avoid inadvertent 0.5/0.6 cross-version mixing |
| Online source-only release #84 and install #83 / PRs #99–#104 | v0.6.0 candidates | Stacked DRAFT series; trust, native sign/activation and independent review NOT VERIFIED |
| CLI/TUI regression #85 / PR #106; sandbox #112 / PR #113; signed external candidate preflight #84 / PR #151 | v0.6.0 candidates | Stacked DRAFT security chain; no mass retarget or merge before criteria PASS |
| Real PyPI compatibility #83/#85 / PR #143 | Already in `main` | **Merged**; CI compatibility evidence is not v0.6 release approval |
| PR milestone policy #145 / PR #147 and live gate #148 | Shared repo governance | Keep independent; do not bypass or silently supersede their default-branch privilege model |

This table is a **routing shortlist**, not an authorization or a complete
inventory of open PRs. Recheck GitHub immediately before each change.

## Continuous integration

The CI PR for #157 adds nonprivileged `push` triggers for both integration
branches to:

- `.github/workflows/tests.yml`: Python 3.12/3.13 unit, CLI v1 and
  mandatory security tests, plus Debian/Alma source bundle smoke.
- `.github/workflows/native-upstream-wheels.yml`: read-only,
  disposable upstream pinned-PyPI compatibility on changed runtime paths.

Existing `pull_request` triggers remain unchanged. The second workflow is
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
