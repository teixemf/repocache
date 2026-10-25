# Release integration lanes — v0.5.0 and v0.6.0

**Status (2026-10-25):** PR #158 has merged into protected `main`
(`9e213d7beb6534181e3ff418a890c5fdf2db2017`), and PR #170 has merged
the reviewed CI backport into protected `integration/v0.5.0`
(`48fed70f4e67a6db45c1b4cba6098e4d6b718f9b`). The latter has a
verified real `push` event with all nine required checks successful.
`integration/v0.6.0` remains at its original baseline pending separately
reviewed PR #171; its PR-head CI is **not** a live protected-branch push.
Tracking issue: #157. No integration branch is a signed or
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
| PR milestone policy #145 / PR #147 and live gate #148 / PR #163 | Shared repo governance | **Completed and merged where applicable**; preserve the trusted-default-branch permission model. **Current GitHub ruleset #25791816 requires** `Require milestone or unambiguous primary issue` for `main` only (observed 2026-10-24); it does not protect the two integration branches. Do not change this live policy silently |

This table is a **routing shortlist**, not an authorization or a complete
inventory of open PRs. GitHub currently assigns #83/#84/#85/#112 to v0.7.0,
while earlier design descriptions call parts of the profile "v0.6". The
**current issue milestone takes precedence for routing**, and any proposed
change to that roadmap needs a separate explicit maintainer decision. Recheck
GitHub immediately before each change; never infer the release from a PR title.

## Continuous integration

Merged PR #158 added nonprivileged `push` triggers for the two named release
integration branches to FOUR existing workflows, preserving the original nine
mandatory unfiltered contexts plus a separate path-filtered compatibility check.
PR #170 propagated that reviewed CI to the protected v0.5.0 lane. PR #171
proposes the same reviewed CI for the v0.6.0 lane, but is **not merged**:

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

## Live integration push evidence and nine exact required contexts

| Branch/event | SHA | Result and limitation |
| --- | --- | --- |
| `main` after PR #158 squash | `9e213d7beb6534181e3ff418a890c5fdf2db2017` | **PASS:** 9/9 required Actions contexts; this does not exercise a protected release-integration push |
| `integration/v0.5.0` after PR #170 | `48fed70f4e67a6db45c1b4cba6098e4d6b718f9b` | **PASS:** real branch `push` with 11/11 successful checks, including all nine required; [Tests #40145596050](https://github.com/teixemf/repocache/actions/runs/40145596050), [offline #40145596035](https://github.com/teixemf/repocache/actions/runs/40145596035), [rollback #40145596044](https://github.com/teixemf/repocache/actions/runs/40145596044), [upstream #40145596053](https://github.com/teixemf/repocache/actions/runs/40145596053) |
| PR #171 HEAD (target `integration/v0.6.0`) | `d8d471a7c82642753b609e4975048424541c9a5e` | **PASS:** 9/9 required contexts and 23/23 check-runs on the PR head; **NOT VERIFIED:** independent project review, explicit PR-specific merge authorization and actual post-merge v0.6.0 `push`. The protected branch still points at `bba3286be209eee85e3b7d8702edaa10af1bfe57` |

The **nine exact mandatory contexts** (Actions app `15368`) are:
`Unit tests (Python 3.12)`, `Unit tests (Python 3.13)`,
`Bundle integrity and unsigned-source refusal (almalinux10)`,
`Bundle integrity and unsigned-source refusal (debian13)`,
`Offline wheels (almalinux:10)`, `Offline wheels (debian:trixie-slim)`,
`Signed release and native offline dependency artifact`,
`Synthetic rootless update and rollback (almalinux:10)`, and
`Synthetic rootless update and rollback (debian:trixie-slim)`.
The separately path-filtered `Real PyPI pinned wheels` jobs are valuable
compatibility evidence but are **not** required unconditionally.

**NOT VERIFIED / follow-up:** current workflow `push` filters explicitly
name only `integration/v0.5.0` and `integration/v0.6.0`. The GitHub
ruleset covers a wider `integration/*` family. Extending workflow triggers
to future release lanes requires a separately scoped review, contract-test
changes and explicit approval; do not silently broaden triggers to old
experimental branches. Neither a successful CI run nor this documentation
authorizes a feature merge, owner signing, staging, publication or production
activation.

CI in GitHub-hosted containers is not actual booted native-kernel/SELinux,
owner-signed candidate acceptance, release publication or production
installation.

## Branch protection — active ruleset and remaining verification

**Observed 2026-10-24:** active GitHub ruleset `#25793496` matches
`refs/heads/integration/*` and nested integration refs. It requires PRs,
strictly up-to-date nine GitHub Actions check contexts, resolved review
threads, and rejects force pushes/deletion with **no bypass actors**.
The exact required contexts match protected-main ruleset `#25436501`
(GitHub Actions app `15368`). Its `required_approving_review_count: 0`
does **not** prove an independent security review or waive the project's
documented reviewer gate. Ruleset presence is **PASS (API inspection)**;
real v0.5.0 integration push CI is **PASS**, while real v0.6.0 push CI,
independent PR #171 review/merge acceptance and the full release gate
remain **NOT VERIFIED**.

The following operator controls remain to be verified or strengthened
before accepting feature changes into **either** integration branch:

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
