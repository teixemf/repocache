# v0.4.0 Release Integration and Acceptance

This is a fresh public repository. `main` is protected by policy; v0.4.0 code is proposed in **draft PRs** until acceptance. **Intended production scope: a CLI/TUI frontend for a separately installed and configured NGINX repository cache on Debian 13 or AlmaLinux 10**, not an NGINX installer. Production-readiness claims must distinguish executed CI from real-host validation; see [existing-NGINX operations](PRODUCTION_EXISTING_NGINX.md). No previous private Git history, protected ref, workflow log or release asset is imported.

## Mandatory acceptance gate

For each issue acceptance criterion, record **PASS**, **FAIL** or **NOT VERIFIED** and an executed command/log or reproducible review reference. Verify functional behavior, failures, privilege/security boundaries, upgrades, rollback, documentation and supported-system impact. A test committed but not run is **NOT VERIFIED**. Deferred real systemd/SELinux and physical power-cut testing remains deferred, not PASS.

Before merging, re-check the PR head, full diff, required CI jobs and results, approvals, unresolved reviews and security blockers. No FAIL/NOT VERIFIED criterion, required check failure or material security finding may be bypassed. The maintainer must **explicitly approve each merge**. PR creation is not approval. Release publication additionally requires separately reviewed signed artifacts and explicit release authorization.

## Public GitHub controls

Configure and verify active branch rulesets for `main`, active release branches and `v*` tags, with required checks, no unauthorized force-push/deletion and controlled review/bypass permissions. Repository visibility by itself does not establish these protections.

GitHub-hosted standard runners on this public repository are intended for PR CI. Treat fork PRs as untrusted: no signing secrets, privileged persistent self-hosted runners, write permissions or publisher credentials. `release.yml` must not automatically publish tags. Keep owner signing keys outside GitHub.

## Legacy migration

Public v0.4.0 is the **first standalone public release**, not an in-place upgrade from pre-public installations. Its signed compatibility allowlist is empty; legacy installations must fail closed, and the historical prototype must not be distributed or enabled. The former historical cutover requirement in issue #5 is explicitly superseded, not reported as PASS. Synthetic recovery rehearsals demonstrate transaction mechanics only. Future historical migration requires new independently accepted criteria, authenticated fixtures and a separate explicit maintainer approval.


## Verified integration branch history (2026-10-20)

The **current**, independently checked GitHub compare
`main...release/v0.4.0` reports `ahead_by=94`, `behind_by=0`,
and merge-base `66f6ddb6dd465d191a60f51c524e1b7ae56a9367`.
At this checkpoint `main` is `66f6ddb6dd465d191a60f51c524e1b7ae56a9367`;
`release/v0.4.0` is `cdd422cb4b2ba2e1d689edf830e38013ce822680`.
This **proves ancestry today**. It does **not prove** the release branch
*initially had the identical SHA as main*, as originally worded in #12.
That historical condition remains **NOT VERIFIED**; do not rewrite history or
force-reset a release branch to make it appear PASS.

The integration branch remains isolated from `main`; do not mistake an
open PR for a merge. The candidate `chore/bootstrap-public-v0.4.0` is
proposed into `release/v0.4.0` by **PR #41**, after issue/CI gates.

## Ordered integration, exact-head evidence and rollback

1. Integrate separately approved candidate PRs into
   `chore/bootstrap-public-v0.4.0`; require the complete change-specific
   criterion checklist, native supported-platform CI and security review.
   **No automatic merge** is allowed, even when every job reports SUCCESS.
2. Re-run the required CI on each resulting squash/merge commit. Record
   the actual new branch SHA and job URLs (old PR-head success is not evidence
   for later commits). Do not close an issue until its supported criteria
   PASS on integrated source.
3. Only after the **entire v0.4.0 acceptance matrix** has PASS for all
   non-deferred requirements may PR #41 be approved separately into
   `release/v0.4.0`. Recheck `main`, the release branch, the PR's
   target/source SHA, review threads, rulesets and nine required status
   contexts before the permitted squash or rebase.
4. Run the complete signed/offline, Debian 13, AlmaLinux 10, CLI/TUI,
   lock, failover and rollback acceptance matrix on the final
   `release/v0.4.0` commit, not just an earlier candidate PR. Check that
   a failure of the frontend leaves an existing operator-configured NGINX
   caching plane and client upstream fallback intact where supported.
5. Propose **one** release-branch-to-`main` promotion PR. Retire obsolete
   duplicate PRs without merging them. Demand distinct maintainer approval
   and enforce protected branch checks before promotion.
6. A separately approved tag/release procedure verifies that the exact
   reviewed `main` commit matches the tag, detached Ed25519 publisher
   signature, complete release archive, offline dependency lock, SBOM,
   asset hashes and provenance. Build in read-only CI, sign offline on a
   trusted workstation, never inject the private publisher key into Actions.
7. For a failed **frontend** update, recover the prior active generation and
   installed manifest using the trusted transaction journal. Production
   NGINX/TLS configuration and APT/DNF sources are operator-managed in
   v0.4.0; a CLI rollback **does not** promise to undo unrelated changes to
   them. Actual release publications and destructive repairs need their own
   explicit authorization.

### Acceptance report format

For **each** issue, record `criterion | PASS/FAIL/NOT VERIFIED |
reproducible evidence | exact SHA | target OS | residual risk`.
A committed test that has not executed is NOT VERIFIED. Containerized native
Docker tests are not real booted systemd/SELinux or physical power-cut tests.
Explicitly approved test deferrals are documented as **NOT TESTED**, not PASS;
a known fundamental exploitable security failure is never deferred merely
because the product version is 0.x.x.

### Enforcement and review

GitHub's actual public **main/release branch ruleset** was checked active on
2026-10-20: it requires a PR, strict nine-context required CI, linear
history, no deletion/force-push, resolved inline threads, and no bypass
actors; the policy currently requires zero independent approving reviews.
The maintainer nevertheless requires a specific affirmative approval of
**every merge**. Read the live ruleset again before acting; policy
documentation is not proof that the setting is still active. Tag rules
and release immutability have separate publication acceptance gates.
