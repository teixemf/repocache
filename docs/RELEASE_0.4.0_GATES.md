# v0.4.0 Release Acceptance and Publication Runbook

**Status: release branch is a development candidate, not a published or approved release.**

The public repository uses an independent Git history and the Apache License
2.0. Previous private release packages, PR discussions and CI artifacts are not
distributed with this project. The intended release is `v0.4.0` targeting
**Debian 13 / Python 3.13** and **AlmaLinux 10 / Python 3.12**.

## CI acceptance

Run the entire required matrix on the **exact** approved commit. Archive the
workflow URLs and each job's executed result. On any change, revalidate the new
head; historical PASS results are evidence for historical commits only.

| Criterion | Proof required |
| --- | --- |
| Python / CLI / Textual | Python 3.12 and 3.13 pytest jobs PASS on the reviewed commit |
| Bundle integrity | Native Debian 13 / AlmaLinux 10 disposable builds validate the complete source archive and Apache LICENSE |
| Refusal of unsafe install | Both disposable OS tests confirm that unsigned source-only installation is rejected |
| Update / rollback | Both native synthetic rootless update and rollback jobs PASS |
| Offline dependencies and SBOM | Native locked wheelhouse and signed provenance rehearsal PASS |
| Rootless lock integrity | Root-owned mode-0440 lock parent and inode verified; `repocache` UID fails to unlink it; rebootless re-bootstrap preserves inode |
| SIGKILL and concurrent updates | Executed unit/subprocess lock, journal, recovery and rollback tests PASS |
| Real legacy migration | Separately authenticated and verified *published* v0.3.0 archive supplied to isolated operator environment. **Not covered by the synthetic version fixture** |
| Nginx, systemd and SELinux | Real disposable VM or target-system results, if available; maintainer may defer these **explicitly** without claiming PASS |
| Real power cut | Not performed; residual risk is documented and deferred, not reported as PASS |
| Final release security / rights review | Public tree scanned and manually inspected; no credentials, private history or deployment values; license and AI disclosure reviewed |
| GitHub publication controls | Active branch/tag rulesets and release immutability observed in the **public** repository, with no bypass of required reviews/checks |

The test and release CI jobs must use read-only credentials, pinned Actions
versions and ephemeral hosted runners. They must not have private signing keys.

## Trusted updater lock

The updater lock is `/opt/repocache-cli/.updater.lock`. Bootstrap creates a
persistent root-owned file with mode `0440` and group `repocache` under the
root-owned non-writable-by-service installation directory. The updater and
root-owned, stdlib-only recovery coordinator open it **read-only** with
`O_NOFOLLOW` and take the same exclusive kernel `flock`. Missing, replaced,
hardlinked, incorrectly owned or permissively writable locks fail closed.

Re-bootstrap must not recreate the inode while it exists. Unprivileged
processes must never delete or replace it. The legacy migration coordinator
provisions or validates this lock **before** allowing authenticated v0.4.0
staging. Service-UID code modifications are a separate integrity threat and
are not made safe merely by using flock; signed release verification,
independently rooted launch/recovery code and restricted ownership still
matter.

## Historical installations

The original v0.3.0 source and release bundles stay in the private archive.
No historical archive, credential, old release URL or Git history is copied
into this public repository.

The `scripts/migrate_v030.py` coordinator verifies the **exact historical
archive SHA-256** and checks the currently installed generation, authenticates
the **new signed v0.4.0** source and offline dependencies, then runs staging
under the dedicated service account. It fails closed if the local original
archive is unavailable or differs from the pinned digest.

**The public synthetic 0.3.0 → 0.4.0 rehearsal is not evidence that the real
published v0.3.0 migrates successfully.** An isolated operator-side run with
the original authenticated archive is required before reporting that criterion
as PASS; it must not be uploaded to public Actions.

## Publication order

1. Resolve release blockers and review this PR, the issue acceptance matrix,
   source inventory and risk log; explicitly approve any accepted scope
   exclusions. Do not redefine test failures as waived requirements.
2. Configure **public** `main`, `release/v0.4.0` and `refs/tags/v*`
   protection: required exact-head CI, no destructive updates, appropriate
   reviews, tightly controlled tag creation and no administrator bypass.
   Confirm protections from GitHub settings and an actual read of live state.
3. Enable and verify **release immutability on this new public repository**.
   Its old private repository's setting is not inherited.
4. After **explicit merge approval**, integrate through the reviewed PR,
   ensure required checks re-run on the resulting commit, and confirm the
   release tag target is an ancestor of protected `main`.
5. After **separate explicit release approval**, create the controlled version
   tag and manually dispatch `.github/workflows/release.yml` **on the tag**.
   The workflow produces an unsigned candidate; it does not publish.
6. On an isolated operator workstation, independently check candidate commit,
   Actions job results, reproducible source, locked wheels, SBOM and public-key
   fingerprint. Run `scripts/offline_sign_release.py` with the **locally held
   encrypted private key**. No private key enters GitHub Actions or git.
7. Independently verify all generated signatures/provenance. Publish the
   authenticated artifacts in a single release; verify that the immutable
   release and its assets are accessible and unchanged.
8. Inspect clean-system install and recovery in real environments after
   publication as previously agreed, record findings and issue regressions.

## Acceptance and ownership

A draft PR, passed tests on a different SHA or new `release/v0.4.0` branch
does **not** authorize merge or tag publication. Each actual PR criterion
must be marked PASS with executed evidence; FAIL and NOT VERIFIED are blockers
unless the maintainer explicitly changes the scope, in which case the
unverified behavior must no longer be represented as a supported promise.

REPOCACHE is substantially developed with generative AI assistance, under
maintainer direction. AI-generated code/reviews may contain defects and do
not constitute an independent audit.
