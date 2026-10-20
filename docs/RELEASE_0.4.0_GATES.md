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
| Installed runtime integrity (#35) | No same-version virtualenv is reused based only on service-writable metadata or executable existence. A selected same-version release is reauthenticated, rebuilt into a fresh generation from signed source and offline pinned wheels, and checked before activation. Structural symlink/owner/mode checks and native tamper-repair regression PASS. Does **not** attest old executable bytes against a compromised service UID. |
| SIGKILL and concurrent updates | Executed unit/subprocess lock, journal, recovery and rollback tests PASS |
| Standalone first-public boundary | v0.4.0 signed policy has `compatible_from: []`; pre-public installs fail closed before activation and historical migrator is absent from release archives. No historical migration support is claimed |
| Nginx, systemd and SELinux | Real disposable VM or target-system results, if available; maintainer may defer these **explicitly** without claiming PASS |
| Real power cut | Not performed; residual risk is documented and deferred, not reported as PASS |
| Final release security / rights review | Public tree scanned and manually inspected; no credentials, private history or deployment values; license and AI disclosure reviewed |
| GitHub publication controls | Active branch/tag rulesets and release immutability observed in the **public** repository, with no bypass of required reviews/checks |

## Same-version repair security boundary

A matching installed `source_digest` or publisher identity only identifies the
release assets; it does **not** attest mutable files inside an installed virtualenv.
The updater must never skip reinstallation based on a readable
`bin/repocache` or mutable `installed.json`. A deliberately selected
same-version update re-verifies signed release assets and hash-pinned offline
wheels, builds a **fresh unique** virtualenv, checks its entry point, and only
then atomically activates it. Unsafe symlink, owner and mode layouts fail closed.
A failed reinstallation leaves the prior symlink and manifest unchanged; the
existing target is retained for forensic analysis, not executed as proof of
integrity. This approach costs rebuild time and storage on explicit retries.

**Residual risk:** The service account owns its running virtualenv and
transaction manifest. A process already compromised under that UID can modify
its own code; these service-controlled files are not a root-owned,
independently authenticated installed-file inventory. The protected
root-owned launcher and recovery helper prevent elevated execution, but they
do not cryptographically validate arbitrary runtime bytes against an attacker
who controls the service account. Never describe these structural checks as
an independently trusted runtime attestation.

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
processes must never delete or replace it. Pre-public installations are
unsupported for in-place migration to v0.4.0. Service-UID code modifications
are a separate integrity threat and
are not made safe merely by using flock; signed release verification,
independently rooted launch/recovery code and restricted ownership still
matter.

## Historical installations and approved scope change

**Decision (2026-10-19): v0.4.0 is the first standalone public REPOCACHE
release.** Historical in-place migrations, including v0.3.0 → v0.4.0, are
**out of scope and unsupported**. This explicitly supersedes the earlier
historical migration acceptance requirement in public issue #5; the
requirement is **not marked PASS**. Do not publish or import historical
artifacts and do not assume historical persistent layouts are compatible.

Release-policy `compatible_from` must be empty in v0.4.0; clean bootstrap
(`0.0.0`) and identical-version identity-checked retries are permitted.
An existing legacy installation must fail closed without rewriting launchers,
cache, configuration, symlinks or manifests. The historical migration
prototype remains source-only and cannot run in this release; it must not
be included in distributed release archives.

Any future migration requires a distinct documented opt-in design, separately
authenticated artifacts, tests on actual migrated state, rollback evidence and
explicit maintainer approval. Synthetic fixtures remain useful for transaction,
locking and recovery validation but **do not prove compatibility with
historical installations**. Do not run first-public bootstrap on a production
host already containing an earlier installation.

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
