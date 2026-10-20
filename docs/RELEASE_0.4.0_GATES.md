# v0.4.0 Release Acceptance and Publication Runbook

**Status: release branch is a development candidate, not a published or approved release.**

**Staged acceptance:** [v0.4.0 phased integration, publication and live verification](RELEASE_0.4.0_PHASED_ACCEPTANCE.md) assigns each original #1/#4/#6/#36/#39 acceptance criterion to the stage where it is executable. Earlier stages cannot claim later evidence as PASS. The intended v0.4.0 product is a **production CLI/TUI frontend for an already installed and operator-configured NGINX repository caching server**, not an NGINX installer. Read [the existing-NGINX deployment contract](PRODUCTION_EXISTING_NGINX.md) and verify the frontend against a representative configured NGINX staging host before claiming host-level production readiness.

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
| Existing NGINX frontend contract | Commands inspect an already installed/configured NGINX without rewriting it; no automatic server provisioning promised. CLI/TUI, repository discovery, bounded metrics and health checks have target-platform regression evidence; non-interactive operations do not prompt. Real configured-host smoke is recorded separately from CI. |
| NGINX, systemd and SELinux host tests | Real booted VM or target results, if available; explicit deferral remains **NOT TESTED**, never PASS. This is a residual risk for production deployments, not a claim that v0.4.0 auto-installs NGINX. |
| Real power cut | Not performed; residual risk is documented and deferred, not reported as PASS |
| Final release security / rights review | Public tree scanned and manually inspected; no credentials, private history or deployment values; license and AI disclosure reviewed |
| GitHub publication controls | Active branch/tag rulesets verified by API. Branch ruleset requires nine contexts and **zero** outside approving reviews by deliberate single-maintainer policy; separate owner approval of each merge remains mandatory. Tag ruleset has an **administrator-role bypass**. Release immutability is owner-attested but not independently read back; actual publication controls belong to Phases C/D. |


## Defensive security release gate (#37, #38, #39)

These tests are **required before each merge that changes release transport,
archive verification or upgrade**. A passing test from another commit is NOT
VERIFIED for a changed PR head.

| Acceptance area | Required executed test | Required proof |
| --- | --- | --- |
| #37 anonymous GitHub transport and redirect confinement | `tests/test_public_release_transport_defensive.py` (explicit pytest gate in both Python versions) | One anonymous API-to-allowlisted-HTTPS-CDN hop, no Authorization header or stale private token, blocked additional hops/host/port/scheme, redacted HTTP errors, expired URLs, bounded/incomplete downloads |
| #38 hostile source/wheel TAR confinement | `tests/test_hostile_archive_defensive.py` (both Python versions), `scripts/ci_hostile_archive.py` (authenticated native offline install) | Traversal, link/device/PAX/GNU, duplicate entries, truncated and oversized archives, symlinked staging/leaf, signed test-only hostile archive, bounded child wall-time/CPU/address-space, no external writes |
| #39 fail-on-omission and release gate | `tests/test_release_integration_contract.py` and required workflow step; the native offline wheel installer must also execute the installed archive test script | A missing/renamed/failed mandatory test fails the normal required CI, not a skipped optional job; each required GitHub status context is checked on the exact reviewed SHA |
| GitHub publication trust (#4, #36) | Live protected rulesets, immutable release control and independently verified asset signature/provenance | Actual admin evidence and fingerprints, never inferred from a green test |
| Runtime and rollback (#3, #7, #8, #11, #32-#35) | Exact-head signed-publisher, wheelhouse and native rootless rollback CI | Per-criterion code SHA, native OS, test case and result, protected lock and journal evidence |

For every merge or release candidate, preserve an English machine-readable or
reviewable table using this schema:

`criterion | PASS/FAIL/NOT VERIFIED | test or reviewed procedure |
GitHub run/job URL | exact Git commit SHA | asset fingerprint | target OS |
remaining uncertainty`

The **asset fingerprint** of the final public archive and wheelhouse is
**NOT VERIFIED** until the signed, published release assets are built and
compared to reviewed source. Do not invent an asset hash from a source commit
or use a disposable CI fixture signature as production publisher provenance.
If the relevant evidence is missing, label that criterion **NOT VERIFIED**;
a new commit invalidates a previous SHA's PASS evidence. No skipped test may
satisfy a required security context. Any FAIL or non-deferred NOT VERIFIED
criterion blocks the merge, regardless of green unrelated jobs.

The 0.4.0 release supports **anonymous public** GitHub discovery and downloads
only. Real private-release retrieval and historical private-to-public
installation migration are **unsupported** (see #37 and the approved #5
scope); testing or retaining old private credentials is not a release
requirement. No test uses real user tokens. Security-sensitive findings should
be reported via **private** GitHub vulnerability reporting rather than by
publishing operationally exploitable details.

CPU, memory, disk and wall-time limits in the #38 deterministic fixtures are
not an independent resource-exhaustion audit. Archive sizes, member counts and
unpacked bytes are bounded; a subprocess test exercises a compressible hostile
payload under Linux RLIMIT_AS, RLIMIT_CPU and a hard subprocess timeout.
Real-life service UID takeover and independent installed-runtime integrity
are separate advanced requirements tracked in #53/v0.7.0.

**Status for this development PR:** tests are not PASS merely by appearing
in the repository; record exact-head executed CI and inspect job logs before
checking any issue/PR acceptance box.

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
   reviews/required status contexts. Branch ruleset has no bypass; the tag
   ruleset has an intentional administrator-role bypass. Record and enforce
   owner authorization and custody controls; never claim immutable tags
   against administrators.
   Confirm protections from GitHub settings and an actual read of live state.
3. Enable and verify **release immutability on this new public repository**.
   Its old private repository's setting is not inherited.
4. After **explicit PR #41 merge approval** and PASS for all applicable
   Phase A acceptance requirements, integrate through the reviewed PR,
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
8. Inspect the **frontend-only installation and recovery** on representative Debian 13 / AlmaLinux 10 hosts that already have NGINX configured, including negative permission paths and a non-disruptive frontend failure test. The operator must validate a real deployment before declaring it operationally tested; record findings and issue regressions. A clean-system NGINX provisioning test belongs to v0.6.0, not this release.

## Acceptance and ownership

A draft PR, passed tests on a different SHA or new `release/v0.4.0` branch
does **not** authorize merge or tag publication. Each actual PR criterion
must be marked PASS with executed evidence; FAIL and NOT VERIFIED are blockers
unless the maintainer explicitly changes the scope, in which case the
unverified behavior must no longer be represented as a supported promise.

REPOCACHE is substantially developed with generative AI assistance, under
maintainer direction. AI-generated code/reviews may contain defects and do
not constitute an independent audit.
