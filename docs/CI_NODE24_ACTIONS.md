# Node.js 24-native GitHub Actions migration (#74)

## Scope and security boundary

The v0.5.0 workflow migration replaces Node.js 20-based upstream
GitHub Actions with pinned Node.js 24-native released commits.
It does **not** modify the published immutable v0.4.0 assets, the offline
Ed25519 signer, release authorization, branch rulesets or package dependency
resolution. Only the public `teixemf/repocache` repository is in scope.

Initially reviewed on 2026-10-23; updated for the protected-main action pins
on 2026-10-25. The `action.yml` `runs.using` value was independently read
at each currently pinned commit:

| Action | Reviewed tag | Exact pinned commit | Runtime |
| --- | --- | --- | --- |
| actions/checkout | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` | node24 |
| actions/setup-python | v6.0.0 | `e797f83bcb11b83ae66e0230d6156d7c80228e7c` | node24 |
| actions/upload-artifact | v6.0.0 | `b7c566a772e6b6bfb58ed0dc250532a479d7789f` | node24 |
| actions/download-artifact (merged #77) | v8.0.2 | `9000827ccba6bdab643e8b6fd33ac0654aef8333` | node24 |

The current checked-in refs are 40-hex commit SHAs, not mutable version tags.
Each pinned action manifest was fetched from the corresponding official
`actions/*` repository by commit SHA and declares `node24`. Earlier upstream
review evidence for the original pins is in PR #116; subsequently updated
pins require renewed release-note and transitive-change review before parent
#74 can be marked fully accepted. Sources:
`https://github.com/actions/<action>/releases` and
`https://raw.githubusercontent.com/actions/<action>/<sha>/action.yml`.
Dependabot proposal/review remains owned by #81; no automatic merge is permitted.

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
  synthetic upgrade rehearsal. All three required workflows also run on
  protected `main` pushes, so integration-commit checks can be inspected
  against that exact SHA without an unauthorized workflow dispatch.
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

## Protected-main integration verification (2026-10-25)

This is an evidence checkpoint for parent #74, **not** a close-out decision.

- PR [#116](https://github.com/teixemf/repocache/pull/116) was merged
  on 2026-10-23 at exact protected-main integration SHA
  `f2d480828279bd7a2220bf6048227f2b0f573a01`;
  child [#117](https://github.com/teixemf/repocache/issues/117) is CLOSED.
- The GitHub REST check-runs endpoint at that **integration commit**
  reported the original nine mandatory checks completed with `success`:
  2 Python unit, 2 Debian/AlmaLinux bundle, 2 offline wheels,
  1 signed-release/offline-dependency artifact, and 2 rootless
  distro-upgrade/rollback checks. Two additional checks also succeeded.
- An independent read of the protected `main` ref on 2026-10-25 resolved
  to `9e213d7beb6534181e3ff418a890c5fdf2db2017`. Its
  [check runs](https://github.com/teixemf/repocache/commit/9e213d7beb6534181e3ff418a890c5fdf2db2017/checks)
  report **11/11 successful**, including the same nine mandatory contexts
  and two additional native upstream dependency jobs.
- The only `Release bundle` `workflow_dispatch` run in the returned
  complete workflow-dispatch history is
  [#39559317114](https://github.com/teixemf/repocache/actions/runs/39559317114)
  on 2026-10-21, `v0.4.0`, source
  `063c86c9a138bffca6f76f7407e8f1c86bfe4390`. It
  completed successfully **before** #116 was merged. This is
  **NOT** proof of a Node24 release-workflow upload.
- The current `main` `pyproject.toml` still declares `0.4.0`.
  The release job requires a tag matching the project version,
  an owner-triggered dispatch, and main-ancestry validation; a genuine
  approved nonpublishing `v0.5.0` source/tag is therefore a prerequisite
  to the remaining end-to-end rehearsal. Do not create a release tag
  or change the version merely to satisfy this documentation gate.

### Parent #74 acceptance evidence

| Acceptance area | State | Evidence or outstanding proof |
| --- | --- | --- |
| Current official actions use full-SHA Node24 pins | **PASS** (manifest inspection) | Current exact `checkout`, `setup-python`, `upload-artifact`, `download-artifact` manifests declare `node24`; SHA contract is source-controlled in `tests/test_actions_node24_contract.py`. |
| Vet every upstream action transition and security-sensitive transitive release change | **NOT VERIFIED** | Refresh review for newer checkout v7.0.1 and download-artifact v8.0.2; check their release notes and relevant behavior against #116 review. |
| Preserve permissions, credentials, offline signing and publication separation | **PASS** (current `release.yml` inspection) / **NOT VERIFIED** (whole-repo final review) | The release workflow still has `contents: read`, `persist-credentials: false`, actor/tag/ancestry gates, and unsigned artifact upload only; final complete diff and reviews remain required. |
| Nine original required contexts on the protected integration commit | **PASS** | Exact merged SHA `f2d480828279bd7a2220bf6048227f2b0f573a01`, 9/9 success; current `main` SHA `9e213d7beb6534181e3ff418a890c5fdf2db2017`, 9/9 success (11/11 total checks). |
| Real `release.yml` Node24 artifact upload and independent readback on a safe approved candidate | **NOT VERIFIED — BLOCKER** | No post-2026-10-23 owner `Release bundle` dispatch found; require an approved version-matched tag, successful upload step, downloadable archive, checksum and source-SHA reconciliation. |
| Document runner 2.327.1+ and offline signing/rollback boundaries | **PASS** (documented) | Runner and manual-release limits below; no native self-hosted runner claim. |
| Maintainer final per-criterion approval and issue closure | **NOT VERIFIED — BLOCKER** | Verify latest exact heads, action review and required checks; obtain distinct owner sign-off. No merge/tag/sign/publication authorized by this checkpoint. |

### Remaining owner-authorized end-to-end rehearsal

Only after a legitimate, reviewed `v0.5.0` candidate/tag exists,
and the owner separately authorizes the nonpublishing rehearsal:

1. Reconfirm exact tag commit, `pyproject.toml` version, protected-main
   ancestry, workflow content and narrow token permissions.
2. Manually dispatch `release.yml` on that approved tag, as the repository
   owner. Do not sign, publish, create an unexpected release or change
   provenance solely for the test.
3. Inspect the actual `assemble` job's Node24
   `actions/upload-artifact` step. A successful unit-test-only dispatch,
   skipped assemble job or earlier PR rehearsal **does not satisfy** #74.
4. Retrieve the resulting `unsigned-release-candidate` artifact; record
   run ID, run/head SHA, uploader step conclusion, artifact ID and digest.
   Verify the ZIP contents, expected archive/checksum members and their
   SHA-256 values against the exact approved source commit.
5. Recheck all acceptance rows against the final reviewed refs and required
   controls. Close #74 only once none is FAIL/NOT VERIFIED and the
   maintainer approves the acceptance report.

## Independent upstream security and integration checkpoint (2026-10-27)

This checkpoint extends the historical 2026-10-25 inventory above. It is
read-only source/release-note review plus documentation; it does **not** supply
the still-missing real `release.yml` execution or authorize release actions.

### Reviewed immutable upstream sources and security-relevant changes

The four pinned SHA refs were compared with official `actions/*` Git tag
refs and the `runs.using: node24` manifests fetched at those *exact SHAs*.
The two subsequently upgraded pins resolve as follows:

- [checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1)
  tag = `3d3c42e5aac5ba805825da76410c181273ba90b1`; GitHub reports a
  verified commit signature. Reviewed the upstream
  [v6.0.0](https://github.com/actions/checkout/releases/tag/v6.0.0),
  [v7.0.0](https://github.com/actions/checkout/releases/tag/v7.0.0)
  and v7.0.1 release notes and compare history: v6 moves persisted Git
  credentials out of `.git/config` into `$RUNNER_TEMP`; v7 changes the
  distributed action to ESM and refuses unsafe fork checkout on
  `pull_request_target`/`workflow_run` by default; v7.0.1 hardens
  `git config --unset` escaping, normalizes branch whitespace handling,
  and refines the default fork safety check. Upstream direct/transitive
  dependencies changed, including security-related dependency upgrades.
  REPOCACHE still sets `persist-credentials: false` at every checkout,
  never opts into `allow-unsafe-pr-checkout`, and the privileged
  `pr-milestone.yml` explicitly checks out the protected default branch,
  **not the untrusted PR head**, while limiting writes to PR metadata.
- [download-artifact v8.0.2](https://github.com/actions/download-artifact/releases/tag/v8.0.2)
  tag = `9000827ccba6bdab643e8b6fd33ac0654aef8333`; GitHub reports a
  verified commit signature. Reviewed official
  [v7.0.0](https://github.com/actions/download-artifact/releases/tag/v7.0.0),
  [v8.0.0](https://github.com/actions/download-artifact/releases/tag/v8.0.0),
  [v8.0.1](https://github.com/actions/download-artifact/releases/tag/v8.0.1)
  and v8.0.2 notes, plus the v7-to-v8.0.2 compare history. v8 migrates to
  ESM, supports direct non-ZIP artifacts, and makes artifact digest mismatch
  a **failing error by default**; v8.0.1 improves name/content-type
  regression coverage; v8.0.2 updates `@actions/artifact` to 6.3.1,
  including HTTP 429/Retry-After handling. REPOCACHE's signed-candidate
  workflow downloads explicitly named, same-run `authenticated-draft-candidate`
  artifacts uploaded by ZIP-producing `upload-artifact@v6`; the upstream
  v8 default preserves ZIP extraction and strengthens digest fail-closed
  behavior. Actual genuine candidate acceptance remains subject to #76.
- [setup-python v6.0.0](https://github.com/actions/setup-python/releases/tag/v6.0.0)
  tag = `e797f83bcb11b83ae66e0230d6156d7c80228e7c`: official notes
  document native Node 24, runner >=2.327.1, Python version handling and
  security-sensitive `form-data`/`setuptools` dependency fixes.
- [upload-artifact v6.0.0](https://github.com/actions/upload-artifact/releases/tag/v6.0.0)
  tag = `b7c566a772e6b6bfb58ed0dc250532a479d7789f`: official notes
  document native Node 24 and an `@actions/artifact` update addressing
  Node 24 compatibility. The `release.yml` step uploads **unsigned only**,
  with `if-no-files-found: error`, 7-day retention, and read-only token.

**Review boundary:** this is an upstream source/tag, manifest, changelog and
security-relevant transitive release-note assessment; it is not an independent
byte-for-byte audit of the upstream bundled JavaScript dependency graphs or
a vulnerability-free guarantee. Any subsequent action pin requires a fresh
review. The minimum hosted runner requirement remains v2.327.1;
checkout's documented v2.329.0 minimum for *authenticated Git inside Docker
container actions* is not exercised by these credential-nonpersisting jobs.

### Current repository and acceptance boundary

- On protected `main=6bb02c824c8d0c7c1ddb860a4b9fd13f7a861000`,
  direct GitHub check-run readback returns **9/9 SUCCESS**. On protected
  `integration/v0.5.0=806d93975aff641b27e87ece5a69e1ec0d97d35f`,
  **9/9 SUCCESS** after the separately authorized #190 merge.
  These are exact-revision CI checks, not a real official release dispatch.
- Read the 18 current `.github/workflows/*.yml` files: first-party JS
  actions use pinned SHA refs; untrusted `pull_request` test jobs remain
  `contents: read`. The separately scoped `label-colors.yml` sync has
  `issues: write` only on `push` or `workflow_dispatch`; the privileged
  `pull_request_target` milestone job retains only its existing
  `pull-requests: write` metadata authority and checks out default-branch
  code with `persist-credentials: false`. No signing key is present.
- The query for repository `workflow_dispatch` runs still found just one
  `Release bundle` run, [#39559317114](https://github.com/teixemf/repocache/actions/runs/39559317114),
  on 2026-10-21 **before** #116 migrated to Node 24. Neither that run nor
  the successful short-lived `tests.yml` Node 24 uploader rehearsal proves
  the original criterion requiring the real `release.yml` `assemble` job,
  `unsigned-release-candidate` artifact readback and source-SHA verification.
- The open documentation PR #179 was still based on an older main commit
  when this checkpoint was written. Its **new HEAD CI/review is NOT VERIFIED**
  after editing this file. Keep it draft; do not merge without exact-HEAD
  review, owner acceptance and separate merge authorization.
- `pyproject.toml` on the protected v0.5.0 integration branch still says
  `0.4.0`. Do **not** manufacture a `v0.5.0` tag or loosen
  `release.yml`'s owner/tag/ancestry requirements to close #74.
  The approved version-matched candidate/tag and explicitly authorized
  nonpublishing `release.yml` dispatch are independent prerequisites.
  Until upload/readback and maintainer sign-off, parent **#74 remains OPEN /
  NOT VERIFIED**, regardless of the other passing evidence.

## Remaining evidence and rollback

The protected-branch integration CI is verified above. The owner-triggered
post-migration release-workflow artifact readback, latest upstream security
review and final maintainer sign-off remain **NOT VERIFIED**. These cannot
be waived by a static contract test or a successful older `v0.4.0` run.

If an official action update fails before publication, revert the
migration PR with a separately reviewed revert, rerun the nine required
checks and investigate the runtime compatibility. Do not alter signed
v0.4.0 release assets or bypass the required release acceptance gate.
Do not silently downgrade to vulnerable Node.js 20 actions in a future
release; any exception needs explicit risk acceptance and a documented
time-bounded remediation.

The read-only signed-candidate acceptance workflow merged via PR #77 uses
these Node24 pins. Its real owner-signed v0.5.0 native acceptance criteria
remain NOT VERIFIED until separately authorized and executed under #76.
