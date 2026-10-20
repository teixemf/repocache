# v0.4.0 staged acceptance — source integration, publishing, and live verification

**Status:** proposed documented acceptance classification; reviewed source candidate
`efcd81a19c77c661d9fe7ab7a7445b014b5fce3a` as of 2026-10-20.
This file records phase ownership and evidence; it is **not** a merge approval,
legal opinion, signing authorization, immutable-asset test, or published release.
The original acceptance criteria in #1, #4, #6, #36 and #39 remain traceable.
A criterion is not PASS merely because execution is impossible before publication.

## Phase A — before PR #41 merges into `release/v0.4.0`

Required **now**, on the exact source candidate, before separately authorized integration:

- **PASS:** the nine required CI contexts in Python 3.12/3.13, Debian 13 and
  AlmaLinux 10, including explicit 104-case security regression gates, native
  signed/offline dependencies, complete source archive identity and rootless
  rollback. Current exact-head evidence:
  [Tests 4/4](https://github.com/teixemf/repocache/actions/runs/39450320116),
  [offline 3/3](https://github.com/teixemf/repocache/actions/runs/39450320131),
  [rootless rollback 2/2](https://github.com/teixemf/repocache/actions/runs/39450320101).
  Another complete 9/9 run set at the same SHA also passed.
- **PASS (API evidence):** active [branch ruleset 25436501](https://github.com/teixemf/repocache/rules/25436501)
  for `main` and `release/*`, requiring PRs, linear history, no force pushes/deletion,
  resolved review threads, and nine strict GitHub Actions contexts. No branch bypass
  actors. This ruleset requires **zero approving reviews**: the maintainer explicitly
  chose single-maintainer operation; separate human approval for **each** merge is
  a project-policy requirement and is not GitHub-enforced reviewer approval.
- **PASS (API evidence with residual risk):** active [tag ruleset 25436613](https://github.com/teixemf/repocache/rules/25436613)
  protects `v*` from ordinary creation/update/deletion/non-fast-forward. A
  repository-role bypass actor (id 5) is configured; the connected owner has
  `current_user_can_bypass=always`. Do **not** claim tag immutability against
  the maintainer/administrators. Custody and authorization controls belong to Phase C.
- **PASS for source-controlled policy:** release CI is manually dispatched,
  `permissions: contents: read`, Actions dependencies use pinned full SHAs,
  `persist-credentials: false`, and no private publisher key or automatic
  release-publish job is present. The label-color maintenance workflow has
  narrowly scoped `issues: write` only in its main-branch synchronization job,
  not an untrusted PR publisher.
- **PASS for bounded inspection; NOT an independent audit:** recursive current
  candidate Git tree returned 102 text blobs, all 102 read, with no inaccessible
  files. Heuristic indicators were checked for private-key headers, common
  credential/token prefixes, former private repository URLs, private IPv4,
  internal DNS and contact identifiers; incidental matches were manually
  identified as synthetic test examples or a Python symbol. The reachable
  public ancestry listed 111 commits back to a root commit containing only
  LICENSE; all 111 commit API patches were scanned for the high-confidence
  private key/credential/internal-host/private-repository patterns without
  confirmed findings or omitted patches. This does not prove absence of
  unknown secret forms, cover unrelated/unreachable Git refs, or provide an
  independent forensic security assessment.
- **PASS for technical source/version consistency:** `pyproject.toml`,
  `src/repocache/__init__.py` and `release-policy.json` all state v0.4.0.
  The signed-archive builder uses an explicit inventory, verified member-by-member
  by tests. First-public standalone policy has `compatible_from: []` and
  `downgrade_from: []`; no historical private migration is supported.
- **NOT VERIFIED (mandatory at the operation):** explicit new maintainer approval
  of **PR #41** itself; recheck changed head/base, its **full 40-file diff**,
  individual acceptance criteria, reviews and required CI immediately before
  merge. Green checks alone do not authorize a merge.

**Phase A decision:** classification of later rights/publishing/asset controls
does not exempt any current source-integrity, privilege, trust-boundary,
rollback or required-CI failure. Do not merge while a Phase A criterion is
FAIL or NOT VERIFIED. The formal release-branch target is still unchanged.

## Phase A2 — immediately after an authorized PR #41 integration

- **NOT VERIFIED until integration exists:** record the actual
  `release/v0.4.0` commit, execute **all nine required contexts on that exact
  branch commit**, and verify no missing or skipped required checks.
- Complete #11's expressly required integrated-release-branch identity criterion
  and #12's integration gate before closing those issues.
- Do not interpret branch integration as a separate approval of `main`, tags,
  signing, publishing or production changes.

## Phase B — before promotion from `release/v0.4.0` to public `main`

- **PASS (maintainer approval already recorded):** original REPOCACHE source
  Apache-2.0 choice and the README's generative-AI-development disclosure.
  This does **not** grant rights to relicense older private versions or third-party
  wheels. `LICENSE`, `README.md`, `SECURITY.md`, `SUPPORT.md`,
  `CONTRIBUTING.md`, and `CODE_OF_CONDUCT.md` exist and link coherently.
- **NOT VERIFIED:** human source and **third-party redistribution/attribution**
  sign-off against final exact wheelhouse/source inventory. The two native
  wheels inventories independently record **13 runtime/application** and
  **2 build** distribution metadata records with pinned hashes and license
  evidence. Notably `mdurl` (MIT classifier), `shellingham` (ISC metadata)
  and build `wheel` (MIT classifier) contain no notice path **under the
  implemented wheel metadata convention**. This is a human review flag, not
  proof of infringement. Inspect actual license texts, upstream notices,
  vendored dependencies and redistributed notice obligations, including
  Pygments (BSD-2-Clause) and typing_extensions (PSF-2.0), before sign-off.
- **OWNER-ATTESTED / no independent end-to-end evidence:** the maintainer stated
  that Private Vulnerability Reporting is enabled in this **public** repository.
  `SECURITY.md` directs private reports, but an externally observable private
  submission test/settings-read is still NOT VERIFIED. Check the effective
  confidential reporting path through the maintainer GitHub UI before
  main/publication sign-off.
- Review current tree **and reachable/unreachable public history**, PR/source
  provenance and all distributed members using an appropriate credential and
  provenance scanner; the Phase A heuristic scan is not blanket clearance.
- Obtain a separately authorized, reviewed `release/v0.4.0` -> `main` PR
  after all non-deferred Phase B criteria PASS. Do not merge the redundant
  original bootstrap PR #2 as a second source promotion.

## Phase C — before owner signing, tag and GitHub Release publication

- **PASS for source-controlled code/rehearsals; operationally NOT VERIFIED:**
  `.github/workflows/release.yml` builds an **unsigned** candidate with
  read-only credentials only on owner-initiated tag workflow dispatch and
  checks protected-main ancestry. Offline
  `scripts/offline_sign_release.py` checks tag/main/Actions identity, private
  key ownership, reviewed publisher public-key fingerprint, complete source
  bundle, pinned wheelhouse and signed provenance. CI uses disposable keys.
- **OWNER-ATTESTED / NOT independently read back:** the public repository's
  `Enable release immutability` setting was confirmed by the maintainer; the
  connector cannot inspect effective administrative configuration. No GitHub
  release exists yet. Preserve the owner attestation as a distinct evidence
  category; do not call effective asset immutability PASS without verification.
- **NOT VERIFIED:** explicit tag bypass-role authority review, physical/private
  offline Ed25519 key custody, backup/rotation/revocation procedure, authorized
  tag pointing to the exact reviewed protected-`main` ancestor, actual
  signed source/manifest/wheelhouse/SBOM/provenance fingerprints, permissions
  of release upload actor, final rights/notice sign-off and confirmed
  confidential vulnerability channel.
- Require **separate**, affirmative maintainer permissions for `main` merge,
  tag creation, offline signing, and release publication; do not combine them.
  Verify final signed artifacts *before* making them public.

## Phase D — after the separately approved, real public release exists

- **NOT VERIFIED until published:** read back the exact immutable GitHub Release,
  its complete asset inventory, SHA-256 hashes, publisher signature, release tag,
  reviewed source commit and trust anchor. Test the effective inability of an
  unauthorized actor to replace/delete assets without performing destructive
  production experiments or relying solely on the local script.
- **NOT VERIFIED until published:** run [#65](https://github.com/teixemf/repocache/issues/65):
  anonymous **live** `update check/list`, selected release install and
  verified repair/failure recovery on disposable Debian 13/Python 3.13 and
  AlmaLinux 10/Python 3.12 targets. Do not label simulated HTTP fixtures PASS
  for public CDN availability.
- Do not consider publication operationally accepted while an applicable
  criterion in this phase is FAIL or NOT VERIFIED; remediate using a new,
  separately approved, signed release rather than mutating immutable assets.

## Original issue criterion routing (no deletion or silent waiver)

| Issue | Original criteria by ordinal | Phase-specific disposition |
| --- | --- | --- |
| #4 | 1 branch PR/checks, 2 tag protection, 3 exact CI | Phase A PASS for the currently inspected state; recheck when integrating |
| #4 | 4 effective release immutability, 5 confidential reporting | Phase C/D and B/C respectively: owner-attested settings, effective verification still pending |
| #4 | 6 maintainer approval | Every relevant operation; approval of earlier merges is not transferable |
| #36 | 1 tag reviewed-main ancestry, 2 immutable unauthorized publisher controls | Source gate reviewed in A, actual owner authorization/asset protection C/D |
| #36 | 3 provenance/action identity, 4 CI release-write isolation | Source/fixture/static controls in A; actual owner signed artifacts C |
| #36 | 5 settings/bypass evidence, 6 separate approvals | Ruleset evidence A, operational administrative proof C, approval each operation |
| #39 | 1–4 signing verifier, rootless locking, crash and hostile transport | Phase A PASS for exact tested supported code and synthetic/native tests |
| #39 | 5 supply-chain publisher settings and results | CI source/control portion A; actual publisher authority/immutability C/D NOT VERIFIED |
| #39 | 6 documentation and 7 fail-on-omission | Phase A PASS on examined source and CI |
| #39 | 8 SHA/platform/test/asset fingerprint matrix | SHA/platform/executed-test portion A PASS; authentic final owner-signed assets C and actual published fingerprints D NOT VERIFIED |
| #1 | source hygiene, new history, version/build, security/CI | Phase A implemented/tested or bounded scan; comprehensive rights/provenance review B |
| #6 | Apache-2.0/AI owner approval and community docs | Phase A/B accepted original policy; effective confidential reporting and third-party rights B, final notice/source artifacts C/D |

**No issue closes merely because its Phase A subset passes.**
Original unresolved criteria remain OPEN until their proper stage is observed.
Real booted systemd/SELinux and physical power-loss remain explicitly
NOT TESTED under the maintainer-approved v0.4.0 limitation; that is not PASS.
