# v0.5.0 governed submissions — current Gate A integration checkpoint

**Checkpoint: 2026-10-24 (UTC). Integration PR #128 / child issue #127.**
**Disposition: NOT VERIFIED — DO NOT MERGE.** This is a developer-led
repository/CI inspection, **not** independent security approval or permission
to enable an endpoint. Parent issue #17 and production Gate B #49 are unchanged.

## Historical documentation boundary

The documents `SUBMISSIONS_V0.5.0_GATE_A_ACCEPTANCE_REVIEW.md`,
`SUBMISSIONS_V0.5.0_GATE_A_REVIEW.md`, and
`SUBMISSIONS_V0.5.0_SECURITY_GATE.md` are **dated 2026-10-20 historical
snapshots of the earlier stacked branches**, not current assertions that
public v0.4.0 bootstrap PR #2 is still unmerged. Do not use their stale
branch-state claims, former SQLite-only audit finding, or earlier CI counts
as a final acceptance decision for this integrated branch. The v0.4.0 public
baseline is already integrated; PRs #77, #116 and #86 are also merged.
The root-controlled decision journal from #59 is now present as a **candidate**
in PR #128, not independently accepted security evidence.

## Immutable pre-documentation checkpoint

- Protected `main`: `293f45885d4596fd528608c60e8febe9c757bb4e`.
- Reviewed PR #128 head **before this documentation commit**:
  `fd2fcff9ec73d2f3982abecaf73d7134c97079f8`.
- Git comparison: ahead 6, behind 0; merge base equals protected main.
  Diff: 30 files, including 118 added client lines, 122 added TUI lines,
  intake/journal/backup modules, disabled deploy examples and tests.
- On that exact **previous** head, the following GitHub Actions runs were
  completed SUCCESS, with nine successful mandatory jobs:
  - [Tests #40077928713](https://github.com/teixemf/repocache/actions/runs/40077928713):
    `Unit tests (Python 3.12)`, `Unit tests (Python 3.13)`,
    `Bundle integrity and unsigned-source refusal (debian13)`,
    `Bundle integrity and unsigned-source refusal (almalinux10)`.
  - [Offline #40077928698](https://github.com/teixemf/repocache/actions/runs/40077928698):
    `Signed release and native offline dependency artifact`,
    `Offline wheels (debian:trixie-slim)`,
    `Offline wheels (almalinux:10)`.
  - [Upgrade #40077928737](https://github.com/teixemf/repocache/actions/runs/40077928737):
    `Synthetic rootless update and rollback (debian:trixie-slim)`,
    `Synthetic rootless update and rollback (almalinux:10)`.
- **These successful checks are NOT transferable to the new commit.**
  After this documentation change, re-read HEAD/base and require all nine
  SUCCESS on the **new exact head** before any readiness decision.
  The combined commit-status endpoint returned no legacy statuses; the
  evidence above is from the actual nine workflow jobs, not an assertion
  about branch-protection configuration.

## #127 independent Gate A criterion matrix

| Criterion | Result | Evidence and outstanding verification |
| --- | --- | --- |
| Canonical CLI, opt-in submission, bounded integration diff | **NOT VERIFIED** | PR #128 is based on current main and preserves client/TUI files rather than replacing them wholesale; full behavioral and contract review still required. |
| HMAC, replay, rate/size/depth, TLS, redirect and SSRF negatives | **NOT VERIFIED** | Python test jobs succeeded on previous SHA; inspect exact negative-case coverage, implementation and results before claiming each security behavior PASS. |
| SQLite quota, PENDING retention, offline backup/restore and interruption | **NOT VERIFIED** | Candidate modules/tests present; complete adversarial failure and custody review not yet recorded for this integrated SHA. |
| Root-owned decision journal, undo, corruption and rollback | **NOT VERIFIED** | Root journal candidate present; verify trust separation, root-only paths, injected commit failures and forged intake SQLite state; no independent audit claimed. |
| Headless TUI privacy, metrics and canonical CLI contracts | **NOT VERIFIED** | Tests succeeded as a workflow, but individual integration expectations and release compatibility still require review. |
| Safe disabled-by-default examples and nonactivation | **PASS (limited static boundary)** | Only example systemd/NGINX paths in the changed-file list; no tag, release, endpoint or production operation performed. Real service installation, root/UID isolation, systemd/SELinux and TLS are **NOT VERIFIED**, reserved to #49. |
| Nine exact-head mandatory jobs, reviews, rules and merge approval | **NOT VERIFIED on new HEAD** | 9/9 SUCCESS on previous SHA only; PR remains DRAFT, no submitted review was observed, branch-protection/ruleset requirements not independently confirmed. No merge. |
| Original #17 Gate A parent acceptance, distinct #49 Gate B | **NOT VERIFIED** | Splitting #127 does not waive any original criterion. No issue closure or production activation. |

## Required next evidence

Re-run/read back all nine mandatory contexts on the new head, inspect the
individual security tests and full 30-file diff, review root/intake UID and
path-race boundaries (including client credential file check/open behavior),
prove Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12 scoped compatibility,
and check reviews, review threads, protected rules and latest base ancestry.
Obtain explicit maintainer merge authorization only after every applicable
Gate A criterion is PASS. Post-merge recheck protected main before closing
#127. #17's complete original criteria and #49's separate production
activation remain independently blocking; a green synthetic suite cannot
substitute for them. No signing, tag, release, key handling or deployment
is part of this checkpoint.


## 2026-10-24 security review follow-up (PR #128)

This section supersedes the earlier snapshot for the specific findings below;
it does **not** declare overall Gate A acceptance. Developer-led review is
not an independent audit.

| Finding / criterion | Status | Evidence / remaining limit |
| --- | --- | --- |
| Client protected credential read/open race | **PASS (code + synthetic tests)** | Recheck mode, UID, size and `(st_dev, st_ino)` using `fstat` on the opened no-follow descriptor. Two replacement-race tests refuse an alternate 0600 inode and an insecure 0644 inode. |
| Intake protected keyring read/open race | **PASS (code + synthetic test)** | Same opened-inode checks on HMAC keyring; replacement between `lstat` and `open` is refused. |
| Retention and forged intake-writable decision state | **PASS (code + synthetic tests)** | Retention acquires the root journal lock, checks every purge candidate against its authenticated root receipt and uses the receipt timestamp, never SQLite `changed`, to authorize expiry. A forged `REJECTED` row without a root receipt aborts the entire transaction; a backdated SQLite row with a recent root receipt is retained. PENDING rows remain outside purge selection. |
| Existing authentication, bounded JSON, nonce replay, TLS/redirect, TUI and recovery tests | **PASS on prior exact head only** | Existing test modules exercise these cases. They must pass again on the final documentation HEAD; CI success alone is not an independent security audit. |
| Native root/intake UID isolation, actual TLS/NGINX/systemd/SELinux and operational backup custody | **NOT VERIFIED** | Separate Gate B #49; endpoint remains disabled. No production or real host changes. |
| Availability of unreviewed proposals after full compromise of the intake UID/SQLite | **RESIDUAL RISK / NOT VERIFIED** | The service-writable database can lose or hide pending records; the protected root journal prevents forged administrator decisions but is not a durable intake-side submission ledger. Do not present absence of visible pending rows as proof that no submissions ever existed. |
| Privileged SQLite open/write in intake-owned directory | **FAIL / SECURITY BLOCKER** | Root-operated TUI and maintenance use `sqlite3.connect(path)` on a service-writable database and SQLite journal sidecars. Python SQLite follows symlinks, and an intake UID can replace files between path checks and SQLite's open. A pre-open `lstat` or `O_NOFOLLOW` on an unrelated descriptor is not sufficient. Require a privilege-separated SQLite worker or an equivalently demonstrated kernel-enforced boundary covering the DB and journal sidecars before Gate A merge. No claim of safe native root/service separation. |
| PR #128 exact-final-head checks, full security review and ruleset/reviews | **NOT VERIFIED until final head** | The original 9 required GitHub Actions contexts must be SUCCESS on the final head and strict up-to-date base; check review threads and merge policy immediately before any ready/merge. |

The pre-documentation code HEAD for this follow-up is
`69a1a5b17256f88495e063c54be3d01e6eb59f92`. Its CI was still
running when this section was prepared; do **not** reuse an earlier
commit's 9/9 result as proof for this or the new documentation commit.

No release signer key, tag, signing, Draft, publication, production
activation, or branch-protection bypass is authorized by this checkpoint.
Original parent #15/#16/#17/#22/#23/#57 and child #127 remain OPEN until
their respective full criteria have evidence.


## 2026-10-24 real-UID privilege-separation checkpoint (PR #128)

**Disposition: still DRAFT / NOT READY TO MERGE.** The previously identified
root-SQLite-on-intake-writable-path defect has a candidate remediation, but
a passing regression is not full Gate A acceptance.

| Criterion | Status | Evidence / residual risk |
| --- | --- | --- |
| Root SQLite privilege boundary, candidate code | **PASS (reviewed design and synthetic execution only)** | `submission_db_worker.py` uses a fixed root-owned `setpriv`, dedicated intake UID/GID, cleared groups, no-new-privs, isolated Python, bounded JSON IPC, root-only decision journal and fail-closed commit acknowledgements. Root queue paths beneath untrusted ancestors or relative paths are refused. |
| Actual worker UID drop, SQLite sidecars, root-owned receipt and backup | **PASS (disposable containers)** | [GitHub Actions #40096004150](https://github.com/teixemf/repocache/actions/runs/40096004150), both Debian13 and AlmaLinux10 jobs completed SUCCESS. Inspected job logs show actual `setpriv` service-UID worker, no direct root SQLite access to service path, receipt-backed review/reconcile, private backup, hostile journal symlink with root sentinel unchanged. Ubuntu runner kernel and Docker userland only; **not** native SELinux/systemd. |
| Offline restore staging and lock | **PASS (synthetic tests)** | Root-only backup directory now holds the restore lock and preverification staging. Atomic `os.replace` into service directory is the only handoff; cross-device EXDEV fails closed. Crash/power-loss/native concurrency remain NOT VERIFIED. |
| Nine required checks on code HEAD `41e645383aa792d3fc2a61a5685b8cd5122431a6` | **PASS (historical SHA only)** | [Tests #40096004125](https://github.com/teixemf/repocache/actions/runs/40096004125) 4/4; [Offline #40096004126](https://github.com/teixemf/repocache/actions/runs/40096004126) 3/3; [Upgrade/real-UID #40096004150](https://github.com/teixemf/repocache/actions/runs/40096004150) 2/2, all SUCCESS. Newer code/docs commits require their own exact-head checks. |
| **Immutable public v0.4.0 → v0.5.0 source inventory compatibility** | **NOT VERIFIED / RELEASE BLOCKER** | The published v0.4.0 `upgrade.RELEASE_FILES` enforces an **exact** archive-member set, while new `repocache.submissions`, intake, decision journal, recovery and worker modules are outside the old source tar allowlist. Blindly adding them to the v0.5.0 source tar would make the immutable v0.4.0 updater reject the release. The separately owner-signed application wheel may carry additional modules, but its source provenance and complete release inventory must be explicitly reviewed and tested under #76 before signing. Do not change the immutable v0.4.0 policy or claim release compatibility based on synthetic CI. |
| Full Gate A review and native production activation | **NOT VERIFIED** | Stress-tested IPC timeouts, malicious parent path swaps, complete recovery concurrency, protected reviews/rules, original #17 and production Gate B #49 remain independent blockers. No endpoint is enabled. |

This update supersedes earlier pre-remediation status for the specific root
SQLite candidate. It does not mark all Gate A criteria PASS, authorize merge,
or create any release/tag/signature/Draft/publication. See
`docs/SUBMISSIONS_PRIVILEGE_SEPARATION_V05.md` for the design and limits.


## 2026-10-24 CLI v1 submission exit-status reconciliation (#127)

The previously documented **blocking numeric conflict** has been resolved in
the proposed implementation, pending exact-head execution and review.
The pre-v1 draft-only submission HTTP mapping returned numeric 4/5/6, which
conflicted with the already integrated canonical
`docs/architecture/CLI_ERROR_CONTRACT_V1.md` registry (0/1/2/3/75).
Those remote-send errors were never released as stable public functionality.
The canonical CLI v1 contract is authoritative here; no approved existing
`check`/list/export/update numeric behavior is changed.

An explicit `repos submit --send --token-file` refusal now returns **2**,
with a v1 JSON object identifying `AUTHENTICATION_REQUIRED` (HTTP 401/403),
`RATE_LIMITED` (HTTP 429), `OFFLINE` (TLS/transport errors), or
`SUBMISSION_REJECTED` (other refused/invalid responses). Messages remain
redacted and the operation never follows redirects or changes APT/DNF.
Negative tests cover numeric 2 and differentiated symbolic JSON errors.

**PASS (code inspection)**: no newly invented numeric statuses; `check` 1/3
and updater 75 unaffected; explicit opt-in preserved.
**NOT VERIFIED (exact-head CI)**: new unit and native regressions until the
new commit jobs are completed and reviewed.
**NOT VERIFIED**: full security Gate A #17, real owner-signed v0.4-to-v0.5
release migration #76 and production activation #49.
These remain distinct blockers. No signing, tag, release or listener enabled.


## 2026-10-24 root backup path-ancestry hardening (#127)

| Criterion | Status | Evidence / remaining boundary |
| --- | --- | --- |
| Privileged SQLite backup destination path | **PASS (code inspection and negative regression added; execution NOT VERIFIED)** | `SubmissionQueue.backup` now refuses relative destinations and non-root-owned, non-sticky writable or symlinked ancestors before creating the root-owned staging inode. A private final directory beneath a simulated user-owned ancestor is rejected without creating files; the existing positive backup test simulates a complete root-controlled ancestor chain. |
| Exact final PR HEAD Python 3.12/3.13, offline wheelchain, disposable Debian13/Alma10 | **NOT VERIFIED** | Re-run and inspect all nine mandatory contexts on the resulting exact HEAD; prior green runs are not transferable. |
| Complete Gate A #17/#57 review and merge policy | **NOT VERIFIED** | The backup path check addresses only one root filesystem trust boundary. Concurrent rename, native host privilege/SELinux, complete security review, approval and review-thread rules remain separately gated. |
| Genuine signed candidate #76 and production Gate B #49 | **NOT VERIFIED** | No private signing material, tag, release, publication, endpoint or production configuration changed. |

This is a scoped code hardening checkpoint, **not** final Gate A approval.
