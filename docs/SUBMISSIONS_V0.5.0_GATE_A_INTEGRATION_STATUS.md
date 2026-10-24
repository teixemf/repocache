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
