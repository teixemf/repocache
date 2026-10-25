# v0.5.0 release scope and acceptance ledger

**Status: proposed governance baseline; NOT a release approval or an approved scope amendment.**
**Snapshot:** 2026-10-25, GitHub issue milestone `v0.5.0` (#2), 28 issues (14 open / 14 closed) and 20 open associated PRs. Reviewed protected `main` reference at inventory: `9e213d7beb6534181e3ff418a890c5fdf2db2017`. This snapshot becomes stale as GitHub changes: **always re-check issues, PRs, branch heads and current gate evidence before acting**.

The purpose of this ledger is to control scope growth across parallel AI sessions and identify work that actually blocks acceptance. It **does not replace** issue criteria, authorize closure, move issues to future versions, freeze a branch, waive security, declare an installer implemented or prove a release is ready. See [AGENTS.md](../AGENTS.md), [development workflow](DEVELOPMENT_WORKFLOW.md), [release policy](RELEASE_ACCEPTANCE_POLICY.md) and [integration lanes](RELEASE_INTEGRATION_BRANCHES.md).

## Release boundary and acceptance invariants

- Keep v0.4.0-to-v0.5.0 compatibility and the approved legacy **owner-signed schema-1/offline-wheelhouse** path. Do not implicitly activate future source-only/online dependency installation (issues #83/#84/#85/#112 are currently assigned to **v0.7.0**, despite historical `v0.6` terminology in draft designs).
- Preserve actual current `repocache`/`repocache-client` behavior, approved client commands, Typer/Rich/Textual and JSON/exit-code compatibility or document an expressly approved migration. Never represent planned CLI objects as shipped.
- Governed HTTPS repository requests may be delivered as **disabled-by-default code** with Gate A security acceptance (#15/#16/#17/#22/#23/#57). **Production endpoint activation** requires distinct Gate B issue [#49](https://github.com/teixemf/repocache/issues/49), currently targeted to **v0.6.0**, and explicit deployment authorization. No automatic NGINX/APT/DNF mutation follows from pending intake or code merge.
- Observability must avoid invented HIT/MISS/coverage, private-path leakage and unsafe log retention. The original #14 acceptance includes opt-in reversible logging, native ownership/rotation and truthful CLI/TUI behavior; synthetic fixtures alone are insufficient.
- Actual signed-candidate acceptance [#76](https://github.com/teixemf/repocache/issues/76) is mandatory before public v0.5.0 release: genuine owner-held Ed25519 signing outside CI; real prior-public-version upgrade, install/repair/rollback, failure/security validation, Debian 13 and AlmaLinux 10 evidence, and separately approved publishing. Postpublication immutable public smoke remains mandatory. Green CI cannot replace owner signing or the appropriate native target gate.
- Approved security, review, required CI, compatibility and rollback gates are **non-negotiable**. The release is NOT VERIFIED until each applicable criterion has exact-revision proof.

## Inventory: open issues as observed 2026-10-25

| Issues | Functional or governance domain | Remaining release decision or evidence |
| --- | --- | --- |
| [#14](https://github.com/teixemf/repocache/issues/14) | Cache metrics and history | Reconcile merged parser/TUI work with original logging, privacy, native rotation/retention and configuration rollback criteria; incomplete parent remains open |
| [#15](https://github.com/teixemf/repocache/issues/15), [#16](https://github.com/teixemf/repocache/issues/16), [#17](https://github.com/teixemf/repocache/issues/17), [#22](https://github.com/teixemf/repocache/issues/22), [#23](https://github.com/teixemf/repocache/issues/23), [#57](https://github.com/teixemf/repocache/issues/57) | Governed intake, admin review, client submission, audit and security Gate A | Reconcile accepted Gate A integration #127/PR #128 on `main` with each **original** parent's acceptance; validate negative tests, offline restore, trusted journal and TUI privacy without claiming Gate B production activation |
| [#74](https://github.com/teixemf/repocache/issues/74) | Pinned Node.js 24 Actions | Review final protected integration evidence and safe `release.yml` artifact rehearsal/rollback requirements in the parent |
| [#76](https://github.com/teixemf/repocache/issues/76) | Signed prepublication candidate | Block on real immutable previous-public-to-owner-signed candidate, provenance, both target-OS acceptance and explicit sign/publish decisions |
| [#79](https://github.com/teixemf/repocache/issues/79) | Multi-release dependency transition epic | **Scope decision required**: identify v0.5-only compatibility requirements versus future online/runtime activation and preserve any original mandatory criteria until the owner approves a split |
| [#81](https://github.com/teixemf/repocache/issues/81) | Dependabot and dependency security | Verify effective GitHub dependency/security settings, complete actual profile inventory and alert evidence; infrastructure already merged does not prove full parent criteria |
| [#88](https://github.com/teixemf/repocache/issues/88) | Offline signing workstation Release Operator | **Scope decision required**: distinguish mandatory secure release acceptance from desirable operator automation; genuine owner-workstation tests and signing/custody remain unverified |
| [#107](https://github.com/teixemf/repocache/issues/107) | CLI convergence and contract enforcement | **Scope decision required**: distinguish implemented command contract and v0.5 regressions from future repository-lifecycle/Release Operator commands |
| [#176](https://github.com/teixemf/repocache/issues/176) | Independent review governance | Conflicting draft review policies PR [#177](https://github.com/teixemf/repocache/pull/177) / [#178](https://github.com/teixemf/repocache/pull/178); **do not treat either as active without reconciliation, owner approval and merge** |

All rows were **OPEN** at the snapshot; no row is declared PASS or accepted for closure merely by this inventory. Historical issue comments and draft stacks can predate already merged changes: inspect `main` and current issue/PR status rather than repeating them.

## Proposed freeze / admission policy (requires explicit maintainer adoption)

After an owner-approved v0.5.0 scope freeze:

1. **Already approved scope:** implement or verify within existing primary issues. Log acceptance evidence there; prefer no new issue.
2. **Release-blocking security defect, regression or mandatory prerequisite:** document privately when sensitive, triage risk and minimum corrective action, and request a recorded owner decision before adding an issue or expanding release scope. Never waive a safety gate just to ship.
3. **Enhancement / refactor / future profile:** propose later milestone or backlog, not automatic v0.5 assignment.
4. **Cross-release parents (#79, #88, #107):** prepare owner-reviewed criterion-by-criterion scope mapping. A deferred criterion is not PASS; retain traceability, test obligations and explicit approval of any amended target.
5. **Overlapping PRs:** inventory unique changes against protected `main` and the correct integration branch before proposing a replacement or closure. Original branches and evidence must not be lost by mass retargeting.

No date, feature or owner decision is invented in this proposed policy. Recording a freeze does not substitute for actual release acceptance or authorize merge/publication.

## Release readiness and evidence report

| Gate | Current disposition | What must be shown |
| --- | --- | --- |
| Functional issues and original acceptance | **NOT VERIFIED** | For each v0.5 criterion: approved scope, actual implementation SHA, PASS/FAIL/NOT VERIFIED and executed evidence |
| Security/code Gate A for optional submissions | **NOT VERIFIED** | Original #17/#57/etc criteria tested and reviewed on final integrated code; no endpoint activation inference |
| Operational Gate B for submissions | **NOT AUTHORIZED**, future release | #49 and owner enablement permission before any live listener |
| CI, dependency, architecture governance | **NOT VERIFIED** | #74/#81/#107/#176 criteria and exact-head checks/reviews under the policy actually in force |
| Genuine signed candidate and native acceptance | **NOT VERIFIED — publication blocker** | #76 real signed assets, immutable v0.4.0 upgrade, native Debian 13 / AlmaLinux 10 evidence, recovery/rollback and security failure paths |
| Tag, sign, stage, publish | **NOT AUTHORIZED** | Separate explicit owner approvals after prerequisite acceptance |
| Published immutable smoke | **NOT VERIFIED; postpublication stage** | Real public artifact identity/digests and installation after an authorized publication |

**Next owner decisions, not silent AI changes:** resolve #177/#178 review-policy conflict; approve or reject the scope freeze; decide the v0.5 boundaries of #79/#88/#107 and any optional automation. Do not adjust existing issues, milestones or agreed acceptance checklists merely because this ledger proposes a smaller release surface.

The release acceptance matrix must be refreshed from live GitHub before any merge or publication. No real signing key, new release, production listener, branch protection change or issue closure is authorized by this document.
