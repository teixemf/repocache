# CLI architecture conformance and migration plan

**Canonical design:** [CLI Architecture v1.0](CLI_ARCHITECTURE.md)  
**Tracking issue:** [#107](https://github.com/teixemf/repocache/issues/107)  
**Status:** Partial implementation under review; not a released public CLI contract.

## Source of truth and test gates

- The approved **design** lives in `docs/architecture/CLI_ARCHITECTURE.md`.
- `tests/cli_surface_inventory.json` lists the **currently registered** server and client command paths, including intentionally retained legacy paths. This is an exact inventory of installed source command registration, **not** a roadmap or a declaration that a planned feature is implemented.
- `tests/test_cli_interface_contract.py` compares the complete Typer and argparse command trees with this inventory. Any newly registered noun, action or alias changes the tree and fails CI until the inventory is reviewed and updated. The tests also cover representative argument placement, JSON output, help-only behavior, nonmutation and client sync refusal.
- `.github/workflows/tests.yml` invokes the contract test independently in the mandatory Python 3.12 and 3.13 job matrix. A missing test module fails the required gate.
- This automated gate **cannot prove semantics or security of new commands by itself**. New commands require explicit tests for authorization, errors, idempotence, preview, recovery, installation impact and Debian 13 / AlmaLinux 10 as appropriate.

## What this first implementation does

- Exposes `repo(s) list/ls`, `repo(s) show` and hidden legacy `repo(s) info` in the server parser. `log` is a hidden alias for `logs`. It does **not** implement the planned repository-mutation verbs.
- Adds server root-level `--json` as well as existing action-level JSON on previously supported finite queries; error messages for missing repository IDs use a stable symbolic code without renumbering the pre-existing exit status. Unsupported JSON modes, including unbounded `logs follow` and the existing privileged `service reload`, are explicitly rejected **before their side effects**, rather than printing misleading plain text.
- Enables root-, object- and action-level `--json` and `--server` in the standalone client; provides `repo(s) list/ls` aliases and object-only help. The four approved client commands retain their existing behavior and exit codes.
- No package source write, NGINX change, client submission transport, download, updater signing, new privileged helper or production activation is introduced.

## Stage B — diagnostic command namespace convergence

This scoped follow-up (#107) introduces the canonical **read-only** diagnostic
forms `repocache system status`, `repocache system check [--deep]` and
`repocache metrics show [--period PERIOD] [--repo NAME]`. Each forwards
to the same existing diagnostic implementation and accepts the established
global or action-level `--json` behavior. No extra network access is
introduced; the optional deep upstream probes remain opt-in.

The old root-level `status` and `health` remain available, and bare
`metrics [--period PERIOD] [--repo NAME]` retains its prior behavior via
an explicit compatibility callback. This **intentional transitional exception**
to object-only-help is documented and regression-tested until the deprecated
spellings can be retired under the project's release policy.

This stage does not add or remove any NGINX, APT/DNF, signed update or server
repository mutation capability. The exact common numeric exit-code registry
and versioned JSON envelopes are a separate integration dependency; payloads
and existing error statuses remain unchanged.

## Stage C — exact-version signed update adapter

The canonical noninteractive entry point is now proposed as:

```console
repocache update install 0.5.0
repocache update install 0.5.0 --json
repocache --json update install 0.5.0
repocache update install 0.5.0 --bundle ./repocache-v0.5.0.tar.gz \
  --checksum ./repocache-v0.5.0.sha256 \
  --manifest ./manifest.json --signature ./manifest.sig \
  --wheelhouse ./wheels.tar.gz
```

**Important:** The new CLI accepts only an explicit, canonical stable `X.Y.Z`
version, with no `v` prefix, pre-release suffix, leading-zero components,
or unbounded numeric string. Missing/invalid version arguments are rejected
*before* calling the updater; the underlying updater remains responsible
for authenticating the publisher signature, metadata, signed wheelhouse,
platform/upgrade compatibility, exclusive lock, recovery, staging and
rollback. A local path option is **not** a bypass of these checks.

The CLI adapter calls the **same** `updater.apply(...)` function used by
the older `repocache update` entry point. For the transition, both
`repocache update` and `repocache update --version X.Y.Z` retain their
current mutating behavior, including their ability to select a version
implicitly when one is omitted. This is a deliberate temporary compatibility
exception to the v1 object-only-help rule, **not** a recommended pattern for
new commands. After an approved deprecation/migration with two stable
release notices once the CLI is stabilized, this exception can be retired.
`repocache update list` and `repocache update check` remain read-only.

Process exit statuses and the legacy updater's JSON fields are unchanged,
including busy status 75. The new adapter adds a symbolic
`INVALID_VERSION` JSON failure for malformed *provided* versions. Typer's
missing-positional-argument parse failure remains a text usage diagnostic;
fully structured JSON for parser failures and an agreed cross-executable
numeric exit-code registry are separate future contract work, not falsely
claimed as complete by this stage. The CLI never prints credentials and
must not prompt or elevate privileges.

The mandatory CLI conformance CI gate includes
`tests/test_cli_update_install.py` on Python 3.12 and 3.13. These are
mocked adapter tests, **not** evidence that a genuine signed candidate can be
installed/rolled back on a native Debian 13 or AlmaLinux 10 host.
Coordinate the dependency-profile and release-acceptance gates with #82–#85;
do not merge incompatible updater-branch changes without semantic review.

## Known transitional differences and dependent issues

| Area | Current source | Next gated work |
| --- | --- | --- |
| Server legacy `metrics`, `status`, `health` | Preserved alongside the new `metrics show`, `system status`, `system check` read-only commands (merged PR #110) | Test equivalent data/exit behavior and maintain the existing TUI; remove no old command before an approved deprecation/migration |
| `catalog publish` | Existing legacy manual export remains | #28/#95 must implement automatic read-only discovery before safely retiring the mutator; do not silently change authorization |
| Repository add/update/remove/enable/disable | Planned in v1.0, **not implemented by this change** | #18/#28/#95/#96 lifecycle, privilege boundaries, migrations |
| `repocache update --version` and bare `update` | Legacy compatibility entry points retained while `update install VERSION` adds explicit target validation (Stage C, pending PR) | Coordinate deprecation and full native signed-upgrade/rollback acceptance with #82–#85; no silent default-target behavior in the new verb |
| Client `sync --apply` | Still refused for safety in current released/merged source | #24: authenticated discovery, backups, verified rollback/fallback on both supported OSs |
| Client `submit --send` | Not exposed in current `main` | Draft PR #46 and #22/#17/#49 security gates; no listener activation by CLI normalization |
| Numeric exit statuses and JSON schema evolution | Existing codes and payload fields retained | Reconcile with concurrent client CLI architecture work; version schemas before an incompatible change |
| Workstation Release Operator | No installed executable in `main` | #88: implement `environment check` / `candidate ...` and add to the inventory with signed owner approval safeguards |
| Branch conflicts | Draft PRs #42/#52 edit server CLI; PR #46 edits client | Rebase or consciously reconcile before integration, never blindly copy obsolete parser code |

## Checklist for any future CLI PR

1. Link the canonical design and affected GitHub issue; identify object/action and authority boundary.
2. Extend the command inventory for **each supported executable**, and add behavior/negative/failure tests (including both accepted option placements where applicable).
3. Verify text vs JSON stdout/stderr, stable symbolic error identity, numeric status compatibility, object-only help, aliases, `--dry-run` safety and repeated idempotent operations where relevant.
4. Verify client source nonmutation, secure NGINX delegation, signed update/provenance or release authority as applicable; reject unsafe requests before side effects.
5. Run the required conformance matrix and CI checks on the exact PR head; record PASS/FAIL/NOT VERIFIED evidence per issue criterion.
6. Assess breaking changes against the two-stable-release deprecation rule **after the redesigned CLI has stabilized**. Never silently remove approved client command anchors.
7. Obtain explicit maintainer merge authorization after all mandatory gates are PASS.

**Not a security audit:** A syntactic inventory test catches unnoticed additions and removals, but does not authenticate command execution or replace independent security/operational acceptance requirements.
