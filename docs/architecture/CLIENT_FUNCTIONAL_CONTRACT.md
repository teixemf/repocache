# REPOCACHE Client — Approved Functional Contract

**Status:** maintainer-approved design, **not** a claim of implementation or platform validation.  
**Decision record:** UC-01 through UC-44, recorded during client planning on 2026-10-22/23.  
**Open decision:** UC-45 (server-published route changes); do not treat any option as approved.  
**Targets:** Debian 13 (APT) and AlmaLinux 10 (DNF) only.  
**CLI reference:** [CLI Architecture v1.0](CLI_ARCHITECTURE.md).  
**Tracking:** [#24](https://github.com/teixemf/repocache/issues/24), [#21](https://github.com/teixemf/repocache/issues/21), [#22](https://github.com/teixemf/repocache/issues/22).

This is a single, reviewable source of functional requirements, not a replacement for the security, compatibility and acceptance gates in existing issues. Changes to an approved behavior need an explicit maintainer decision. The client has **no TUI** in this phase. All commands are noninteractive.

## Approved use-case decisions

| UC | Approved behavior |
| --- | --- |
| UC-01 | Per-repository configuration and rollback: one failed repository must not roll back unrelated successful changes; safe bootstrap configures known, compatible local sources. |
| UC-02 | REPOCACHE is the preferred source and original upstream is the fallback; on cache recovery, use REPOCACHE again automatically without a client daemon or runtime client intervention. Requires real native validation; not guaranteed for every failure mode. |
| UC-03 | Discover newly added sources during an explicit client sync/execution, not via periodic tasks or daemon. Respect previously disabled sources and preferences. |
| UC-04 | Unknown repositories may be submitted individually, in an explicitly selected set or all in one explicit action; sanitize sensitive fields, and never activate the server on submission. |
| UC-05 | Allow administrator-requested addition of compatible catalog repositories not already installed locally, with independent trust/key approval; never auto-add third-party sources solely because catalog-listed. |
| UC-06 | Support global and per-repository REPOCACHE enable/disable; preserve originals and disabled choices during subsequent syncs. |
| UC-07 | Detect modifications made outside the client, preserve them and report conflicts; never silently overwrite them. |
| UC-08 | If a **valid** current catalog confirms server-side deactivation/removal, report it but require an explicit local management decision; an unavailable catalog is not evidence of removal. |
| UC-09 | Keep local request references; authorized on-demand Repository Request status checks, without periodic polling. |
| UC-10 | The REPOCACHE server HTTPS origin is **explicitly configured**; no DNS/DHCP discovery or implicit placeholder/default server. |
| UC-11 | Preserve the original state and the state immediately preceding the most recent effective change; no full historical backup chain. Preserve relevant filesystem metadata. |
| UC-12 | Install the client even when the server/catalog is unavailable or invalid, but leave all package sources untouched and report failure; never bypass TLS checks. |
| UC-13 | Uninstallation restores managed original sources and removes REPOCACHE dependence; an unsafe restore or external conflict blocks normal uninstallation. |
| UC-14 | Version checks and software upgrades are explicit and authenticated; preserve config and rollback capability; no automatic software update during sync. |
| UC-15 | Read-only inspection works without root when readable. Administrative source changes require explicit OS authorization and narrowly scoped privileges; no automatic elevation, no arbitrary privileged execution. |
| UC-16 | Never enable cache routing when a working upstream fallback has not been demonstrated for the particular source/format. Keep direct upstream access. |
| UC-17 | New repository signing keys require independent fingerprint validation and explicit approval; preserve existing package-signature policy. |
| UC-18 | Validate catalog over strictly checked HTTPS with schema, origin and content constraints; **no separate catalog signing requirement** at this stage. Catalog cannot grant new signing trust or disable package-signature checks. |
| UC-19 | One explicitly configured REPOCACHE server per client. Native upstream fallback is the continuity mechanism, not multiple cache servers. |
| UC-20 | Keep protected, rotated local operational/audit records for effective mutations, restores, failures, conflicts and updates; redact secrets. Idempotent no-ops are not modification events. |
| UC-21 | Client/server version mismatch is acceptable when the versioned protocol and required capabilities are compatible; fail closed on incompatible operations without auto-upgrading. |
| UC-22 | `repos sync` is a non-mutating plan; `repos sync --apply` revalidates and applies eligible changes. Separate explicitly approved installation/bootstrap behavior does not make ordinary sync implicitly mutating. |
| UC-23 | Keep repositories requiring HTTP credentials, bearer tokens, client certificates or equivalent authentication directly on upstream; do not route them through the cache or upload secrets. |
| UC-24 | Inventory disabled local repositories but do not modify or enable them; consider them for configuration only after explicit local enablement. |
| UC-25 | Recover interrupted transactions automatically, per repository where safe, using atomic writes, protected transaction state and backups. Unknown or externally changed state requires operator action. |
| UC-26 | Single exclusive native lock for all local state mutations and recovery. Fail concurrent mutation attempts promptly with a specific nonzero status. Allow compatible read-only inspection. |
| UC-27 | Sync all eligible repositories by default, or one/multiple explicitly identified repositories; stable unique identifiers and the same dry-run/apply contract. |
| UC-28 | Explicit server URL change followed by normal sync plan/apply migrates routes, preserving preferences, original upstreams and backups. |
| UC-29 | Respect a source deliberately deleted from the host; never silently recreate it. Preserve recovery metadata until explicitly cleaned; ambiguous partial deletion is a conflict. |
| UC-30 | Explicit conflict resolution may either accept a validated external change as the new managed baseline or restore the last valid managed configuration; preview and audit both. |
| UC-31 | Stable, machine-readable per-repository results and an explicit nonzero exit status for partial failure. Intentionally skipped sources are not necessarily errors. Cross-executable numeric mappings remain to be reconciled. |
| UC-32 | Without a valid current catalog, sync makes no repository changes; do not apply stale cached catalogs. Local catalog-independent recovery remains possible. |
| UC-33 | Modify only safely separable eligible entries in mixed APT/DNF files; otherwise leave the whole file unchanged. Backups/atomic writes are necessarily file-scoped, even with per-repo logical decisions. |
| UC-34 | Preserve original multiple-mirror, mirrorlist and metalink behavior as fallback; if not safely possible, keep direct upstream sources. |
| UC-35 | Always perform local post-write validation and roll back affected changes on failure. Online metadata/connectivity probes are explicit optional checks and must not install/upgrade packages. Distinguish untested fallback from proven fallback. |
| UC-36 | **No client TUI for now.** CLI only; keep business logic separable for a future TUI without adding TUI dependencies. |
| UC-37 | Trust system CAs or an explicitly selected private CA for client-to-server HTTPS, without modifying global trust or disabling verification. |
| UC-38 | Where supported and properly isolated, configure private CA verification specifically for APT/DNF access to REPOCACHE; otherwise retain direct upstream. |
| UC-39 | Do not cache repositories with inadequate effective package/metadata signing verification. Respect differences between APT and RPM/DNF signatures. |
| UC-40 | Keep repositories explicitly added by the client after client uninstallation, but reconfigure them for direct upstream access. |
| UC-41 | After fully validated removal, clean up client-owned configuration, state, backups and audit. Preserve recovery information and block normal removal on failures. Never delete third-party-owned files. |
| UC-42 | Refuse source changes during incompatible APT/DNF activity. Do not delete native package-manager locks or assume lock-file presence means a live process. |
| UC-43 | Native package uninstallation uses explicit prepare/validate before package-manager removal; block normal removal without valid preparation where OS mechanisms permit. Forced-removal bypass requires documentation. |
| UC-44 | Bind uninstallation preparation to a protected, validated state snapshot; recheck immediately before normal removal and reject invalidated preparation. |

## Non-negotiable trust and recovery boundaries

1. Treat network catalogs, repository metadata, locally discovered configuration and user-selected identifiers as untrusted input. The server is **not** a new package-signing authority, nor an authority to distribute trust anchors.
2. Never remove upstream access just to enable cache routing. Debian 13 and AlmaLinux 10 require separate real-machine tests for APT/DNF fallback, DNS/TLS failures, unavailable cache, malformed metadata, metadata-signature failures and upstream mirrors. Unknown failover semantics are **NOT VERIFIED**, not PASS.
3. Resolve file-level vs per-repository write/rollback conflicts conservatively. Stage complete files, recheck drift, write atomically, preserve ownership/modes and sensitive file content, and avoid replacing external edits. Define durable transaction-journal and power-loss limits in implementation.
4. Authenticated, rate-limited Repository Request transport (#22/#15/#16) does not activate a repository: server-side approval, controlled activation (#96) and a validated active catalog (#95/#28) are separate operations. Do not activate production submission endpoints before #17/#49 security gates.
5. Repositories requiring private credentials, missing signature guarantees, invalid CA trust or unverifiable fallback stay direct. Do not leak secrets through JSON, stdout, errors, request payloads or logs.
6. Keep `repocache-client check`, `repos list`, `repos submit` and `repos sync`. `check` includes source validation; never reintroduce `check --repos`. Preserve approved CLI aliases/help/output semantics and document any breaking change.
7. Never execute untrusted application or downloaded dependencies as root. A privileged bootstrap/helper may only perform fixed, validated operations. CLI commands remain noninteractive.
8. Installation/offline failure and unavailable catalog must never silently remove or rewrite package sources.

## Implementation and acceptance sequencing

**Phase 0: contract/preflight (this initial scoped PR)**

- Record approved UCs and identify unresolved cross-UC dependencies.
- Remove the installer's implicit example-server fallback; require an explicit, validated HTTPS origin without network dependency.
- Add isolated parser/preflight regression tests. No source rewrites or catalog/network access introduced.

**Phase 1: safe read-only engine — #24 and #107**

- Build a shared typed inventory and side-effect-free sync plan for APT `.list`, deb822 `.sources`, local mirrors and DNF `.repo`, preserving source content/ownership boundaries.
- Separate eligible, unsupported, disabled, authenticated, unsigned, externally changed, ambiguous and unverified-fallback results.
- Strict catalog/protocol compatibility and provenance validation. Support stable IDs, selected targets, per-target results, redacted JSON and exact CLI conformance.
- Measure acceptance with nonmutation tests, malformed paths/symlinks, fuzzed inputs and read-only under non-root. **Do not enable `--apply` yet.**

**Phase 2: transactional apply — #24, depends on #28/#95 and native fallback proof**

- Introduce verified per-format fallback policy first; refuse unsafe combinations (UC-16).
- Implement scope-aware protected backups, journal, exclusive locks, drift detection, atomic writes, preflight checks, rollback and reproducible interrupted-write recovery.
- Ensure mixed-file changes cannot accidentally undo another valid reconfiguration. Verify root/non-root privilege boundaries, concurrent APT/DNF activity and no-op idempotence.
- Only then implement opt-in `repos sync --apply`, with negative tests before positive native-platform acceptance.

**Phase 3: lifecycle and integration — #21/#22/#96**

- Explicit catalogue addition, submission/status, server route migration, trust CA handling, conflict resolution, software updates, uninstall preparation and clean removal.
- Preserve native package-manager safety, recovery ability, and user choices through upgrades/reinstallation.

**Acceptance rule:** For each phase, map each relevant UC/issue criterion to executed test, verifiable manual procedure or a reproducible review finding. Record PASS/FAIL/NOT VERIFIED. CI-only synthetic tests do not establish native APT/DNF/systemd/SELinux behavior. No merge without maintainer approval and all mandatory gates.

## Unresolved decisions and coordination

- **UC-45 is not approved:** behavior when an otherwise valid current catalog changes the cache route. Neither automatic nor manual-only policy may be claimed until decided. Existing `--apply` is never a blanket authorization for new trust boundaries.
- **UC-01 vs UC-22:** initial setup may configure safe known repositories only with explicit installer/administrative authorization and proven fallback. Ordinary `repos sync` remains a dry-run. Bootstrap behavior requires a separate documented acceptance contract; no surprise installation-time writes.
- **UC-08 vs UC-32:** a verified server-side removal requires operator action, while a missing catalog cannot establish removal; never silently switch to a changed server or trust key.
- **UC-11/UC-25/UC-30/UC-33:** two retained backups and per-repository recovery must be made consistent with file-level transactions. If a shared-file edit cannot be recovered without disturbing external changes, refuse automation.
- **UC-13/UC-41/UC-42/UC-43/UC-44:** native package-manager uninstall scripts and racing repository changes may limit enforceability. Document and test whether removal hooks can fail safely; forced package removal must not be portrayed as impossible.
- **UC-10 in existing runtime:** `client/repocache_client.py` still contains an example default origin when neither `--server` nor installed configuration exists. This phase only fixes the installer. Eliminate this runtime fallback with a reviewed compatibility/test migration in a follow-up. Never use example.org as a production cache.
- **#24 milestone:** the live GitHub assignment is milestone #4, **v0.6.0** (verified 2026-10-23). The issue body retains an older mismatch note; preserve history but use the current assignment as source of truth. Milestone assignment does not establish readiness.
- **Overlapping draft PRs:** #46 changes client submit behavior and #107 owns CLI parser convergence; review and reconcile before any client parser/transport integration. Server work #95/#96/#28 must precede claims of an available managed cache catalog.
