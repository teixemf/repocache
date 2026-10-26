# Server installation and managed repository contract v1 (proposed)

**Primary issue:** [#18](https://github.com/teixemf/repocache/issues/18) · **Target:** v0.6.0 design track  
**Status:** PROPOSED / DESIGN REVIEW REQUIRED. No installer, schema parser, NGINX generator, privilege helper, migration or production activation is implemented by this document.  
**Applies to:** Debian 13 (OS Python 3.13) and AlmaLinux 10 (OS Python 3.12), with distribution-provided NGINX.  
**Example:** [server-install-v1.json](../examples/server-install-v1.json) is deliberately inert and uses invalid example hosts, absent certificate/key references and disabled repositories. It is not a deployable configuration.

## 1. Boundaries and non-goals

The server provisioner has **two independently authorized operations**: installation/update of the authenticated REPOCACHE application, and provisioning of host-owned native infrastructure (NGINX, cache directories, TLS references, service units, logs and optional firewall policy). They must not be conflated with client installation, approval of client requests, or release publication.

- Preserve the existing v0.4.0 **frontend-only, existing-NGINX non-adoption contract** documented in [PRODUCTION_EXISTING_NGINX.md](../PRODUCTION_EXISTING_NGINX.md). Its current `install.sh` is a non-root application installer, not an implicit native infrastructure installer. Never change its behavior as a side effect of accepting this design.
- The first v0.5.0 signed transition uses the existing owner-authenticated **schema-1 offline-wheelhouse** release profile. This document does **not** switch v0.5.0 to an online, source-only or wheelhouse-free profile. Future online dependencies belong to [#79](https://github.com/teixemf/repocache/issues/79), [#80](https://github.com/teixemf/repocache/issues/80), [#82](https://github.com/teixemf/repocache/issues/82), [#83](https://github.com/teixemf/repocache/issues/83) and [#84](https://github.com/teixemf/repocache/issues/84), with separate release and migration gates.
- Provision only on **Debian 13 and AlmaLinux 10**. Reject Debian 12, AlmaLinux 9, derivatives, mismatched versions, unknown IDs and unsupported architectures **before package installation or any persistent write**. Running inside a container is not proof of booted systemd/SELinux compatibility.
- Repository management is the sole operator-facing lifecycle object. NGINX routes, zones, location identifiers and the published catalog are *derived* outputs, never a second user-managed source of truth. Follow the agreed [CLI architecture](CLI_ARCHITECTURE.md); planned `deployment preflight/install/status/verify/rollback`, `config validate/apply` and `repos add/update/...` commands are not claimed to exist.
- #94 is an **optional, disposable** priority-eviction feasibility experiment. A NO-GO in #94 must not prevent #18/#25/#29/#95/#97 from implementing normal retention, safe default removal and native-NGINX disk-pressure behavior.

## 2. Versioned declarative input and state

The proposed operator configuration is strict UTF-8 JSON with top-level `kind: "repocache.server.install"`, integer `schema_version: 1`, one `deployment` object and a `repositories` array. This schema is **separate** from public client discovery catalog schema 1 and publisher-signed release schema 1/2. No current code is asserted to parse this format.

All fields below are proposed **v1 keys**, to be locked only after #18 design review and implementation negotiation with #95/#28/#29/#31. Implementations MUST reject unknown/duplicate JSON keys, unexpected types, trailing data, excessive depth/size, non-normalized identifiers and missing required fields before mutation. Canonical serialization for comparisons/hashes must be specified and tested; do not use an arbitrary user JSON file as an authorization token.

| Input | Meaning / validation |
| --- | --- |
| `deployment.listen` | Exact bind IP, DNS hostname and HTTPS port; no public bind or firewall opening without explicit operator selection. |
| `deployment.tls` | `operator-provided` certificate/private-key **file references**, not PEM content or secrets. Reject missing/unreadable/insecure paths before activation. Never copy key bytes into config/catalog/logs. |
| `deployment.native_packages.policy` | `explicit-review`: preview required distribution packages and package-manager effects. Actual package changes require the authorized privileged install operation; no silent global Python/pip update. |
| `deployment.nginx.ownership` | `new-managed-only`; refuse automatic adoption, replacement or service takeover of an unrelated NGINX configuration. An explicit audited migration plan is distinct. |
| `deployment.paths` | Canonical preflight-checked candidate roots for managed NGINX include, persistent state, cache and logs. Path names are not proof of ownership. |
| `deployment.firewall.modify` | Default false; true requires a separate privileged plan covering exact service/ports, state and reversibility. |
| `deployment.logging` | Opt-in metrics and bounded ordinary operational-log retention. Request logs must omit tokens, URL credentials and sensitive query strings. #14/#29 own actual formats/rotation. |
| `deployment.cache_policy` | Global native NGINX policy with storage-pressure thresholds. Per-repository `cache_overrides` inherit unset global values; unsupported directives/isolation fail closed. |
| `repositories[].id` | Optional administrator-supplied, strictly validated stable ID; absent means one-time generated ID allocated and persisted by the privileged lifecycle engine. |
| `repositories[].kind` | Exactly `apt` or `dnf` with a complete, compatible layout descriptor and independently configured metadata-signature trust. |
| `repositories[].upstream` | Explicit HTTPS base URL and finite exact allowed host list; no credentials, query or fragment. Canonicalization, redirects, DNS/IP safety and TLS validation are mandatory. |
| `repositories[].desired_state` | `active` or `disabled`. A requested state is not sufficient authorization; activation requires trusted operator authorization or an independently auditable approved request decision. |
| `repositories[].cache_overrides` | Optional per-repository native inactivity/capacity settings; overrides cannot assume per-repository cache zones exist until #28/#29/#97 validate supported stock-NGINX isolation. |

Input must not contain a user-editable `approved: true` / `authorized: true` or route list. The protected repository-state record holds generated ID, normalized repository identity, desired and observed states, trusted authorization/decision provenance, effective policy, configuration generation, storage ownership and last activation result. Use a **distinct versioned state format** (`state_schema_version`) so upgrades can reject unsupported state safely; input schema v1 is not a backwards-compatible promise for state internals. State creation/update is privileged, locked, journalled, atomic and never inferred from an untrusted catalog, requests queue or readable config file.

### Repository identifiers and request states

- A supplied ID is lowercase ASCII matching `^[a-z][a-z0-9-]{0,47}$`, contains no slash/dot/Unicode/confusable character, and is checked for canonical and case-folded collisions. Names are identifiers, **not** directory paths or NGINX expressions.
- Generate a random opaque ID of at least 128 bits from the operating system CSPRNG when omitted; prefix with a safe letter and encode using a fixed lowercase alphabet. Allocate once and persist before exposure. A URL-derived hash or client discovery ID must **not** be used as the sole stable ID.
- Repeated identical additions resolve to the existing ID only after a trusted comparison of canonical identity and authorization; conflicting IDs or duplicate upstream+layout identities are rejected, not overwritten. Rename or identity changes require an explicit controlled operation.
- Repository observed states: `disabled`, `awaiting-validation`, `activating`, `active`, `activation-failed`, `removed-retained`, with recoverable last-known-good generation and transition audit. They are **proposed internal states**, distinct from request queue states (`pending`, `rejected`, `approved/awaiting-activation`, etc.) owned by #96. Neither pending nor approved-only requests imply exposure.
- Normal remove disables/withdraws route and catalog entry while **retaining owned cache bytes**, with no removal-specific expiry; normal native inactivity/capacity eviction may still apply. Force-cleanup is separate, explicitly authorized and only permitted with demonstrably exclusive path/object ownership and safe concurrency handling (#95/#29). Never delete opaque live shared NGINX cache entries as a shortcut.

### APT/DNF repository semantics

An APT repository descriptor includes an HTTPS base, suites, components, architectures and an independently provisioned trusted Release signing key reference. A DNF descriptor includes base URL, expected release/architecture and the signing-key reference(s) appropriate to metadata and package verification. The trust references are **paths to public trust material**, not a permission to disable APT signature verification or DNF GPG checks. Detailed accepted layouts, package/metadata signature settings and source grammar are delegated to #28/#95 and require native tests.

For both types enforce bounded URL/path normalization, safe host allowlisting, no credentials in URLs, no redirects to unapproved origins, no localhost/link-local/private/metadata endpoints unless an independently reviewed explicit trusted upstream rule authorizes them, no DNS-rebinding bypass, and no open-proxy variable forwarding. Request cache keys and HTTP method/status handling must preserve integrity/freshness of signed metadata and package artifacts. TLS verification remains on. Disabling verification is never a valid deployment fallback.

## 3. Filesystem, system ownership and privileges

The paths in the example are **proposed managed namespace candidates**, not permissions to overwrite files found there. The implementation must use secure directory-fd / no-symlink ownership checks and refuse unexpected existing paths, hardlinks and mount boundary transitions. Exact Linux user/group/modes and packaging names need #27/#29/#64 native implementation review.

| Boundary | Owner / rule |
| --- | --- |
| Native APT/DNF, OS-provided Python/venv and distribution NGINX | Trusted, narrowly delegated root provisioning stage only, from operator-approved distribution repositories. Record planned native package additions/changes. |
| NGINX global configuration, unrelated vhosts, system certs and existing service | **Externally owned by default**; do not adopt, overwrite, reload for diagnostics or silently change. Conflict means preflight refusal or independently authorized migration. |
| REPOCACHE managed NGINX include, launcher/helper, systemd unit and SELinux labeling | Root-owned, limited writes via reviewed fixed-purpose helper, with manifest of exact paths/content/owners/creation generation. No arbitrary privileged shell command. |
| Cache/log directories | Persistent REPOCACHE-owned namespace; allow NGINX the minimum write access, not world-write. Retain across reinstall/upgrades. Never assume deletion ownership from a prefix alone. |
| Release application venv/generations | Installed and executed as unprivileged `repocache` account; never global pip, runtime wheel install as root or private signing key on server. |
| TLS public cert and private key | Operator-managed references, least readable access by NGINX; REPOCACHE app/intake must not read the private key. |
| Client APT/DNF sources and upstream failover | **Outside server provisioning**; no automatic client source edits or removal of native upstream fallback. |

On AlmaLinux 10, SELinux **enforcing** is an acceptance requirement. Verify correct package-native contexts or narrowly scoped, durable policy for each managed cache/log/config path; no `setenforce 0`, permissive-mode workaround or blanket context/permission broadening. On Debian 13, verify packaged NGINX, systemd unit boundaries and access controls. Refuse conflicting port bindings and unmanaged instances without mutation.

## 4. Preflight, dry-run and activation transaction

A later `repocache deployment preflight` and `config validate --file FILE` should report a deterministic, sanitized assessment. `deployment install --file FILE --dry-run` (planned grammar, to be confirmed with [CLI v1](CLI_ARCHITECTURE.md)) MUST NOT write persistent state, create directories, install packages, reload/restart services, change firewall rules, contact arbitrary upstreams or create a client catalog. Read-only local inspection and explicitly disclosed probes are allowed. No automatic sudo/prompt; return stable symbolic errors, exit status and one machine-readable JSON outcome if requested, consistent with CLI error contract.

Preflight reports at least:
1. OS `ID`/`VERSION_ID`/architecture and package-native Python, NGINX binary/module/directive support (`inactive`, `max_size`, optional `min_free`) without assuming feature availability solely from distribution name.
2. Privilege/ownership/SELinux, open ports, existing NGINX instance/vhosts/managed-manifest drift, symlinks, mounts, free space, CA trust, TLS key references and rollback backups.
3. Canonical repository identity/allowlist, proposed derived routes and cache zones, inherited policy, planned managed-file diff and exact native package/service/firewall changes; redact credentials, signing information and potentially sensitive paths from general logs.
4. Dependency-profile eligibility and signed release verification. If online-wheel profile is separately approved in the future, check authenticated complete pinned/hashes/target wheel closure and approved index/TLS/redirect policy *before* any runtime acquisition. PyPI outage, no trust anchor, foreign wheel or missing hash must fail without activation; v0.5.0 legacy offline profile is not replaced by this design.

An authorized activation proceeds as follows; individual steps belong to later implementation issues:

1. Obtain an exclusive cross-process lock and journal the previously working managed generation, ownership manifest, catalog digest and intended operation. Refuse drift and independently owned resources.
2. Validate **trusted** administrator authorization (or separately audited request approval via #96). Create a new candidate generation and stage files on the same filesystem, with restrictive modes/owners and fully validated path containment. Prepare native prerequisite changes separately with their irreversible/non-atomic effects disclosed.
3. Render deterministic NGINX config from validated repository state (#28); validate complete candidate via packaged `nginx -t` in the intended configuration context, not a synthetic fragment. Never change the live config on validation failure.
4. Activate the reviewed managed include under a recoverable atomic file replacement, then perform a controlled explicitly authorized NGINX reload and exercise read-only operational/metadata checks. No silent service restart or new privileged listener.
5. **Only after successful route activation and checks**, atomically publish a read-only versioned catalog derived from **active, authorized, validated and actually exposed** mappings. No separate catalog approval database/list. Unapproved, disabled, failed and removed entries must never be newly advertised.
6. Commit the generation and ownership manifest with durable sync/rename semantics; retain the prior known-working material needed for recovery. Report actual observed state and sanitized evidence. Repeated identical apply is a no-op.

**Cross-plane atomicity caveat:** an NGINX reload and a separate catalog rename cannot be one atomic operation. If either fails, immediately attempt a tested rollback to the prior managed NGINX generation and prior catalog, then verify both. If a rollback/reload cannot be verified, mark the server **NEEDS_RECONCILIATION**, stop further automated changes and fail closed on **new** advertisements; report the possibility of transient/inconsistent live routing rather than claiming a clean rollback. Test interrupted process, ENOSPC, power-loss recovery, cert rotation and concurrent admins. Do not delete active cache on rollback.

The native APT/DNF transaction is **not** generally reversible by an NGINX/venv file swap. Record partial changes and compensating actions without promising atomic OS-package rollback. A failed online dependency acquisition must not mutate NGINX, active app generation or client configuration.

## 5. Native NGINX policy and disk-pressure contract

Use stock NGINX manager behavior as the baseline (#97) with global `inactive_seconds` and `max_size_bytes` defaults. Allow only validated per-repository overrides when the packaged NGINX version **and proven isolated zone/path design** support them; otherwise report unsupported capabilities before activation. Storage pressure thresholds and warnings are advisory until #29/#97 implement and test them. `max_size` is not a hard synchronous filesystem quota; `min_free` may be absent on a distribution build. Invalid capability/low-space handling must not silently disable native safe defaults.

The lifecycle engine retains cache on ordinary repository removal (#95), but **does not assume** stock NGINX can automatically reclaim orphan files after their cache zone is removed. #94 separately investigates priority eviction and orphan reclamation; no policy choice or deletion algorithm from its spike is built into this contract. Under pressure prefer upstream pass-through/failover where actually supported; do not promise uninterrupted package access without executed native/ENOSPC tests. Incomplete metrics are **unknown**, not zero usage.

## 6. Migration and compatibility

- **Clean host:** install only into newly created verified managed paths, with explicit native package and TLS prerequisites and no implicit firewall exposure. Preserve zero-mutation rejection for unsupported hosts.
- **Existing operator-managed NGINX / v0.4.0 frontend:** keep existing NGINX, site routes, TLS keys, cache and logs untouched. Detect, report and refuse adoption. A separate, opt-in, auditable migration (#31/#25) must inventory old static route/catalog/approval records, bind each to a reviewed normalized repository, record exact owned paths and allow rollback before enabling generated routes.
- **Legacy catalog:** existing `src/repocache/catalog.py` currently consumes a separately maintained static route allowlist and validated NGINX discovery; do not mistake that legacy implementation for the desired repository-centric model. Migrate explicit approvals into trusted repository/decision state, compare against actual routes, reject ambiguous/shared/conflicting entries, and switch to generated read-only catalog only in a tested staged cutover. Never silently elevate an old catalog entry or client submission to administrative authorization.
- **Schema/version migration:** reject unknown input/state versions; require explicit reversible migrations with snapshots. A state schema bump does not imply an automatic rollback of incompatible persisted state. Preserve old signed release generations and recovery guardrails.
- **Client behavior:** existing `repocache-client check`, `repos list`, `repos submit` and read-only `repos sync` must remain compatible. New server repositories do not rewrite client APT/DNF sources. Their upstream package-manager fallback continues to require separate proof.

## 7. Ownership of dependent delivery

| Issue | Primary responsibility; #18 only specifies interface |
| --- | --- |
| [#25](https://github.com/teixemf/repocache/issues/25), [#27](https://github.com/teixemf/repocache/issues/27), [#19](https://github.com/teixemf/repocache/issues/19) | Native package/NGINX provisioning and end-to-end Debian/Alma acceptance. |
| [#95](https://github.com/teixemf/repocache/issues/95), [#96](https://github.com/teixemf/repocache/issues/96) | One authoritative repository engine, secure IDs/lifecycle and separately gated request approval-to-activation. |
| [#28](https://github.com/teixemf/repocache/issues/28), [#31](https://github.com/teixemf/repocache/issues/31) | Derived NGINX/catalog generation, transactional staging, validation, rollback and migration. |
| [#29](https://github.com/teixemf/repocache/issues/29), [#97](https://github.com/teixemf/repocache/issues/97) | Owned storage/logging/SELinux and native policy/pressure protection. |
| [#94](https://github.com/teixemf/repocache/issues/94) | Optional priority-eviction experiment **only**; no dependency from baseline deployment. |
| [#14](https://github.com/teixemf/repocache/issues/14), [#24](https://github.com/teixemf/repocache/issues/24), [#49](https://github.com/teixemf/repocache/issues/49), [#64](https://github.com/teixemf/repocache/issues/64) | Metrics privacy, client opt-in/fallback, separately authorized production request intake and least-privilege host controls. |
| [#79–#85](https://github.com/teixemf/repocache/issues/79), [#76](https://github.com/teixemf/repocache/issues/76) | Release-signed application dependencies, immutable v0.4 → signed v0.5 bridge and future separately gated online profile. |

## 8. Review, test and acceptance matrix

The following are **required future acceptance procedures**, not executed test results. Every criterion must remain **NOT VERIFIED** until supported by reviewed, exact-revision evidence:

| #18 acceptance item | Evidence required | Current status |
| --- | --- | --- |
| English design and Debian 13 / AlmaLinux 10 sample | Review this document and strict JSON parsing/security review of example; reconcile with downstream owners. | NOT VERIFIED — design PR awaiting review |
| Explicit supported OS matrix | Negative preflight on Debian 12, AlmaLinux 9, alternate distro, versions/arch mismatch; verify no writes. | NOT VERIFIED — implementation absent |
| Preview/validation before activation | Actual nonmutating dry-run, native `nginx -t` on staged candidate, own/foreign NGINX path collisions, unsupported directives, TLS failures. | NOT VERIFIED — implementation absent |
| No embedded secrets | Static sample review, generated artifacts/log scans for credentials/keys, permission and redaction negative tests. | NOT VERIFIED — generated runtime absent |
| Design review before provisioning merge | Maintainer/independent review of schema, rollback, CLI and dependency ownership, followed by separately authorized integration. | NOT VERIFIED — review pending |
| Public dependency links and native evidence before closure | Link actual issue-specific implementation PRs, executable Debian 13 and AlmaLinux 10 systemd/NGINX/SELinux enforcing tests, cache hit/metadata, ENOSPC/restart/rollback. | NOT VERIFIED — native tests absent |

**Minimum staged checks:** (a) static example JSON parse and strict schema/credential checks; (b) dry-run / unsupported-OS / conflicting-NGINX / invalid input / no-mutation; (c) disposable NGINX render and rollback; (d) native Debian 13 and AlmaLinux 10 clean installation, restart, TLS, metadata/signature, package bytes and cache HIT/MISS; (e) AlmaLinux SELinux enforcing and disk-full/concurrent-recovery cases. Only (a) can be attempted from this docs-only branch; the remainder belong to #19/#25/#28/#29/#31/#95/#97.

**Hold point:** Do not merge dependent provisioning implementations on the strength of this proposal alone. Resolve review comments, agree the final schema with owners of related issues, and collect each issue's independent acceptance evidence. No merge, release, signing, production service activation or NGINX changes are authorized by this document.
