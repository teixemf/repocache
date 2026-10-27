# Server installation and managed repository contract v1 (proposed)

**Primary issue:** [#18](https://github.com/teixemf/repocache/issues/18) · **Target:** v0.6.0 design track  
**Status:** PROPOSED / DESIGN REVIEW REQUIRED. No installer, schema parser, NGINX generator, privilege helper, migration or production activation is implemented by this document.  
**Applies to:** Debian 13 (OS Python 3.13) and AlmaLinux 10 (OS Python 3.12), with distribution-provided NGINX.  
**Example:** [server-install-v1.json](../examples/server-install-v1.json) is deliberately inert: it uses invalid example hosts, placeholder certificate/key file paths (the referenced certificates and private keys are not supplied), and disabled repositories. It is not deployable as-is.

## 1. Boundaries and non-goals

The server provisioner has **two independently authorized operations**: installation/update of the authenticated REPOCACHE application, and provisioning of host-owned native infrastructure (NGINX, cache directories, TLS references, service units, logs and optional firewall policy). They must not be conflated with client installation, approval of client requests, or release publication.

- Preserve the existing v0.4.0 **frontend-only, existing-NGINX non-adoption contract** documented in [PRODUCTION_EXISTING_NGINX.md](../PRODUCTION_EXISTING_NGINX.md). Its current `install.sh` is a non-root application installer, not an implicit native infrastructure installer. Never change its behavior as a side effect of accepting this design.
- The first v0.5.0 signed transition uses the existing owner-authenticated **schema-1 offline-wheelhouse** release profile. This document does **not** switch v0.5.0 to an online, source-only or wheelhouse-free profile. Future online dependencies belong to [#79](https://github.com/teixemf/repocache/issues/79), [#80](https://github.com/teixemf/repocache/issues/80), [#82](https://github.com/teixemf/repocache/issues/82), [#83](https://github.com/teixemf/repocache/issues/83) and [#84](https://github.com/teixemf/repocache/issues/84), with separate release and migration gates.
- Provision only on **Debian 13 and AlmaLinux 10**. Reject Debian 12, AlmaLinux 9, derivatives, mismatched versions, unknown IDs and unsupported architectures **before package installation or any persistent write**. Running inside a container is not proof of booted systemd/SELinux compatibility.
- Repository management is the sole operator-facing lifecycle object. NGINX routes, zones, location identifiers and the published catalog are *derived* outputs, never a second user-managed source of truth. Follow the agreed [CLI architecture](CLI_ARCHITECTURE.md); planned `deployment preflight/install/status/verify/rollback`, `config validate/apply` and `repos add/update/...` commands are not claimed to exist.
- #94 is an **optional, disposable** priority-eviction feasibility experiment. A NO-GO in #94 must not prevent #18/#25/#29/#95/#97 from implementing normal retention, safe default removal and native-NGINX disk-pressure behavior.

### Explicit installer delegation and supported-host matrix

A future **operator-invoked** deployment command/wrapper may orchestrate two separate, audited phases: (1) verify the publisher-authenticated release and prepare an unprivileged REPOCACHE application generation, then (2) **only on a separate explicit infrastructure-install request** dispatch a fixed-purpose privileged native provisioning helper after read-only preflight and reviewed plan. The privileged helper must take validated structured inputs, not shell fragments or commands from the unprivileged runtime. It must not execute downloaded application scripts as root. The existing `install.sh` stays an unprivileged application-only installer and must not call `sudo`, create privileged files, enable NGINX, modify the firewall or launch the native phase automatically. Separate journalling and compensating/recovery procedures are required for the non-atomic native package transaction and the versioned unprivileged application generation.

| Host OS | Native packages | OS Python | Native acceptance boundary |
| --- | --- | --- | --- |
| Debian **13** | APT, distribution NGINX | 3.13 | systemd service, NGINX config, TLS/filesystem and APT package/metadata checks on actual target |
| AlmaLinux **10** | DNF, distribution NGINX | 3.12 | systemd service, NGINX config, RPM metadata/packages **and SELinux enforcing** on actual target |
| Debian <=12, AlmaLinux <=9, other/derivative/unknown systems | None allowed | Unsupported | Reject before any persistent mutation; no best-effort fallback or automatic OS migration |

## 2. Versioned declarative input and state

The proposed operator configuration is strict UTF-8 JSON with top-level `kind: "repocache.server.install"`, integer `schema_version: 1`, one `deployment` object and a `repositories` array. A mutating apply additionally requires `expected_state_generation`, an optimistic concurrency precondition from protected server state; its value is `0` when no managed state exists. It is not an authorization credential, and must never be derived from the untrusted catalog or request queue. This schema is **separate** from public client discovery catalog schema 1 and publisher-signed release schema 1/2. No current code is asserted to parse this format.

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


### Normative v1 field dictionary (B2)

This is the **closed, proposed v1 JSON shape**, including the sample. Every table row denotes an exact JSON field name: no other keys are accepted at that level, including in nested objects. All objects shown as required are non-null. For mandatory fields, omission is an error; optional defaults are defined explicitly. **Only** the optional fields described below may be omitted. This is a normative design for independent parser implementations, **not** evidence that a parser or native policy exists.

**Common validation rules:**

- UTF-8 input, maximum **1 MiB**, maximum **16 nested JSON levels**, one complete JSON document only; refuse byte-order marks, trailing data, duplicate keys anywhere, non-finite numbers and unknown fields at every level. Validate before host mutation. JSON numeric fields require the actual JSON **integer** type (not Boolean, float or numeric string). Integer values must not exceed `9223372036854775807` (signed 64-bit maximum); additionally reject host-NGINX unsupported values before activation.
- Every string must be UTF-8 valid, nonempty, trimmed and free from control characters; ≤2048 UTF-8 bytes unless narrowed below. A list contains unique, normalized nonempty items (no duplicates after case/semantic canonicalization); lists have at most **32** items unless stated otherwise. Identifiers, filenames and hostnames have the narrower rules below. Reject unknown or missing required fields **recursively**, including conditional per-type `layout`.
- A **host** is an ASCII DNS name of 1–253 characters, with 1–63-character LDH labels (letters/digits/hyphens), no wildcard, trailing dot, username, port or IPv4/IPv6 literal; normalize case to lowercase for comparison. IP addresses are used only where the separate bind field explicitly permits them. Runtime DNS and destination safety checks remain mandatory. A **path** is an absolute canonical Unix path without NUL, `.`/`..` segments, empty repeated separators, `~` expansion or control characters, and within the verified path namespace. A **key reference** is `file:` followed by such an absolute path to **public** trust material; no embedded PEM, key bytes or arbitrary URI scheme.
- An **upstream URL** is an HTTPS URL with an ASCII DNS host, no userinfo, query, fragment or backslash, and a slash-terminated canonical path. Reject encoded/unescaped traversal, ambiguity or unsafe IP/redirect resolution; its normalized host **must** appear in `allowed_hosts`. A safe input string/host alone does not prove the eventual NGINX data plane blocks SSRF; #28/#95 must fail closed when supported stock NGINX cannot enforce actual resolved destinations and redirects.
- A **repository token** (suite, component, architecture, releasever, basearch) is an ASCII 1–64-character string matching `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`; reject `.`, `..` or token-to-path interpretation. A **metadata path** is a relative slash-delimited sequence of such tokens (no absolute path, empty segment, query, fragment or traversal). These are input syntax constraints, **not** substitutes for APT/DNF metadata compatibility and signatures.

| Field (path relative to document root) | Required/type | Exact value/validation; omission/default |
| --- | --- | --- |
| `kind` | Required string | Exactly `repocache.server.install`. |
| `schema_version` | Required integer | Exactly `1`, distinct from release-manifest and protected state schema versions. |
| `expected_state_generation` | Required integer for **mutating** apply/install; optional for read-only validate/preview | 0 for absent managed state; otherwise exact current nonnegative monotonically increasing **protected** state generation. No implicit value on mutation. |
| `deployment` | Required object | Closed fields: `listen`, `tls`, `native_packages`, `nginx`, `firewall`, `paths`, `logging`, `cache_policy`. All except `firewall` are required. |
| `deployment.listen` | Required object | Exactly `bind_address`, `hostname`, `https_port`, all required. |
| `deployment.listen.bind_address` | Required string | Canonical IPv4/IPv6 literal as parsed by the OS; loopback is the safe example; any non-loopback bind requires explicit network-exposure authorization and verified firewall/TLS constraints. |
| `deployment.listen.hostname` | Required string | DNS host syntax above; certificate must cover it. |
| `deployment.listen.https_port` | Required integer | 1–65535; privileged/listening port binding requires authorized provisioning. |
| `deployment.tls` | Required object | Exactly `mode`, `certificate_file`, `private_key_file`; all required. |
| `deployment.tls.mode` | Required string | Exactly `operator-provided` in v1. No automatic issuance/import implied. |
| `deployment.tls.certificate_file`, `deployment.tls.private_key_file` | Required strings | Absolute managed-reference paths; certificate and key must match, be valid for hostname/time, and have safe ownership/access. Contents never embedded, logged or copied into a sample/catalog. |
| `deployment.native_packages` | Required object | Exactly `policy`; required. |
| `deployment.native_packages.policy` | Required string | Exactly `explicit-review` in v1. Package names/versions come from platform-specific reviewed implementation plans, not arbitrary input. |
| `deployment.nginx` | Required object | Exactly `ownership`; required. |
| `deployment.nginx.ownership` | Required string | Exactly `new-managed-only`. Third-party NGINX adoption needs separate out-of-band authorized migration. |
| `deployment.firewall` | Optional object | If omitted, equivalent to `{"modify":false}`. If supplied, contains **only** required Boolean `modify`; `true` requires a separately authorized change plan. |
| `deployment.paths` | Required object | Exactly `generated_include`, `state_root`, `cache_root`, `log_root`; all required. |
| `deployment.paths.generated_include`, `deployment.paths.state_root`, `deployment.paths.cache_root`, `deployment.paths.log_root` | Required strings | Canonical absolute paths; no path is adopted on name alone. Verify containment, root/NGINX ownership, symlink/hardlink/mount and third-party conflicts before use. |
| `deployment.logging` | Required object | Only `metrics_opt_in` and `retention_days` allowed; `retention_days` required. |
| `deployment.logging.metrics_opt_in` | Optional Boolean | Default `false`. No logging listener enabled by omission. |
| `deployment.logging.retention_days` | Required integer | 1–3650, subject to explicit operator retention/privacy policy; does not override externally managed logs. |
| `deployment.cache_policy` | Required object | Exactly `engine`, `global`, `disk_pressure`; all required. |
| `deployment.cache_policy.engine` | Required string | Exactly `nginx-native`; does not authorize #94 advanced eviction. |
| `deployment.cache_policy.global` | Required object | Exactly `inactive_seconds`, `max_size_bytes`; both required. |
| `deployment.cache_policy.global.inactive_seconds` | Required integer | Positive 1–2147483647; native capability/units must be checked before generation. |
| `deployment.cache_policy.global.max_size_bytes` | Required integer | Positive 1–9223372036854775807; actual filesystem/NGINX limits must be checked. |
| `deployment.cache_policy.disk_pressure` | Required object | Exactly `warning_free_bytes`, `critical_free_bytes`; both required. |
| `deployment.cache_policy.disk_pressure.warning_free_bytes`, `deployment.cache_policy.disk_pressure.critical_free_bytes` | Required integers | Each positive 1–9223372036854775807; **warning ≥ critical**; effective policy/alert hysteresis implementation belongs to #97. |
| `repositories` | Required array | 0–500 repository objects. Empty means no **listed** repositories, **not** deletion of existing managed repositories. |
| `repositories[].id` | Optional string | ASCII `^[a-z][a-z0-9-]{0,47}$`; a missing ID permits one-time CSPRNG allocation or an exact trusted canonical-identity match. |
| `repositories[].kind` | Required string | Exactly `apt` or `dnf`; selects one disjoint, strict `layout` shape. |
| `repositories[].desired_state` | Required string | Exactly `active` or `disabled`; **desired**, not observed or proof of authorization. |
| `repositories[].upstream` | Required object | Exactly `base_url`, `allowed_hosts`; both required. |
| `repositories[].upstream.base_url` | Required string | HTTPS upstream URL syntax above. |
| `repositories[].upstream.allowed_hosts` | Required array of strings | 1–32 unique exact DNS hosts; must include the URL's host. No wildcard or arbitrary approved IP range inferred. |
| `repositories[].layout` for `apt` | Required object | **Only** `suites`, `components`, `architectures`, `release_key_refs`; all required. All four are arrays with 1–32 unique nonempty items; tokens use the repository-token rule; trust refs use the public-key-reference rule. Flat repositories without components are **not represented** by v1 and must be refused pending an approved schema extension. |
| `repositories[].layout` for `dnf` | Required object | **Only** `releasever`, `basearch`, `metadata_path`, `gpg_key_refs`; all required. First two are repository tokens; metadata_path is a bounded relative path (≤512 bytes); `gpg_key_refs` is an array of 1–32 unique public-key references. |
| `repositories[].cache_overrides` | Optional object | Only `inactive_seconds` and `max_size_bytes` accepted, either or both optional, same integer ranges as global equivalents. If absent or `{}`, inherit **both** global values. If only one is present, the other inherits; omission **does not preserve** an earlier local override for that field when updating an explicitly listed repository. |

At the repository level, the only allowed keys are `id`, `kind`, `desired_state`, `upstream`, `layout`, `cache_overrides`; all except `id` and `cache_overrides` are required. Authorization metadata, cache paths, routes, policy-effective values, state generations and deletion flags **never** come from the repository object; they are protected derived/runtime state. JSON path keys are not shell expressions and must not be passed to an unrestricted root helper.

### Declarative reconciliation and concurrency (B1)

**Authoritative split:** the protected repository-state store owns assigned IDs, canonical identities, authorization/approval provenance, observed state, ownership manifests, effective generation and activation results. The JSON document is **requested configuration**, not evidence of owner approval or observed exposure. The protected store plus actual checked NGINX exposure determines which mappings may be advertised; neither a static allowlist nor the catalog is independently writable authority.

**Apply semantics:**

1. `deployment` is a **complete desired specification** of managed deployment settings, subject to the documented optional defaults. It may change only after a reviewed diff and trusted operator authorization. Each explicitly listed repository is a **complete desired record** for that repository, not a patch; only that record's optional fields can default/inherit. `repositories: []` does **not** imply "remove all".
2. Applying input explicitly reconciles repository-specific desired fields **only for repositories listed** by stable ID or, when ID is omitted, by unambiguous canonical repository identity after trusted look-up. An omitted repository retains its explicit desired fields, ID, authorization provenance, lifecycle intent, ownership and existing observed state; **omission never disables, removes or purges** it. This does **not** freeze any effective settings derived from `deployment.cache_policy.global`: an explicitly authorized global-policy change recomputes inherited values for **every affected managed repository**, including omitted ones, while retaining any per-field local override. Such derived changes are part of the same staged, validated and journalled transaction, not implicit repository edits or automatic cache cleanup. Existing IDs cannot be reassigned; differing identity for an existing ID or duplicate/colliding identities fail closed. A newly declared repository must pass all admission and authorization gates; an `active` request is not authority to create a live route.
3. For an explicitly listed existing repository, all supplied required fields replace its **desired** values on a successful apply; omitted optional `cache_overrides` means inheriting global policy, not silently retaining prior overrides. On any change to a global inherited field, compute **all** affected effective per-repository policies from the new global values plus each repository's stored explicit overrides, including records omitted from this file. Preview every resulting effective change, capability/ownership consequence and managed NGINX generation diff; validate the entire candidate and refuse the **whole** mutation before activation if any affected repository cannot safely support the new policy. Persist effective inherited settings and the protected generation coherently only on successful activation, using #31 rollback/reconciliation on partial failures; never silently keep stale effective settings, partially apply a global change or directly purge cache as a shortcut. Existing observed state is not optimistically overwritten; activation, disablement, catalog changes and last-known-good state are controlled by the staged lifecycle transaction. **Removal and optional destructive cleanup are exclusive to separately authorized, explicit `repos remove` / purge operations**, never a side effect of apply omission.
4. A mutating install/apply must supply the exact `expected_state_generation` from the trusted state snapshot used for preview; it is 0 only for a genuine previously unmanaged installation. While holding the same exclusive lock used to commit state, **re-read** the generation, ownership and current files before effects; any stale generation or drift that would cause a write must fail **without persistent mutation**, with a structured concurrency/conflict error and a new read-only diff for the operator. If a stale input is provably an exact no-op against the current authorized, observed desired state, it may succeed without writes or generation increment, but may not silently update any field.
5. Each successfully committed actual state change increments the protected generation once, with durable journal and manifest; no-op applies do not increment it. Validation and dry-run do not mutate or reserve a generation. Retrying interrupted work follows the journal recovery contract of #31; a crash cannot be treated as an implicit approval to use stale input. Concurrent CLI actions, request activation and config apply **share** this locking/generation discipline. A matching generation is a precondition, **not** permission to bypass authorization, external ownership checks, `nginx -t` or rollback gates.

**Illustrative non-destructive reconciliation cases (not executed):**

| Protected state before apply | File contents | Required result |
| --- | --- | --- |
| Repositories A, B; generation 8; global policy unchanged | A only, `expected_state_generation: 8` | Reconcile A after checks; **retain B** and its cache/authorization and effective policy unchanged. |
| Repositories A, B; generation 8 | Empty `repositories: []`, generation 8 | No implicit disable/remove; an authorized global-policy update still affects inherited settings of **both** A and B and requires preview/validation. |
| Repository A has local `inactive_seconds` override; generation 8 | A with `cache_overrides: {}`, generation 8 | A re-inherits current global inactive setting after authorized activation. |
| Repositories A and omitted B; generation 8; B has no local `max_size_bytes` override; global maximum is 10 GiB | File lists A only and changes global `max_size_bytes` to 5 GiB, generation 8 | Preview B as **implicitly affected**; retain B's identity, approval and lifecycle but validate and activate an effective 5 GiB setting for B. Commit **one** protected generation increment only after the entire update succeeds. |
| Repository B has an explicit 3 GiB `max_size_bytes` override but inherits `inactive_seconds` | File omits B and changes global `max_size_bytes` and `inactive_seconds` | Preserve B's explicit 3 GiB maximum; preview/validate only B's inherited inactivity change. |
| Repository B is omitted and the proposed global policy cannot be safely supported by its active NGINX zone | File changes a global inherited value | **Reject the entire update before activation**, preserving the last-known-good global policy and B's effective policy; no silent partial rollout. |
| Admin changes B to generation 9 | Stale A document with `expected_state_generation: 8` | Reject any attempted write as **STALE_STATE**; no overwrites or partial activation. |
| No managed state; external NGINX exists | Generation 0, valid desired A | Refuse unauthorized NGINX adoption even with matching generation. |

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

A later `repocache deployment preflight` and `config validate --file FILE` should report a deterministic, sanitized assessment. Preview must report current protected `state_generation`, the input's `expected_state_generation`, a list of explicitly modified repositories, preserved omitted repositories, and **all implicitly affected omitted repositories** when global defaults change. For each affected repository, show previous/proposed effective values, inherited versus explicit override provenance, resulting managed NGINX/configuration differences, any native-policy/ownership incompatibility, and a conflict/drift decision. The preview must reveal the complete proposed change set for separate trusted authorization, and refuse unsupported global changes as a whole without host mutation. It must never present a stale-apply preview as authorized. `deployment install --file FILE --dry-run` (planned grammar, to be confirmed with [CLI v1](CLI_ARCHITECTURE.md)) MUST NOT write persistent state, create directories, install packages, reload/restart services, change firewall rules, contact arbitrary upstreams or create a client catalog. Read-only local inspection and explicitly disclosed probes are allowed. No automatic sudo/prompt; return stable symbolic errors, exit status and one machine-readable JSON outcome if requested, consistent with CLI error contract.

Preflight reports at least:
1. OS `ID`/`VERSION_ID`/architecture and package-native Python, NGINX binary/module/directive support (`inactive`, `max_size`, optional `min_free`) without assuming feature availability solely from distribution name.
2. Privilege/ownership/SELinux, open ports, existing NGINX instance/vhosts/managed-manifest drift, symlinks, mounts, free space, CA trust, TLS key references and rollback backups.
3. Canonical repository identity/allowlist, proposed derived routes and cache zones, inherited policy, planned managed-file diff and exact native package/service/firewall changes; redact credentials, signing information and potentially sensitive paths from general logs.
4. Dependency-profile eligibility and signed release verification. If online-wheel profile is separately approved in the future, check authenticated complete pinned/hashes/target wheel closure and approved index/TLS/redirect policy *before* any runtime acquisition. PyPI outage, no trust anchor, foreign wheel or missing hash must fail without activation; v0.5.0 legacy offline profile is not replaced by this design.

An authorized activation proceeds as follows; individual steps belong to later implementation issues:

1. Obtain an exclusive cross-process lock; re-read and compare the `expected_state_generation` and ownership/manifest state with the preview snapshot, then journal the previously working managed generation, ownership manifest, catalog digest and intended operation. Reject any stale mutation or drift before effects; do not equate a matching generation with authorization.
2. Validate **trusted** administrator authorization (or separately audited request approval via #96). Create a new candidate generation and stage files on the same filesystem, with restrictive modes/owners and fully validated path containment. Prepare native prerequisite changes separately with their irreversible/non-atomic effects disclosed.
3. Render deterministic NGINX config from validated repository state (#28); validate complete candidate via packaged `nginx -t` in the intended configuration context, not a synthetic fragment. Never change the live config on validation failure.
4. Activate the reviewed managed include under a recoverable atomic file replacement, then perform a controlled explicitly authorized NGINX reload and exercise read-only operational/metadata checks. No silent service restart or new privileged listener.
5. **Only after successful route activation and checks**, atomically publish a read-only versioned catalog derived from **active, authorized, validated and actually exposed** mappings. No separate catalog approval database/list. Unapproved, disabled, failed and removed entries must never be newly advertised.
6. Commit the generation and ownership manifest with durable sync/rename semantics; retain the prior known-working material needed for recovery. Report actual observed state and sanitized evidence. Repeated identical apply is a no-op.

**Cross-plane atomicity caveat:** an NGINX reload and a separate catalog rename cannot be one atomic operation. If either fails, immediately attempt a tested rollback to the prior managed NGINX generation and prior catalog, then verify both. If a rollback/reload cannot be verified, mark the server **NEEDS_RECONCILIATION**, stop further automated changes and fail closed on **new** advertisements; report the possibility of transient/inconsistent live routing rather than claiming a clean rollback. Test interrupted process, ENOSPC, power-loss recovery, cert rotation and concurrent admins. Do not delete active cache on rollback.

The native APT/DNF transaction is **not** generally reversible by an NGINX/venv file swap. Record partial changes and compensating actions without promising atomic OS-package rollback. A failed online dependency acquisition must not mutate NGINX, active app generation or client configuration.

## 5. Native NGINX policy and disk-pressure contract

Use stock NGINX manager behavior as the baseline (#97) with global `inactive_seconds` and `max_size_bytes` defaults. A later global-default change **must reach every managed repository that inherits that field, whether explicitly listed in the input or not**, while preserving each stored per-field local override. Derived effective settings are not a promise of permanent cache retention: native NGINX eviction/capacity behaviour may change after a validated policy update, but no omitted repository is implicitly disabled, removed or explicitly force-cleaned. Allow only validated per-repository overrides when the packaged NGINX version **and proven isolated zone/path design** support them; otherwise report unsupported capabilities before activation. Storage pressure thresholds and warnings are advisory until #29/#97 implement and test them. `max_size` is not a hard synchronous filesystem quota; `min_free` may be absent on a distribution build. Invalid capability/low-space handling must not silently disable native safe defaults.

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
