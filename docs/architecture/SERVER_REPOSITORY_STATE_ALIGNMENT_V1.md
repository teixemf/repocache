# Declarative repository ↔ protected-state v1 read-only alignment

**Primary issue:** #95 (v0.6.0) · **Related:** #18, #28, #29, #31, #97, #107.

This PR-only proposal defines a **non-authoritative read-only compatibility
check** between validated install-v1 repository entries and the *inert* protected
state-v1 records from #31. It is not an adopted protected-state extension,
a lifecycle writer, an activation interface, or a security approval.

`preview_declarative_state_alignment(current_document, protected_snapshot,
current_generation=...)` checks closed schemas, exact generation agreement,
same stable IDs, SHA-256 of the #208 canonical source/layout identity, and
the same desired-state intent. It refuses mismatched, missing or extra entries.
Caller-supplied snapshots are **not trusted**; equality does not authenticate
OS-owned files or operator approval and is not a concurrency barrier.

The present state-v1 store supports **at most 32** records, while the
install-v1 contract allows **up to 500**; no larger-scale persistent lifecycle
is implemented by this check. The state-v1 format cannot represent historical
ID tombstones, removed repositories or a real observed active/failed state.
Its `configuration_sha256` has no accepted canonical install-document byte
binding at this interface and **is deliberately NOT claimed verified**.

A future reviewed privileged orchestrator must, under one exclusive protected
transaction lock: independently authenticate the administrator's operation;
read a pinned OS-owned state/ownership manifest; reconcile schema capacity,
persistent ID/tombstone reservations and full configuration digest; check
the actual active NGINX files/inodes, DNS/TLS trust and cache ownership;
stage complete generated configuration; run packaged NGINX validation and
controlled reload; publish an atomic active-only catalog; recover consistent
prior exposure on all failures. It must repeat all validation after lock
acquisition and must not treat a preview or a `desired_state=active` as
proof of actual exposure.

No routine here reads or writes protected files, spawns processes, performs
DNS/network calls, grants service-reload/catalog permission or deletes cached
bytes. A normal remove must retain cache data; forced cleanup requires separate
verified ownership and explicit authorization under #29/#95. Policy inheritance
continues to be inspected by the #214 planner; #97 owns eventual native policy
behavior. CLI commands under #107 must consume future authoritative status,
never this untrusted preview as actual state.

## Suggested focused regression

```console
python -m pytest -q tests/test_server_repository_reconcile_v1.py
```

Tests added in this PR cover matching intent, stale generations, malformed
protected schema, mismatched/missing/extra identities, nonmutation and
non-authorizing output. Test presence is NOT executed evidence. Full original
#95 and #31 acceptance, including real native Debian 13/AlmaLinux 10
NGINX/SELinux/cache/recovery and trusted root authorization, remains
**NOT VERIFIED**.


## Inert persistence transition intent (second increment)

`plan_inert_persistence_transition` requires validated #18 current/proposed
documents, an aligned but **untrusted** #31 state-v1 snapshot and exact
generation. It refuses generation exhaustion, new or removed IDs, and changes
to an existing ID's canonical source/layout identity that #31's current writer
cannot preserve. The output describes the closed state-v1 repository ID,
identity and desired-state projection and conservatively identifies IDs whose
changes would require authenticated administrative review, including global
policy changes affecting omitted repositories. Existing inputs are not
mutated. Activation remains separate from intent.

**Crucially, this is not a persisted configuration transaction or a complete
state-v1 record.** Approval references and the `configuration_sha256` binding
are deliberately omitted, preventing the plan itself from being accepted by
`validate_protected_state` as a directly committable state object. It never
calls `_commit_under_root`; that API remains private to #31 Linux FD fixtures.
A focused test explicitly constructs a *synthetic, non-authenticated* complete
state candidate, calls #31's private fixture writer under a disposable root,
observes durable atomic write, clean recovery and stale-CAS refusal. This
proves schema interoperability in the fixture **only**. It does not approve
any existing host write, NGINX activation or real administrative operation.

The next operational development must first agree with the #31 owner on a
protected, canonical and recoverable configuration payload/digest, durable
tombstone history, capacity (install v1 <=500 vs state v1 <=32), and an
authenticated authorizer under the same state lock. An immutable-identity
migration or force-cleanup is separately blocked pending approved ownership
and recovery design. No PR is merge-ready merely because this fixture passes.


## Declarative lifecycle → inert NGINX candidates (#95 with merged #28)

`preview_declarative_nginx_candidate` composes **the existing** validated
#95 transition planner with #28's already merged
`render_repository_nginx_bundle_candidate`. It accepts current and partial
proposed install-v1 configuration, an untrusted inert state-v1 snapshot,
an exact generation, complete candidate DNS pin sets for **every desired-active
repository** (and none for disabled IDs), and a syntactically valid CA path.
The first step freezes validated declarative input, confirms ID/identity/
desired-state alignment and rejects stale generations, source identity
reassignment, missing persistent IDs or invalid partial updates.
The second delegates to #28 for complete public-address pin validation,
host/SNI/TLS-verifying HTTPS fragments, redirect isolation, NGINX ordering
and bounded output. A missing, extra, unsafe or disabled-repository pin fails
the entire candidate, not only the individual route. No DNS lookup occurs.

The output distinguishes **changes in desired intent**, not live service
state: `desired_new_route_ids`, `desired_withdraw_route_ids`, and
`desired_retained_route_ids` describe the candidate diff against the
current untrusted declaration. They do **not** attest that any route currently
exists or will be activated. Normal desired disablement does not clean a
cache. The output contains only proposed NGINX fragments, never a client
discovery artifact. Every state-write, NGINX-activation, catalog and cache
cleanup authorization remains false; no filesystem, network or subprocess
operation is performed by this function. No `nginx -t` or packaged-NGINX
reload has been executed by this pure adapter. A complete managed include
and cache directives remain independent design/testing work.

Before actual apply, the #31 protected owner must independently authenticate
administrator approval, canonical and recoverable install configuration bytes,
generation and all-time ID/tombstone state **under the same native lock**.
The #28 owner must then pin authorised DNS identities, stage a complete managed
include, validate actual packaged NGINX, control reload/exposure/rollback,
and publish an atomic active-only catalog only after successful exposure.
No authority may be inferred from an untrusted candidate, synthetic approval
hash, desired state or CI-green result.

Focused #95+#28 regression command:

```sh
python3 -m pytest -q tests/test_server_repository_reconcile_v1.py
```

Full PR and distro-specific NGINX tests are separate exact-HEAD evidence
requirements. The original #95 operational AC1–AC7 and #28 live activation
acceptance remain NOT VERIFIED by this composition.


## Exact-HEAD native syntax coverage

The existing #28 `.github/workflows/server-nginx-pins-native.yml`
path filters now include the #95 lifecycle reconciler and its tests.
In its Debian 13 and AlmaLinux 10 disposable packaged-NGINX containers, the
workflow invokes the existing strict #28 pin/redirect tests **plus**
`tests/test_server_repository_reconcile_v1.py`. The latter includes a
fixture-only full `nginx -t` for the two-layout declarative composition,
using a private temporary `nginx.conf` and no running service. On a host
without packaged NGINX, that test is explicitly SKIPPED rather than
misrepresented as PASS.

This syntax fixture cannot verify the privileged managed include, complete
cache zones/HIT, authenticated approval, root ownership, actual reload,
operational rollback or client catalog, which remain NOT VERIFIED.


## Explicit add/update/enable/disable/remove → inert NGINX preview

`preview_repository_lifecycle_nginx_candidate` extends the already merged
pure #95 operation planner and #28 strict pinned NGINX candidate adapter to
all five **explicit administrative intents**. It requires the current full
declarative document and an aligned (still untrusted) #31 inert state-v1
snapshot at the exact expected generation. An explicit add requires a
caller-supplied all-time reserved/tombstoned ID snapshot; it is checked but
**never trusted as a durable ledger**. Auto-generated suggestions still
belong to the existing `propose_automatic_repository_id` helper and must be
revalidated and reserved under an independently authenticated writer lock.

The operation produces a validated complete declarative candidate,
re-verifies that retained IDs have unchanged canonical upstream identities,
rejects generation exhaustion and renders exactly its desired-active
repositories through #28's strict IP, Host/SNI, TLS and redirect safeguards.
An invalid, missing or extra pin set fails the *entire* proposal. It reports
only *desired* route deltas, fresh approval requirements and IDs requiring
all-time tombstones when removed. Removal is explicitly **cache-retaining**,
not a cleanup request. A missing-ID remove is idempotent at the pure plan
level. It never confuses successful preview with observed active exposure.

The result is NOT an authenticated command or an acceptable #31 state-v1
candidate: `trusted_id_ledger_verified`, `approval_provenance_verified`,
`configuration_digest_binding_verified`, `active_exposure_verified`,
`cache_ownership_verified` and every state/NGINX/catalog/cache authority
flag remain false. In particular, the currently implemented #31 state-v1
store cannot persist removal tombstones or the full authoritative install
document, and cannot accept the synthetic approval hash as permission.
**No production write, NGINX reload, catalog publication, cache deletion or
privileged CLI invocation is enabled by this helper.**

The #31 owner must version and review the persistent configuration/ID ledger
and authenticated, locked journalled write interface before any operational
connection; #28 must verify real reload/exposure and atomic active-only
catalog. Fixture tests and temporary nginx -t do not demonstrate original
#95 operational acceptance. The tests in this increment cover an explicit
APT add, desired enable/disable, trust-key update, active removal with cache
retention, stale state, all-time ID reuse refusal, forbidden identity
reassignment, unsafe DNS pins, and prohibited host effects.


## Known desired-active configuration changes are not activated exposure

The two inert NGINX adapters now report
`desired_config_revalidation_ids` alongside
`desired_retained_route_ids`. The latter means an ID was desired-active in
both declarations, **not** that its route is unchanged, approved, valid or
live. The new field conservatively identifies a subset of retained
desired-active IDs whose declared effective repository configuration or
deployment configuration changed. In particular, trust-key rotation or
inherited global policy changes require fresh native route validation even
when a repository was omitted from a partial update.

**An empty list is not clearance:** candidate DNS address changes, TLS trust
changes on disk, managed NGINX inode drift, SELinux/ACL state, service failures
and real exposure cannot be determined from two untrusted declarations.
Regardless of this hint, every eventual privileged activation must revalidate
all desired routes and protected state under a single authenticated native
transaction. The fields are diagnostic-only and never authorize NGINX reload
or discovery publication.

## Proposed operator-facing lifecycle and legacy NGINX migration evidence

The following is a non-executable **operational acceptance specification**,
not an implemented CLI, a v2 state schema adoption or an approved migration
tool. An administrator must be able to distinguish:

- **Desired disabled:** retained configuration with no permitted new route or
  discovery entry; any old exposed route must first be withdrawn and verified
  absent, with cache data retained.
- **Desired active, pending validation:** an administrator's requested state,
  NOT a claim of an operating cache. Candidate fragments, public DNS pins and
  a successful disposable `nginx -t` alone must not publish discovery.
- **Verified active (future, not implemented):** status can only be asserted
  after authenticated approval, owned managed-include validation, a successful
  native full-context NGINX syntax check, reload, and proof of actually
  exposed routes. The atomic derived client catalog must reflect only this
  verified subset.
- **Failed or recovery-required (future, not implemented):** do not advertise
  a requested route whose staged change, reload, exposure check or catalog
  transaction failed. Report blocked recovery with preserved known-good
  state and verified rollback evidence rather than silently claiming success.
- **Removed with retained cache:** withdraw route and catalog, persist the
  ID/identity tombstone and retain cached bytes under normal storage rules.
  Explicit forced cleanup is a distinct ownership-verified, authorised action;
  a missing historical ID cannot be silently recycled.

For migration from a previously **operator-managed NGINX frontend**, a
future administrator procedure must first inventory managed and foreign
includes, service/TLS ownership, active client catalog and cache files
without mutation. Fail closed on a foreign/conflicting managed-include path;
do not auto-adopt it, delete unrelated NGINX content, or overwrite TLS keys.
Prepare an isolated managed candidate using the normal #31 transaction
engine, require explicit approved cutover, verify native `nginx -t`, reload,
real route/cache HIT and signed APT/DNF metadata, and only then publish the
new atomic catalog. On failure keep or restore previous known-good exposure
and catalog, preserve retained cache, TLS, logs and metrics, and leave client
APT/DNF sources unchanged. Test idempotent retry and upgrades on booted
Debian 13 and AlmaLinux 10 (including SELinux enforcing where relevant).

This section is a measurable future acceptance checklist, not an assertion
that any of these host-level transitions, persisted states or migration
commands already work. The #31 proposed v2 review-only state contract
(`preview_proposed_v2_state_transition`, existing PR #237) remains
unmerged and non-authorizing; neither that proposal nor this #95 PR
implements its privileged writer, actual observed-state attestation, or
catalog publication.


## Proposed v2 handoff: complete next-generation install intent only

The two non-authorising #95 NGINX preview functions return
`next_generation_configuration_preview` only when they detect a real
declarative change. This is a **complete, validated install-v1 document**
with `expected_state_generation` incremented from the old
`current_generation` to the proposed next generation. It is deliberately
separate from the existing `candidate_document`, which still bears the
old generation for comparison against the untrusted current state and for
the #28 candidate renderer. No-op results return `null`, and generation
exhaustion refuses a changed proposal rather than wrapping.

The proposed/unmerged #31 v2 contract expects canonical full configuration
bytes whose internal expected generation equals the proposed state
generation; this additional pure projection avoids accidentally passing
old-generation declarative input to that contract. It is **not** a
`state_schema_version=2` snapshot, a canonical serialized payload, an
authenticated decision or a persistable record. It intentionally omits
state-v2 reservation history, observed-state evidence, approval reference,
canonical SHA-256 and filesystem/NGINX ownership. The independently trusted
#31 owner must rebuild and revalidate the entire transaction under its own
OS-root-owned lock, including exact v1/v2 migration policy and ID/tombstone
history, rather than accepting this returned object as authority.

Fixture tests cover explicit enable and remove, an idempotent no-op, partial
updates that preserve omitted repositories, generation-exhaustion refusal,
the exact separation between old and new generations, strict install-v1
revalidation, and false mutation/activation/catalog/cleanup permissions.
This does not imply that #31's proposed v2 design has been accepted, or
that persistent v2 interoperation has been executed.
