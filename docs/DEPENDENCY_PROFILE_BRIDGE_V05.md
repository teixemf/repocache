# Consolidated signed dependency-profile bridge — issue #82

**Status: DRAFT / PARTIAL — NOT RELEASE ACCEPTED.** This branch consolidates the overlapping implementations in [PR #89](https://github.com/teixemf/repocache/pull/89), [PR #90](https://github.com/teixemf/repocache/pull/90) and [PR #91](https://github.com/teixemf/repocache/pull/91). Architecture issue [#80](https://github.com/teixemf/repocache/issues/80) and [draft PR #86](https://github.com/teixemf/repocache/pull/86) define the future online-profile contract. No merge, release, signing, live host mutation or PyPI install is authorized.

## Non-negotiable bootstrap order

1. **Immutable published v0.4.0** understands only manifest schema 1 + compatibility policy schema 1 + owner-signed offline wheelhouse. It must not be modified.
2. **First v0.5.0 transition candidate MUST publish the same schema 1 formats, with explicit `compatible_from: ["0.4.0"]` and real signed wheelhouse assets.** No schema 2 / source-only bundle can bootstrap the v0.4.0 updater.
3. After an owner-signed v0.5.0 transition is actually installed, the upgraded code may *recognize but refuse to install* a future schema-2 signed envelope for v0.6.0+. Reject an online profile before release-source archive extraction, third-party code execution or any new environment activation.
4. Later [#83](https://github.com/teixemf/repocache/issues/83)/[#84](https://github.com/teixemf/repocache/issues/84) must extend this in a new PR with independently verified profile-specific release assets, wheelhouse-free packaging, exact locks/hashes/approved URL policy and native transactional install/rollback. Recognition of signed fields alone is **not authorization** to use upstream wheels.

## Conflict disposition

| Prior draft | Retained in consolidated branch | Deferred or rejected |
| --- | --- | --- |
| #89 signed envelope | Strict schema 1 compatibility plus bounded schema-2 `dependency_profile`, `dependency_lock_sha256`, `asset_inventory_sha256`; duplicate/unknown/type/hash and contradictory legacy/online records rejected; real Ed25519 tests; early installation refusal | No new profile fetch or activation; field names provisional until #80/#84 is approved. Explicitly refuse schema 2 for versions before v0.6.0. |
| #91 legacy installed identity | `LEGACY_DEPENDENCY_PROFILE`; absent marker in *old* installed manifests maps to historical legacy mode; explicitly unknown/online marker fails closed; verified offline signed profile marked on newly installed generation; non-root update still requires signed wheelhouse | Installed manifest marker is service-writable metadata and **not** a trust anchor for authorization. No online install. |
| #90 builder/compatibility policy | Preserve its critical bootstrap invariant and tests: v0.4.0→v0.5.0 must remain **schema 1**. Legacy code still rejects unknown policy fields/versions. | **Do not take its compatibility-policy schema-2 acceptance yet.** That would suggest a partially installable schema-2 legacy format while the unified updater deliberately refuses all schema-2 installs. The source builder already requires schema 1, so no schema-2 builder change is justified before #84. |

The first two test modules remain separate and traceable rather than overwriting identically named tests from the competing PRs. The existing v0.4.0 application updater, `releases.discover`, `release-policy.json`, `scripts/build_release.py`, signing scripts, CI workflows, CLI/TUI and NGINX bootstrap are unchanged by this proposed integration.

## Signed envelope, trust and recovery

- The existing original owner-provisioned Ed25519 key is the **only** publisher trust anchor. Strict schema-2 parsing is part of `signatures.verify()` and requires a valid signature before returned metadata is considered authenticated.
- The speculative schema 2 does not validate an asset inventory or online dependency lock merely by storing its digest. A later trusted updater must fetch the bytes, verify signed digests/format and reject unsupported index/network policy **before** processing or executing any wheel.
- The upgrader refuses schema-2 installation immediately after authenticating the manifest and source bytes, before archive extraction or new venv. The historical signed wheelhouse code path and its same-version identity checks remain intact for schema 1.
- The installed profile marker is recorded only after signed source/wheelhouse verification. Old manifests without the field are legacy; anything else is rejected unless explicitly supported by a *future* authenticated release profile implementation. It is not evidence of installed executable integrity (see #53).
- Any real downgrade to an older application/runtime version must additionally pass compatibility and persistent-state gates (#10). A signed manifest is not proof a downgrade is safe.
- A new schema-2 envelope is only accepted for **v0.6.0+**; pre-v0.6.0 formats require unchanged schema 1 even if synthetically signed with an ephemeral key.

## Validation and release blockers

- Tests exercise native-target compatibility-policy fixtures, malformed/ambiguous installed manifests, disallowed profile flags, real ephemeral Ed25519 signed-envelope tampering, unknown/contradictory profiles, schema-2 refusal before extraction/install, and the original no-network update gates. **These are synthetic fixtures, not owner-key final release artifacts**.
- Required exact-head CI must show all nine jobs PASS (Python 3.12/3.13, Debian 13, AlmaLinux 10, signed offline wheelchain, rootless rollback), with actual log evidence. One test's mere presence is not PASS.
- A **genuine final owner-signed v0.5.0 release candidate** must be prepared through the existing gated [#76](https://github.com/teixemf/repocache/issues/76)/[#78](https://github.com/teixemf/repocache/issues/78)/[PR #77](https://github.com/teixemf/repocache/pull/77) workflow, then native real v0.4.0 upgrade, same-version repair, interruption/rollback and host-configuration preservation verified. Until this happens, #82's real upgrade criterion is **NOT VERIFIED**, not PASS.
- An accepted #80 design review must resolve any remaining schema-2 field naming and source-only asset envelope before merging profile-format code. Tests and CI must be revalidated after changes, reviews and branch-base updates.
- Do not close or merge the overlapping #89/#90/#91 PRs until the single integration diff is reviewed and the exact disposition is recorded. No merges without explicit maintainer authorization.

**Result:** one coherent, fail-closed review branch; future profile installation and the genuine signed candidate remain separate blocked delivery stages.
