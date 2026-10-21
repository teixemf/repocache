# Signed dependency-profile bridge: v0.5.0 engineering contract

**Status:** INITIAL IMPLEMENTATION / NOT ACCEPTED. Tracking [#82](https://github.com/teixemf/repocache/issues/82), parent [#79](https://github.com/teixemf/repocache/issues/79), design [#80](https://github.com/teixemf/repocache/issues/80), online installation [#83](https://github.com/teixemf/repocache/issues/83), release profile [#84](https://github.com/teixemf/repocache/issues/84). This is **not** a published v0.5.0 release candidate and is not permission to install third-party packages online.

## Why a bridge is required

Immutable v0.4.0 accepts **only** genuine owner-signed legacy source + hash-pinned wheelhouse bundles. It authenticates the schema-1 release manifest and an exact release-policy schema-1 structure, and GitHub discovery recognizes the legacy wheelhouse asset set. Replacing published dependency wheels with PyPI downloads in a single step would strand v0.4.0 installations.

Therefore the proposed **v0.5.0 bridge itself MUST still use the unchanged schema-1, signed offline-wheelhouse release profile**, with a signed compatibility policy expressly permitting upgrade from v0.4.0. The current repository still declares v0.4.0 and `compatible_from: []`; this PR does not invent or modify a signed v0.5.0 candidate. Real acceptance of v0.4.0 -> v0.5.0 is separately required by #76/#78 and the owner-signed draft acceptance workflow.

## Implemented in the initial #82 draft

- `signatures._parse` accepts the **existing schema 1 without any field changes**. It also recognizes an explicitly versioned **schema 2** detached Ed25519 manifest envelope with exact additional fields:
  - `dependency_profile`: `legacy-offline-wheelhouse` or `online-hash-locked-wheels`.
  - `dependency_lock_sha256`: required SHA-256 for online; exactly `null` for legacy.
  - `asset_inventory_sha256`: required exact lowercase SHA-256 syntax for both schema-2 profiles.
  - Existing signed `wheelhouse_sha256`: required for schema-2 legacy and exactly `null` for schema-2 online.
- Reject unknown profiles, extra/missing fields, duplicate JSON keys, invalid type/hash/profile combinations and any attempted mixing of schema-1 and schema-2 syntax. The real detached Ed25519 signature must authenticate **every** schema-2 field; no unsigned compatibility fallback.
- The current production updater **accepts only schema 1 for installation**, rejecting every schema-2 profile immediately after verifying its real signature and archive digest, **before checksum interpretation, archive extraction, virtualenv creation or pip execution**. This deliberate gate is required while #83/#84 do not implement online lock/index/asset-inventory validation.
- The existing schema-1 bundle, signature validation, immutable release metadata, client/CLI/TUI commands, NGINX, TLS, cache, native package manager and rootless journaling paths are unchanged.
- Tests use ephemeral, disposable Ed25519 keys and synthetic assets; **no real publisher private key is introduced**.

## Do not conflate recognition with installation support

A signed schema-2 envelope containing `dependency_lock_sha256` and `asset_inventory_sha256` binds their claimed hashes, but **does not authenticate the actual assets unless those bytes are separately verified**. The current code deliberately refuses to install such a release. The current `releases.discover` still requires legacy wheelhouse assets, and `upgrade.RELEASE_FILES` and `scripts/build_release.py` still enforce the legacy source archive layout. This is intentional for v0.5.0; do NOT describe new-profile publishing or migration as complete.

**Next required work**, subject to an approved #80 manifest contract:
1. Add signature-verified, profile-specific release asset enumeration in #84; download **only** trusted asset IDs, size-check, compute actual `asset_inventory_sha256` against the signed digest and authenticate complete per-target dependency lock contents. Never treat a GitHub tag, checksum or unsigned asset list as a trust anchor.
2. Add safe online installer in #83 that downloads exact reviewed binary wheels under sanitized non-root environment, checks per-target hashes, rejects source builds, validates installed CLI and TUI and keeps a working prior generation on failures.
3. Prove complete, *real signed* v0.4.0 -> v0.5.0 bridge -> v0.6.0 new-profile update, recovery, failure injection and any explicitly supported downgrade direction on native disposable Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12. Do not claim availability solely from this synthetic test module.
4. Extend the release candidate acceptance in #76/#78/PR #77 with versioned schema-2 handling under #84 without weakening the **eight-asset** legacy profile gate or moving the publisher private Ed25519 key into CI.

## Trust-boundary and rollback notes

- Root-owned publisher public keys and existing signature verification remain the entry gate. The private signing key never belongs in a generated release, PR, CI secret or ephemeral test checkout.
- The existing updater lock and journal protect staged activation and rollback; this PR does not change their algorithms. Recognized-but-unsupported profiles fail before touching the active environment. Rootless checks remain in effect.
- The v0.4.0 updater does not know schema 2, and must never be modified to accept it. A v0.5.0 bridge signed under schema 1 makes the next format transition possible *only after* its own later release-code implementation is tested.
- Reusing current `--wheelhouse` / `--bundle` CLI flags to perform unsigned online downloads is forbidden; no API or undocumented fallback is added here.
- Any rollback involving persistent data schema changes must satisfy #10, not just replace a venv symlink. Future installed-runtime tamper detection is separately scoped to #53.

## Initial acceptance matrix

| #82 criterion | Status | Evidence / blocker |
| --- | --- | --- |
| Real published v0.4.0 -> owner-signed v0.5.0 candidate | NOT VERIFIED | Real approved, signed v0.5.0 not yet staged; #76/#78 gates |
| Reject altered/ambiguous/unknown future profiles before execution | Tests added; execution pending | `tests/test_dependency_profile_bridge_v05.py`: true Ed25519 signatures, missing/extra/mutated fields, inactive schema-2 gate |
| Legacy schema-1 updates, same-version repair, rollback, interrupted network preserve prior | NOT VERIFIED on new head until CI | Existing native offline fixtures and updater journal regressions must rerun |
| Preserve new candidate acceptance #76/#78 and PR #77 | REVIEW ONLY | Schema 1 unchanged; exact-head diff and signed-candidate runs still required |
| Complete future profile installation | NOT IMPLEMENTED, not part of #82 initial draft | #83/#84 |
| Documentation and per-criterion verification | PARTIAL | This document, individual CI logs and release-candidate proof pending |
| Review / merge authorisation | NOT VERIFIED | Remain draft; explicit maintainer approval required |

Even if the PR's test suite is green, **#82 must not be closed as accepted** until its real v0.4.0 -> v0.5.0 owner-signed transition and other complete original criteria are verified.
