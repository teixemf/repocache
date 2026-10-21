# Signed offline dependency-profile bridge (v0.5.0 design)

**Status:** PARTIAL IMPLEMENTATION / NOT RELEASE-ACCEPTED — [#82](https://github.com/teixemf/repocache/issues/82), parent [#79](https://github.com/teixemf/repocache/issues/79). This is an additive transition mechanism, not online dependency installation. No release, merge or production activation is authorized.

## Compatibility contracts

The immutable v0.4.0 publisher manifest, signed eight-asset wheelhouse, installed runtime and pinned public Ed25519 anchor are **unchanged**. The implementation supports two strictly delimited policy formats:

| Compatibility policy | Allowed application version | Authenticated dependency profile | Install transport |
| --- | --- | --- | --- |
| `schema: 1` | Existing versions, including v0.4.0 | Implicit `legacy-offline-wheelhouse` | Authenticated offline hash-pinned wheelhouse only |
| `schema: 2` | v0.6.0 or newer, after a schema-1 v0.5.0 bridge | Required exact string `legacy-offline-wheelhouse` | Same authenticated offline wheelhouse, **not** PyPI |
| Future online profile | Not yet supported | `online-hash-locked-wheels` | **Fail closed** pending #83/#84 |

The normal release manifest still uses its original **Ed25519 signed schema 1** with `archive_sha256`, `policy_sha256` and `wheelhouse_sha256`. A future schema-2 compatibility policy is bound by the already-authenticated signed `policy_sha256`; it **does not** create a second unsigned trust root.

The release builder rejects new unsigned/unknown policy profile values. The actual upgrader validates the complete schema and explicit allowlists after signature, wheelhouse digest and source archive authentication. Unknown or premature future online profile values are rejected before any supplied source is installed; there is **no** fallback that treats these as legacy or contacts an unapproved index.

**Critical bootstrap invariant:** the immutable v0.4.0 updater rejects policy schema 2. Therefore the **first v0.5.0 release MUST still use signed policy schema 1** with explicit v0.4.0 in `compatible_from` and the original offline wheelhouse. Only a successfully installed v0.5.0 runtime can recognize schema 2 in a subsequent **v0.6.0+** release. Synthetic fixtures cannot prove actual owner-signed migration.

### Example post-bridge v0.6+ legacy-profile policy (illustrative only)

```json
{
  "schema": 2,
  "version": "0.6.0",
  "python_min": "3.12",
  "python_max_exclusive": "3.14",
  "targets": [
    {"id": "debian", "major": "13"},
    {"id": "almalinux", "major": "10"}
  ],
  "compatible_from": ["0.5.0"],
  "downgrade_from": [],
  "config_schema": 1,
  "api_schema": 1,
  "dependency_profile": "legacy-offline-wheelhouse"
}
```

This is not a signed actual publisher release. This is **not** an acceptable v0.5.0 release policy: the first v0.5.0 remains schema 1. The unchanged v0.4.0 release is immutable. Future online/source-only profile semantics must be designed separately under #83/#84.

## Trust and failure boundaries

1. Authenticate the source release manifest with an independently provisioned publisher key **before extraction/execution**; GitHub SHA-256 alone is not publisher identity.
2. Verify the source archive hash, signed policy hash and wheelhouse hash, then unpack only the fixed allowlisted regular-file archive layout. Duplicate/extra policy keys, unknown profiles and schema/version mismatches are errors.
3. Check native OS/Python/compatibility and previous installed release policy. Downgrade from a future online-profile runtime to an older wheelhouse profile is blocked pending an independently reviewed migration contract (#10/#84), even if old version numbers appear in a downgrade allowlist.
4. Under the legacy profile, reuse the original non-root, exclusive updater transaction: exact authenticated, hash-pinned wheels; fresh per-run venv; `pip check`, CLI version test, staged atomic activation, journal recovery and rollback.
5. No PyPI network call, global pip mutation, trust-on-first-use or modification of NGINX, certificates, cached data, client APT/DNF sources or publisher private keys is authorized by this issue.

## Tests and remaining acceptance

`tests/test_dependency_profile_bridge.py` covers strict schema/profile/version checks, v0.4.0 schema preservation, explicit predecessor allowlists, refusal of online/unknown profile, inadmissible downgrade, actual ephemeral Ed25519 verification of synthetic **v0.6.0 post-bridge** archive/policy/wheelhouse identity, altered signed policy digest and rejection before installer invocation. Existing CI/real signed legacy tests remain the regressions of record.

**Synthetic test trust limitation:** Tests stub the wheelhouse installation and service-account environment to avoid privileged live-host installation. They validate signature/authenticated-profile dispatch and rejection, **not** actual v0.5.0 publisher signature, native systemd/SELinux, online wheel download or end-to-end migration. All real publisher-key release candidate tests stay mandatory under [#76](https://github.com/teixemf/repocache/issues/76), [#78](https://github.com/teixemf/repocache/issues/78) and [PR #77](https://github.com/teixemf/repocache/pull/77).

Before declaring #82 complete:

- [ ] Approve [#80](https://github.com/teixemf/repocache/issues/80) ADR (currently a draft proposal) and freeze signed dependency-profile schema/compatibility semantics; revise this staging implementation if the approved design differs.
- [ ] Build and externally owner-sign an actual v0.5.0 legacy-profile candidate, with exact eight release assets and a genuine v0.4.0 predecessor installation.
- [ ] Verify authentic native Debian 13/Python3.13 and AlmaLinux10/Python3.12 upgrade/repair/rollback and failure injection, including unavailable/corrupted wheels, signatures, interruption/concurrency, permissions, NGINX/TLS/cache/APT/DNF preservation, using #76's independent gate.
- [ ] Review repeated same-version repair, invalid/downgrade compatibility, and persistent-state safety separately (#10/#53).
- [ ] Integrate future versioned asset/provenance schema and signed online locks only under #83/#84, with their own reviewed release/CI acceptance evidence.
- [ ] All acceptance criteria PASS, required protected-branch reviews/CI green, and explicit maintainer merge authorization.

This document distinguishes implementation that can be unit tested from unverified release/operational proof.
