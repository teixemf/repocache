# Publisher-authenticated dependency preparation — proposed v0.6.0 contract

**Status:** DRAFT / UNWIRED. Implementation issues [#83](https://github.com/teixemf/repocache/issues/83) and [#84](https://github.com/teixemf/repocache/issues/84), security/design review [#80](https://github.com/teixemf/repocache/issues/80). This branch is stacked on [PR #99](https://github.com/teixemf/repocache/pull/99), which itself depends on [PR #98](https://github.com/teixemf/repocache/pull/98). It incorporates the original standalone source of [PR #93](https://github.com/teixemf/repocache/pull/93) and does **not** supersede its acceptance gates or authorize independent merges.

## Single authenticated path

```text
caller-supplied candidate bytes (untrusted)
    |
    v
signatures.verify() -- independently provisioned Ed25519 key; exact source digest
    |
    v
release_inventory.verify_bound_assets() -- signed inventory, lock, SBOM, source
    |
    v
signed_dependency_staging._validate_compatibility_policy()
    -- extract bounded original release-policy.json from authenticated archive
    -- verify its exact publisher-signed policy_sha256, supported schema/versions/OS
    |
    v
signed_dependency_staging._validate_sbom()
    -- both strict platform-specific pinned direct/transitive lock inventories
    -- SBOM component name/version closure must match union of locked packages
    |
    v
online_deps.parse_verified_lock(raw, signed["dependency_lock_sha256"], target)
    -- select exact target, validate each pinned wheel URL/version/hash
    |
    v
online_deps.stage_wheels() -- non-root only; private fresh directory;
                              bounded, no-proxy/no-redirect TLS transport;
                              exact byte sha256 + wheel archive inspection
    |
    v
private, signed-hash-locked offline wheel inventory; **STOP**
    -- no pip, no app execution, no venv activation or production updater wiring
```

`signed_dependency_staging.verified_candidate_wheels` is a **read-only** gate with **no network effects** and does not allow the caller to pass an independent lock hash. `stage_signed_candidate` adds a network-staging step only after that gate passes. A caller must provide candidate bytes in the seven-asset proposal and a preselected fixed target and administratively approved CA trust path. The old production updater remains fail-closed for schema 2.

## Explicit constraints and remaining threats

- **Bootstrap:** public v0.4.0 and the first v0.5.0 transition continue to use schema 1 and the genuine signed offline wheelhouse. All currently published assets stay immutable.
- **Release authority:** only the existing external publisher trust anchor authenticates new online profiles. A signature validates authorship of metadata, **not** that the signed upstream dependencies are trustworthy or that all code in a source archive is original. Release-specific adversarial review and provenance required.
- **Dependency policy:** this first staged integration supports the conservative v0.6.0 compatibility policy with exactly Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12, and an explicit predecessor v0.5.0. Other versions and migration profiles need reviewed rules, not arbitrary operator overrides.
- **SBOM closure:** package name/version sets must match both strict per-target JSON inventories; this catches omitted and additional components. **It does not prove the dependency solver's actual complete direct+transitive closure**, wheel ABI compatibility or provider provenance. The lock must eventually be checked against independently resolved, reviewed `pyproject.toml` and platform wheel metadata in native test environments.
- **Privilege/environment:** `online_deps.stage_wheels` requires a non-root user, private owner-controlled parent and explicit CA file and never invokes pip; however, the module is not yet transaction-locked or integrated into systemd runtime ownership. Its trust-boundary contract MUST be enforced by the final updater; don't call it as arbitrary privileged code.
- **Source-only archives:** an obvious-binary/symlink/TAR-path scanner exists in #99, but is NOT the comprehensive release ownership/third-party redistribution audit required by #84. Do not release until nested payload and exact allowed source-set scanning is implemented and verified.
- **Actual online I/O:** the new combined tests use genuine ephemeral Ed25519/OpenSSL operations and fake upstream/staging hooks. No real PyPI, CDN, CA-proxy, native installation or rollback path is tested here. That is a **NOT VERIFIED** acceptance blocker, not a PASS.
- **CLI/TUI:** preserve `repocache update list`, approved `repocache-client` verbs, Typer/Rich/Textual, script-friendly command behavior and recoverable activation. Integration acceptance requires exact version/JSON/headless TUI smoke and real native Debian 13/AlmaLinux 10 install/repair/failover evidence (#85).
- **Owner signature:** this code does not use or require the private publisher signing key; only tests' disposable Ed25519 keys. An actual published owner-signed v0.5.0 bridge and a real source-only v0.6.0 candidate are pending (#76/#78/#84).

## Conflict resolution and future integration

The branch **copies** #93's strict staging module and its tests, rather than modifying #93's existing draft in place, to form a complete reviewable chain with #99's signed inventory. **Do not merge both copies into `main` independently.** When approvals allow integration, review the combined diff against exact upstream heads, choose one approved implementation, and close redundant PRs after final disposition. #98 remains the prerequisite signed-envelope bridge and #86 remains the proposed architecture contract.

Required next engineering tranche: authenticated release asset discovery/download with a bounded, exact **seven-asset** source-only release profile; native and source-only build layout; verified complete lock/SBOM; user-owned transactional venv execution and rollback; owner-signed release candidate with explicit #76/#78 gates. No merges/releases/production activations approved by this draft.
