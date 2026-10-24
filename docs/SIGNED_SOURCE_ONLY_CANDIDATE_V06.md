# Source-only candidate authenticity — v0.6.0+ proposal (#84)

**Status: PARTIAL IMPLEMENTATION / UNWIRED / NOT READY TO MERGE OR PUBLISH.** This branch is stacked on the independently reviewed but unmerged [#82 integration PR #98](https://github.com/teixemf/repocache/pull/98). Source-only release architecture is proposed under [#80](https://github.com/teixemf/repocache/issues/80), with non-root wheel staging under [#83](https://github.com/teixemf/repocache/issues/83). The immutable public v0.4.0 and mandatory signed **schema-1 v0.5.0** bridge are not modified.

## Candidate format

The offline publisher signs a **v0.6.0+ schema-2** Ed25519 manifest containing `dependency_profile=online-hash-locked-wheels`, `dependency_lock_sha256`, `asset_inventory_sha256`, and `wheelhouse_sha256=null`. The manifest also binds release version/commit, original source archive and compatibility policy hashes, validity times, key ID and official repository. No signing key enters Actions.

The proposed source-only candidate input inventory contains exactly these **four signed-by-inventory assets** (in addition to the inventory JSON itself, detached manifest and detached signature):

| Role | On-disk filename | Purpose |
| --- | --- | --- |
| `archive` | `repocache-vX.Y.Z.tar.gz` | Original REPOCACHE release source; tar member audit |
| `checksum` | `repocache-vX.Y.Z.tar.gz.sha256` | Exact SHA-256 and filename of source |
| `dependency_lock` | `repocache-vX.Y.Z.tar.gz.dependency-lock.json` | Two-profile package closure intended for Debian13/Python3.13 and Alma10/Python3.12 |
| `sbom` | `repocache-vX.Y.Z.tar.gz.sbom.json` | External dependency CycloneDX inventory |

The exact deterministic `repocache-vX.Y.Z.tar.gz.assets.json` inventory is additionally bound by the detached offline owner Ed25519 signature of the final `repocache-vX.Y.Z.tar.gz.manifest.json`; the detached signature is `.manifest.json.sig`. **No circular hashing** of the signature or manifest occurs. Final publication must verify exactly the intended **seven** candidate asset names (four listed, inventory, manifest, signature), sizes, public asset identity and immutable release metadata before upload; the code here does not publish, enumerate GitHub uploads, or assert that all candidate bytes are ready.

## Trust boundaries and usage

- `release_inventory.build_inventory(version, assets)` rejects unexpected roles/filenames, checksum disagreement, non-regular source TAR members, traversal, obvious .whl/native binary payloads, incompatible schema/version and missing platform closures. It emits deterministic JSON for **offline human-controlled signing**.
- `scripts/sign_release.py` retains its historic schema-1 behavior. With `--online-lock` and `--online-sbom` together, it creates a schema-2 manifest (version 0.6+ only), signed inventory and detached signature, using a protected external private Ed25519 key. It must not be invoked automatically by GitHub Actions or receive that private key in CI.
- `release_inventory.verify_signed_candidate(...)` first invokes `signatures.verify` with the independently administered trusted public key, authenticating the exact manifest and source bytes **before interpreting candidate metadata**. Then it matches actual source, checksum, runtime lock and SBOM bytes to the authenticated inventory. Never call the lower-level `verify_bound_assets` with unverified metadata received from JSON, a GitHub release, a CLI flag or the lock itself.
- The returned lock bytes can eventually be sent, with the verified `dependency_lock_sha256`, to #83's strict `online_deps.parse_verified_lock` *only after the trusted #84 updater has been integrated and explicitly release-gated*. This branch makes **no** network requests, stages no third-party wheels and does not activate a venv; the existing updater continues to refuse all schema-2 installs.
- Initial source-only scanning rejects obvious embedded .whl/.so/.pyd/.dll/executables, nonregular or duplicate TAR members and ZIP/ELF payloads. **It is not an exhaustive embedded-content, nested-archive, origin or licensing audit.** The final publishing gate must inventory all candidate files, ensure original code ownership, forbid transitive upstream redistribution, prove SBOM/lock/pip dependency graph equivalence and check actual exact wheel tags and indexes.

## Acceptance matrix: this first engineering tranche

- [ ] Parser/signer regression PASS on exact head with ephemeral Ed25519 private keys and both supported CPython versions, including tampered manifest/asset/inventory, refusal of prior versions and bundled wheel/TAR attacks.
- [ ] All current protected-branch legacy test contexts PASS, including signed v0.4.0 source + offline wheelchain, Debian13/Alma10 synthetic rootless recovery and mandatory security suites.
- [ ] Full source-only provenance audit of actual v0.6.0 owner-authored release files: **NOT VERIFIED**; this module only checks obvious dangerous payload forms.
- [ ] Real release-appropriate dependency locks/SBOMs, exact transitive closure and PyPI URL/cert/ABI availability for both Linux targets: **NOT VERIFIED** (#80/#81/#83).
- [ ] Publisher-signed final **real** v0.5.0 schema-1 predecessor, real final v0.6.0 signed source-only candidate, clean install, upgrade, repair and rollback on native Debian13/Alma10: **NOT VERIFIED** (#76/#78/#84/#85).
- [ ] Final reviewed #80 schema, #82 integration, controlled `releases.discover` profile-specific asset lookup, `updater` transaction integration, explicit owner merge + separate release/publication authorization: **NOT VERIFIED**.

A successful synthetic signature/asset test is **not** full #84 acceptance. Leave issue #84 and this PR open/draft. Never merge or publish on the strength of the first tranche.
