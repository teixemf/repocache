# ADR 0004: A signed first-party wheel for v0.6.0+

**Decision:** Selected for implementation on 2026-10-23. Security/design review and release acceptance are still required. Related issues: #80, #83, #84, #85, parent #79. This supersedes the earlier PROPOSED seven-asset v0.6.0+ online profile, not any published release.

## Decision and exact public assets

Publish an **original REPOCACHE application wheel** deterministically built from the publisher's owned source, alongside a source TAR. Third-party dependency wheels are never redistributed in the new online profile; they are individually fetched from approved HTTPS origins only by hash-locked, non-root clients.

The v0.6.0+ online profile has **eight** public release assets:

| Role | Exact filename |
| --- | --- |
| Owned source | repocache-vX.Y.Z.tar.gz |
| Source checksum | repocache-vX.Y.Z.tar.gz.sha256 |
| Third-party dependency lock | repocache-vX.Y.Z.tar.gz.dependency-lock.json |
| Third-party SBOM | repocache-vX.Y.Z.tar.gz.sbom.json |
| **First-party application wheel** | repocache_control-X.Y.Z-py3-none-any.whl |
| Authenticated inventory | repocache-vX.Y.Z.tar.gz.assets.json |
| Owner-signed manifest | repocache-vX.Y.Z.tar.gz.manifest.json |
| Detached Ed25519 signature | repocache-vX.Y.Z.tar.gz.manifest.json.sig |

The five primary data assets are recorded by exact name, byte length and SHA-256 in the inventory; its digest is included in the Ed25519-signed manifest, along with the original source archive and third-party lock digests. The manifest and signature themselves are not included in the inventory (no circular hash). The inventory and all referenced bytes MUST be authenticated before any online wheel is downloaded or installed. GitHub release metadata is discovery only, never the publisher trust anchor.

## Why this approach

1. A separately owned wheel allows REPOCACHE CLI/TUI to be installed into an isolated managed venv **without executing unreviewed build hooks on the destination**.
2. The wheel generator uses Python stdlib only, reading strictly reviewed first-party Python files, package metadata and license from the same signed source archive. It generates deterministic wheel member order, timestamps, metadata and RECORD. The verifier regenerates the expected complete wheel bytes and requires an exact match, not just a filename or checksum supplied by the same party.
3. Pure-Python py3-none-any is appropriate only while the first-party package remains pure Python. Any native extension requires a separate reviewed versioned ABI design.
4. This makes a clear distinction between the original REPOCACHE wheel that we own/distribute and Typer, Rich, Textual and transitive upstream wheels that clients retrieve online as pinned bytes.
5. SHA-256 and Ed25519 authenticate exact bytes; they **do not** establish upstream wheel safety, application code quality, legal compliance or complete SBOM provenance. Those remain independent gates.

## Compatibility and trust

- The published v0.4.0 is immutable and recognizes only signed policy/manifest schema 1 and its original wheelhouse.
- The first v0.5.0 MUST still ship signed schema 1 + offline wheelhouse for a bootstrappable v0.4.0 upgrade.
- Only future v0.6.0+ online-profile releases use the new eight-asset scheme and schema-2 signed manifest. Existing upgrader guards MUST continue rejecting schema-2 install until actual lock, application wheel, native install/repair and rollback acceptance all PASS.
- Original application wheel is built at release preparation, with no external build backend run on user systems, and is offline-installed into a new non-root venv after trusted verification. All upstream packages are pinned to reviewed, exact dependency-closure hashes. No runtime pip resolution or latest-version selection.
- Exclusive updater lock, recovery journal, last-known-good environment, NGINX/client configuration and repository fallback must remain functional. Real CLI/TUI smoke and whole-graph dependency proof are mandatory prior to atomic activation.

## Rejected alternatives

- **Seven assets and source TAR only:** no authenticated installable application wheel without build-on-target. Rejected.
- **Embed executable wheel inside source TAR:** obscures executable/provenance distinction and source audit. Rejected.
- **Redistribute upstream wheelhouse:** conflicts with online-profile goal; retained solely for immutable legacy and first v0.5.0 transition.
- **Execute setuptools/build isolation or pip install from application source on managed server:** unreviewed build backend and dependency exposure. Rejected.

## Remaining acceptance blockers

Canonical builder/verifier and synthetic CI evidence are implementation evidence, not proof of actual publisher-signed native releases. Real direct/transitive wheel closures for Debian13/Python3.13 and AlmaLinux10/Python3.12, application wheel offline pip smoke, trusted source provenance and licensing, real final v0.5.0 to v0.6.0 transition, signed public eight-asset publication/readback, SELinux/systemd and transactional CLI/TUI activation/recovery must be proved independently. Every relevant criterion needs a PASS with reproducible evidence. NOT VERIFIED or failed checks block merge. Require independent security review and explicit maintainer authorization for merges/releases.

**This design decision does not authorize a merge, release or production modification.**
