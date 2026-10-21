# v0.5.0 dependency profile: backward-compatible bridge (#82)

**Status: IMPLEMENTED IN PART / NOT VERIFIED FOR REAL SIGNED v0.5.0.**
This document describes the initial fail-closed compatibility boundary only.
It is not authorization to publish a v0.5.0 release, activate new services, or
switch to an online package index.

## Compatibility invariant

The already published immutable v0.4.0 updater recognizes **only** a schema-1
Ed25519-signed release manifest, schema-1 signed compatibility policy, and
a SHA-256-bound offline wheelhouse. The v0.5.0 *transition release* therefore
**must preserve the schema-1 envelope and legacy wheelhouse format**. A direct
v0.4.0 -> source-only online release is not supported by the old updater.

| Installed release | Candidate | Required profile | Decision |
| --- | --- | --- | --- |
| v0.4.0 | v0.5.0 (future genuine signed candidate) | legacy signed offline wheelhouse, schema 1 | Eligible **only if** authenticated compatibility policy explicitly allows `0.4.0`; actual signed candidate acceptance NOT VERIFIED |
| v0.4.0 | v0.4.0 exact same-version repair | legacy signed offline wheelhouse | Authenticated identity and fresh generation required; existing protections unchanged |
| v0.4.0 | unknown or unsigned future profile | none | Reject before activation |
| v0.5.0 | v0.6.0 online profile | future signed profile schema, release-approved hashes, online resolver | **Disabled in this PR**; implementation #83 and publisher/candidate gate #84 required |
| v0.5.0 | v0.4.0 downgrade | legacy | Reject unless **both** policies and persistent-state compatibility permit; do not infer downgrade safety |
| Unknown/malformed installed profile | any | none | Reject, not assumed to be offline legacy |

## What changed in the initial implementation

- `updater.LEGACY_DEPENDENCY_PROFILE` identifies `legacy-offline-wheelhouse`. A missing installed-manifest marker is interpreted as that *existing* historical profile only; any explicit unknown/malformed marker is rejected.
- `upgrade._verified_dependency_profile` executes after the official Ed25519 manifest verifier and the source policy SHA-256 check. It accepts only the reviewed schema-1 envelope, exact legacy policy keys and a 64-hex signed wheelhouse digest. It **does not** invent a new signed manifest field, change the publisher's trust anchor or permit online dependencies.
- The verified release's installed manifest records the legacy profile as part of `release_identity`. Same-version repair continues to rebuild a new generation, never trust the existing venv, and validate the signed source/wheels.
- `updater._install_source_locked` explicitly refuses attempts to select any future profile before creating a venv or running pip. The preexisting no-network, signed-wheelhouse and rootless safeguards remain mandatory.
- Additional regression tests cover supported v0.5.0 schema-1 *synthetic* policy compatibility, invalid or unapproved profile schemas, unknown installed markers, and fail-closed future profile refusal before mutation.

### Why no new policy schema is published in v0.5.0

Even a correctly Ed25519-signed schema-2 compatibility policy would be rejected
by the already published v0.4.0 updater. Changing the schema in a purported
v0.5.0 transition release would strand real v0.4.0 installations. The future
source-only release needs its own authenticated manifest/profile schema and
asset inventory, separately designed and exercised in #83/#84. In particular,
the v0.5.0 release-acceptance infrastructure (#76/#78, draft PR #77) may keep
its exact eight-asset signed wheelhouse gate; **do not** reuse it as proof that
the later online profile works.

## Security / operations limitations

- These changes **do not** validate an owner-signed real v0.5.0 artifact,
  publish anything or guarantee the existence of a v0.5.0 upgrade route.
  The compatibility allowlist, real publisher manifest signatures, source
  commit and wheel hashes need a separate owner-signed Release Candidate.
- No dependency is fetched from PyPI in this implementation. Online
  download origin/TLS/proxy policy, dependency hash lock, ABI matrix, no
  source builds, and fail-safe network acquisition remain for #83.
- No installed-file independent integrity attestation or proof of safe
  persistent-schema downgrade is implied. Follow-up #53/#10 remain active.
- CI running inside disposable native-container jobs is **not** real systemd,
  enforcing SELinux on an installed host, or power-loss fault injection.

## Outstanding acceptance / next work

- [ ] Agree the final online profile/schema under ADR #80, without changing v0.5.0's legacy bootstrap envelope.
- [ ] Preserve release/archive asset inventory and exact signed source/profile identity under #84.
- [ ] Build an authentic owner-signed v0.5.0 Release Candidate; prove real
  v0.4.0 -> v0.5.0 upgrade, repair, rollback and negative paths on Debian 13
  and AlmaLinux 10 through #76/#78; do not accept fixture signatures.
- [ ] Implement a dedicated, signed online lock/installer under #83,
  and verify the full source-only v0.6.0 profile with separately approved
  native candidate acceptance in #84/#85.
- [ ] Review exact PR head, all required CI job results, branch protection,
  security findings and issue acceptance before requesting merge approval.

**Do not merge or publish** based on these planning and unit tests alone.
