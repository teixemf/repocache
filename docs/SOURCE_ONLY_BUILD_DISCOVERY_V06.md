# Source-only candidate build and public discovery (v0.6.0+)

**Status:** PARTIAL / DRAFT / NOT PUBLISHABLE. Issue [#84](https://github.com/teixemf/repocache/issues/84), prerequisite signed staging [#83](https://github.com/teixemf/repocache/issues/83). The branch builds upon [PR #100](https://github.com/teixemf/repocache/pull/100), itself stacked on [#99](https://github.com/teixemf/repocache/pull/99) → [#98](https://github.com/teixemf/repocache/pull/98). The repository still declares v0.4.0; these commands are **synthetic forward-looking interface contracts**, not production release instructions.

## Exact candidate build mode

The historical invocation remains unchanged, including the original signed legacy wheelhouse handoff:

\`\`\`sh
python scripts/build_release.py --tag v0.5.0 --output dist
\`\`\`

A **future, correctly versioned v0.6.0+ checkout** may opt into the source-only layout:

\`\`\`sh
python scripts/build_release.py --tag v0.6.0 --output candidate-dist \
  --online-lock /path/to/reviewed-two-platform-runtime-lock.json \
  --online-sbom /path/to/reviewed-cyclonedx-sbom.json
\`\`\`

Both arguments are required. The command validates the exact project/release-policy version, fixed supported OS/Python targets, permitted first v0.5.0 predecessor, owned source-file allowlist and source-only archive structure. It produces the checksum and two canonical lock/SBOM files **without publishing, signing or generating any third-party wheelhouse**. It includes three new owned runtime modules under \`src/repocache\` only in online mode.

The builder intentionally does not generate a fake signed manifest or invent a lock, its upstream wheel digests, an SBOM or signing key. \`scripts/sign_release.py\` remains a **separate offline privileged publisher operation**. The resulting source-only candidate may then be offered for signing only after its release file inventory and independently resolved full transitive lock/SBOM have been accepted. The draft signer in #99 creates \`assets.json\`, \`manifest.json\` and \`.sig\` only after protected external-key signing.

The resulting proposed public asset names are exactly:

\`\`\`text
repocache-vX.Y.Z.tar.gz
repocache-vX.Y.Z.tar.gz.sha256
repocache-vX.Y.Z.tar.gz.dependency-lock.json
repocache-vX.Y.Z.tar.gz.sbom.json
repocache-vX.Y.Z.tar.gz.assets.json
repocache-vX.Y.Z.tar.gz.manifest.json
repocache-vX.Y.Z.tar.gz.manifest.json.sig
\`\`\`

The immutable v0.4.0 and initial v0.5.0 legacy profile **still require schema-1 signed manifest/policy plus wheelhouse** and cannot be converted to a source-only update by changing file names. The legacy builder remains the default.

## Public discovery is not installation authority

For v0.6.0+ GitHub releases, the read-only anonymous discovery parser recognizes the online layout **only if** all seven exact names, unique positive asset IDs, positive lengths, \`draft=false\`, \`prerelease=false\` and \`immutable=true\` are present. Missing, duplicate, extra and mixed wheelhouse assets cause rejection. The original legacy layout remains discoverable even for later versions, so compatibility is not implicitly removed.

A result has \`dependency_profile_hint=online-hash-locked-wheels\`, \`eligible=false\`, \`compatibility=unknown\` and an explicit warning that the installed updater cannot yet execute it. These are **untrusted GitHub API labels**: a manifest and every asset must still be downloaded and authenticated independently with the owner-provisioned Ed25519 public trust anchor. The existing production updater **continues to refuse schema-2 installations**. The discovery enhancement cannot be used to bypass that guard.

## Outstanding acceptance gate

- Complete per-target direct/transitive wheel lists, stable version/hash provenance, real index URLs/CA/TLS and Python wheel tag verification on Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12: **NOT VERIFIED**.
- End-to-end seven-asset candidate *source ownership* audit for nested third-party code/binaries, consistency of actual \`pyproject.toml\` with the SBOM and exact resolved wheels, immutable release readback and licensing notices: **NOT VERIFIED**.
- Genuine offline owner-signed v0.5.0 bootstrap candidate, v0.6.0 final signed candidate, real machine clean installs/upgrade, CLI/TUI, idempotent same-version repair, interrupted downloads, transactional rootless environment activation, NGINX/SELinux/systemd and rollback: **NOT VERIFIED**.
- Native release-specific pipeline/acceptance workflow and profile-aware updater installation are **NOT IMPLEMENTED**; the legacy wheelchain CI continues as an unchanged regression.
- Independent final #80 architecture review, #98/#99/#100 prerequisite integration, complete acceptance matrices, required GitHub checks/reviews and **explicit user merge/release authorization** are pending.

Never merge or publish based only on green synthetic legacy CI. This PR does not modify a real published release, tag, private key or host configuration.
