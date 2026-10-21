# Release acceptance: candidate gates and published smoke

This policy applies to subsequent releases. First-public v0.4.0 is special:
there was no earlier public REPOCACHE distribution against which the public
update and installation pipeline could be tested. This is not permission to
publish future releases before exercising their signed installers.

## Stage A: release candidate (prepublication, mandatory for v0.5.0 onward)

1. Freeze the reviewed commit, compatibility policy and dependencies. Test
   an upgrade from the most recent already published stable version.
2. Produce reproducible candidate source archive and offline wheelhouse.
   Authenticate the exact FINAL candidate with the genuine offline publisher
   signature and an independently provisioned trust anchor, not a disposable
   CI signing key. Never place the signing private key in GitHub Actions.
3. Before extracting or running candidate code, verify signatures, source
   digest, signed policy, runtime wheelchain hashes, SBOM and lockfile.
4. On disposable Debian 13 / Python 3.13 and AlmaLinux 10 / Python 3.12
   systems: clean install, upgrade from the prior public stable, selected
   version, same-version repair, rootless privileges, journal recovery,
   rollback, concurrency and failure injection. Preserve NGINX/TLS/APT/DNF.
5. Reject incompatible and unsupported downgrade paths, including all
   unapproved private/pre-public migration attempts.
6. Map EVERY acceptance criterion to executed PASS/FAIL/NOT VERIFIED evidence.
   Any applicable FAIL or NOT VERIFIED prevents release authorization.

This requires a separate authenticated candidate-artifact handoff workflow
for v0.5.0: a draft release is not yet an immutable, anonymously downloadable
public endpoint. The new candidate gate cannot be asserted implemented merely
because the v0.4.0 public release smoke is operational.

## Stage B: published smoke (mandatory immediately after every public release)

1. Discover the official stable version anonymously through the GitHub API.
2. Read back exact release ID, immutable=true, tag, source commit, eight
   approved public asset identities, sizes and SHA-256 hashes.
3. Download the actual public assets, verify independent public-key fingerprint,
   real Ed25519 manifest/provenance signatures, code and wheelhouse identity.
4. Run the real REPOCACHE discovery CLI, smoke a disposable native public install
   or upgrade, and record real exit codes and host identity.
5. Report PASS/FAIL/NOT VERIFIED with a concrete workflow/run. If broken,
   investigate and publish a newly reviewed signed version, never rewrite
   immutable release assets or tags.

For unique first-public v0.4.0, issue #71 explicitly also requires the
DEEPER real CDN-backed installation, repair and negative tests that could not
be exercised before the original public publication.

## Automation and trust boundary

- .github/workflows/public-release-acceptance.yml: read-only published v0.4.0
  verification, including actual signed downloads and disposable native Linux
  containers. Workflow dispatch/PR smoke; no automatic release publishing.
- scripts/public_release_targets.json: pinned independent reviewed asset ID,
  hash, commit and publisher fingerprint. Future versions must be separately
  approved via PR and explicitly selectable from the workflow inputs.
- scripts/public_release_acceptance.py: anonymous HTTPS API and CDN reads;
  check immutable release, exact tag/run, all local hashes and detached
  signatures before extraction or any publisher-supplied code execution.
- scripts/ci_public_release_native.py: disposable native bootstrap/installation
  and same-version repair, negative checks and preservation sentinels.
- tests/test_public_release_acceptance.py: mock-only parser and refusal tests;
  these NEVER count as successful native/real-network acceptance.

Use pinned Actions SHAs, contents:read permissions, no credentials persisted
by checkout, no publisher private key, and unprivileged actual application
execution. No tests are authorized to mutate a published Release or
production system. Container tests are NOT real booted-systemd or host-SELinux
tests; physical power-cut remains NOT TESTED as accepted for the first release.
