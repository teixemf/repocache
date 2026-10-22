# Online wheel staging prototype — trust and acceptance

**Status:** PARTIAL / UNWIRED / NOT PRODUCTION-READY. Issue [#83](https://github.com/teixemf/repocache/issues/83). Design [#80](https://github.com/teixemf/repocache/issues/80) and [online lock contract](ONLINE_DEPENDENCY_LOCK_SPEC_V1.md) are proposals; real publisher signing/release layout is [#84](https://github.com/teixemf/repocache/issues/84). Do not distribute or activate online-profile releases using this module alone.

## Implementation slice

\`src/repocache/online_deps.py\` is **stdlib-only** and is not imported by the v0.4.0 release updater or package builder. It provides:

1. \`parse_verified_lock(raw, expected_signed_digest, target)\`: strict, bounded JSON parsing **after** verifying the exact bytes against a trusted expected SHA-256, fixed Debian13/3.13 and AlmaLinux10/3.12 profiles, no duplicate package names/keys, no nonstable or unrecognized field/URL/filenames. **The caller MUST obtain expected_signed_digest only from a genuinely verified publisher Ed25519 release manifest**, never from untrusted CLI input, a mutable GitHub checksum, or the same upstream serving the wheels.
2. \`stage_wheels(records, destination, cafile=...)\`: refusal of root UID, newly created private user-owned staging directory, explicit CA file, no ambient HTTP/S proxy, no HTTP redirect, only original \`files.pythonhosted.org\` URLs from trusted records, bounded streaming, fail-closed SHA-256 checks and bounded ZIP identity/layout checks. Partial staged directories are deleted on errors; no pip or application execution occurs here.
3. \`offline_install_argv(interpreter, verified_requirements)\`: generate the existing \`pip install --no-index --no-deps --require-hashes --no-input\` invocation **without executing it**. Source builds/unknown dependencies remain disallowed by the future trusted installer.

The prototype explicitly restricts stable versions to a conservative numeric PEP-440 subset, exact file naming with normalized package names, and direct wheel URLs with no redirects. Versions, wheel filenames and CDN transport forms not satisfying this profile must be handled by a separately reviewed contract change, **not by silently loosening URL/type validation**.

## Current limitations / blockers

- No source release signs or carries the online lock. The **actual signature/digest binding** must be added to the owner-signed release schema and verified by \`signatures.verify\` / \`upgrade\` **before invoking this module** (#84). A digest passed to a function is not self-authenticating.
- This does not prove direct/transitive package closure, availability of real wheel URLs on PyPI, wheel compatibility with the actual Linux platform, valid system CA trust, a safe offline install, or a running CLI/TUI. #80/#81/#83/#85 must provide those proofs.
- \`stage_wheels\` is not integrated with \`update_transaction\`, the service-owned environment, \`updater.install_source\`, signed rollback identity, privileged preflight or an actual publisher-authenticated v0.6.0. There are **no live dependency downloads** in tests; its transport is monkeypatched to in-memory bytes.
- The exact online asset count, platform wheel locks, final SBOM/notice inventory, source-only release files and owner-signed native candidate remain blocked on #84. v0.4.0/first v0.5.0 **schema-1 legacy offline** guarantees remain unchanged.
- Narrow URL policy intentionally refuses alternate indexes, dynamic redirects and proxies for now. This prevents deployment in some operator environments; any exception must be an explicit reviewed policy and cannot be inferred from \`HTTPS_PROXY\`, \`PIP_INDEX_URL\` or local pip configuration.
- The module currently trusts a **provided** CA file path. The future trusted caller must select a known, administrator-approved OS trust path with secure ownership/permissions; do not interpret this argument as approval of arbitrary CA material.
- Dependency wheel contents are executable Python; signed hashes attest only to reviewed byte identity, not absence of malicious code. Supply-chain provenance, advisories and human inspection remain required.

## Negative / security test matrix

\`tests/test_online_dependency_staging.py\` exercises exact digest refusal before JSON parsing; required platform inventories; schema, types, duplicates, hostile lock keys; unknown/nonstable versions; credential/port/query/redirect/path traversal/alternate mirror URLs; malicious nested JSON; in-memory fake binary wheel download, byte/hash integrity, redirect/status/length refusal, ZIP path traversal refusal, root UID refusal, new private staging and cleanup, and offline pip invocation arguments.

These tests are synthetic. They do **not** substitute for real signed v0.4.0 → v0.5.0 → v0.6.0 upgrade/repair/rollback, real Debian13/Alma10 TLS/PyPI install, whole-graph SBOM/Dependabot coverage, native NGINX/SELinux checks or an independent security audit. All mandatory criteria in #83 remain NOT VERIFIED until the full implementation and required evidence are available. No merge, release or production change is authorized by creating this draft.
