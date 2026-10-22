# Online dependency lock v1 — proposed implementation contract

**Status: PROPOSED / NOT RELEASE-ACCEPTED.** Owner: [#80](https://github.com/teixemf/repocache/issues/80), implementation [#83](https://github.com/teixemf/repocache/issues/83), publisher/release schema [#84](https://github.com/teixemf/repocache/issues/84), monitoring [#81](https://github.com/teixemf/repocache/issues/81). This defines the minimal auditable dependency interface before implementing network-dependent production upgrades. It is not a signed release manifest itself.

## Version and migration rules

- **Published v0.4.0** has a publisher-signed manifest schema 1, compatibility policy schema 1 and offline wheelhouse. Its updater cannot parse a different compatibility schema or a source-only release.
- The first **v0.5.0 bootstrap** MUST retain **policy schema 1**, with an explicit permitted upgrade from v0.4.0 and the genuine signed wheelhouse. Its updated runtime can subsequently recognize a future profile. Do not introduce a policy-schema 2 v0.5.0 artifact (#82, PR #90).
- **v0.6.0+ proposed online profile:** introduce a new signed release-manifest schema containing an additional \`runtime_lock_sha256\` and explicit \`online-hash-locked-wheels\` profile. This must be cryptographically verified with the independently provisioned Ed25519 publisher key BEFORE the installer parses the external lock or makes any network requests.
- The production installer must **never** accept an arbitrary user-supplied digest as a substitute for an authenticated signed manifest. The digest is a caller precondition to the v1 lock parsing primitive; only the trusted updater may supply it after signature verification (#84).
- No rewrite, substitution or re-signing of historic v0.4.0 assets. Genuine v0.4.0 → signed v0.5.0 → signed online v0.6.0 upgrade proof is mandatory, not a synthetic fixture.

## Separate source of truth for GitHub versus installation

1. \`pyproject.toml\` keeps upstream compatible bounds and original CLI/TUI entrypoints (Typer, Rich, Textual).
2. The reviewed, exact resolved constraints for both runtime targets are exposed as **Dependabot-recognizable pip requirements** at \`deps/requirements-debian13-py313.txt\` and \`deps/requirements-almalinux10-py312.txt\`, using PEP 508 normalized names, pinned exact versions and hashes. GitHub's *actual* ingestion and full transitive alerts remain NOT VERIFIED until #81 provides evidence.
3. Build-time tools are separately locked; build wheels are never fetched or built on the installed production host merely to install runtime dependencies.
4. The version-specific signed **runtime lock JSON** is a derived, machine-oriented manifest: exact filename, hash and independently reviewed upstream download URL for each package for each supported target. Its bytes are bound by the publisher's signed \`runtime_lock_sha256\`, not simply by a GitHub checksum.
5. Lock-generation CI must verify exact package/version/hash equivalence across the per-target pip requirements, JSON manifest, CycloneDX SBOM, expected original application package metadata and *actual* resolved installation. File presence is not proof of a complete transitive graph.
6. The installer **does not** resolve latest stable dependencies; Dependabot opens review PRs for candidate versions. Newest compatible stable versions enter a new immutable REPOCACHE release only after CI and reviewer approval. No automatic merge, release publication or silent pip upgrades.

## Canonical runtime lock payload

The following structure uses fictitious digests and wheel URLs. It is **illustrative**, not a valid release or a tested PyPI artifact. Exactly two platform profiles are required:

~~~json
{
  "schema": 1,
  "profiles": {
    "debian13-py313": [
      {
        "name": "rich",
        "version": "15.0.0",
        "filename": "rich-15.0.0-py3-none-any.whl",
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "url": "https://files.pythonhosted.org/packages/placeholder/rich-15.0.0-py3-none-any.whl"
      }
    ],
    "almalinux10-py312": [
      {
        "name": "rich",
        "version": "15.0.0",
        "filename": "rich-15.0.0-py3-none-any.whl",
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "url": "https://files.pythonhosted.org/packages/placeholder/rich-15.0.0-py3-none-any.whl"
      }
    ]
  }
}
~~~

**Syntax and consistency:**

- UTF-8 JSON, up to 128 KiB; no duplicate object keys, unknown fields, numeric/boolean type confusion, nested free-form instructions, embedded credentials or insecure URLs. Serialize with deterministic UTF-8 JSON and bind its **exact bytes**; canonical formatting is helpful but must never replace verifying the signed digest of the actual file.
- Top-level exact fields \`schema=1\`, \`profiles\`; exact profile names \`debian13-py313\`, \`almalinux10-py312\`, each with a bounded nonempty list of unique normalized PEP 503-style package names. The lists are explicitly closed inventories, never partial requirements.
- Wheel records contain exactly \`name\`, \`version\`, \`filename\`, \`sha256\`, \`url\`. Reject nonstable/prerelease versions as a normal policy, confusing canonical names, duplicate package names or destination filenames, unsupported platform, fake wheel suffix, missing fields and extra directives.
- URLs must be independently reviewed, immutable, HTTPS, credential-free, query-free and tied to \`files.pythonhosted.org\` for the **initial** policy. No alternate ports, fragments, userinfo, URL-encoded filename, traversal, IP literals, arbitrary mirrors or signed URLs carrying credentials. Restrict and independently validate any redirect; preferably no redirects, failing closed until a safe documented CDN transport is proven.
- Compare exact URL basename to the locked wheel filename; record and enforce the **SHA-256** of the downloaded wheel bytes. Per-wheel limit proposed 25 MiB, cumulative limit 100 MiB, and bounded timeouts. Reject symlinks and world-writable state. Download into a private, newly created directory only.
- No remote response may affect package selection, dependency names, URLs or versions. Never interpret arbitrary HTML/simple-index instructions at install time.
- A lock can bind *different target-specific wheel files* for the same name/version. The strict file/ABI tag check must be done on each target using its native Python/pip before activation; never assume that pure-Python wheels are the only eventual dependency type.
- Do not accept \`requirements.txt\` directives, VCS/editable requirements, \`--extra-index-url\` or broad version constraints as executable runtime policy. A lock compiler/reviewer must cross-check them and reject unsupported entries.

## Staged installation boundary

1. An independently trusted updater has verified the exact source release signature, source SHA-256, release compatibility and new signed \`runtime_lock_sha256\`. Reject untrusted lock before reading or processing a URL.
2. Select exactly the native OS/Python profile from preflight; refuse unsupported distributions/versions/architectures. Create a private staging location owned by the non-root REPOCACHE account.
3. Fetch only the signed filenames from approved hosts with bounded TLS transport, no redirected auth, no env-supplied proxy/CA override or user pip config. Compare SHA-256 **as a stream**; delete partial files on failure.
4. Check local wheel filename and wheel archive structure, fail on non-wheel/invalid ZIP, unexpected metadata or unsafe member paths before install; do not import or execute any downloaded Python yet.
5. Create a **fresh, versioned venv**. Invoke the interpreter's pip with **offline/no-index**, \`--no-deps\`, \`--no-input\`, \`--no-cache-dir\`, and \`--require-hashes\` using a locally generated exact-file requirements inventory. Explicitly disable source builds; wheel tag compatibility is checked by pip on the target runtime.
6. Install the separately authenticated original REPOCACHE application artifact without resolving unreviewed dependencies. Run \`pip check\`, CLI version/JSON smoke, Textual headless smoke and rootless recovery hooks; activate atomically with existing journal only after all validations. Never install into system site-packages or execute setup scripts as root.
7. A missing PyPI host, missing wheel, bad signature, TLS/redirect violation, malformed lock, bad hash, incompatible wheel, permission error or application failure leaves the previous active venv, NGINX, cache, certificates and APT/DNF source configuration unchanged. A first installation fails with actionable sanitized diagnostics.
8. Optional customer-provided *independently fetched* approved offline wheels may be supported, but REPOCACHE must never ship those third-party bytes as part of new source-only public artifacts.

## Dependencies and open gates

- [#82 / PR #90](https://github.com/teixemf/repocache/pull/90) prepares the legacy-only profile schema parser. It **does not** enable this v1 online lock.
- [#83](https://github.com/teixemf/repocache/issues/83) owns strict lock parsing, immutable URL/byte verification, least-privilege download/staging and online installation. Tests must cover hostile JSON and URLs, poisoned environment variables, malicious wheel files, file integrity and network interruption.
- [#84](https://github.com/teixemf/repocache/issues/84) owns authenticated on-disk release layout, real owner-signed manifest schema, artifact count, public asset inventory, source-only packaging, migration and final candidate acceptance.
- [#85](https://github.com/teixemf/repocache/issues/85) owns exact-version CLI/TUI and native OS regression acceptance; [#53](https://github.com/teixemf/repocache/issues/53) owns future independently trusted installed-byte attestation.
- [#81 / PR #87](https://github.com/teixemf/repocache/pull/87) owns the actual GitHub Dependabot configuration, dependency graph, advisory behavior and alerts. YAML existence alone does not prove those work.
- [#76/#78 / PR #77](https://github.com/teixemf/repocache/pull/77) remain the authoritative genuine owner-signed v0.5.0 **legacy profile** release acceptance, with no signing key in CI.
- [#18/#25](https://github.com/teixemf/repocache/issues/25) own independently privileged native APT/DNF system prerequisites and NGINX services. No overlap with rootless Python application wheel installation.
- **Review before merge:** approve and test full signed schema and transport policy, both real platform lock inventories, actual Dependabot ingestion, own release asset inventory, native signed-candidate install/upgrade/repair/rollback and existing security gates. Until then: **NOT VERIFIED**, no merge.

*This design cannot by itself ensure an operator legally assumes all responsibility for third-party dependencies. It materially reduces REPOCACHE's direct upstream-wheel redistribution while retaining its obligations for its own software.*
