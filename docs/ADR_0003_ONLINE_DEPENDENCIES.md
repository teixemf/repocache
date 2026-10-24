# ADR-0003: Reviewed online Python dependencies without publishing upstream wheels

**Status:** PROPOSED — issue [#80](https://github.com/teixemf/repocache/issues/80), epic [#79](https://github.com/teixemf/repocache/issues/79). Architecture/design only; no runtime change, no approval to merge/publish/enable new services.

## Bootstrap compatibility decision — 2026-10-22

**The first v0.5.0 release MUST use the unchanged signed compatibility policy
`schema: 1` and the authentic offline wheelhouse.** The *already published*
v0.4.0 updater rejects schema 2 and requires signed wheelhouse bytes. Shipping
schema 2 for v0.5.0 would strand currently installed clients regardless of the
publisher's signature. After v0.5.0 is correctly bootstrapped, its updater
may recognize a new, authenticated profile for **v0.6.0 or later**; consolidated
draft [PR #98](https://github.com/teixemf/repocache/pull/98) still
refuses unimplemented online-profile installation. Real owner-signed native candidate
evidence remains a distinct requirement (#76/#78).

The declarative security contract is further detailed in
[ONLINE_DEPENDENCY_LOCK_SPEC_V1.md](ONLINE_DEPENDENCY_LOCK_SPEC_V1.md).
This document is still a proposal; publishing third-party-wheelhouse-free artifacts and
switching a production updater remain separately gated under #83/#84.

## Selected first-party wheel inventory (2026-10-23)

ADR [0004](https://github.com/teixemf/repocache/blob/feat/v0.6.0-signed-first-party-wheel-84/docs/ADR_0004_SIGNED_FIRST_PARTY_WHEEL.md)
and draft [PR #103](https://github.com/teixemf/repocache/pull/103)
record the selected eight-asset **v0.6.0+** release design,
superseding the earlier provisional seven-asset, TAR-only proposal:

1. `repocache-vX.Y.Z.tar.gz` — reviewed first-party source.
2. `repocache-vX.Y.Z.tar.gz.sha256` — source checksum.
3. `repocache-vX.Y.Z.tar.gz.dependency-lock.json` — exact upstream wheel identities.
4. `repocache-vX.Y.Z.tar.gz.sbom.json` — SBOM.
5. `repocache_control-X.Y.Z-py3-none-any.whl` — deterministic **first-party application wheel**.
6. `repocache-vX.Y.Z.tar.gz.assets.json` — exact five-primary-asset inventory.
7. `repocache-vX.Y.Z.tar.gz.manifest.json` — owner-signed manifest.
8. `repocache-vX.Y.Z.tar.gz.manifest.json.sig` — detached Ed25519 signature.

The inventory binds the five primary assets by exact name, size and SHA-256;
the manifest signs that inventory digest without a circular reference.
The first-party wheel must be independently reproducible from authenticated
source and installed without target-side build hooks. **No third-party wheels
are redistributed** in this profile. The unchanged v0.5.0 predecessor still
publishes the original eight-asset source + wheelhouse format; the identical
asset count does NOT imply profile interchangeability.

This is a selected architectural direction, **NOT** runtime activation
approval or full #80/#83/#84/#85 acceptance. Real owner-signed candidate
evidence, final signed schema and native rollback tests remain mandatory.

## Current bridge reconciliation (2026-10-22)

The overlapping [#89](https://github.com/teixemf/repocache/pull/89), [#90](https://github.com/teixemf/repocache/pull/90) and [#91](https://github.com/teixemf/repocache/pull/91) signed-update drafts are now **consolidated for review** in [PR #98](https://github.com/teixemf/repocache/pull/98). The consolidated implementation carries strict *schema-1* legacy verification and installed-profile refusal, recognizes provisionally signed schema-2 envelopes for **v0.6.0+**, but **refuses every schema-2 install** until the authenticated lock/asset inventory and staged install have been verified under #83/#84. This is an engineering proposal, not approval to merge #82 or publish v0.5.0.

The proposed schema-2 signed envelope field names are `dependency_profile`, `dependency_lock_sha256`, `asset_inventory_sha256`, and the inherited `wheelhouse_sha256` with profile-dependent values. The first v0.5.0 signed bundle MUST retain schema 1, because the immutable v0.4.0 updater knows no other format. Final field/schema approval and real owner-signed native candidate evidence remain outstanding.

## Context, goal and non-goals

REPOCACHE v0.4.0 ships an immutable, owner-Ed25519-signed source release and its own separate signed offline wheelhouse. The v0.4.0 updater rejects source-only installs, and its publisher acceptance checks expect an exact legacy asset set. The project aims to stop **publishing copies of third-party Python distributions** while retaining a structured **Typer + Rich CLI**, a full **Textual TUI**, resilient self-update/rollback and safe native Linux provisioning.

- **Goal:** future releases ship only original REPOCACHE application code/metadata and signed dependency identities; an installer fetches exact reviewed third-party Python wheel bytes from an administrator-approved online package index into a new non-root managed venv.
- **Non-goal:** rewrite CLI/TUI to stdlib/curses, unpin dependencies at install time, make global `pip install` modifications, embed NGINX or PyPI wheels, grant permission to edit/replace v0.4.0, or assert that operator installation transfers *all* legal liability.
- Supported runtime targets remain **Debian 13 / OS Python 3.13** and **AlmaLinux 10 / OS Python 3.12**. No other platform is implicitly supported.

## Decision proposal

1. **Keep the interfaces.** Typer/Rich CLI and Textual TUI remain first-class required server features. Preserve `repocache update list`, `update check`, explicit version installs, JSON schemas/exit codes and noninteractive command invocation. Preserve the approved daemonless client verbs `repocache-client check`, `repos list`, `repos submit`, `repos sync`. The server runtime requirements must not leak into an independent client install.
2. **Separate origin and installation.** Signed REPOCACHE Releases contain only original application source/wheel, declarative metadata, OS/Python/architecture compatibility, publisher verification materials and dependency identity (including SBOM/lock/provenance). The **operator's machine** contacts approved upstream indexes to acquire third-party wheels; REPOCACHE is not their binary redistributor in this mode. NGINX and native Python prerequisites come separately from the host's authorized APT/DNF repositories under narrowly delegated privileges.
3. **Two resolution moments.** CI/maintainer reviews the newest non-prerelease compatible upstream candidates, security advisories, licenses and platform coverage. A **specific release** then pins a complete tested direct+transitive+build dependency closure and SHA-256 hashes. Runtime does **not** resolve a new highest version or dynamically update that signed lock. Emergency fixes require a new reviewed, signed REPOCACHE release or separately approved signed policy mechanism.
4. **Isolated runtime.** Acquire approved wheels in a private bounded download staging directory as a dedicated non-root service user; check signed lock and all sha256 bytes before an offline `pip install --no-index --only-binary=:all: --no-deps --require-hashes` into a fresh versioned virtual environment. The program-owned application wheel is itself signed/hash-pinned and installed without dependency resolution, build isolation or third-party build execution at runtime. `pip check`, CLI/JSON smoke and Textual/headless smoke precede atomic activation. Root only performs audited bootstrap/native-package operations.
5. **Fail closed.** Missing dependencies, expired CA trust, HTTP/index/CDN redirects outside reviewed policy, missing wheels for target tags, malicious `PIP_*` env, altered hashes, insufficient space, incompatible versions and network outages must not change the active generation/NGINX/APT/DNF/TLS. Avoid arbitrary proxy environment inheritance and credential leakage. A separately acquired, verified exact offline wheel set supplied by the operator is a possible optional mode, **not** a REPOCACHE-uploaded wheelhouse.
6. **Continuity.** A **schema-1 signed, legacy-compatible** transition runtime (target v0.5.0, [#82](https://github.com/teixemf/repocache/issues/82)) is needed because unchanged public v0.4.0 cannot bootstrap an unfamiliar wheelhouse-free manifest. v0.4.0 and any v0.5.0 legacy profile may continue to ship unchanged audited offline wheels. Target v0.6.0 introduces the wheelhouse-free online profile only after genuine signed-candidate migration/install/repair/rollback evidence ([#83–#85](https://github.com/teixemf/repocache/issues/83)).
7. **Maintain monitoring.** Dependabot watches recognized Python project and lock manifests, plus pinned GitHub Actions ([#81](https://github.com/teixemf/repocache/issues/81), [#74](https://github.com/teixemf/repocache/issues/74)); alert/settings effectiveness needs real GitHub proof. Its update PRs are review candidates, not deployment triggers. [PR #116](https://github.com/teixemf/repocache/pull/116) completed the Node24 infrastructure migration, but parent [#74](https://github.com/teixemf/repocache/issues/74) remains OPEN for the real nonpublishing release-workflow artifact rehearsal and sign-off. Separate actual deployed-host inventories are the operator's responsibility.

## Release profiles and trust boundaries

```text
                 offline owner Ed25519 private key
                          |
            signed REPOCACHE release identity
                          |
       +------------------+----------------------+
       |                                         |
   v0.4 / v0.5 legacy                       v0.6+ online
   signed source+wheelhouse                 signed original code
   exact legacy asset set                   + signed wheel hash lock
       |                                         |
    non-root staged install                  operator-approved PyPI TLS
       |                                         |
   controlled venv                          downloaded bytes verified
       |                                     against publisher-signed lock
       +------------------+----------------------+
                          |
                non-root new managed venv
                          |
          tests -> journaled atomic activate -> rollback
```

**Authenticity is not equivalent to safety.** The Ed25519 signature authenticates a release authored by this publisher; hashes bind upstream wheel *bytes* to previously approved identities. Neither proves the upstream package is free of malicious behavior, nor provides continuous attestation of mutable installed files. CVE/review/provenance tracking and the future trusted-runtime [#53](https://github.com/teixemf/repocache/issues/53) remain separate.

### Illustrative signed policy (NOT an implementable schema)

This is deliberately an **example**, not a second accepted format or a real publisher-signed release. No digest below is real.

```json
{
  "schema": "proposed-dependency-profile-v1",
  "release": "v0.6.0",
  "distribution_profile": "online-hash-locked-wheels",
  "supported": [
    {"os": "debian", "major": 13, "python": "3.13"},
    {"os": "almalinux", "major": 10, "python": "3.12"}
  ],
  "index_policy": {
    "source": "https://pypi.org/simple/",
    "wheel_delivery_hosts": ["files.pythonhosted.org"],
    "operator_override": "explicitly-approved-only"
  },
  "dependencies": {
    "lock_format": "hash-pinned-requirements",
    "lock_sha256": "<64 hex digits>",
    "sbom_sha256": "<64 hex digits>",
    "profiles": ["debian13-py313", "almalinux10-py312"]
  },
  "artifacts": {
    "manifest_version": "profile-specific",
    "no_third_party_wheels": true
  },
  "compatibility": {
    "compatible_from": ["0.5.0"],
    "downgrade_from": []
  }
}
```

A final spec MUST decide signature envelope, canonical JSON, whitelist of accepted keys/redirect hosts, release asset names/counts, applicability of exact wheel tags, lock/SBOM digests, package provenance policy and migration behavior. The example cannot be silently treated as executable configuration. Do not equate a signed JSON flag such as `no_third_party_wheels` with a successful scanned artifact inventory.

### Manifest/lock file format selection

- The existing PEP 621 `pyproject.toml` gives Dependabot a recognized source for **direct version ranges**, but is not a reliable record of exact shipped v0.4.0 transitive versions. Existing custom `deps/runtime-wheels.lock` is a release evidence file, not a verified Dependabot-compatible source.
- **Proposed:** retain `pyproject.toml` for original package API and allowed ranges; generate reviewed, pinned `requirements`-style hash locks containing every transitively installed dependency for each supported Python/OS profile. Link them to an authenticated canonical inventory/SBOM and production signed-release manifest. File path/syntax must be verified with Dependabot update jobs and dependency graph before freezing: GitHub's `pip` updater can monitor `requirements*.txt` and PEP 621 manifests; hash pin rewriting and complete transitive coverage **remain NOT VERIFIED**.
- Reconcile build requirements separately: the release-builder can create the REPOCACHE-owned wheel in CI with pinned/audited build tools; an end user never compiles upstream source distributions as part of online install. The signed build provenance lists build-tool versions and digests even if they are not distributed by REPOCACHE.
- Pin *all* accepted platform wheel hashes per fixed package version. Do not assume identical wheels/ABI for Python 3.12 versus 3.13 or both Linux targets. Generate and check in a controlled review environment; do not allow source archive fallback or an unbounded new dependency graph at install time.
- Declarative requirements files are security-sensitive: never permit index overrides, `--extra-index-url`, `--trusted-host`, environment interpolation, URLs to unapproved hosts, editable/VCS dependencies or arbitrary resolver flags in signed runtime locks. A safe strict parser/build-time validator must reject them.
- If Dependabot does not expose full transitives for both native targets, investigate the GitHub dependency submission API with a narrowly permissioned workflow (only on protected trusted commits), and prove coverage rather than claiming that `pyproject.toml` is enough. Automated PRs **never** gain offline signing keys or GitHub release write permission.

## Native install and privilege boundary

| Area | Responsibility / mechanism |
| --- | --- |
| NGINX, system Python, `venv`, system CA and service tooling | Operator-authorized APT/DNF, separately privileged installer, issues #18–#31 |
| Typer/Rich/Textual and transitives | Owner-reviewed signed lock; obtained by the host from a configured trusted package index under non-root install |
| CLI and TUI | Original REPOCACHE Python code, preserved as first-class supported interfaces |
| Source manifest / signature | Ed25519 owner-held key, independent trust anchor, exact final release |
| NGINX route/cache management | Explicit opt-in changes only after existing validation and recovery gates |
| Published third-party license notices | Required for historical wheelhouse assets; new first-party-only releases must retain correct code/provenance/notice wording for anything actually included |
| Upstream dependency terms and operator cache redistribution | Responsibility follows applicable licenses and actual conduct; no blanket legal liability transfer asserted |

## Upgrade, repair, rollback and availability

- v0.4.0 is immutable. Its runtime does not understand an online-only profile. Accept v0.4.0 -> signed bridge release only when signed compatibility says so, retaining previous installed generation for recovery; no unsigned source-only workaround.
- The bridge updater negotiates the exact signed profile. Under legacy mode, keep the complete original wheelhouse. Under online mode, first validate the signed online lock; fetch only approved wheels, verify, stage and smoke. Do not present an arbitrary call-site policy as signed authorization.
- Failure before activation leaves the previous generation and installed manifest untouched. Power loss, journal recovery and identical-version repair use the established exclusive transaction scheme; real booted-systemd/SELinux limitations must be disclosed, not marked PASS.
- Without reachable upstream PyPI, a *fresh* online-profile installation fails with a clear diagnostic; existing running REPOCACHE and NGINX remain available. In independently designed opt-in offline recovery, users may supply exact approved hashed wheels independently acquired, without the project distributing them.
- Dependency-only security fixes require a newly reviewed package lock and owner-signed release; never silently mutate an immutable published release or install a newer unreviewed dependency in place.

## Migration / conflicting work

- [#76](https://github.com/teixemf/repocache/issues/76) remains OPEN; its independently testable infrastructure [#78](https://github.com/teixemf/repocache/issues/78) was completed and [PR #77](https://github.com/teixemf/repocache/pull/77) merged. Genuine owner-signed, offline, eight-asset *v0.5.0* candidate acceptance remains NOT VERIFIED. New v0.6.0 online acceptance is separately implemented under #84; keep owner key off GitHub Actions. Do not weaken earlier gates.
- [#18](https://github.com/teixemf/repocache/issues/18), [#25](https://github.com/teixemf/repocache/issues/25), #26/#27/#31: system APT/DNF installation remains distinct from online app wheels; privileges, native verification, NGINX rollback and existing-service ownership are not weakened.
- [#14](https://github.com/teixemf/repocache/issues/14), [#23](https://github.com/teixemf/repocache/issues/23), stacked draft [PR #52](https://github.com/teixemf/repocache/pull/52): preserve metrics/privacy and administrator authorization under Textual and CLI behavior. No UI rewrite.
- [#10](https://github.com/teixemf/repocache/issues/10), [#53](https://github.com/teixemf/repocache/issues/53): authenticated runtime identity is not proof of compatible persistent-schema downgrade or independent installed-file attestation.

## Open design choices / verification before implementation

- [ ] Independently verify real PyPI transport policy, safe redirects/CDN host restrictions, proxy/CA behavior, and how to pass a complete lock into `pip download` without executing upstream build scripts. Reject unsupported schemes and untrusted host overrides.
- [ ] Decide exact file name/syntax of per-target locks by testing Dependabot parsing, correct direct+transitive graph contents, and dependency update PR behavior.
- [ ] Verify complete packages with wheels supporting *both* native targets; missing wheels are a release blocker rather than permission to build source on install.
- [ ] Define a backwards-compatible signed `release-policy` profile/version schema and prove genuine v0.4.0 -> v0.5.0 bridge acceptance before enabling the first-party wheel/online dependency profile.
- [ ] Define independent CLI/TUI/version/JSON/API acceptance matrix, online/offline native distro harness, check results and reviewer ownership.
- [ ] Human security and legal review of new distribution terms and actual final artifacts; engineering metadata does not grant legal clearance.

**References:** [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/), [GitHub dependency graph](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-graph-data), [GitHub Dependabot manifests](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories).

No existing acceptance criterion is considered PASS merely because this ADR has been drafted.
