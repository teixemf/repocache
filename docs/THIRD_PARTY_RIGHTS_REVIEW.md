# Third-party rights and published-artifact review — v0.4.0

This is a **mandatory evidence worksheet**, not legal clearance. The first
public release is a **CLI/TUI frontend for an already configured NGINX**.
It does not bundle or install NGINX itself.

## Evidence collection

Every native offline wheel verification runs
`scripts/audit_wheel_licenses.py` against the **previously SHA-256 verified
wheelhouse contents**. The disposable Debian 13 / Python 3.13 and AlmaLinux 10
/ Python 3.12 CI jobs log a `CI LICENSE EVIDENCE:` JSON record for each
package, including exact wheel filename/hash, distribution name/version,
license-expression or legacy license/classifiers, packaged notice paths and
`legal_compatibility: NOT VERIFIED`.

The script rejects missing distribution metadata, conflicting wheel identity,
missing license evidence, oversized metadata, duplicate distributions and
invalid ZIP structures. It does **not** execute wheel code, use package indexes,
or infer that a license is legally compatible merely because a license string
is present. The resulting audit remains **candidate evidence**: public release
assets and publisher-signed SBOM hashes do not yet exist.

## Verified technical inventory at candidate SHA

[The staged release acceptance document](RELEASE_0.4.0_PHASED_ACCEPTANCE.md)
requires human redistribution/notice approval **before protected main promotion**
(Phase B) and final signed-asset reconciliation **before publication**
(Phase C/D). The original REPOCACHE source's Apache-2.0 license and AI
development disclosure were separately approved by the maintainer; that does
**not** grant blanket third-party rights.

At `efcd81a19c77c661d9fe7ab7a7445b014b5fce3a`, [native signed/offline CI](https://github.com/teixemf/repocache/actions/runs/39450320131)
logged **13 runtime/application wheels** (including `repocache-control`) and
**2 build tools** on Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12.
The same source passes [Python/native CI](https://github.com/teixemf/repocache/actions/runs/39450320116)
and [rootless rollback](https://github.com/teixemf/repocache/actions/runs/39450320101).
The inventory's **legal_compatibility** field for every package is deliberately
`NOT VERIFIED` — CI records metadata, not license clearance.

| Artifact | Version | Reported license metadata | Embedded notice paths found | Review action |
| --- | --- | --- | --- | --- |
| mdurl | 0.1.2 | MIT classifier | None under the audited convention | Retrieve exact upstream distribution LICENSE and establish obligations |
| shellingham | 1.5.4 | ISC License | None under the audited convention | Verify complete ISC license and notice/attribution requirements |
| wheel (build tool) | 0.45.1 | MIT classifier | None under the audited convention | Verify exact distribution notice and whether build-only artifacts are redistributed |
| Pygments | 2.21.0 | BSD-2-Clause | Two paths | Read copyright/redistribution notices and confirm any vendored obligations |
| typing_extensions | 4.16.0 | PSF-2.0 | One path | Read specific license and redistribution provisions |

Other runtime/build distribution license records include MIT-classified
`annotated-doc`, `linkify-it-py`, `markdown-it-py`,
`mdit-py-plugins`, `platformdirs`, `rich`, `textual`, `typer`,
`setuptools`, and Apache-2.0 `repocache-control`. The CI inventory also
records wheel hashes and exact filenames. Check the authenticated artifacts,
not only this human-readable summary; do not equate the absence of a detected
embedded notice path with actual copyright infringement.

A **source-only** snapshot scan reviewed all 102 current text blobs and a
heuristic scan reviewed all 111 reachable public commits' file patches on
2026-10-20 without confirmed common-secret/internal-address findings.
This does not replace a trusted full-history/asset/provenance scanner or
human inspection and is not independent audit certification.

## Proposed source-bundled notices (review required)

[The notice proposal](../THIRD_PARTY_NOTICES.md) carries exact version-tagged
upstream MIT/ISC copyright and permission texts for `mdurl 0.1.2` and
`shellingham 1.5.4`, plus the upstream `mdurl` transitive Joyent notice.
The source archive builder and strict updater allowlist must both include
this file so release authentication covers these bytes. The existing hashed
wheels are **not rewritten**. The upstream tag provenance is documented
in that file; notices were fetched from upstream GitHub sources, not
reconstructed from SPDX shorthand. The build-only `wheel 0.45.1` is
tracked separately in the SBOM and must be assessed according to actual
redistribution.

This remediation is a proposed technical notice-delivery mechanism,
**not** a finding that all redistribution obligations or third-party rights
have been independently reviewed and accepted. Confirm that **all final
published assets** are provided together as required by license terms.

## Manual acceptance before release

- [ ] For the **exact final signed wheelhouse hash**, read the license text and
  notice obligations associated with every listed runtime and build tool;
  validate necessary attribution distribution and project license compatibility
  with Apache-2.0. Resolve any unclear or conflicting licenses without guessing.
- [ ] Cross-reference the inventory with `deps/runtime-wheels.lock`,
  `deps/build-wheels.lock`, the signed release SBOM and wheel metadata on both
  native OS builds. Confirm names, versions, wheel hashes and source commit.
- [ ] Review the public source **Git history** and all distributed archive
  members using a trusted credential and secret-scanning process. A simple
  pattern scan of current source is not enough to claim no secrets anywhere.
  Do not publish finding details in a public issue; report via private
  vulnerability reporting and rotate any affected credentials.
- [ ] Verify `SECURITY.md`, `SUPPORT.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, the Apache-2.0 LICENSE and the AI development
  disclosure from the actual published sources.
- [ ] Confirm public repository settings: branch protections, exact required
  checks, `v*` tag publisher bypass role, effective immutable releases and
  private vulnerability reporting in the maintainer UI. Do not confuse an
  owner attestation with read-only API evidence.
- [ ] After separate merge, tag and publication approval, verify final source
  archive SHA-256, dependency wheelhouse, complete signed manifest, offline
  Ed25519 key fingerprint and provenance against the reviewed `main` commit.
  Store sanitized results in the v0.4.0 release acceptance issue.

Until all relevant items above have inspected evidence, rights and publication
acceptance remain **NOT VERIFIED**. The deterministic CI/license inventory is
not an independent legal review or a production NGINX/systemd/SELinux test.
