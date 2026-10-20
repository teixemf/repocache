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
