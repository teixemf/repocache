# Third-party rights and published-artifact review — v0.4.0

## Evidence review — 2026-10-20, protected release base `ed1ebc54ff67027af15b886c5489c7dea7b53625`

**Assessment scope:** exact native Debian 13/Python 3.13 and AlmaLinux
10/Python 3.12 wheels, reviewed source and current public repository
history. This is an engineering examination of license grants and notice
delivery, **not a title-of-ownership certificate, an independent legal opinion
or an assurance that an unknown secret cannot exist**.

### Actual distributable set and rights obligations

The matching, completed `push` runs on that **base commit** are
[Tests 4/4](https://github.com/teixemf/repocache/actions/runs/39480669942),
[offline wheels 3/3](https://github.com/teixemf/repocache/actions/runs/39480669996)
and [native rollback 2/2](https://github.com/teixemf/repocache/actions/runs/39480669812).
The two wheelchain native logs each contained a JSON `CI LICENSE EVIDENCE:`
record. Exactly **12 external runtime wheels + one REPOCACHE application
wheel** were present; names, versions, SHA-256 and license notice paths of
all **12 external wheels match across both OSs**. The self-built REPOCACHE
application wheel has OS-specific bytes/hashes, so it is not counted as an
external upstream binary or asserted reproducible across those builds.

| Locked external wheel | SHA-256 (exact PyPI wheel) | Declared grant | License/notice delivery |
| --- | --- | --- | --- |
| `annotated-doc 0.0.5` | `117bac03a25ede5df5440e855b32d556049ca169ead221505badf432fed4b101` | MIT | Embedded LICENSE |
| `linkify-it-py 2.2.0` | `3adc40eb5af300b2605fcfdb968c24e1d780a90f1f2221af7c15e5111e94d443` | MIT | Embedded LICENSE |
| `markdown-it-py 4.2.0` | `9f7ebbcd14fe59494226453aed97c1070d83f8d24b6fc3a3bcf9a38092641c4a` | MIT | Embedded LICENSE **and** LICENSE.markdown-it (upstream attribution) |
| `mdit-py-plugins 0.6.1` | `214c82fb2ac524472ab6a5bcab1de80f73b50443e187f401bfd77efbc7c6481d` | MIT | Embedded LICENSE |
| `mdurl 0.1.2` | `84008a41e51615a49fc9966191ff91509e3c40b939176e643fd50a5c2196b8f8` | MIT | Separate exact-tag MIT **plus Joyent** notice in `THIRD_PARTY_NOTICES.md` |
| `platformdirs 4.13.5` | `53d3ec4280b815c1e0b02edad7f9ee8fda1ba9c0865dd9c2e6e63849ce82fc1e` | MIT | Embedded LICENSE |
| `Pygments 2.21.0` | `2363c69b61c4a97c838da3b130dcd6468f4848992b21a82f2a63ec34377137d9` | BSD-2-Clause | Embedded LICENSE **and AUTHORS**; retain copyright/disclaimer in binary distribution |
| `rich 15.0.0` | `33bd4ef74232fb73fe9279a257718407f169c09b78a87ad3d296f548e27de0bb` | MIT | Embedded LICENSE |
| `shellingham 1.5.4` | `7ecfff8f2fd72616f7481040475a65b2bf8af90a56c89140852d1120324e8686` | ISC | Separate exact-tag ISC notice in `THIRD_PARTY_NOTICES.md` |
| `textual 8.2.8` | `267375fd402dc8d981457212efa71f0e3365fd17bba144ba9bb3ed7563cb374a` | MIT | Embedded LICENSE |
| `typer 0.27.3` | `e50022f28b82a86313e54501317a1db64bf8f8d036ff8cfe5ca7e47675454aff` | MIT | Embedded LICENSE |
| `typing_extensions 4.16.0` | `481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8` | PSF-2.0 | Embedded LICENSE; preserve PSF copyrights/terms; this wheel is not modified |

Build-only wheels, **not shipped in the separate runtime wheelhouse**:
`setuptools 80.9.0` SHA-256
`062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922`
(MIT, embedded LICENSE), and `wheel 0.45.1` SHA-256
`708e7481cc80179af0e556bbf0cc00b8444c7321e2700b8d8580231d13017248`
(MIT, no license file under the audited wheel convention). Both are pinned
in `deps/build-wheels.lock` and named in the signed-build SBOM. The
`pip` executable is an OS/virtual-environment build tool, not an extra
downloaded or redistributed runtime wheel in this release.

**Terms reviewed:** MIT and ISC permit copying and redistribution when
copyright and permission notices accompany copies; BSD-2-Clause permits
binary redistribution provided copyright, conditions and disclaimer are
reproduced in accompanying materials; PSF-2.0 grants redistribution
subject to its notices and requires change summaries for derivatives
when applicable. These 12 binaries are used as independent, unchanged
dependencies of Apache-2.0 original code; **we do not relicense them
under Apache-2.0** or claim an independent legal opinion. Embedded
LICENSE/AUTHORS copies appear under each ZIP's
`.dist-info/licenses/` directory in native evidence. Absence from
that directory in mdurl/shellingham means the upstream notices must
accompany distribution by another trustworthy route.

**Upstream exact-version confirmation:** compared original tagged
`executablebooks/mdurl@0.1.2:LICENSE` and
`sarugaku/shellingham@1.5.4:LICENSE` **verbatim** against the content
added in [PR #68](https://github.com/teixemf/repocache/pull/68).
Also read the release-tag LICENSE entries from
`fastapi/annotated-doc@0.0.5`,
`tsutsu3/linkify-it-py@v2.2.0`,
`executablebooks/markdown-it-py@v4.2.0`,
`executablebooks/mdit-py-plugins@v0.6.1`,
`tox-dev/platformdirs@4.13.5`,
`pygments/pygments@2.21.0`,
`Textualize/rich@v15.0.0`,
`Textualize/textual@v8.2.8`,
`fastapi/typer@0.27.3`,
`python/typing_extensions@4.16.0`,
`pypa/setuptools@v80.9.0`, and
`pypa/wheel@0.45.1`. The locked
`linkify-it-py 2.2.0` wheel's official PyPI SHA-256 also matches
the source-distribution listing and PyPI-published provenance for
`tsutsu3/linkify-it-py`. **Upstream license texts were not extracted
from every actual locked wheel**; the wheel inventory reports exact
notice *paths*, not a per-byte, per-file copyright audit. Any unexpected
vendored code or license exceptions discovered during final archive
inspection must stop publication.

### Correction required before final rights clearance

An authenticated source archive already carries the exact original notices
for mdurl and shellingham, but the wheelhouse is a **separate GitHub Release
asset** and may be downloaded by itself. Therefore *source-only* placement
does not adequately establish independent wheelhouse NOTICE delivery.

[Correction PR #70](https://github.com/teixemf/repocache/pull/70)
adds an exact copy of `THIRD_PARTY_NOTICES.md` to the wheelhouse TAR,
without changing any `.whl` byte. The strict verifier must require a
bounded, valid UTF-8 notice, and the signed-candidate verifier must compare
the wheelhouse notice against the source archive's reviewed notice. A
separate wheelhouse signed SHA-256 binds the notice bytes, so a missing or
modified file fails. **This paragraph describes a proposed correction until
PR #70 is actually CI-PASS, reviewed and merged**; previous source CI does not
verify the revised wheelhouse. Do not publish independent wheelhouse assets
without accompanying notices.

### Current publicly verifiable source privacy inventory

At base `ed1ebc54ff67027af15b886c5489c7dea7b53625`, the complete
GitHub recursive tree was `truncated=false` with **105/105 UTF-8
tracked files read**. A bounded scan inspected current contents for
common PEM private keys, GitHub/cloud tokens, hard-coded long passwords,
URLs naming the historical private origin, RFC1918 address literals and
private `.local/.internal/.lan` hostnames. There were **no confirmed
credentials or private-origin URLs**; one apparent domain hit in
`src/repocache/updater.py` was the ordinary Python `threading.local()`
API, not a hostname. The project history root commit
`66f6ddb6dd465d191a60f51c524e1b7ae56a9367` contained only the
Apache-2.0 LICENSE; current Git ancestry stays on this independent
public origin. GitHub reported the historical
`teixemf/repocache-priv` repository **private**, and no public
GitHub Releases or version tags existed as of this audit.

**Limits:** these are regex/content review findings, not a forensic
credential scanner; they do not cover nonreachable Git objects, encoded
secrets, original ownership/third-party IP agreements, or artifacts that
do not exist yet. Previous bounded patch-history review is recorded in
[#1](https://github.com/teixemf/repocache/issues/1); it is not retested
as an independent forensic guarantee here.

### Release blockers that cannot be inferred from license metadata

1. **Origin/title:** only the maintainer/source owner can attest it owns
   or has sufficient permission for all *original* REPOCACHE private-era
   source imported into the new public Apache-2.0 project. AI drafting
   and a new Git root do **not** transfer third-party copyright.
2. **Effective reporting:** the owner confirms private reporting enabled;
   the connected tooling cannot open the reporter-only confidential
   intake end-to-end. An actual external reporter view of
   `Security → Advisories → Report a vulnerability` is required
   (opening the private form without submitting fabricated vulnerabilities).
3. **Final real assets:** reconcile final post-merge signed source and
   wheelhouse digests, runtime wheel contents, notices and provenance only
   once an owner-authorized publisher creates them. Any new dependency
   or NOTICE bytes requires new audit and signed hashes.

**Decision:** technical licensing patterns and published terms are
consistent with permitted **unchanged** third-party wheel redistribution
*provided all mandatory notices really travel with each asset*.
The listed condition is being remediated; rights/title and final
publisher-asset confirmation remain **NOT VERIFIED**. Do not label an
AI-produced rights review an independent legal opinion, do not close
issue #6 without all original criteria PASS, and do not promote PR #67
until the issue #1/#6 pre-main acceptance gate is explicitly resolved.

---

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
