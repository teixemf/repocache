# Third-party rights and published-artifact review — v0.4.0

## Maintainer acceptance and protected-branch CI checkpoint — 2026-10-20

[Issue #6](https://github.com/teixemf/repocache/issues/6) is **closed for pre-main source/community/rights-policy acceptance**, with its [original five-criterion PASS matrix](https://github.com/teixemf/repocache/issues/6) bound to protected `release/v0.4.0` commit `7ba8288cb57afaac796f4d8c0d266b5dd9fd67b5`.

In a four-question direct review, the maintainer confirmed (1) authority over original REPOCACHE source and Apache-2.0 release, without known conflicting employer/customer/third-party claims; (2) acceptance of the documented MIT/ISC/BSD-2-Clause/PSF-2.0 third-party licensing/redistribution under original grants and required notices; (3) successful access to the private vulnerability reporter form from a non-administrator GitHub account, **without submitting a report**; and (4) no known unauthorized disclosure of credentials, customer information or private infrastructure in the public source/docs/history. These are maintainer attestations, **not an independent legal opinion or forensic secrecy guarantee**.

[PR #68](https://github.com/teixemf/repocache/pull/68) and [PR #70](https://github.com/teixemf/repocache/pull/70) were **merged** into the release branch: the original upstream `mdurl`/Joyent and `shellingham` notices accompany **both** the authenticated source archive and the independently downloadable wheelhouse. Their presence and byte equality are checked by the candidate build/verification tests; the original pinned wheels are not altered. Post-merge [tests 4/4](https://github.com/teixemf/repocache/actions/runs/39495716866), [native offline 3/3](https://github.com/teixemf/repocache/actions/runs/39495716843) and [rootless rollback 2/2](https://github.com/teixemf/repocache/actions/runs/39495716845) completed **9/9 SUCCESS** at the exact SHA. Python 3.12 and 3.13 logs show 407 general plus 105 mandatory security tests passed per interpreter.

**Important scope boundary:** the historical pending-PR and pre-owner-approval statements below are retained as earlier candidate evidence and are superseded by this checkpoint where they disagree. Technical wheel-license inventory and maintainer acceptance do not establish per-byte inspection of every embedded or vendored copyright text, independent legal counsel review, or protection of future **actual** release assets. Final publisher tag, owner-held real Ed25519 signing, signed artifact/SBOM/license/notice inspection, immutability, PR #67 protected-main promotion and public download checks remain separately gated in #4/#36/#39/#71. Closure of #6 alone does **not** authorize any merge, tag, signature or publication.

---


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

### Historical pre-PR #70 wheelhouse notice gap (now corrected)

Before PR #70, an authenticated source archive carried exact original notices
for mdurl and shellingham, but the wheelhouse was a separate planned GitHub
Release asset that could be downloaded by itself. *Source-only* placement
therefore did not establish independent wheelhouse NOTICE delivery.

[Merged correction PR #70](https://github.com/teixemf/repocache/pull/70)
added an exact copy of `THIRD_PARTY_NOTICES.md` to the wheelhouse TAR,
without modifying any `.whl` byte. The strict verifier requires a bounded,
valid UTF-8 notice and the signed-candidate verifier compares its bytes with
the source archive's reviewed notice. An archive-hash mismatch or modified
notice fails closed. **PR #70 was reviewed and merged**, and protected release
branch native CI subsequently passed all nine required checks at the checkpoint above.
Do not publish any new wheelhouse asset without independently verifying that
its final notice bytes and signed SHA-256 match the approved source and policy.

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
historical development repository **private**, and no public
GitHub Releases or version tags existed as of this audit.

**Limits:** these are regex/content review findings, not a forensic
credential scanner; they do not cover nonreachable Git objects, encoded
secrets, original ownership/third-party IP agreements, or artifacts that
do not exist yet. Previous bounded patch-history review is recorded in
[#1](https://github.com/teixemf/repocache/issues/1); it is not retested
as an independent forensic guarantee here.

### Release blockers that cannot be inferred from license metadata

1. **Origin/title — owner-accepted for this source candidate:** the maintainer
   attested sufficient rights to publish original REPOCACHE source under
   Apache-2.0, without known conflicting claims. AI drafting and an independent
   public Git root do **not** transfer third-party copyright or establish
   independent statutory title certification.
2. **Effective reporting — reporter-side form verified:** the maintainer
   opened `Security → Advisories → Report a vulnerability` using a non-admin
   GitHub account. A completed private report, maintainer delivery and
   operational response remain **NOT TESTED**; no fabricated report is required.
3. **Final real assets — NOT VERIFIED:** reconcile the actual owner-signed
   source and wheelhouse digests, runtime wheel contents, notices and
   provenance only after separately authorized publishing. Any dependency
   or notice change requires renewed audit and newly signed hashes.

**Decision:** technical licensing patterns and published terms are
consistent with permitted **unchanged** third-party wheel redistribution
*provided all mandatory notices really travel with each asset*.
The notice-delivery condition was remediated by merged PR #70. The maintainer
has accepted the documented source ownership and third-party licensing policy
for this bounded candidate; independent legal certification and final publisher
asset verification remain **NOT VERIFIED**. This AI-assisted engineering
review is not an independent legal opinion. Although #1 and #6 are closed
for their bounded pre-main source acceptance, **PR #67 remains draft**:
its separate exact-head review, GitHub gates and explicit owner merge
approval are required before protected-main promotion.

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

## Integrated source and independent wheelhouse notices

[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) contains exact
version-tagged upstream MIT/ISC copyright and permission texts for
`mdurl 0.1.2` and `shellingham 1.5.4`, plus the transitive mdurl Joyent
attribution. Both the source archive and independent wheelhouse include
the reviewed notice through the merged, authenticated builder/verifier
allowlists. Original hash-pinned `.whl` bytes are **not rewritten**. The
upstream license-tag provenance is recorded in the notice document; the
texts were taken from upstream, not reconstructed from SPDX shorthand.
Build-only `wheel 0.45.1` remains separately recorded in the SBOM, rather
than being asserted to ship in the runtime wheelhouse.

The maintainer accepted these documented redistribution conditions for
the bounded source candidate; this is **not** independent legal clearance
or evidence for not-yet-created actual publisher artifacts. Inspect final
signed assets to confirm copyright notices accompany each distribution.

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

Until the publication-stage checks above have reproducible evidence, actual
signed-asset notice delivery, release immutability and publication acceptance
remain **NOT VERIFIED**. The source/maintainer rights-policy acceptance in #6
is complete within its documented scope; the deterministic CI/license
inventory is not an independent legal opinion or a production
NGINX/systemd/SELinux test.
