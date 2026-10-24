# Signed release candidate acceptance (v0.5.0+)

This initial implementation is strictly for an **actual v0.5.0 candidate
upgraded from published v0.4.0**. The workflow framework can be adapted for
later releases, but the verifier deliberately refuses v0.5.1, v0.6.0 and other
unreviewed tags until a separate reviewed PR changes the pinned prior-public
baseline, approved version choice, compatibility requirements and native tests.
A passing v0.5.0 test is NOT evidence of v0.6.0 compatibility.

This is a controlled **prepublication operator runbook**, not authorization to
tag, sign, merge, publish, bypass GitHub rulesets or change production systems.
This workflow consumes the **actual FINAL owner-signed bytes**, not CI fixtures
or rebuilt equivalents. See #76 and docs/RELEASE_ACCEPTANCE_POLICY.md.

## Trust boundaries and staging

1. Maintainer reviews/merges source code separately through protected main,
   approves a distinct version tag and runs the existing official unsigned
   release.yml build with the owner account. All build jobs must succeed.
2. The maintainer independently verifies the official unsigned artifact and
   uses scripts/offline_sign_release.py to sign the exact final source archive,
   real wheelhouse and provenance with their encrypted Ed25519 **private key
   held ONLY on their trusted workstation**. Never upload key/passphrase,
   tokens or encrypted private-key material to GitHub or a runner.
3. With distinct approval, stage exactly eight final signed files as assets
   on an existing **GitHub Draft Release**, bound to the exact reviewed tag.
   A Draft remains mutable, is not an immutable public release and requires a
   read-only authenticated API to access its assets. **Do not Publish**.
4. Run the read-only Signed release candidate acceptance workflow by manual
   workflow_dispatch on protected main. Its GH_TOKEN has only contents:read
   and actions:read (source-run/job and evidence-artifact API access), with
   NO contents:write, actions:write or publisher signing permissions.
   Credentials are NEVER forwarded from api.github.com to a redirect/CDN.
5. The verifier checks immutable reviewed tag/source ancestry, owner-triggered
   official run, 8 draft asset IDs and SHA-256, real Ed25519 manifesto and
   provenance signatures, independent public-key DER fingerprint, compatibility
   with the already-published v0.4.0 and signed source/dependency locks.
   Candidate code is not executed before authentication.
6. Native disposable Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12
   jobs first install the genuine published v0.4.0 from its pinned real
   signed bytes, then use the noninteractive CLI and exact authenticated
   offline draft candidate to exercise supported upgrade, same-version
   repair, fail-closed negative paths, rollback and NGINX/TLS/APT/DNF
   preservation. No CI signing key or production host is involved.
7. Only when both native jobs and authenticated draft verification succeed,
   the final CI job rechecks the draft IDs/hashes and uploads canonical
   acceptance evidence. That evidence is itself checked against its immutable
   GitHub Actions artifact SHA-256 and the originating successful workflow.

## Immutable v0.4.0 archive and reviewed v0.5 first-party wheel

The publicly released v0.4.0 updater accepts **exactly** its frozen
`RELEASE_FILES` source TAR members. An archive containing the new v0.5
`submissions`, `intake`, or privileged review modules will fail closed.
**Do not modify the public v0.4.0 verifier or append new TAR members.**

The v0.5 legacy eight-asset profile must retain that source archive while
shipping every reviewed first-party Python module in the **separately signed
and hash-locked application wheel**, inside the signed wheelhouse. For this
transition, `scripts/verify_release_candidate.py`, invoked by the
**owner's offline signer before unlocking the private key**, now checks
all of the following on the actual candidate files:

1. Rebuild the old-compatible source archive deterministically from the
   reviewed checkout and require exact SHA-256 identity.
2. Verify the wheelhouse TAR, its signed-bound SHA-256, complete pinned
   wheel lock/SBOM, license notices and application wheel version.
3. Compare the **full first-party Python module inventory and exact bytes**
   between the reviewed checkout and the extracted, hash-pinned application
   wheel; refuse missing, extra, modified, symlinked, duplicate ZIP or
   unreviewed installer-path contents. This check is repeated at
   **signing time**, not merely assumed from an earlier CI wheel build.
4. Reject all discrepancies before requesting access to the owner key.
   This check alone does not authenticate the signing identity or replace
   signed Draft Release / published-v0.4 native acceptance.

The trusted checkout and complete source commit must be independently
authenticated by the existing protected release-operator identity checks.
The owner signer additionally refuses first-party Python modules that are
missing from the checked-out Git index or present as untracked/ignored local
files. Matching a local changed wheel to an unreviewed working-tree file is
not sufficient evidence of reviewed provenance.
Do not sign from an altered/unreviewed checkout. The final owner-signed
candidate must still be exercised through
`signed-candidate-acceptance.yml` on Debian 13 and AlmaLinux 10 with
actual public v0.4.0 baseline. Installed CLI/TUI/submission imports and
recoverability must be proven; **full C7 remains NOT VERIFIED** until
the genuine test has completed with immutable evidence.

## Prerequisites for each real signed candidate

- All relevant feature and security PRs merged/reviewed with exact-head
  required CI successful; separate owner approval for tagging and signing.
- Tag and version metadata consistent with the reviewed commit, and all
  original source release.yml build jobs successfully completed (record run
  ID and attempt). Previous version must be a **real published stable**
  release, never a synthetic v0.3.0 fixture.
- Reviewed candidate release-policy.json must contain version matching the
  tag, support Debian 13 and AlmaLinux 10 and explicitly permit migration
  from the real v0.4.0 in compatible_from. A breaking config/API/schema
  migration not implemented/tested is a release BLOCKER.
- All eight exact signed candidate assets staged as Draft with no missing,
  extra or modified files. Store signing keys outside repo and Actions.
- No previously accepted draft has changed after validation. If it has,
  rebuild/re-sign/retest rather than suppress any failing criteria.

## Running CI

In GitHub: Actions > Signed release candidate acceptance > Run workflow.
Select the **default main branch** and supply all required inputs:

| Input | Meaning |
| --- | --- |
| tag | Exact owner-approved tag, e.g. v0.5.0 |
| commit | Full 40-character reviewed commit SHA |
| draft_release_id | Numeric existing Draft Release ID |
| source_run_id | Owner-triggered successful official release.yml build run |
| source_run_attempt | Exact successful run attempt, normally 1 |

Four jobs must complete SUCCESS, without skips or omissions:
Signed draft publisher and asset identity; Upgrade signed candidate
(debian13); Upgrade signed candidate (almalinux10); and Freeze final candidate
acceptance evidence. Collect the workflow run URL, job logs and candidate
asset fingerprints. Any FAIL, missing/skipped job or unfinished native run
blocks publication.

## Mandatory prepublication check (trusted operator terminal)

After a fully successful CI execution, on a clean checkout of the same
protected main commit and with the authenticated GitHub CLI available,
replace the numeric CI run ID in this command:

    GH_TOKEN="$(gh auth token)" python3 scripts/draft_release_gate.py guard \
      --ci-run-id 12345678901

The guard fetches the **actual immutable GitHub Actions acceptance artifact**
(not a locally crafted JSON document), verifies its GitHub ZIP SHA-256 and
association with the specified run, confirms that run was manually
owner-triggered on protected main with **four successful jobs**, and compares
the original eight reviewed asset ID/size/hash values to the **current
mutable Draft Release**. The guardian makes no GitHub modifications.

A successful guard is necessary but **does not authorize publication**.
The owner must separately approve publishing this exact Draft/asset inventory.
Immediately after the owner publishes, perform a fresh readback of the
immutable Release: it must be draft=false, immutable=true, with exactly the
same eight IDs/sizes/SHA-256 hashes, tag and commit. Verify anonymous API/CDN
and real CLI discovery/installation smoke against the actual published
release bytes.

**Security limitation:** an administrator can press Publish or replace draft
assets outside the workflow. These are documented procedural and cryptographic
comparison gates, not a server-side rule preventing a privileged user from
publishing without acceptance. Enforce strict owner review/authorization; no
workflow has write/publish privileges.

## Future published smoke, failures and deferred scope

Existing public-release-acceptance.yml and its reviewed target inventory are
v0.4.0-specific. A **separate reviewed PR** must add and approve the new final
published release's IDs/digests and smoke policy. Never treat testing one tag
as verification of a different published version. If a published immutable
release fails its public smoke tests, open an incident/fix and publish a new
reviewed, signed version; never mutate the immutable public assets.

As of implementation time there is **no genuine signed v0.5.0 draft**.
End-to-end owner-signed draft CI, real v0.4.0 -> v0.5.0 upgrade, postpublication
smoke and physical/booted native-host testing are **NOT VERIFIED**, not PASS.
Container checks do not prove a booted systemd host, enforced SELinux, real
power loss or interactive TUI runtime.
