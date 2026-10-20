# v0.4.0 signing and publication — operator procedure (NOT YET AUTHORIZED)

**Read first:** [phased acceptance](RELEASE_0.4.0_PHASED_ACCEPTANCE.md),
[release acceptance gates](RELEASE_0.4.0_GATES.md) and
[third-party rights worksheet](THIRD_PARTY_RIGHTS_REVIEW.md).

This is a **preparation checklist**, not permission to perform any of these
operations. The first public v0.4.0 is a CLI/TUI frontend for **existing
operator-configured NGINX** on Debian 13 and AlmaLinux 10; it does not
provision NGINX or upgrade private/pre-public installations.

## Preconditions and distinct approvals

Record the precise GitHub acceptance comment/authorization for each:

1. **PASS — complete:** documentation [PR #66](https://github.com/teixemf/repocache/pull/66) was
   separately owner-approved and merged into the candidate; nine exact-head
   required CI checks passed on the resulting source commit.
2. **PASS — complete:** candidate [PR #41](https://github.com/teixemf/repocache/pull/41) was
   separately owner-approved and squash-merged to `release/v0.4.0`;
   original issue #11 and owner-approved revised issue #12 both have
   traceable acceptance PASS and are CLOSED. Source acceptance after those
   integrations was revalidated on the actual release branch.
3. **PASS — correction scope, not legal clearance:** [PR #68](https://github.com/teixemf/repocache/pull/68)
   was owner-authorized and merged, carrying verbatim mdurl 0.1.2 MIT/Joyent
   and shellingham 1.5.4 ISC notices in the authenticated release archive,
   without rewriting pinned wheels. Exact protected release branch SHA:
   `f52c13e4b532d80fa657cc6c5e336d4849ee4497`.
   The nine mandatory **post-integration push jobs all PASS**:
   [Tests](https://github.com/teixemf/repocache/actions/runs/39478901928),
   [offline](https://github.com/teixemf/repocache/actions/runs/39478901879),
   [rollback](https://github.com/teixemf/repocache/actions/runs/39478901941).
   If this runbook is edited later, recheck the latest release-branch SHA.
4. **NOT VERIFIED / pre-main gate:** complete human-approved
   license/NOTICE redistribution and privacy/source provenance evidence
   (#1/#6) for *all* final third-party wheels, embedded/vendored code and
   actual source archive; verify the effective confidential reporting
   channel. The owner reconfirmed that Private Vulnerability Reporting and
   Release Immutability are enabled in the public repository settings.
   These statements are **owner attestations**; confidential end-to-end
   reporting and immutable published-asset behavior have **not** been
   independently tested. Record the remaining publication-trust evidence
   under #4/#36/#39.
5. **NOT AUTHORIZED:** separately review and approve the prepared
   **release-to-main** [PR #67](https://github.com/teixemf/repocache/pull/67)
   only after its own head/base, nine required checks, source-rights
   signoff and all blocking reviews are complete. PR #67 is a
   **protected-main promotion**, not a correction PR; prior permission to
   integrate correction PRs does not authorize it.
6. **NOT AUTHORIZED / separate operations:** version tag creation,
   execution of offline Ed25519 owner signing and publication of actual
   release assets each need separate explicit affirmative maintainer
   approval. No previous merge consent covers these actions.
7. **PASS / prepublication technical gate:** [#65](https://github.com/teixemf/repocache/issues/65)
   has 7/7 maintainer-approved *replacement prepublication* criteria PASS on
   protected release SHA `1f5c70e3b230865853470be863ab2ed5fd449e1c`,
   with actual native Debian13/Alma10 offline/signed-fixture CI **9/9 PASS**:
   [Tests](https://github.com/teixemf/repocache/actions/runs/39486622574),
   [offline/signing](https://github.com/teixemf/repocache/actions/runs/39486622633),
   [native rollback](https://github.com/teixemf/repocache/actions/runs/39486622677).
   The seven *original* actual public-release tests were separately preserved
   under [#71](https://github.com/teixemf/repocache/issues/71) for execution
   **immediately after** owner-authorized publication; they are NOT VERIFIED.
   No alpha is required or can replace verification of official v0.4.0 assets.

No private signing key, passphrase, private credential or unsigned developer
checkout belongs in ordinary CI, PR artifacts, logs, issue comments or Git.

## A. Protected main, reviewed tag and unsigned artifact workflow

The following shell commands are **examples to run only after authorizations**
on a **trusted maintainer workstation** with `git`, `gh`, `python3`,
`openssl`, SHA-256 tools, Docker and the platform-specific wheelchain
prerequisites, as applicable. Use the root of a *clean, independently checked*
local REPOCACHE checkout; replace angle-bracket placeholders with real values.

```bash
set -Eeuo pipefail
REPO="teixemf/repocache"
TAG="v0.4.0"

gh auth status
git fetch --no-tags origin main
# Fetch only the separately approved tag; do NOT force-update tag refs.
git fetch origin "refs/tags/$TAG:refs/tags/$TAG"
git switch --detach "$TAG"
COMMIT="$(git rev-parse --verify "$TAG^{commit}")"
test "$(git rev-parse HEAD)" = "$COMMIT"
test -z "$(git status --porcelain --untracked-files=no)"

# Inspected tag commit MUST be on protected main (main identical or ahead).
STATUS="$(gh api "repos/$REPO/compare/$COMMIT...main" --jq .status)"
case "$STATUS" in ahead|identical) ;; *) echo "STOP: unreviewed tag" >&2; exit 1 ;; esac

# After separate tag approval, the *owner* manually dispatches the
# read-only release workflow ON this tag through GitHub CLI:
gh workflow run release.yml --repo "$REPO" --ref "$TAG"

# Read the resulting run ID and ATTEMPT from GitHub Actions after success.
gh run list --repo "$REPO" --workflow release.yml --event workflow_dispatch --limit 5
```

**Important:** do not create a tag as part of a check. The tag must already
exist, have separate affirmative owner authorization, and point to the reviewed
protected-main commit. The `v*` ruleset includes a repository-administrator
role bypass; owner privilege is not evidence of tag immutability. Never
force-move a release tag; use a new version if a signed release needs repair.

The release workflow `.github/workflows/release.yml` is a manual
`workflow_dispatch` workflow with `contents: read`. Its assembly checks
the owner, tag/version identity and ancestry, then builds **unsigned**
source/checksum and pinned offline wheels. It does **not** sign or upload a
GitHub Release. Its `unsigned-release-candidate` CI artifact has a retention
limit; download the exact successful workflow attempt before that deadline.

## B. Download and verify the unsigned exact-run candidate

```bash
# Fill these ONLY from the owner-dispatched, completed SUCCESS Actions run.
RUN_ID="<successful-run-id>"
ATTEMPT="<run-attempt>"
case "$RUN_ID:$ATTEMPT" in *[!0-9:]*|:*|*:) echo "STOP: invalid run IDs"; exit 1 ;; esac

mkdir -p dist
gh run view "$RUN_ID" --repo "$REPO"
gh run download "$RUN_ID" --repo "$REPO" \
  --name unsigned-release-candidate --dir dist

(
  cd dist
  sha256sum --check "repocache-$TAG.tar.gz.sha256"
)
python3 scripts/verify_release_candidate.py dist

# Independently compare the fixed trust anchor to the reviewed fingerprint.
openssl pkey -pubin -in keys/repocache-2026-10.pem -outform DER \
  | sha256sum
# Expected DER public-key SHA-256:
# 7bbf4b840f762a610da648869564a5b77669f24191d0c5c7af04c14c043dc0fb
```

Note: GitHub `gh run view` must show exact SHA `$COMMIT`, event
`workflow_dispatch`, branch `$TAG`, actor `teixemf`, same run attempt,
all required source/OS wheelchain checks `SUCCESS`, and no unauthorized
source files. The offline signer **rechecks this identity** via GitHub's API.
Reject mismatched or inaccessible run/asset identities.

## C. Owner-held offline signing (separate explicit approval)

Keep the private Ed25519 key outside the Git checkout, ideally on an
isolated signing workstation. The public verification key committed to Git
is **not secret**. The encrypted private key must match the pinned
`repocache-2026-10.pem` fingerprint, be a regular **0600** file, and be
backed up securely with documented key rotation/revocation procedure.

```bash
# Placeholder only: never commit or share the actual private key path/content.
KEYFILE="/secure/offline/location/repocache-signing-key.pem"
test -f "$KEYFILE" && test ! -L "$KEYFILE"
test "$(stat -c '%a' "$KEYFILE")" = 600

# Run ONLY after separate offline-signing approval. Password is requested
# securely at the terminal and must not be passed on a command line or logged.
python3 scripts/offline_sign_release.py \
  --bundle "dist/repocache-$TAG.tar.gz" \
  --private-key "$KEYFILE" \
  --commit "$COMMIT" \
  --run-id "$RUN_ID" \
  --run-attempt "$ATTEMPT"
```

The signer performs independent candidate SHA-256 / wheelchain / SBOM /
source-lock verification, approved public key check, GitHub tag/main/workflow
identity validation, then creates and immediately verifies:

- `repocache-v0.4.0.tar.gz.manifest.json`
- `repocache-v0.4.0.tar.gz.manifest.json.sig`
- `repocache-v0.4.0.tar.gz.provenance.json`
- `repocache-v0.4.0.tar.gz.provenance.json.sig`

The unsigned build supplies the source archive, exact `.sha256`, pinned
`.wheelhouse.tar.gz` and its `.sha256`. Signing keys must **not** be
replaced with ephemeral CI test keys.

## D. Separate approval to publish all eight official assets

**Do not run before distinct publication authorization and legal/rights gate.**
List and review the complete eight-file inventory, then publish in one
controlled GitHub Release. Use GitHub's **draft release** to stage artifacts
before publishing, while observing release immutability settings.

```bash
BUNDLE="dist/repocache-$TAG.tar.gz"
for suffix in "" ".sha256" ".manifest.json" ".manifest.json.sig" \
  ".wheelhouse.tar.gz" ".wheelhouse.tar.gz.sha256" \
  ".provenance.json" ".provenance.json.sig"; do
  test -f "$BUNDLE$suffix" && test ! -L "$BUNDLE$suffix"
done
sha256sum "$BUNDLE"*
# Only with separately approved publication and finalized release notes:
gh release create "$TAG" \
  --repo "$REPO" --verify-tag --draft \
  --title "REPOCACHE $TAG" \
  --notes "First standalone public REPOCACHE CLI/TUI frontend release for existing NGINX." \
  "$BUNDLE" "$BUNDLE.sha256" "$BUNDLE.manifest.json" \
  "$BUNDLE.manifest.json.sig" "$BUNDLE.wheelhouse.tar.gz" \
  "$BUNDLE.wheelhouse.tar.gz.sha256" "$BUNDLE.provenance.json" \
  "$BUNDLE.provenance.json.sig"
```

Before publishing the staged draft, inspect displayed asset names, hashes,
release notes, signed manifest/public trust anchor, expected tag/source
commit, final rights/NOTICE records, effective immutability and private
security reporting. Publishing a draft is a **separate owner-authorized**
operation; release creation itself may require publication permissions and
must not be mistaken for verified immutable final assets.

## E. After publication: mandatory operational acceptance

Record final public GitHub Release URL/asset IDs, archive/wheelhouse SHA-256,
signed manifest hash and publisher key ID, provenance statement/signature,
reviewed tag/main commit, actions run ID and run attempt, actual release
immutability evidence, and security reporting status. Keep secrets private.

[Issue #71](https://github.com/teixemf/repocache/issues/71) then requires
live **anonymous** `repocache update check` and `repocache update list`,
real selected version public-download install, same-version repair and
failure/rollback on clean, disposable Debian 13/Python 3.13 and AlmaLinux
10/Python 3.12. Test actual published assets, not CI-only fixtures.

Every **applicable prepublication issue** must have evidence-backed PASS
before promoting/publishing v0.4.0. The original seven real-public-release
criteria were transferred unwaived from closed #65 to OPEN #71, under the
v0.5.0 milestone for tracking, and **must be exercised immediately after**
publication; they cannot be used as a prepublication circular dependency. Real booted systemd/SELinux and physical energy loss remain
explicitly deferred **NOT TESTED**, never reported as successful tests.

**STOP conditions:** any unreviewed source/tag/run, missing asset, wrong
signature/key fingerprint, unsafe dependency lock, rights/notice blocker,
confidential-reporting failure, failed required check or unapproved action.
Do not mutate/re-upload an already published immutable release: investigate,
rollback if supported, and prepare a new reviewed version for any fix.
