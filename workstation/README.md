# REPOCACHE Release Operator — workstation-only, partial implementation

Issue: [#88](https://github.com/teixemf/repocache/issues/88)
Architecture: [CLI v1.0](../docs/architecture/CLI_ARCHITECTURE.md)

**Status: foundation only.** This package is not the server executable.
It is installed separately on the trusted maintainer workstation.
No signing key ever enters GitHub Actions. Not a substitute for real
signed-candidate acceptance [#76](https://github.com/teixemf/repocache/issues/76).
Do not use it to publish a release.

## Install from a trusted, reviewed checkout

With Python 3.12+, `venv` support and the standard Python packaging toolchain installed, use an isolated unprivileged virtual environment. Avoid `pip --user` because Debian 13 and other distributions may enforce PEP 668 externally managed Python:

```console
python3 -m venv ~/.local/share/repocache-release/venv
~/.local/share/repocache-release/venv/bin/python -m pip install -e ./workstation
~/.local/share/repocache-release/venv/bin/repocache-release --help
```

An eventual workstation installer should make the virtual environment, `gh` prerequisite and launcher setup idempotent. That installer is **not yet implemented**; the commands above are a development-only installation example.

The development source root must have `origin` set to the official
`teixemf/repocache` repository. Execute from the checked-out source
directory; `prepare` creates a detached tag worktree in private XDG
state, not inside a mutable development branch.

## Currently registered operations

```console
repocache-release environment check --json
repocache-release candidate prepare v0.5.0 --json
repocache-release candidate status v0.5.0 --json
```

The `environment check` validates the tools, GitHub authentication,
independently pinned Ed25519 public fingerprint and protected key path.
It reports if the signer file is missing, but does not unlock it. The
default encrypted PEM path remains
`~/repocache-signing/repocache-release-private.pem` (owner-only 0600).
The key is not copied or backed up by the program.

`candidate prepare` requires exactly one finished, successful and
owner-triggered release-workflow run for an existing version tag reachable
from reviewed `main`. It obtains the unsigned GitHub Actions artifact
under `$XDG_STATE_HOME/repocache-release/vX.Y.Z`, checks the source
archive by deterministic rebuild and checks exact locked dependency
digests. Reusing the same immutable inputs succeeds with no new
generation. A mismatched run or altered asset fails closed; interrupted
preparation leaves a quarantined directory for manual review, not
destructive auto-cleanup. GitHub releases are not created.

The password for `candidate sign` is read from an existing **protected
file descriptor**, never a CLI argument, environment variable, log or
interactive fallback:

```console
repocache-release candidate sign v0.5.0 --passphrase-fd 3 --json
```

The caller must securely provide FD 3. Do **not** pass the password by
`echo ...`, through shell history, or from an unprotected plaintext file.
The signer authenticates the reviewed GitHub run again, verifies the exact
candidate bytes, validates the encrypted private key against the approved
public fingerprint, and creates/round-trip verifies the original release
manifest and provenance. No release is staged or published as a result.

`candidate status` only inspects the local versioned, nonsecret state
and bytes. Until the external signed-candidate acceptance engine is
merged and run, it always reports `"acceptance": "NOT VERIFIED"` and
`"ready_to_publish": false`. This is deliberate.

**Gated commands (implemented but fail closed until #76/#78 is merged and
an actual signed candidate passes):**

```console
repocache-release candidate stage v0.5.0
repocache-release candidate status v0.5.0 --acceptance-run-id 123456789 --json
repocache-release candidate publish v0.5.0 --acceptance-run-id 123456789 --approve-sha256 EXACT_CANDIDATE_FINGERPRINT
```

The local operator refuses to load `draft_release_gate.py` unless it is
present, unchanged and tracked on **exact protected main**. The gate
infrastructure [PR #77](https://github.com/teixemf/repocache/pull/77)
is now merged, but **no actual owner-signed v0.5.0 Draft candidate has been
accepted** under [#76](https://github.com/teixemf/repocache/issues/76).
A merged verifier does not authorize staging or publication. `stage` is a separately requested **remote write**: it
uploads all eight owner-signed files once into a Draft Release, never publishes,
then reads back the complete remote inventory and stores its ID. It refuses
existing versions unless it is resuming a previously recorded exact-matching
Draft. A crash after upload but before state commit may require an operator
inspection; the command never overwrites or auto-retries missing assets.

`status --acceptance-run-id` consults the **real signed-candidate acceptance
artifact and required 4/4 CI jobs** through the merged #76 verifier and checks
that its assets and draft ID still match the local signature. It reports
`NOT VERIFIED` without a verified run and never infers acceptance from a
synthetic test. An authentic CI result is necessary, not sufficient, for
publication.

`publish` must be invoked **separately** with the exact reviewed SHA-256
fingerprint displayed by `candidate status` and the accepted CI run ID.
Immediately before the only publish write, the operator revalidates:
the local signed bytes, the owner's account, the Draft release ID and asset
hashes, the exact successful owner-run native Debian 13 / AlmaLinux 10
acceptance evidence and the reviewed release policy. After publication it
requires `immutable: true` and the unchanged IDs/sizes/hashes on the real
GitHub Release. If postpublication verification fails, report
`POST_PUBLISH_UNVERIFIED` and **do not claim rollback was possible**.

The commands' presence is **not** approval to publish. The merge, tag,
signature, stage and publication each require the owner's own authorization
at the relevant time. This implementation PR does not perform any of them.


## Scriptability and security

- JSON on both success and failure; global `--json` accepted before the
  object or after the command. Human errors on stderr.
- Version identity must be a literal `vX.Y.Z`, never an alias for
  an arbitrary latest version. Only exact owner-initiated successful
  GitHub Actions runs are eligible.
- All commands are noninteractive: no implicit credentials, SSH agent
  prompts, root escalation or hidden confirmation.
- Candidate directories are owner-only, JSON records 0600, written
  by fsync-and-rename. Do not edit them while an operation is active.
- This is a preliminary partial operator: concurrency/lock hardening,
  robust authentication of candidate downloads and real operator-key
  rehearsal must pass their own acceptance tests before use on a live
  version. The general CLI v1.0 exact error/exit status registry and
  JSON schema are still cross-program integration dependencies.
- A GH account token is used locally for read-only candidate retrieval.
  Never share it. No production release is created.

## Verified scope versus real-signature gate

The workstation package is separately installable and tested through disposable
unit/security/CLI scenarios on both supported Python versions, but those tests
do **not** demonstrate using the owner's actual encrypted Ed25519 PEM,
staging eight owner-signed candidate assets, running the genuine native
candidate-acceptance workflow or publishing an immutable release.

Only the source code, tests and documentation can be integrated before the
proprietor uses the private key on their local development workstation.
The parent acceptance criteria in #88 and #76 remain **NOT VERIFIED** until
those real operations and their exact returned hashes/run IDs are recorded.
Integration of this infrastructure must never set either issue to PASS by
itself. No release tag or Draft is created by importing/installing the package.

## Operational constraints

Compatibility requires genuine Debian 13 and AlmaLinux 10 tests in CI
and on representative hosts before declaring the tool supported.
No tests or documentation permit merging, signing, staging or publishing
without distinct authorization. The v0.4.0 public release and its eight
immutable signed assets must remain unchanged; v0.6.0+ source-only
dependency profiles require independent signed-profile validation
(#80/#82/#84), not the v0.5.0 legacy wheelhouse parser.
