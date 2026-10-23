# REPOCACHE Release Operator — workstation-only, partial implementation

Issue: [#88](https://github.com/teixemf/repocache/issues/88)
Architecture: [CLI v1.0](../docs/architecture/CLI_ARCHITECTURE.md)

**Status: foundation only.** This package is not the server executable.
It is installed separately on the trusted maintainer workstation.
No signing key ever enters GitHub Actions. Not a substitute for real
signed-candidate acceptance [#76](https://github.com/teixemf/repocache/issues/76).
Do not use it to publish a release.

## Install from a trusted, reviewed checkout

With Python 3.12+ and the standard Python packaging toolchain installed:

```console
python3 -m pip install --user -e ./workstation
repocache-release --help
```

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

**Not yet exposed**: `candidate stage` and `candidate publish`.
They require the authentic signed Draft candidate gate in #76/#78 and
the separate owner authorization of an immutable publication. Do not
create placeholder subcommands that can accidentally issue writes.
The approved **target syntax** is documented in
[PR #108](https://github.com/teixemf/repocache/pull/108), which has
not been merged into main.

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

## Operational constraints

Compatibility requires genuine Debian 13 and AlmaLinux 10 tests in CI
and on representative hosts before declaring the tool supported.
No tests or documentation permit merging, signing, staging or publishing
without distinct authorization. The v0.4.0 public release and its eight
immutable signed assets must remain unchanged; v0.6.0+ source-only
dependency profiles require independent signed-profile validation
(#80/#82/#84), not the v0.5.0 legacy wheelhouse parser.
