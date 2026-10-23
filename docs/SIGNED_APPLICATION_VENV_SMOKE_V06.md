# Signed first-party wheel rehearsal and CLI/TUI smoke — v0.6.0+

**Status:** PARTIAL / INTERNAL ONLY / NON-ACTIVATING. Work for #83, #84 and #85; stacked on draft [PR #103](https://github.com/teixemf/repocache/pull/103) → #102 → #101 → #100 → #99 → #98. Source-only online release signing and actual installation are not yet production-ready.

## Trust and execution sequence

1. The existing `updater.update_transaction` exclusive lock is taken; recovery and installed layout checks run under that lock. Only the dedicated non-root REPOCACHE account on Debian 13/Python 3.13 or AlmaLinux 10/Python 3.12 can proceed.
2. `signed_dependency_staging.verified_candidate_wheels` authenticates the original publisher Ed25519 manifest and source, the **eight-asset** inventory, independently authenticated REPOCACHE-owned wheel, signed release-policy bytes, transitive dependency locks and SBOM identities. Verification finishes **before** upstream download.
3. `application_wheel.verify` regenerates every expected first-party wheel byte from the already signed source and refuses any mismatch. The authenticated upstream dependency lock is also rejected **before networking** if it contains the REPOCACHE application's own normalized package name (`repocache-control`); publisher approval alone must not permit upstream first-party impersonation. The approved third-party wheels are downloaded separately from approved HTTPS origins into a private new temporary workspace.
4. A native Python venv is created. The existing rootless `--isolated --no-index --no-deps --only-binary=:all: --require-hashes` pip step installs all approved third-party wheels. The identical verified first-party wheel is written using exclusive `O_NOFOLLOW | O_EXCL` file creation and fsync; a **local SHA-256-locked** application requirements file is generated without invoking a build backend, resolver, or index. The REPOCACHE-owned wheel is then installed offline using the same restrictive pip flags.
5. Run `pip check` and `pip list --format=json`; require all approved third-party name/version pairs **plus exactly repocache-control at the signed release version**. Reject unexpected or duplicate packages, allowing only the isolated venv's bootstrap pip/setuptools/wheel extras.
6. Run the just-installed `repocache --version` and require its precise version, then `repocache --help` and confirm the update command is exposed. Import `RepoCacheApp` under the fresh venv using `python -I -c` and verify the class is a Textual App with key bindings. **This is a read-only import smoke, NOT a complete headless Textual interaction or functionality validation.**
7. Delete the entire staged dependency/wheel/app/venv workspace on success or ordinary error. Return `status=application-and-dependencies-verified-only`, `activated=false`. The current-generation pointer, installed.json, recovery journal, NGINX, TLS, APT/DNF and application services are never updated.

Tests inject failures in signature acceptance, first-party byte verification, downloads, native venv, each pip operation, `pip check`, installed package inventory, CLI version/help and TUI import, and demonstrate the active signed legacy generation and unrelated operator configuration remain untouched.

## Remaining mandatory acceptance gates

- **NOT VERIFIED:** Complete owner-signed real v0.6.0 eight-asset candidate; final immutable public release readback and complete original-code/licensing/source-to-wheel audit.
- **NOT VERIFIED:** Real third-party PyPI wheel download of every locked direct/transitive wheel and clean native installs on Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12. CI mocked network and application orchestration; older tests install a synthetic first-party wheel in a real disposable venv, **not** the complete application with dependencies.
- **NOT VERIFIED:** Headless Textual `run_test` keyboard/interaction contract, all approved client CLI commands, CLI JSON contract and full #14/#23 UI functionality.
- **NOT VERIFIED:** Production updater profile-aware signed download, atomic active-generation switch, same-version repair, rollback after SIGKILL/abrupt power loss, SELinux/systemd and disk-exhaustion/orphan cleanup. These cannot be inferred from a successful disposable rehearsal.
- **NOT VERIFIED:** Independent architecture/security review, all dependency PR acceptance, required final native CI/reviews and explicit maintainer merge/release authorization.

The first v0.5.0 bootstrap release must retain schema-1 owner-signed wheelhouse; immutable public v0.4.0 is never rewritten. No production activation, merges, releases, real publisher signing keys or third-party redistributions are part of this branch.
