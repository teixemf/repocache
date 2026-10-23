# Rootless signed-wheel venv rehearsal — v0.6.0+

**Status: PARTIAL / NON-ACTIVATING / NOT RELEASE-ACCEPTED.** Issue #83, parent #79. Stacked on draft PR #101 → #100 → #99 → #98. Immutable published v0.4.0 and initial v0.5.0 schema-1 signed wheelhouse remain unchanged.

## Internal, non-interactive rehearsal

The new online_generation.rehearse_signed_install API is deliberately UNWIRED to the production updater and does not add a CLI flag.

1. Acquire the existing root-owned, process-wide exclusive update transaction and recover a pending old update. Verify the current managed layout before any changes; never execute existing installed code merely to prove it is genuine.
2. Refuse root UID, mismatched native OS/Python, downgrade/same-version preparation and unsafe managed directory ownership. Only Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12 are eligible.
3. Verify publisher Ed25519 signature and inventory, signed policy digest, SBOM closure and exact platform-locked wheel URLs/hashes before any network or pip action. Verify again before invoking the staging downloader.
4. Create a new random owner-private staging location under the managed root. Fetch only approved HTTPS URLs through the strictly bounded and rootless #83 staging primitive.
5. Create a fresh native Python venv. Invoke isolated pip using -I -m pip --isolated install, --no-index, --no-deps, --only-binary=:all:, --require-hashes, --no-cache-dir, --no-input and the exact locally generated wheel lock; updater._run strips ambient pip/PYTHONPATH/proxy/loader environment.
6. Check pip dependencies and exact installed package versions, refusing unexpected runtime packages. Only bootstrap pip/setuptools/wheel may remain besides approved packages.
7. Destroy the downloaded wheel files AND the ephemeral venv both on success and on ordinary failure before releasing the lock. Return status dependencies-verified-only with activated=false. No current symlink, installed.json, transaction journal, NGINX/TLS, cache or client APT/DNF configuration is written.

This is a real code path for a disposable **installation rehearsal**, not a deployable online REPOCACHE generation. A SIGKILL or power loss can leave an orphaned staging directory; all retries use new random paths and never reuse an orphan. Safe orphan cleanup and disk quota tests remain required.

## Critical unresolved security and compatibility work

- The proposed eight-asset source-only candidate now includes a publisher-inventory-bound original-REPOCACHE application wheel (see #84). This non-activating rehearsal does not yet install or smoke-test that first-party wheel. Do not use implicit build-isolation, arbitrary pip install on a source tree, unsigned self-built application wheels or root-run Python build hooks. The #84 first-party wheel contract is a reviewed-merge candidate, not an accepted release; genuine owner-signed native installation and the full activation/rollback gate remain outstanding.
- The existing production updater intentionally refuses schema-2 online releases. The final online-only activation path must reuse its journal/recovery, compare authentic same-version identities, run CLI/TUI smoke and prove last-good rollback. **This PR does not activate any generation.**
- No actual owner signing key, native real PyPI/CA/ABI proof, exact approved transitive lock, managed REPOCACHE CLI/TUI install, real owner-signed v0.5.0→v0.6.0 migration or immutable GitHub release is provided here. Synthetic subprocess/staging mocks are not real online installation proof.
- Runtime wheel hashes prove byte identity, not third-party code safety. Dependabot advisories, provenance, exact license inventory and independent security review remain release gates.
- This branch is stacked on four UNMERGED drafts. Reconcile duplicate PR #93 staging code before integrating; do not merge separately.

## Tests and current evidence rules

The dedicated tests verify transaction ordering, recovery, native target denial, correct isolated pip command flags, pip check, exact dependency inventory, root/symlink refusal, cleanup after each simulated signature/download/venv/install/check/list failure, untouched current generation, installed manifest and NGINX sentinel on injected pip failure. Existing signed candidate/authentication and legacy native container CI is also required at the exact PR head.

A PASS for these tests is **synthetic only**. Real Debian 13 and AlmaLinux 10 installation/recovery and publisher-key owner-signed candidate tests remain NOT VERIFIED until actually executed. No merge, release, signing or production activity is authorized by this draft.
