# v0.6.0 owner-signed online candidate — non-activating acceptance entrypoint

**Status: preparatory tooling; no genuine publisher-signed candidate has been provided.** Tracks #83, #84, #85 and #112; stacked draft PR, no merge/activation/publication.

## Input and trust

The publisher must build the candidate from reviewed, versioned 0.6.0 owned source, approve BOTH complete direct/transitive platform locks with exact upstream URLs, hashes and provenance, and create the CycloneDX SBOM. Sign only outside GitHub Actions with the protected actual owner Ed25519 private key. Keep signing authority away from repository, CI, GitHub secrets and disposable test keys.

The v0.6.0 source-only candidate consists of exactly eight files:

1. repocache-v0.6.0.tar.gz
2. repocache-v0.6.0.tar.gz.sha256
3. repocache-v0.6.0.tar.gz.dependency-lock.json
4. repocache-v0.6.0.tar.gz.sbom.json
5. repocache_control-0.6.0-py3-none-any.whl
6. repocache-v0.6.0.tar.gz.assets.json
7. repocache-v0.6.0.tar.gz.manifest.json
8. repocache-v0.6.0.tar.gz.manifest.json.sig

Do not treat an eight-file synthetic fixture or merely renamed v0.4 source as a genuine candidate. The 0.4→0.5 bootstrap must still use the genuine signed schema-1 offline-wheelhouse profile before accepting any 0.6 profile.

The lock must contain exact per-wheel identity, binary wheel filename, SHA-256 and approved files.pythonhosted.org URL for both Debian13/Python3.13 and AlmaLinux10/Python3.12. The SBOM must match both platforms. Existing reviewed legacy pins are **not automatically approved final 0.6 locks**.

## Signed preflight (no candidate execution or package index network)

Provision the genuine publisher public key independently in the existing root-owned /etc/repocache/trust.d key store, following the signatures trust-store requirements; do not import a key from release assets.

On a controlled checkout of this branch, run:

    python3 scripts/verify_online_candidate.py --assets-dir /safe/candidate-v0.6.0 --version 0.6.0

The script requires exactly eight assets and safe regular file metadata, opens files using a pinned directory file descriptor with no symlinks and bounded reads, then reuses the production Ed25519/inventory/source-equivalence/policy/lock/SBOM verification. Success emits script-friendly JSON with activation=false, failure emits a concise error and exits nonzero. It does not download, install or activate anything.

## Non-activating real rehearsal on disposable native supported OS

Once the authentic owner-signed assets are available, a prepared signed 0.5.x predecessor is installed, and the OS has the required native interpreter, protected update lock, patched non-setuid Bubblewrap and CA bundle:

    python3 scripts/verify_online_candidate.py --assets-dir /safe/candidate-v0.6.0 --version 0.6.0 --rehearse --ca-file /etc/ssl/certs/ca-certificates.crt

Use the appropriate native CA file path on each platform. The rehearsal routes into the existing exclusive-transaction, fail-closed online_generation.rehearse_signed_install path. It downloads the signed-lock-approved upstream wheels over TLS, executes wheel-only offline pip/CLI/Textual inside Bubblewrap, checks state and cleans the disposable venv. It must return activated=false. Missing prerequisites are a failure, not an unsandboxed fallback.

No signing, tag, public release, production activation, migrations or host provisioning are performed by this tool.

## Status and acceptance limitations

| Requirement | Verdict |
| --- | --- |
| Exact signed eight-asset preflight and strict no-network rejection | Tests added; check CI results and signature test logs before PASS |
| Genuine owner-signed immutable v0.6.0 archive, original app wheel and both approved dependency lock graphs | **NOT VERIFIED** — no actual signed candidate provided |
| Real v0.6 candidate full execution on native Debian and Alma kernels, SELinux enforcing, failure matrix | **NOT VERIFIED** |
| Actual signed v0.4→0.5→0.6 migration, transactional activation/recovery/rollback | **NOT VERIFIED** — this program intentionally does not activate |
| Independent security review, parent PR acceptance, maintainer merge/release approval | **NOT VERIFIED** |

The previous Docker tests did pass real third-party wheel installation, CLI and Textual under Bubblewrap, but with legacy pins and v0.4 application source on the runner's Ubuntu kernel. That is not equivalent to a genuine owner-signed release candidate.
