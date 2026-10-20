# REPOCACHE

REPOCACHE is an Apache-2.0-licensed Linux package-repository cache management project. It provides a Python server CLI/TUI, an experimental daemonless client, release authenticity checks, and tooling for resilient updates and recovery.

> **Status: v0.4.0 development candidate.** The initial public source import is **not an approved release**, not a tested clean-system NGINX deployment, and not production-ready. Supported targets under development are **Debian 13** and **AlmaLinux 10** only. Do not deploy this branch to production or publish a version tag.

## AI development disclosure

**REPOCACHE is being developed with substantial assistance from generative AI.** AI is used to write and modify code, tests, documentation, and proposed security changes under the maintainer's direction. AI-generated work can contain defects or insecure assumptions. An AI review is not an independent security audit; only executed, reproducible test evidence establishes verified behavior.

## Source, version and trust

This repository was created with a **new, independent public Git history**. Older development history and previously published versions are not imported or republished. The first intended public release is **v0.4.0**, subject to its acceptance and security gates. **It is a standalone first public installation, not an in-place upgrade path from pre-public versions.** The v0.4.0 signed policy deliberately has an empty `compatible_from` allowlist; legacy installs fail closed. Do not reuse historical installed state or overwrite pre-public launchers. A separately reviewed and tested migration path may be designed later, but is not currently supported.

Release assets must be independently authenticated with offline Ed25519 signatures and separately provisioned public trust anchors. Checksums alone do not prove release authenticity. Do not introduce private signing keys or GitHub release-write tokens into ordinary PR workflows.

**Same-version updates:** Explicitly selecting the currently installed release re-verifies the publisher signature and hash-pinned offline dependencies, builds a fresh virtual environment and atomically replaces the active generation. It never treats a service-writable manifest and a present executable as proof of installed-runtime integrity. A retry can take time and consume additional storage; operators should monitor available space. Do not execute a possibly compromised managed CLI as a recovery mechanism: restore through a separately authenticated, trusted installation environment. The service UID still owns its runtime, so this is not a root-owned cryptographic attestation of all installed files.

## Components

- `src/repocache/`: server CLI/TUI, update verification, recovery and release tools.
- `client/`: experimental Debian/APT and AlmaLinux/DNF client diagnostics.
- `scripts/`: build, signing rehearsal, and isolated test tools.
- `tests/`: automated unit and integration regression tests.

The server caching/provisioning features are **not yet a fully verified clean-system installer**. CLI operations remain non-interactive; use `repocache` for interactive management. Approved client commands include `repocache-client check`, `repocache-client repos list`, `repocache-client repos submit`, and `repocache-client repos sync` (sync apply remains disabled pending its safety review).

## Development

Use a supported system, with the system Python supplied by Debian 13 (3.13) or AlmaLinux 10 (3.12). This repository's CI uses isolated test environments.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e . pytest
python -m pytest -q
```

Run as a regular user. Do not run installation, migration or rollback experiments against a production host. **Passing unit tests alone is not authorization to release or merge.**

## Community and security

See [LICENSE](LICENSE), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [SUPPORT.md](SUPPORT.md). Vulnerabilities must be reported privately, not in public issues. All changes require evidence against documented acceptance criteria and explicit maintainer merge approval.

