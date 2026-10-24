# CLI and TUI compatibility matrix — v0.4 legacy and proposed v0.6 online

**Status: PARTIAL regression coverage for #85, NOT release acceptance.** Design depends on signed first-party wheel [draft #103](https://github.com/teixemf/repocache/pull/103), nonactivating staged installation [draft #104](https://github.com/teixemf/repocache/pull/104), accepted source-only [#84](https://github.com/teixemf/repocache/issues/84) and client architecture decisions. Existing production CLI/TUI behavior must not silently regress.

| Contract | Legacy signed wheelhouse | Proposed source-only v0.6+ | Evidence / gap |
| --- | --- | --- | --- |
| `repocache --version` exit 0 and exact version | Required | Required | Real Typer in-tree test, staged online subprocess mock |
| `repocache --help`, `repocache update --help` non-interactive | Required | Required | Actual in-tree Typer commands; installed-v6 staged invocation mocked |
| `repocache update check --help`, `repocache update list --help` and `--json` option | Required | Required | Actual Typer parser help, no network; online discovery remains read-only |
| `repocache update list --json` result schema, offline/error exit codes and approved version selection | Required | Required | Actual in-tree JSON offline/error exit-code tests plus parser help; **NOT VERIFIED** on real native signed release |
| `repocache-client check`, `repos list`, `repos submit`, `repos sync` | Required | Required | In-tree argparse/JSON tests against **disposable Debian 13 APT and AlmaLinux 10 DNF trees**; both exercise inventory, protected export, read-only sync, refused --apply and synthetic offline check. Added AlmaLinux fixture test requires exact-head CI confirmation; **NOT VERIFIED** in a real signed native online venv; client packaging remains separate |
| `repocache repos --help`, `repocache health --help` | Required | Required | Actual in-tree CLI parser/help test; behavior on real host requires NGINX |
| No-argument TTY starts interactive management TUI; no-argument non-TTY follows legacy JSON/status contract | Required | Required | **NOT VERIFIED** across separately installed target versions |
| Textual mounts `RepoCacheApp`, shows overview/repositories/metrics/diagnostics | Required | Required | Real `App.run_test` against in-tree code, installed staged invocation mocked |
| Textual key bindings 1/2/3/4, A (auto), I (interval), P (period), R (refresh) | Required | Required | Real headless `run_test`; data polling disabled to avoid NGINX/network/files |
| Textual full metrics, live diagnostics, on-demand probe, keyboard navigation, privacy and admin UI from #14/#23 | Planned where merged | Required as integrated | **NOT VERIFIED** in online native generation, existing drafts still pending |
| Signed installed wheel, full real pinned third-party closure, no prompts, no pip resolving | Wheelhouse (legacy) | Mandatory | Ephemeral Ed25519 security tests and **mocked** staged orchestration; no real PyPI/native signature evidence |
| Pre-activation absence of state changes | Mandatory | Mandatory | Read-only current-target/installed-manifest digest comparison detects accidental changes but does not sandbox same-UID executable code |
| Native Debian 13/Python 3.13, AlmaLinux 10/Python 3.12, NGINX, SELinux, systemd, rollback and same-version repair | Mandatory | Mandatory | Legacy disposable container regressions only; online real native signed candidate **NOT VERIFIED** |

The AlmaLinux 10 test covers DNF INI sections, enabled/disabled repository filtering, exported-file permissions, dry-run catalog matching, offline diagnostics and byte-for-byte source preservation. It is a **synthetic filesystem fixture**, not a booted AlmaLinux 10, root/SELinux or signed-release test.

## Pre-activation trust boundaries

The nonactivating venv rehearsal authenticates the source + original REPOCACHE wheel and third-party locks before network access. It then stages and offline-installs both types of wheel, runs `pip check`, checks exact package versions and makes non-interactive CLI calls. Headless Textual is an actual `run_test` from the **fresh staged venv**, with its data polling replaced before mounting. The preactivation canary compares prior active symlink and installed manifest bytes after smoke; it fails closed on unexpected changes.

**Residual security threat:** staged code executes under the managed account. A malicious or compromised wheel may alter any writable path or exfiltrate information independently of whether the canary catches a changed symlink/manifest. Full production install needs a separately tested filesystem/network/namespace privilege boundary or documented equivalent isolation, and only then transaction journal/atomic pointer activation. The canary is not rollback, and it cannot repair damage already caused.

Headless keyboard navigation is useful but does not prove the full TUI #14/#23 workflows, client packages, all CLI JSON error codes, actual PyPI availability, full provenance or native installed release acceptance. Each missing criterion remains **NOT VERIFIED** and blocks merges under the project's acceptance gate.

**No merge, release, signing operation, production activation or privileged host change is authorized.**
