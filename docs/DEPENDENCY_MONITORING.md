# Dependency monitoring and review policy

**Status:** initial v0.5.0 monitoring proposal for [#81](https://github.com/teixemf/repocache/issues/81), tracked by [#79](https://github.com/teixemf/repocache/issues/79). This does **not** change the immutable v0.4.0 release, enable online dependency installation, or close the full #81 acceptance gate.

## Scope and authority

- REPOCACHE retains its Typer/Rich command-line interface and Textual TUI. The v0.4.0 signed release installs its own audited, immutable offline dependency wheelhouse. **Do not** change its files, signatures or acceptance record.
- `.github/dependabot.yml` checks Python packaging manifests under `/` and SHA-pinned GitHub Actions in `.github/workflows` weekly, on default branch `main`.
- Dependabot version-update PRs are **proposals**, not authorization to upgrade released installations. Reviewers must not enable auto-merge. Do not install unreviewed latest upstream releases in production.
- Existing `pyproject.toml` declares version **ranges** for Typer/Rich/Textual. The custom `deps/runtime-wheels.lock` and `deps/build-wheels.lock` pin actual v0.4.0 wheels/hashes but are **not guaranteed to be ingested** by GitHub's dependency graph or Dependabot. Neither Dependabot's recognition of the PEP 621 `pyproject.toml` nor the presence of this config proves detection of the exact runtime and transitive packages. A recognized, complete lock for both supported Python targets is designed under [#80](https://github.com/teixemf/repocache/issues/80) and implemented/reconciled before claiming #81 complete.
- For initial Python version updates, `increase-if-necessary` avoids casually rewriting existing broad version bounds. It may produce **no** update PR when a new stable version already satisfies the current constraints. This is not a substitute for monitoring an exact signed release dependency lock.
- Existing branch protections, reviewer approval, pinned action SHAs, CI, owner-only offline Ed25519 signing and publication gates still apply.

## One-time maintainer verification

In **Settings > Security & analysis** (the wording may vary), independently inspect/enable:
1. Dependency graph.
2. Dependabot alerts.
3. Dependabot security updates.
4. Notifications for vulnerability/security alerts in repository and account notification settings.

Dependabot **version** updates become active only after the reviewed `.github/dependabot.yml` is merged into the default branch. Alerts/security updates are not enabled by that YAML alone. The GitHub connector used for this initial implementation does not expose reliable read/write APIs for these effective settings; record operator-side evidence in #81, not an invented PASS.

After the config is merged, inspect **Insights > Dependency graph**, **Security > Dependabot alerts**, and the **Dependabot** update jobs/logs on the repository's GitHub UI. Record which direct/transitive packages, resolved versions, and supported Python profiles actually appear. Save a sanitized job URL or PR proving that each ecosystem's update check executed. Never introduce a deliberately vulnerable live dependency solely to demonstrate alerting; a controlled fixture in a nonproduction test repository or verified historical public advisory can be used if the workflow permits.

## Reviewing new versions / security alerts

1. For alerts: record advisory reference, affected installed/declared versions and available fixes. Distinguish vulnerable released wheelhouse versions from future source-only installs. Prioritize exploitable or remotely reachable exposure and high-severity advisories; if no safe fixed release exists, document mitigations and deployment guidance.
2. For version PRs: inspect origin, release notes, removed or added transitives, license notices, Python ABI/platform support, wheel availability, package provenance, suspicious ownership or dependency changes, API/CLI/TUI compatibility and security impact.
3. Verify every direct/transitive/build dependency from a complete release-specific lock under the supported Python interpreters: Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12. Changes to signed lock entries/hashes and dependency policy require explicit owner review; **never automatically replace a v0.4.0 pinned wheelhouse**.
4. Run exact-head CI, full CLI/JSON/exit-code/TUI regressions, native installation and transactional rollback tests, offline legacy release tests and, after #83/#84, online hash-pinned download plus outage/compromised-index negative tests. Tests must check results, not merely existence. Block merge on any required FAIL or NOT VERIFIED.
5. Before merging review branch head, reviews, checks, protected branch rules and all issue acceptance criteria. Require explicit maintainer approval. Merge is **not** a release: prepare an independently signed release candidate, execute the [#76](https://github.com/teixemf/repocache/issues/76) acceptance gate, then separately authorize signing and publication.
6. Publish emergency security maintenance releases through the same authenticated process. Do not hot-swap Python wheels inside immutable previously published assets or silently upgrade user installations.

### Interaction with #74

[#74](https://github.com/teixemf/repocache/issues/74) exclusively tracks GitHub Actions migration to reviewed Node.js 24-native releases. Dependabot PRs updating `actions/checkout`, `actions/setup-python`, or `actions/upload-artifact` **must not bypass** that issue's full-SHA, artifact-upload, credential-scope or nine required status-check criteria. If both the maintainer and Dependabot propose the same change, select one reviewed PR and close the redundant one after verifying exact SHA; do not merge both blindly.

## Planned additional coverage (NOT VERIFIED)

- Release-recognized direct/transitive/build dependency locks accepted by Dependabot for both supported target interpreters, or a least-privilege GitHub dependency submission strategy if static graph ingestion is incomplete (#80/#81).
- Evidence that security alerts and security-update PRs work using a safe controlled advisory example (not tested yet).
- Evidence that actual weekly checks produce actionable Python and Actions version-update PRs (not tested yet).
- A future wheelhouse-free, online-hash-locked source-only release profile (#82–#85).

## Acceptance status (initial PR)

| Criterion | Status | Evidence |
| --- | --- | --- |
| Version-update config authored for pip and Actions | PARTIAL | `.github/dependabot.yml` in draft PR; syntax/local validation to be recorded |
| Live Dependabot jobs / update PRs | NOT VERIFIED | Requires config on `main` and actual GitHub runs |
| Alerts / security-update repo settings enabled | NOT VERIFIED | Operator must inspect GitHub settings |
| Resolved direct + transitive vulnerability graph | NOT VERIFIED | Existing custom release wheel locks are not a verified supported manifest |
| Safe controlled security-alert test | NOT VERIFIED | Not executed |
| No auto-merge / Actions release authority | PARTIAL | No auto-merge configured; requires branch-policy and live-PR verification |
| Required CI / exact-head reviews / owner approval | NOT VERIFIED | Inspect after PR checks; no merge approved |
