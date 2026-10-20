# v0.4.0 Release Integration and Acceptance

This is a fresh public repository. `main` is protected by policy; v0.4.0 code is proposed in **draft PRs** until acceptance. **Intended production scope: a CLI/TUI frontend for a separately installed and configured NGINX repository cache on Debian 13 or AlmaLinux 10**, not an NGINX installer. Production-readiness claims must distinguish executed CI from real-host validation; see [existing-NGINX operations](PRODUCTION_EXISTING_NGINX.md). No previous private Git history, protected ref, workflow log or release asset is imported.

## Mandatory acceptance gate

For each issue acceptance criterion, record **PASS**, **FAIL** or **NOT VERIFIED** and an executed command/log or reproducible review reference. Verify functional behavior, failures, privilege/security boundaries, upgrades, rollback, documentation and supported-system impact. A test committed but not run is **NOT VERIFIED**. Deferred real systemd/SELinux and physical power-cut testing remains deferred, not PASS.

Before merging, re-check the PR head, full diff, required CI jobs and results, approvals, unresolved reviews and security blockers. No FAIL/NOT VERIFIED criterion, required check failure or material security finding may be bypassed. The maintainer must **explicitly approve each merge**. PR creation is not approval. Release publication additionally requires separately reviewed signed artifacts and explicit release authorization.

## Public GitHub controls

Configure and verify active branch rulesets for `main`, active release branches and `v*` tags, with required checks, no unauthorized force-push/deletion and controlled review/bypass permissions. Repository visibility by itself does not establish these protections.

GitHub-hosted standard runners on this public repository are intended for PR CI. Treat fork PRs as untrusted: no signing secrets, privileged persistent self-hosted runners, write permissions or publisher credentials. `release.yml` must not automatically publish tags. Keep owner signing keys outside GitHub.

## Legacy migration

Public v0.4.0 is the **first standalone public release**, not an in-place upgrade from pre-public installations. Its signed compatibility allowlist is empty; legacy installations must fail closed, and the historical prototype must not be distributed or enabled. The former historical cutover requirement in issue #5 is explicitly superseded, not reported as PASS. Synthetic recovery rehearsals demonstrate transaction mechanics only. Future historical migration requires new independently accepted criteria, authenticated fixtures and a separate explicit maintainer approval.
