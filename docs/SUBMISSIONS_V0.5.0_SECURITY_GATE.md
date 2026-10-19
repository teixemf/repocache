# v0.5.0 Submission Security Acceptance Gate — Issue #17

**Status: BLOCKED. The production submission endpoint must remain disabled.**

This is a developer security review, **not an independent security audit**. It does not authorize a merge, live deployment, signing, publication or an activated network listener.

## Dependency graph and evidence references

- #15, design PR #43: provisional HMAC wire contract; unresolved operational approval.
- #16, implementation PR #45: bounded validation, SQLite pending queue and local-only intake.
- #22, client PR #46: explicit opt-in transmission, TLS certificate checks and redirect refusal.
- #23, TUI PR #47: privileged local review, two-step confirmation and audited undo.
- #14, metrics PR #42: **separate, unmerged** TUI privacy fix needed before combined deployment.
- #17, this PR: disposable end-to-end TLS/HTTP and adversarial security checks.

Every PR is still stacked on the unmerged public v0.4.0 bootstrap PR #2.

## Threat boundaries

The remote client is untrusted. Authentication must precede JSON interpretation; submitted URLs must remain inert metadata. The isolated intake service may only insert PENDING rows and never modify the NGINX catalog or host package repositories. The privileged TUI needs independently authorized local OS credentials and must never publish routes. Future explicit catalog approval needs its own DNS rebinding, internal destination and TLS safeguards. Logs must never expose credentials, arbitrary paths or original request bodies.

## Acceptance matrix (review findings, before exact-head CI)

| Security criterion | Status | Evidence and blocker |
| --- | --- | --- |
| Forged signatures, expired credentials/nonces and malformed JSON rejected | NOT VERIFIED | Automated negative tests added; current exact-head CI and audit pending |
| Intake cannot resolve or fetch arbitrary upstreams, including private addresses | NOT VERIFIED | Negative URL corpus with DNS deliberately blocked; code contains no upstream I/O |
| Credential-bearing redirects rejected and HTTPS certificate verified | NOT VERIFIED | Client unit tests and disposable loopback TLS test added |
| Requests remain pending; untrusted clients cannot publish NGINX routes | NOT VERIFIED | Isolated database review transitions, no publication code; acceptance review pending |
| Bounded body/headers, concurrent requests, retries and rate limits | NOT VERIFIED | HTTP/request tests added; live NGINX resource controls are absent |
| Listener disabled by default and stoppable | NOT VERIFIED | Local test listener requires explicit opt-in, no installed service; stop test added |
| Root-authorized TUI and immutable audit evidence | NOT VERIFIED | UID-gated local actions and version checks exist, but SQLite audit is NOT cryptographically immutable; native service UID and privilege boundary untested |
| Database retention, backup, growth cap and recovery | **FAIL** | An explicit root-authorized retention method, bounded store growth and non-overwriting SQLite online backup with tests now exist in #17; **operator-approved policy, end-to-end restore, native permissions and failure-injection recovery still missing** |
| Real NGINX TLS endpoint, firewall, systemd and SELinux | NOT VERIFIED | No native deployment or production endpoint has been provisioned |
| Redaction of secrets and request-path identifiers throughout the TUI | NOT VERIFIED | Sensitive recent-request rendering fix ported to #23/#17 with a regression test; still need reviewed integration of all #14 metrics UI and deployed log formats |
| Key custody, rotation/revocation, account permissions and restoration | NOT VERIFIED | No operator-reviewed policy nor clean-host service installation |
| Independent adversarial security review | NOT VERIFIED | Developer-generated tests and code review are not independent |
| Separate explicit maintainer production activation approval | NOT VERIFIED | No activation authorized |

Any FAIL or mandatory NOT VERIFIED condition blocks integration readiness and live service activation. Tests passing on a synthetically mocked environment do not prove real deployment safety.

## Required completion before a PASS gate

1. Implement explicit operator-approved retention, storage quotas, safe pruning, secure backups, recovery and data integrity checks. Never silently erase pending proposals.
2. Complete the clean-host service-user ownership and root-to-intake trust boundary, privilege sandbox and operational credential/key rotation workflow.
3. Provide opt-in, reversible NGINX HTTPS termination configuration with reviewed safe defaults and independent denial-of-service/SSRF controls. No automatic listener or firewall change during upgrade.
4. Exercise real Debian 13 with Python 3.13, AlmaLinux 10 with Python 3.12, systemd and SELinux enforcing as applicable; test TLS failures, restoration after interruptions and secure shutdown.
5. Reconcile TUI privacy changes from #14, perform an independent code/security review, map every accepted condition to an executed exact-commit test or documented manual proof, and obtain separate maintainer approval to activate.

## Release boundary

All related branches stay draft and unmerged. The existing v0.4.0 release candidate does not gain a submission listener, a new service or altered APT/DNF configuration. Green CI is evidence for selected tests only, not a waiver of #17's unresolved operational and security requirements.

## Implementation additions and continued blockers

The gate branch now includes an explicit root-only maintenance method that
retains **all PENDING rows**, prunes expired nonces only beyond their replay
window and purges previously decided items only after an approved, bounded
retention duration. Queue growth limits bound DB size, all proposal rows,
pending rows and audit entries; capacity failure rejects intake safely.
An operator-only SQLite backup uses a private destination directory,
non-overwriting atomic hard-link publication and a database integrity check.
A disposable non-root test simulates destination ownership for its *positive*
backup path; it does **not** prove real root-owned backup or SELinux behavior.

Restoration/rotation of backed-up state and permissions, storage corruption,
backup media custody, operator-approved retention and full host crash/rollback
remain **NOT VERIFIED**. No periodic purge or backup daemon is started by the
code and no pending proposal is automatically deleted.

The TUI review branch #23 and this security branch now independently redact
URI/request paths in recent-event output, reducing dependence on merge order
with the metrics PR #42. The full cross-branch TUI changes still require a
combined, reviewed integration diff before any security sign-off.
