# Opt-in NGINX metrics logging and rollback (v0.5.0, #14)

**Status: proposed operator-run migration, not installed, activated or native-tested.** REPOCACHE currently reads a bounded NGINX NDJSON metrics log and does **not** own the NGINX configuration. This document supplies a minimal, reversible *staging* example. It neither closes #14 nor changes the existing v0.4.0 NGINX/deployment contract.

## Scope and security boundaries

- HTTP-context format: [`nginx-metrics-http.conf.example`](../deploy/examples/nginx-metrics-http.conf.example). Per-approved-location example: [`nginx-metrics-location.conf.example`](../deploy/examples/nginx-metrics-location.conf.example).
- Both are inert files with an `.example` suffix. Nothing in the installer, updater, unit files or CI installs or includes them. Do **not** copy either example into an active site without adapting and testing it.
- The log contains only UTC timestamp, an administrator-defined canonical repository route label, HTTP status, NGINX cache status, response bytes and elapsed seconds. Never add `$request`, `$uri`, `$request_uri`, `$args`, `$remote_addr`, `$http_*`, `$host` or headers. Restrict read access and retention anyway: timing and volume can still be commercially sensitive.
- The trusted `$repocache_metric_repo` variable must be set as a literal `"/approved/route/"` **inside each already approved repository proxy location**. Never derive it from submitted URLs, untrusted metadata, client headers or a user-provided label. A URI rewrite or nested NGINX location may change the effective selected location: review the full effective configuration and test routing/attribution. Do not log intake/authentication endpoints.
- Install the `log_format` in the **http** context once, but add `access_log /var/log/nginx/repocache-metrics.log repocache_metrics;` **only** within the individually approved repository proxy locations. Do not install a server-wide access log that counts unrelated locations as cache traffic. Do not add or modify proxy routes, TLS, cache policy, client APT/DNF sources or upstream access as part of logging activation.
- **NGINX inheritance warning:** a location-level `access_log` supersedes inherited access logs. Explicitly preserve existing compliance/audit or required traffic logging in the relevant locations; do not silently turn existing logging off. Confirm no conflicting `access_log off;` applies to the desired route.

## Explicit operator staging and acceptance

Use a disposable representative Debian 13 and AlmaLinux 10 environment before any production rollout. Commands below are **operator procedures, not executed-test evidence**.

1. Inventory all effective NGINX `http`/`server`/`location` blocks, proxy routes, current access-log inheritance, TLS policies and logrotate rules. Confirm exact canonical route labels using the approved server configuration, not merely request paths. Verify the current `REPOCACHE_METRICS_LOG` setting or its default `/var/log/nginx/repocache-metrics.log`.
2. Save a **root-controlled, non-symlinked, permission-preserving backup** of each NGINX and logrotate file that would be changed. Record the original config checksums, modes, ownership, SELinux contexts and reload procedure. Keep private configurations out of PRs, CI artifacts and issue comments. Stage copies with restrictive permissions; avoid writing directly to a live configuration before the approved change window.
3. Adapt the format once in `http{}` and the two location directives separately for each approved proxy route. Reject ambiguous names, overlapping prefix assumptions, unapproved rewrites or a missing literal label. Inspect the final config to retain existing access/audit logs. Check the metrics file's parent directory, ownership, ACL and SELinux label. Grant the REPOCACHE metrics reader the **minimum read access** required; never make logs world-readable or broaden TLS-key access.
4. Run `nginx -t` under the appropriate operator privileges against the **staged complete config** before making any live change. A valid syntax test alone does not prove the correct log is selected, routes remain unchanged or user data is excluded. Inspect `nginx -T` in a protected terminal/workspace; it can reveal private configuration, so do not publish its raw output.
5. Require a separate **explicit operator approval** before deploying a validated diff and running `systemctl reload nginx`. This documentation grants no automatic deployment/production authorization. A failed preflight means **no reload**. Verify reload status and unchanged existing repository requests, origin fallback and TLS behavior.
6. Generate disposable fixture requests against each approved route and one deliberately *unapproved* route. Parse each new log line as JSON and verify that only approved-route events were written, their literal labels match the trusted locations, and no query, path, authorization token or client IP is present. Test distinct HIT, MISS and BYPASS cases when the cache can actually produce them; do not claim those statuses if the environment cannot exercise them.
7. Check `repocache metrics show --period 1h --json` and the 1h, 6h, 24h, 7d and 30d read-only views, including per-repository TUI filtering. Missing or sparse data is **not** a hit-rate of zero or proof of a complete time window. Record the exact version, supported OS, NGINX build, results and sanitized evidence for the issue.

## Rotation and retention (must be reconciled, not blindly installed)

- Audit the platform's existing `/etc/logrotate.d/nginx` and any matching `/var/log/nginx/*.log` glob before adding rotation rules. **Never manage the same log twice**: choose one reviewed ownership/rotation policy. Prefer normal NGINX reopen-on-rotation to `copytruncate` where feasible, and verify privileges/SELinux for created files.
- The parser currently considers the active file and **at most 16 sequential numbered** plain or `.gz` rotations, with finite per-file byte and decompression caps. Date-suffixed filenames, missing rotation numbers and files older than that bounded window are not guaranteed to be visible. A daily scheme with only 16 rotations cannot prove 30-day coverage. Weekly rotations with sufficient retention may keep older observations but still cannot prove completeness across high volume, outages, missing data or large archives.
- Agree retention, maximum disk usage, archive size and access controls with the operator. Perform controlled rotation and corruption/gap tests, including whether the NGINX process successfully reopens its file. The CLI must report sampled, partial, truncated or unavailable data honestly; it is **not** a billing-grade traffic recorder.

## Reversal and failure handling

If syntax checks, log access, privacy, route attribution or service behavior fail, do not promote the change. After an already authorized activation, restore the **exact backed-up NGINX and logrotate configuration** under the preserved ownership/modes/SELinux contexts, validate `nginx -t` again, then perform an operator-approved reload and test original routes. Do not delete cache data, TLS keys, existing audit logs, package manager sources or customer history as part of rollback. Newly created metrics logs remain subject to a separately approved retention/deletion policy; turning off logging does not retroactively erase sensitive records.

## Evidence and unresolved #14 acceptance

| Requirement | Current status | Evidence / required next step |
| --- | --- | --- |
| Minimal, no-URI log schema and per-location opt-in example | PARTIAL | Static example and automated contract tests in the scoped PR; no live log |
| Preserved existing NGINX routes and access logs | NOT VERIFIED | Staging effective-config diff, syntax check, active requests and audit-log check |
| Permissions, logrotate, retention and rollback | NOT VERIFIED | Native root/logrotate/reload rehearsal on both supported OSs, including SELinux |
| Correct CLI/TUI metrics and 30-day quality signaling | NOT VERIFIED | Real active NGINX log with representative traffic, gaps, rotations and native runtime |
| Privacy/no credential or identifying paths retained | PARTIAL | Static field allowlist only; real log capture and operator security review still required |

The parser and TUI work under #14 PRs #42/#52 remains separate. Coordinate the final implementation with future NGINX provisioning; do not merge overlapping parser or TUI changes merely because this documentation exists.
