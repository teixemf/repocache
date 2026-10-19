# Repository metrics contract (v0.5.0, issue #14)

## Scope and trust boundaries

The current CLI `repocache metrics --period 1h|6h|24h|7d|30d --json` and
Textual metrics tab consume **read-only**, bounded NDJSON request log samples.
They do not calculate authoritative lifetime traffic totals. A log may have
rotated, been truncated, be unreadable, or lack fields. The output must never
be described as complete history on the basis of a partial file read.

This first implementation step hardens route attribution, quality reporting
and TUI event redaction. It **does not configure NGINX**, enable a new listener,
retroactively recover rotated logs, or close issue #14.

## Optional logging format proposal

Future managed NGINX provisioning (coordinate with #29) should generate
a route label from **administrator-approved and validated** locations, not
untrusted client submissions. For example, *only after the operator has
approved these exact paths*:

```nginx
# Illustrative server-managed configuration; not an active installer feature.
map $uri $repocache_metric_repo {
    default "-";
    ~^/debian/ "/debian/";
    ~^/almalinux/ "/almalinux/";
}

log_format repocache_metrics escape=json
  '{"time_iso8601":"$time_iso8601",'
  '"repocache_repository":"$repocache_metric_repo",'
  '"status":"$status",'
  '"upstream_cache_status":"$upstream_cache_status",'
  '"body_bytes_sent":"$body_bytes_sent",'
  '"request_time":"$request_time"}';

# Optional after nginx -t and explicit operator approval.
# access_log /var/log/nginx/repocache-metrics.log repocache_metrics;
```

Avoid `$request_uri`, `$args`, authorization headers, machine identifiers,
client addresses, query strings and unreviewed user-agent fields in the
metrics format. Even paths can contain identifying data. The route identifier
should come from an allowlist, not a free-form request attribute. The parser
also supports legacy `request_uri`/`uri` fields, matching an anchored,
strict route prefix before `?` as a read-only transition aid. It never
persists request paths in its aggregate results. The TUI's recent-events
display shows only normalized time, response code and cache state; malformed
lines are suppressed rather than echoed.

This configuration is a **proposal**, not a tested drop-in NGINX template.
Its final generation, approval, TLS/server-block placement, opt-in migration,
`nginx -t` validation and rollback belong to the controlled server
provisioning implementation. Existing logging stays untouched by this PR.

## Output semantics

The `--json` output retains the existing machine-readable keys and adds:

- `bypass`: number of observed cache BYPASS responses.
- `coverage`: one of `unavailable`, `no_observations`, `invalid`,
  `sampled`, `partial`, or `truncated`.

The `coverage` label is a data-quality signal **not a proof that all
requests in the requested period were captured**. `sampled` still means the
current logfile was sampled up to 8 MB; other rotated files may exist.
`truncated` means the initial portion of the current logfile was omitted;
`partial` means malformed records were ignored; `invalid` means no
valid records were found among malformed lines. Missing/unreadable/symlink
sources are unavailable. No-observation windows report unavailable HIT-rate,
bytes and duration rather than estimated values.

Cache HIT rate is HIT divided by *all requests with a known cache status*,
including MISS, BYPASS, EXPIRED, STALE, UPDATING and REVALIDATED. This
is **not** byte-efficiency. Bytes and latency are sampled only where the
corresponding fields are present. UTC windows are aligned to the current
instant; day charts have partial boundary days.

## Deployment, retention and follow-up acceptance

1. Validate the route allowlist and logging design, privacy/data-retention
   policy and read permissions with the operator. Logs should be protected,
   rotated under explicit limits and excluded from third-party publication.
2. Prepare generated NGINX logging separately from the running service;
   `nginx -t` must succeed before opt-in activation, with a reversible
   managed-file backup and recovery plan. Do not adopt unrelated logs.
3. Test rotation, out-of-order timestamps, sparse/malformed content, more
   than 8 MB of data, prefix collisions, multiple approved routes and
   1h/6h/24h/7d/30d representations. Record the exact CI SHA and results.
4. Test native Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12 scenarios.
   Real NGINX/systemd/SELinux logging and long-term history are **NOT VERIFIED**
   until executed with appropriate infrastructure.
5. Close #14 only when the full per-repository CLI/TUI, opt-in logging,
   rotation and data-retention requirements have individually verified
   acceptance evidence.

No secrets, internal destinations, client identities or production sample
logs are required in CI fixtures.
