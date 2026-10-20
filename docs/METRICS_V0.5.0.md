# Repository metrics contract (v0.5.0, issue #14)

## Scope and trust boundaries

The current CLI `repocache metrics --period 1h|6h|24h|7d|30d --json` and
Textual metrics tab consume **read-only**, bounded NDJSON request log samples.
They do not calculate authoritative lifetime traffic totals. A log may have
rotated, been truncated, be unreadable, or lack fields. The output must never
be described as complete history on the basis of a partial file read.

This first implementation step hardens route attribution, quality reporting
and TUI event redaction. It **does not configure NGINX**, enable a new listener,
recover compressed or unlimited historical rotated logs, or close issue #14.

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
active logfile and up to seven numbered uncompressed rotations were sampled (8 MiB each); older or compressed history can be missing.
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
3. Test rotation gaps, compressed rotation exclusion, out-of-order timestamps, sparse/malformed content, more
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

## Bounded historical rotation and interactive route filter (second pass)

- The parser reads the active NDJSON file plus **at most 16 numbered**
  `.1`, `.2`, ... plain-text or `.N.gz` rotations. Each rotated source
  is sampled to 4 MiB (including a strict 4 MiB decompressed gzip cap);
  the active file remains capped at 8 MiB. The entire history can be
  incomplete even if no individual source reports truncation.
- Missing, duplicated or corrupt rotations, symlinked source files and
  inaccessible compressed files are not silently treated as complete.
  Compressed input is never expanded without limits, and log files are
  opened with O_NOFOLLOW where supported. This does not prove complete
  history after copytruncate or external log rotation failures.
- In the interactive repository list select a repository and press **F**
  for its per-repository metrics chart. Press **G** to switch back to
  global metrics. Periods remain **1h, 6h, 24h, 7d, 30d** via **P**.
  A selected repository must be an actually discovered NGINX route;
  the filter never edits NGINX or writes any log or source file.
- Tests cover real gzip files, decompression cap, path collisions,
  compressed corruption, symlinked rotations, all five periods and
  headless TUI route/global switching. Exact SHA CI is required to
  confirm execution; this text is not a pass report.

**Operational gap:** the example logging configuration remains proposed,
not automatically installed or validated against a live NGINX process.
An approved, opt-in logging migration with managed ownership, rotation,
retention, NGINX syntax tests, backups and reversible activation must be
verified before issue #14 can be closed. The 30-day graph shows only
*observed* samples from retained bounded files and never claims that
all traffic in the period was captured.
