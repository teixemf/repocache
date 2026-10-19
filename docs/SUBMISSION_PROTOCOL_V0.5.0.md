# Governed repository submissions: v0.5.0 protocol proposal

Status: **DESIGN PROPOSAL / NOT APPROVED / NOT IMPLEMENTED**. Parent #15;
implementation #16, client contract #22, administrator TUI #23, final security
gate #17. This is a separate, optional capability from v0.4.0 read-only
catalog export. The endpoint is **disabled** unless approved and provisioned
through an independently reviewed deployment.

## Existing client compatibility

The v0.4.0 candidate already implements the non-interactive
`repocache-client repos submit --output FILE` export of schema 1:

```json
{
  "schema": 1,
  "os": {"id": "debian", "version": "13"},
  "repositories": [
    {"type": "apt-deb822", "url": "https://mirror.example.org/debian/"}
  ]
}
```

The existing client export sanitizes URL credentials and omits source paths,
hostnames and package-manager secrets. It also supports `apt-list` and
`dnf` values. Remote submission **must not** imply `repos sync --apply`;
the latter is separately scoped to #24. Neither successful nor failed intake
changes NGINX, APT, DNF, source files or the published catalog.

Proposed endpoint: `POST /v1/repository-submissions` with
`Content-Type: application/json`, fixed schema 1 and bounded UTF-8 body.
No URL fetching, DNS lookup, redirect following or executable content
processing is permitted on intake.

## Authentication and replay

Use HTTPS with ordinary certificate verification on every client; terminate
TLS in administrator-configured NGINX and proxy only to a dedicated
loopback/Unix-socket service. Do not expose the application directly on
a public interface.

Prefer per-credential HMAC-SHA256 proof of possession using a random 256-bit
shared secret provisioned out of band and a non-identifying key identifier.
This is a proposed protocol, not an activated credential format.

Required headers:

- `X-Repocache-Key-ID`: strict ASCII opaque identifier, maximum 64 bytes.
- `X-Repocache-Timestamp`: Unix UTC seconds, maximum 30-second clock skew
  subject to an operator-reviewed policy.
- `X-Repocache-Nonce`: 128-bit-or-higher random value, base64url, unique
  per credential and attempt.
- `X-Repocache-Signature`: hex-encoded HMAC-SHA256 over the exact bytes of
  `repocache-v1\\nPOST\\n/v1/repository-submissions\\n<TIMESTAMP>\\n<NONCE>\\n<SHA256_HEX_BODY>`.

All fields need an exact canonicalization and known-answer test vector before
implementation. Authenticate **before** interpreting untrusted URLs;
compare HMAC with constant-time comparison, and never log tokens, headers,
signatures or original payloads. Store client secrets in protected files
(0600 and trusted directory ownership), never in repo or Actions.

Repeated nonce and identical body may return the same outcome during the
idempotency retention window **without another queue insert**. A nonce reused
with different body is rejected as a replay. Nonces must be persisted
transactionally and cleaned up after a bounded window. This needs a
crash/retry/concurrency test, including a database restart. Missing/bad
credentials or stale timestamps return generic failures.

## Input boundary and normal forms

- Max body: 64 KiB; max repositories per request: 32; max URL length:
  2048 bytes; cap pending queue size and per-credential daily submissions.
- Reject unknown JSON keys, duplicated keys, non-UTF-8, NaN/Infinity,
  nested unknown types, control characters, oversized collections or
  strings, and unsupported `schema`, OS or repository types.
- Accept only the declared `debian/13` and `almalinux/10` combinations,
  consistent with the release support policy; do not infer support for
  arbitrary platform labels.
- Validate each HTTP(S) repository URL as inert *metadata*: absolute,
  nonempty FQDN with explicit DNS policy; no credentials, fragments, queries,
  encoded delimiters, backslashes, host whitespace, dot-segment traversal,
  invalid ports or local/private IP literals. Normalize host case and
  trailing slashes only under a documented deterministic rule.
- Debian/DNF source URLs may historically use plain HTTP. Preserve those
  proposals as **pending manual review** with an insecure-transport flag;
  never elevate them automatically into an approved catalog. A final policy
  decision on HTTP versus HTTPS metadata is required before shipping.
- Intake must never resolve untrusted DNS names, connect to upstream hosts,
  read local files selected by payloads or create server routes. SSRF checks
  must be repeated, with DNS rebinding and redirect tests, at the later
  catalog approval/publication boundary.
- Deduplicate canonical `type + url` pairs; preserve the original payload
  nowhere except any explicitly controlled, time-limited forensic fixture.
  Store sanitized and normalized fields only.

Use parser tests for userinfo, IPv4/IPv6 literals, IDNA/punycode, localhost,
link-local/RFC1918/CGNAT, ambiguous percent encoding, Unicode control
characters and scheme confusion. Domain allowlist policy must be defined
before any upstream connectivity feature is introduced.

## Local persistent queue and audit lifecycle

Introduce a separate SQLite store in a dedicated owned directory under
`/var/lib/repocache/`, with a non-login submission service UID and mode 0700.
Do not place writable queue data inside immutable release trees. SQLite
transactions must atomically cover idempotency record, payload validation
outcome, deduplication and pending insertion. Bound busy timeout, WAL
growth and disk quota; fail closed without touching NGINX on storage errors.

Proposed states:

```text
PENDING --authorized reject--> REJECTED
   |
   +--authorized accept-for-review--> REVIEWED
                                        |
                                        +--separate catalog validation-->
                                            ELIGIBLE_FOR_PUBLICATION
```

`REVIEWED` is **not** a live approval or route. Catalog publication is a
different privileged, reviewed operation based on the existing
`load_approvals`/`build_catalog` contract. Administrator action requires
a separately authenticated OS-local identity (for example peer-credential
checked Unix socket with restrictive group membership); never trust a role
passed from the remote client or a TUI field. Protect against TOCTOU and
concurrent decisions with optimistic row versioning and transactions.

Audit entries should contain timestamp, stable proposal ID, action,
result and locally authorized actor ID, **not** raw URLs, credentials,
client identities or complete request bodies. The audit database is
privileged operational state, not a cryptographically immutable ledger;
document tamper and backup limitations. Define owner-approved retention,
for example provisional 30-day pending and 180-day minimal audit records,
with explicit purge/expiry tests and encrypted operator-controlled backups.
Do not silently discard undecided proposals.

## Stable non-interactive responses

Responses carry a short machine-readable code, redacted message and, where
applicable, a randomly generated proposal ID. Do not reflect invalid values,
the submitted URL or any credential. Proposed statuses:

| HTTP status | Meaning |
| --- | --- |
| 202 | New pending proposal or safe identical idempotent retry |
| 400 / 415 / 413 / 422 | Unsupported shape/type/size/content; no insert |
| 401 / 403 | Missing/invalid proof or credential disabled |
| 409 | Conflicting idempotency key or state |
| 429 | Authenticated rate limit (bounded Retry-After) |
| 503 | Store/resource unavailable; retry is safe with same nonce |

Client exit-code mapping must be frozen together with #22 and must not
break the existing `--output` behavior. Any network mode is explicit
and non-interactive; do not silently fall back from offline export to
transmission. TLS errors and offline servers must never mutate APT/DNF
sources or leave credentials in command output.

## Network enablement: separate security gate (#17)

Default configuration must be *disabled*: no installed public location,
no running listener, no enabled systemd socket and no firewall opening.
Enable only by a separate operator action after security and deployment
review, with documented TLS/certificate ownership, log redaction, per-IP
and per-credential quotas, request timeout, storage and rollback boundaries.

A disable or rollback must be tested to stop network intake without losing
already-committed queue entries. No upgrade should turn an off endpoint on.

## Acceptance/test plan and ownership

| Work item | Independent acceptance evidence |
| --- | --- |
| #15 | Approved threat model, approved schema, pending-only invariants, review policy |
| #16 | Unit+HTTP integration: 202/4xx/429/503, HMAC replay, concurrency, offline/no DNS, service disabled |
| #22 | Client export retained; TLS failure, no secret redirects, retry/status contract, no source changes |
| #23 | Headless TUI + OS-local authorization, duplicate decisions, audit trail, rollback, no catalog publish |
| #17 | Separate independent security review, operator retention approval, attack tests, safe opt-in and recovery |

Use Python 3.12/3.13 and disposable Debian 13/AlmaLinux 10 integration
targets. Do not claim that containers prove actual systemd or SELinux
deployment behavior. Publish test cases/results with exact reviewed SHA.
Any FAIL/NOT VERIFIED in the security/deployment gate blocks enabling
the live endpoint. This design document does **not** approve activation,
deployment, merging or release publication.
