# Governed submissions: Gate A security review (v0.5.0, #17)

Review date: 2026-10-20. Status: **NOT VERIFIED / DO NOT MERGE** until
all Gate A evidence is complete on the FINAL INTEGRATED SHA. This is
a developer-led adversarial code/security review, **not an independent audit**.

Issue #17 was amended with explicit maintainer authorization to distinguish
code acceptance from real production activation. Issue #49 retains the
mandatory, independent **activation decision**, not an independent reviewer.
Both must be evidence-based; a unit-test PASS does not imply host validation.

## Reviewed branches and trust boundaries

1. Design #15 / PR #43; intake #16 / PR #45; client #22 / PR #46;
   TUI #23 / PR #47; prior security PR #48.
2. Offline root-only restore, credential operations, disabled runner and
   static deployment examples in PR #51 (this code branch).
3. Metrics #14 / PR #42 and TUI cross-branch reconciliation PR #52.
4. Unmerged public v0.4.0 bootstrap PR #2 remains the integration baseline.
   Neither release/v0.4.0 nor public `main` contains this v0.5.0 code.

The authentication key file, HTTP body, queued URL metadata, SQLite store
and root-only TUI are different trust boundaries. Intake NEVER DNS-resolves
submitted upstreams, fetches client URLs or writes NGINX/APT/DNF config.

## Gate A criterion-to-evidence matrix

| Requirement | Status | Evidence | Remaining |
| --- | --- | --- | --- |
| Authenticated HMAC, nonce, replay/rate limits and invalid-body refusal | **PASS in previous #48 synthetic suite; NOT VERIFIED on integrated head** | `test_submissions_v05.py`, `test_submission_security_gate_v05.py`, #48 CI 283 tests per Python version | Fresh #51/#52 CI; verify duplicate signed headers and slow body failure bounds |
| Strict inert URLs, no SSRF/DNS or NGINX source changes | **PASS in scoped negative tests; NOT VERIFIED as integrated release** | URL corpus, monkeypatched DNS test, no upstream IO call in intake implementation | Combined code review and any future active upstream validation are separate |
| Persist only sanitized PENDING submissions; authorized review/undo is audited | **PASS synthetic / NOT VERIFIED native** | SQLite transactions and TUI headless tests (#47) | Root/service-UID file boundary, backup ownership and rate abuse review |
| Backup, bounded retention, restore, interrupted swap, data-preserving rollback | **NOT VERIFIED on final head** | `test_submission_retention_backup_v05.py`, `test_submission_restore_v05.py`: synthetic nonroot-owned fixtures; explicit offline service stop required | Execute latest tests, verify actual root-owned backup, database restore and interrupted writes on test host under #49 |
| No default listener; optional hardened service identity | **NOT VERIFIED operationally** | Service refuses missing opt-in flag/marker/UID; `test_submission_keys_service_v05.py`; optional disabled examples only | Validate native systemd/SELinux/NGINX under #49, and exact installed executable paths |
| Private HMAC issue/revoke and redacted errors | **NOT VERIFIED on final head** | `submission_keys.py` root-only issue/revoke, exclusive 0600 client file, offline tests; no secret printed | Native file custody and restart-based revocation/rotation #49 |
| #14 / #23 metrics and admin TUI together | **PASS on prior integration head, NOT VERIFIED on updated head** | PR #52, headless combined suite (including #14 regression); request-path display redacted | Sync final #51 security changes, rerun exact combined suite and review diff |
| Adversarial review, full CI and explicit merge approval | **NOT VERIFIED** | This file is an inspectable threat-boundary review and tracks adverse findings | Exact final SHA CI, check required statuses, resolve failures and obtain explicit merge approval |

## Findings addressed in this development pass

- **High impact:** SQLite's standard context manager commits but does not close
  the connection. Changed `SubmissionQueue._connect()` to always close via
  `contextmanager`; add a descriptor-closure regression test. Unbounded
  descriptors would otherwise be a denial-of-service risk.
- **High impact:** HTTP Content-Length/Transfer-Encoding ambiguity and
  duplicate signed headers might produce request desynchronization or unsafe
  replay across NGINX/HTTPServer. The local adapter now refuses duplicate
  framing/signed headers and excessive header counts; negative test added.
  Full NGINX parity and denial-of-service testing remain **NOT VERIFIED**.
- **High impact:** Raw SQL database replacement while intake is writing may
  lose or corrupt proposals. Root-only `restore` refuses unless systemd
  explicitly reports inactive, validates a bounded trusted snapshot and
  preserves a root-owned copy of the old file before atomic replacement.
  Power-loss and service-user escape are outside these tests.
- **Privacy:** Python BaseHTTPRequestHandler originally advertises Python's
  version in HTTP response headers; now suppressed. Raw TUI request paths are
  redacted in #23/#17 and metrics #14; combined PR #52 must retain both.
- **Key lifecycle:** Offline issuing/revoking and 0600 handoff implemented;
  no automatic network key distribution. **Revocation requires a controlled
  service restart**; a compromised key remains effective in a running
  process until restart. Emergency stop and rotation remains a Gate B
  security prerequisite.
- **NGINX example:** `client_header_timeout` belongs in http/server context,
  not location. Example corrected. The snippets remain drafts and have not
  passed native `nginx -t`.

## Residual risks / intentionally deferred activation controls

- The service account owns its queue. A compromised service UID can tamper
  with local operational SQLite records; the audit is not cryptographically
  append-only. No automatic catalogue/NGINX publication occurs, reducing
  escalation, but real OS-local trust and backup protections must be tested.
- `SQLite` restore is bounded and carries an offline preflight, but the
  atomic swap and fsync do not guarantee physical-power-loss safety.
  Root-owned source snapshots and restored SELinux labels remain to be
  verified natively.
- The example loopback HTTPServer is single-process and expects an approved
  NGINX TLS and rate-limiting boundary. Do not advertise it as an internet-safe
  listener without completing #49 and documenting all HTTP resource limits.
- The prototype has no automatic maintenance/backup schedule. Queue fullness
  fails closed; operator procedures need lifecycle retention and recovery
  validation. Production key rotation/revocation and real backup media
  custody remain Gate B.
- Tests run on Python 3.12/3.13 CI runners, with container-based synthetic
  Debian 13/AlmaLinux 10 checks. They do **not** constitute real systemd
  startup, SELinux enforcing or live NGINX TLS evidence.

## Merge and activation constraints

- Gate A: never merge with FAIL/NOT VERIFIED mandatory code criteria, failed
  required CI, blocking security findings or absent explicit merge approval.
- Gate B #49: regardless of a future approved Gate A merge, never provision
  a public location, create the enable marker, start the intake or accept
  live external clients until native validation and a separate explicit
  maintainer activation approval are recorded.
- Recheck the final branch heads/targets and CI after every meaningful
  commit or retarget. Successful earlier runs do not validate a new SHA.
