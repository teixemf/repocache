# Optional submissions: secure operations and recovery (v0.5.0 draft)

**State:** NOT APPROVED FOR PRODUCTION. Issue #17 is the Gate A code acceptance
checklist; [issue #49](https://github.com/teixemf/repocache/issues/49) is the
independent **production activation decision**. These optional files/commands
must not be deployed or used to accept live traffic until #49 has PASS evidence
and the maintainer separately authorizes activation.

## Architecture and installation boundaries

- `repocache-intake` binds **127.0.0.1:8765 only**, and only after the
  `--enable-local-only` argument, root-controlled enable marker and the
  dedicated unprivileged `repocache-intake` UID all validate. It never edits
  NGINX, catalog, APT or DNF sources; proposals remain PENDING.
- No systemd unit, NGINX location, firewall rule, service user or enable marker
  is installed by the v0.4.0 installer or by this branch.
- `deploy/examples/repocache-intake.service` is a disabled, **uninstalled**
  *design candidate*. NGINX example snippets are also uninstalled. The package
  declares console-script entrypoints; a versioned REPOCACHE rootless package
  must make the binary accessible at the exact path from the unit before the
  unit can be considered deployable. This has **not been validated**.
- The optional daemon's listen socket is plain HTTP only on loopback. External
  HTTPS requires separate approved NGINX TLS termination, per-source controls,
  certificate custody and attack testing. An NGINX reverse proxy is NOT
  automatically installed, configured or activated.
- Existing NGINX TLS and package-serving routes must be preserved. Deploying a
  conflicting server{} block or duplicating limits is not approved.

## Proposed host ownership — require native verification

Target access model (operator must validate on Debian 13 and AlmaLinux 10):

| Object | Owner/group | Mode | Reason |
| --- | --- | --- | --- |
| `/etc/repocache-intake` | root:repocache-intake | 0750 | Only operator writes config; service traverses |
| `/etc/repocache-intake/keyring.json` | repocache-intake:repocache-intake | 0600 | Only service and root can read active HMAC secrets |
| `/etc/repocache-intake/enable-local-intake` | root:root | 0644 | Explicit operator-created opt-in, never created by upgrade |
| `/var/lib/repocache/submissions` | repocache-intake:repocache-intake | 0700 | Private SQLite storage |
| `/var/lib/repocache/submissions/queue.sqlite3` | repocache-intake:repocache-intake | 0600 | Service writes; root-only TUI administrates |
| Root-owned offline backup directory | root:root | 0700 | Intake cannot modify recovery artifacts |
| Backup/rollback snapshot | root:root | 0600 | Prevent unprivileged replacement or tampering |
| Client handoff directory | root:root | 0700 | One-time out-of-band transport of a per-client secret |

The account must be fixed and non-login, and the service must run as that UID.
The example unit has `NoNewPrivileges`, a strict read-only system tree,
restricted address families, resource ceilings and writes only under the
private queue path. Real ownership, SELinux contexts, rootless installation,
the systemd binary path and clean-host repeatability are **NOT VERIFIED**.
SELinux changes must be designed and tested with enforcing mode; do not
blindly set permissive mode or disable host enforcement.

## Non-interactive credential lifecycle

The server and each client share a **distinct** 256-bit random HMAC secret.
No passphrase/token/key must be put on a command line, issue/PR body, GitHub
Actions log, shell output or embedded installer.

The explicit root-only command interface is:

```text
repocache-submissions-keys issue --id CLIENT_ID --client-output /root/private/client.json --approve
repocache-submissions-keys revoke --id CLIENT_ID --approve
```

The `--client-output` path must be new, private and inside an approved root-owned
directory. The command writes mode 0600 without printing the secret. The
recipient must receive the file through a trusted, confidential, out-of-band
method, then store it at the client with restrictive ownership. Existing
offline `repocache-client repos submit --output` remains unchanged.

**Rotation:** issue a *new* key ID, deliver and test the new credential,
only then revoke the old key ID. The service currently loads its keyring
at startup. A **controlled restart** is needed to enforce any issue/revoke;
rotation/revocation is **not effective immediately** against a running process.
Do not claim revocation complete before validating that an old credential is
rejected after a restart. The last key is deliberately not revocable through
this helper. Emergency response requires stop/disable and a separate
replacement procedure. Actual restart/rollback and lost-key handling remain
Gate B items.

## Durable database operations

The root-only tool is deliberately non-interactive and has no automatic
periodic jobs:

```text
repocache-submissions-admin backup --output /root/private/backup-YYYYMMDD.sqlite3 --approve
repocache-submissions-admin maintain --retention-days 180 --approve
repocache-submissions-admin restore --input /root/private/known-good.sqlite3 --approve
```

- **Backup:** takes a SQLite-consistent online snapshot, checks integrity,
  publishes to a new file only (never overwrites), fsyncs and uses a trusted,
  root-owned mode-0700 destination directory. Secure off-host media copies,
  encryption, backup verification schedules and retention are operator
  responsibilities; no background job is installed.
- **Retention:** only an explicit root/approval action can remove *decided*
  proposals older than the selected retention interval. All PENDING rows
  persist until reviewed. Nonces expire after at least 24 hours; the
  request timestamp window remains 30 seconds. Queue/audit limits are
  fail-closed if capacity is exceeded. Select a retention duration formally
  before the gate passes: 180 days is only the current example/default.
- **Restore:** requires a root-controlled offline snapshot, strict owner/mode,
  regular files without final-component symlinks, bounded file size, SQLite
  integrity/schema checks and a *verified inactive* systemd
  `repocache-intake.service`. Absence of systemd or an unknown state denies
  restoration. It writes to a private temporary file, fsyncs, saves the
  **previous** database in the root-owned backup directory and atomically
  replaces the active file. Rollback is a **second** separately authorized
  offline restore from that preserved snapshot, never automatic.
- **Interruption risks:** a successful fsync+atomic rename on the same
  filesystem reduces crash windows but does not prove power-loss safety,
  filesystem durability or correct SELinux labels. All host recovery and
  actual power-cycle tests remain **NOT VERIFIED** under Gate B.
- Stop the intake and verify it remains stopped before restoring. Never
  switch the SQLite inode while writers may be active. After restoration,
  operators must inspect queue state, audit records, permissions and
  policy context *before* separately starting the service.

## HTTPS/Nginx proposal and fail-closed activation

The draft templates require HTTP context limits and a location inside an
existing operator-managed HTTPS server block. `client_header_timeout` must
be applied at HTTP/server level, not inside location. Disable request logs
containing paths/tokens; review the error-log redaction policy separately.
Review all `X-Repocache-*` header forwarding, client IP rate limits, request
size, timeout, TLS trust, no redirects and no public plaintext alternate
listeners. **NGINX -t has not been performed on a live host/config.**

Activation, when separately authorized under #49, must prove this sequence
on a disposable native test host: clean install with endpoint off, validate
the configuration and credentials, explicit operator enable, positive and
adversarial client tests, disable, rollback, recovery and restart with old
credentials rejected. No production endpoint may be enabled while required
criteria are FAIL/NOT VERIFIED.

## Current acceptance evidence and residual risks

Python 3.12/3.13 and Docker synthetic CI verify parts of the code, not
actual Debian/AlmaLinux service lifecycle. Tests using mocked root ownership
do **not** prove live service/root trust boundaries. The HTTP adapter is
single-process, and the local loopback test is not a full external rate-limit,
TLS or denial-of-service rehearsal. Native systemd, SELinux, NGINX, credential
handoff and rotation, encrypted off-host backups and recovery all require
recorded Gate B results. The code acceptance Gate A remains separately
blocked until its full, integrated SHA-based review is complete.

Security review is a **documented developer threat review**, not an
independent audit. No claims of independently certified security or
untested platform compatibility are made.
