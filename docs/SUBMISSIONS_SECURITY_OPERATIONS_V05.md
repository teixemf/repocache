# Optional submissions: secure operations and recovery (v0.5.0 draft)

**State:** NOT APPROVED FOR PRODUCTION. Issue #17 is the Gate A code acceptance
checklist; [issue #49](https://github.com/teixemf/repocache/issues/49) is the
independent **production activation decision**. These optional files/commands
must not be deployed or used to accept live traffic until #49 has PASS evidence
and the maintainer separately authorizes activation.

## Architecture and installation boundaries

- The internal `repocache.intake_service` module binds **127.0.0.1:8765 only**, and only after the
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
| `/etc/repocache-intake/keyring.json` | root:repocache-intake | 0640 | Root alone can change persistent keys; service group can read |
| `/etc/repocache-intake/enable-local-intake` | root:root | 0644 | Explicit operator-created opt-in, never created by upgrade |
| `/var/lib/repocache/submissions` | repocache-intake:repocache-intake | 0700 | Private SQLite storage |
| `/var/lib/repocache/submissions/queue.sqlite3` | repocache-intake:repocache-intake | 0600 | Service writes; root-only TUI administrates |
| Root-owned offline backup directory | root:root | 0700 | Intake cannot modify recovery artifacts |
| Backup/rollback snapshot | root:root | 0600 | Prevent unprivileged replacement or tampering |
| Client handoff directory | root:root | 0700 | One-time out-of-band transport of a per-client secret |

Offline credential issuance has an additional root trust boundary:
`repocache-submissions-keys issue` refuses a root-owned keyring or client
handoff directory if **any higher ancestor** is controlled or renamable by
an unprivileged local user. The client handoff directory must be root-owned
and private (0700); the keyring directory must be root-owned and not
group/other-writable. A higher root-owned sticky ancestor is permitted
only above these protected directories. These are code and synthetic-CI
checks; actual target filesystem, service account and SELinux protection
remain **NOT VERIFIED** before production activation (#49).

**SEC-GA-26-01 credential integrity:** The active keyring and its parent
must be provisioned as `root:repocache-intake 0640` (file) and
`root:repocache-intake 0750` (directory), respectively. A service-owned
`0600` keyring is deliberately rejected by both startup and root-only key
management. **There is no automatic migration**: stop/disable the intake,
preserve a private operator-controlled backup, review the existing credentials,
and explicitly migrate ownership/mode offline using approved root procedures
before restarting. Actual native host checks, SELinux labels and restart
approval remain #49 Gate B. The service can still read currently valid HMAC
secrets by design; compromise of the running service requires immediate
operator key replacement and controlled restart.

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
/opt/repocache-cli/managed/current/bin/python -m repocache.submission_keys issue --id CLIENT_ID --client-output /root/private/client.json --approve
/opt/repocache-cli/managed/current/bin/python -m repocache.submission_keys revoke --id CLIENT_ID --approve
```

The `--client-output` path must be new, private and inside an approved root-owned
directory. The command writes mode 0600 without printing the secret. The
recipient must receive the file through a trusted, confidential, out-of-band
method, then store it at the client with restrictive ownership. Existing
offline `repocache-client repos submit --output` remains unchanged.

**Credential transaction integrity (RC169-F01/F02):** root-only
`issue` and `revoke` serialize their full read/modify/publish operation using
a root-owned, private `.keyring.lock` within the protected keyring directory.
Concurrent operators wait for bounded lock acquisition, then reread the
current keyring; unsafe locks fail closed. The confidential client handoff is
fsynced together with its parent directory *before* the service keyring
is published. Publishing the keyring uses a staged, fsynced inode and atomic
rename followed by parent directory fsync. If an error occurs within or after
the rename boundary, the operation returns
`credential_publication_uncertain`: for issuance the already durable
root-private client credential is **retained**, not destroyed. Operators must
stop/disable the optional intake, examine the protected handoff and effective
keyring offline, reconcile without reusing key IDs, and explicitly decide on a
controlled restart; revocation is similarly treated as uncertain until its
effect has been verified. These steps do not execute automatically.
A prepublication error removes and syncs away the uncommitted handoff.
Crash/power-loss recovery on real native storage remains Gate B #49.

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
/opt/repocache-cli/managed/current/bin/python -m repocache.submission_admin backup --output /root/private/backup-YYYYMMDD.sqlite3 --approve
/opt/repocache-cli/managed/current/bin/python -m repocache.submission_admin maintain --retention-days 180 --approve
/opt/repocache-cli/managed/current/bin/python -m repocache.submission_admin restore --input /root/private/known-good.sqlite3 --approve
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
  integrity and preflight validation of proposal state, IDs, versions,
  timestamps, OS metadata, canonical repository URLs, and the required nonce
  replay/audit table layout, even when SQLite `integrity_check` succeeds.
  Restoration also requires a *verified inactive* systemd
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


## Privileged decision audit boundary (#57)

Before any administrator review, an operator must provision a **separate
root-owned mode-0700** \`/var/lib/repocache/decisions\` directory with
a root-owned non-group-writable parent. The intake service must never own
or have write access to this directory. Its receipt files are 0600
and bound to a hash-linked decision history; intake SQLite's \`audit\`
table is a convenience copy and must not be presented as authoritative.

On a failed SQLite write after a durable review receipt, the TUI refuses
further decisions on that proposal. Investigate the store and verify the
systemd intake service is **inactive** before explicitly reconciling:

\`\`\`text
/opt/repocache-cli/managed/current/bin/python -m repocache.submission_admin journal-verify
/opt/repocache-cli/managed/current/bin/python -m repocache.submission_admin journal-backup --output-dir /root/private/decisions-2026-10-20 --approve
/opt/repocache-cli/managed/current/bin/python -m repocache.submission_admin reconcile --id <approved-proposal-id> --approve
\`\`\`

The private journal snapshot and the SQLite backup are separate recovery
artifacts; retain both and independently verify them. There is no
automatic root journal creation, pruning, reconciliation or service startup.
See [SUBMISSIONS_DECISION_JOURNAL_V05.md](SUBMISSIONS_DECISION_JOURNAL_V05.md)
and Gate A #17 / Gate B #49. Real root-owned filesystem and SELinux
enforcing validation remains **NOT VERIFIED**.

## Canonical CLI reconciliation (2026-10-24)

The approved public executables are exactly `repocache`, `repocache-client`,
and the separately installed workstation-only `repocache-release`. The
intake and root-only maintenance modules are internal implementation aids,
not new public CLI families. The disabled service template uses the verified
managed Python path rather than an uninstalled `repocache-intake` executable.
Module invocations in this internal operations runbook are temporary
maintenance mechanisms, **not** substitutes for the planned canonical
`repocache requests` administration tree (#107/#15). Until that tree is
fully accepted, do not advertise these internal modules as production-facing
public user commands, and do not enable the optional service (#49).
