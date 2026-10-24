# v0.5.0 governed submissions: SQLite privilege boundary (#127, #57)

**State: candidate Gate A implementation; not approved for production or
merge without final-head review.** The intake service remains disabled.
This is developer-led source and synthetic testing, not independent security
assessment or a substitute for native Gate B (#49).

## Threat and authority separation

The `repocache-intake` account owns the pending-proposal SQLite database
and its directory. A compromised intake account can change, erase, hide or
delay pending proposals and alter the SQLite convenience audit table. It must
**not** be able to author a valid administrator decision. Root-controlled
decision receipts under `/var/lib/repocache/decisions` are the only
authoritative decision history. They bind a proposal digest and version and
must be checked under the protected journal lock.

The original root TUI/admin code opened the service-writable SQLite file with
`sqlite3.connect(path)`. SQLite can create sidecar files and follows
filesystem paths independently of a prior `lstat` or unrelated
`O_NOFOLLOW` descriptor. A service-UID attacker could race those paths.
That design is a **security FAIL** even when all synthetic CI jobs pass.

## Proposed code-level mitigation

- A root process opening a queue in a **service-owned directory** uses a
  short-lived, separate `repocache.submission_db_worker` process. It is
  launched only via the fixed `/usr/bin/setpriv` binary, after checking
  binary owner/mode, the root-managed Python executable and the dedicated
  `repocache-intake` UID/GID. The child runs with
  `--reuid`, `--regid`, `--clear-groups` and `--no-new-privs`.
  It starts with a minimal environment, Python isolated mode (`-I`),
  no inherited shell or `PYTHONPATH`, and a private 0077 umask.
- **Only the dropped-UID child** calls SQLite on the intake-owned path or
  creates its SQLite journal/rollback sidecars. The parent root process
  communicates via bounded JSON pipes. SQL and parameters originate from
  trusted parent code, not from a submitted repository payload. Every
  command has bounded input/output and a timeout; errors and unavailable
  worker binaries fail closed. A child exit or lost acknowledgement is not
  reported as a successful decision.
- The parent holds the root decision-journal lock across the worker
  transaction. Root writes a durable, hash-linked decision receipt first;
  the child then updates the untrusted queue. If the queue commit fails,
  the operator must explicitly reconcile from the authoritative receipt
  after stopping intake. No intake account can write the root journal.
- The worker streams a consistent SQLite backup into a **root-private**
  staging inode. Root verifies the resulting snapshot before committing a
  backup; the worker never receives a root-owned destination path to open.
  A compromised worker can still send corrupt or incomplete bytes, which
  must be refused, not trusted as a verified backup.
- Offline restore now takes its lock and creates/verifies its staging file
  in the **root-only backup directory**, never in the service-writable
  SQLite directory. The validated file is moved into place atomically
  only after a retained root-private rollback copy is durable. If staging
  and queue directories are on different filesystems, `os.replace` fails
  closed with EXDEV; an operator must provision same-filesystem root-only
  staging before production acceptance. No fallback to an unsafe copy.
- A root process accessing a root-owned queue directory directly is allowed
  only when the path ancestors are root-controlled (root-owned sticky
  ancestors such as `/tmp` protect root-owned names). A directory under
  an intake-renamable ancestor is rejected even if its own inode is
  root-owned. Arbitrary local user ownership is never accepted as the
  service identity.

**Limits:** SQLite rows and IPC results remain untrusted; the root journal
protects authorization, not the availability of intake records. There is no
durable independently protected intake-submission ledger. Worker code and
its Python installation must be root-controlled. The service UID must not
have write access to its own executable, `setpriv`, Python installation,
or the root journal. Do not treat a green CI as proof of these OS facts.

## Evidence and remaining acceptance

The new synthetic tests exercise the worker SQL transaction/response
protocol, refusal of wrong UID and symlink/unsafe queue, root-to-worker
delegation without direct root SQLite, root-private restore staging/lock,
and fail-closed cross-device restore. Existing tests cover authenticated
intake, replay, bounded JSON, root decision receipts, malicious SQLite
state, headless TUI, client HTTPS and restore rollback. **Check exact-head
GitHub Actions results before assigning PASS**; earlier green runs are
historical and cannot be carried to a changed commit.

**PASS (disposable container real-UID smoke, not a booted native OS):**
GitHub Actions [run #40096004150](https://github.com/teixemf/repocache/actions/runs/40096004150)
completed both Debian 13 and AlmaLinux 10 jobs successfully on code HEAD
`41e645383aa792d3fc2a61a5685b8cd5122431a6`. Both actual job logs
include `PASS: real dropped UID, no root SQLite, decision journal, backup
and hostile sidecar`. The script provisions a dedicated service UID, uses
real `setpriv`, prevents the root Python process from opening the
service-owned SQLite path, exercises root-only receipt authority, verifies a
root-private backup, reconciles a forged SQLite state and protects a root
sentinel against a service-owned malicious journal symlink. These are real
UID transitions inside Docker on an Ubuntu-hosted runner kernel; they do
**not** prove host SELinux/systemd or every adversarial race.

**NOT VERIFIED / mandatory before Gate A merge:** full adversarial code
review of worker IPC, timeout and crash paths; process and disk quotas;
exhaustive hardlink/rename/parent-path swap and executable replacement
races; actual backup/reconcile/restore interruption and concurrency under
hostile service-UID activity; source-archive and wheel provenance
compatibility with the immutable v0.4.0 updater; exact-final-head nine
required CI checks, protected branch rules/reviews.

**NOT VERIFIED / separate production Gate B (#49):** real host
systemd/NGINX/TLS, SELinux enforcing contexts, service account provisioning,
approved HMAC credentials, operational backup custody, filesystem layout,
native reboot/power-loss behavior and explicit endpoint activation approval.
Nothing in this PR creates a tag, release, signer key, public endpoint or
production installation. Do not enable the example service until Gate B
has independently passed.


## 2026-10-24 privileged offline-restore adversarial hardening

**Candidate only; Gate A is not accepted.** A service-controlled SQLite inode
may grow, be replaced with another regular inode, or become a FIFO between
root's initial metadata check and the rollback copy. A private backup
directory alone does not prevent root from copying until attacker-chosen EOF,
opening a blocking FIFO, or following an attacker-renamable ancestor during
the final privileged `os.replace`.

- Restore copies now have an exact byte cap of 128 MiB, check source device,
  inode, ownership, mode, size, ctime and mtime both before and after copying,
  and reject extra bytes or a changed inode. The old service-owned queue
  must match the inode inspected before the source backup was verified.
- Root opens the service queue with `O_NOFOLLOW | O_NONBLOCK`, so a malicious
  named pipe is refused rather than hanging the privileged operator.
- Backup and service-owned queue directory ancestors must be root-controlled;
  a service-owned queue directly under a sticky, service-renamable parent is
  refused even though that parent belongs to root. A root-owned private
  directory beneath an attacker-controlled ancestor is also refused.
- New synthetic tests cover inode substitution, concurrent file growth,
  bounded-copy refusal, sticky-parent/ancestor swaps and nonblocking FIFO
  refusal. The disposable Debian 13/AlmaLinux 10 real-UID probe now also
  exercises actual offline restore/rollback and FIFO refusal, without enabling
  the intake service.

**PASS (source review and negative test coverage):** the intended fail-closed
boundaries are represented in the implementation and tests.

**NOT VERIFIED:** the new tests and native probes on the final exact GitHub
SHA, real host SELinux/systemd and power-loss behavior, independent adversarial
review, source/wheel compatibility with the immutable public v0.4.0 updater,
and full original #17 acceptance. Do not merge, enable intake, sign or publish
on this checkpoint. Previous successful CI runs apply only to their exact
historical commits.


## 2026-10-24 bounded backup IPC follow-up (feature PR, #17/#57)

**Threat addressed (code-level):** a service-UID worker could repeatedly send
empty or tiny syntactically valid backup frames. The former parent loop
enforced a 128 MiB byte cap and a timeout **per response**, but neither
bounded the number of zero-length frames nor enforced a deadline for the
whole transfer. A misbehaving worker could therefore keep the privileged
backup operation open indefinitely without producing a valid snapshot.

**Proposed mitigation:** reject empty frames and decoded chunks larger than
the worker's fixed 64 KiB protocol, cap the stream at 2048 data frames,
and apply a 120-second total monotonic deadline in addition to the existing
10-second per-response limit. The normal worker sends 64 KiB chunks followed
by a terminal frame; a valid snapshot still requires downstream SQLite
integrity verification. This change does **not** relax backup-size,
root-private staging, trusted inode, journal, or restore requirements.

**PASS (source inspection):** the bounded-progress checks and deterministic
positive/negative regression tests have been added on a separate feature
branch. **NOT VERIFIED:** exact-final-head Python 3.12/3.13 tests, all nine
required Actions jobs, independent security review, real native UID/SELinux
and power-loss behavior, and the full #17/#57 acceptance matrix. No merge
or production activation is authorized by this scoped fix.
