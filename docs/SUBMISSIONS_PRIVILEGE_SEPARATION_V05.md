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
  worker binaries fail closed. Control replies for ping, SQL execution,
  schema scripts and commit/rollback must contain exactly their documented
  fields; cursor IDs must be positive and SQLite row counts at least -1.
  Malformed or extra fields fail closed rather than being silently ignored.
  These shape checks cannot authenticate a compromised worker's positive
  acknowledgement or replace protected-journal reconciliation. A child exit
  or lost acknowledgement is not reported as a successful decision.
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


### Privileged backup staging inode guard (same scoped feature PR)

The root-side backup stream now opens the pre-created private staging path
with `O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC` and checks the **opened inode**
before sending the backup request. A FIFO substituted at open cannot hang
root; hardlinked or nonempty staging files are rejected rather than reused.
The caller still creates a fresh root-private 0600 temporary file and checks
SQLite integrity before atomically publishing a non-overwriting backup.

Synthetic negative regressions cover a FIFO swap at open, a second hardlink
and stale bytes, plus the existing bounded-frame and deadline tests. These
are **code-level defenses, not proof of hostile-root resistance**: native
service-UID, SELinux, power-loss and operational custody remain Gate B #49.
All new tests and nine required contexts on the updated PR HEAD are **NOT
VERIFIED** until their fresh GitHub Actions jobs complete successfully;
previous-head CI results must not be reused.


### 2026-10-25 global backup read deadline refinement

A further scoped adversarial review found that the 120-second backup deadline
was previously checked **around** `_recv()`, while each final pipe read could
still wait for its own fresh 10-second timeout. The worker transport now
accepts an optional absolute deadline and uses the **minimum** of its
per-message timeout and the remaining overall backup deadline. Normal SQL
requests retain the original per-message limit. Deterministic tests verify
that a stalled last frame receives only the remaining two-second wait and
that every backup frame uses the same absolute deadline.

**PASS (implementation review only):** no key, host, listener, release, or
privilege configuration changes. **NOT VERIFIED:** exact-new-HEAD nine GitHub
Actions jobs, independent security review, original #17/#57 acceptance and
native host gates; earlier SHA results cannot be reused after this change.


### 2026-10-25 strict backup IPC frame and symlink regressions

The root-side backup parser now accepts exactly two documented worker
response shapes: a nonempty base64 data frame (`ok`, `chunk`) or a
terminal frame (`ok`, `done`). Mixed, unexpected or extra fields fail
closed before any bytes are accepted. An isolated negative test also checks
that a swapped symlink to an otherwise safe-looking staging file is refused
by the existing no-follow open. These tests strengthen the same scoped
privileged-backup IPC boundary; they do not claim a native hostile-UID,
power-loss, SELinux or production backup-custody acceptance.

**PASS (source-level review):** the frame allowlist is consistent with the
worker's existing reply emitter and does not change ordinary SQL requests.
**NOT VERIFIED:** exact-new-HEAD GitHub Actions 9/9 and Python test results
until they finish; independent review/merge approval and original #17/#57,
#76 and #49 criteria remain separate. No endpoint, release or host mutation.


### 2026-10-25 duplicate-key worker JSON refusal (same #17/#57 feature branch)

A hostile service-UID worker could encode repeated JSON object keys (for
example, conflicting `ok`, `done` or `chunk` values), which Python's
ordinary JSON decoder otherwise resolves by silently retaining the last
value. The privileged parent now rejects duplicate keys at **any depth**
before evaluating the already strict backup-frame allowlist. Deterministic
negative wire tests cover duplicate status/data/terminal and nested keys;
a positive wire test preserves the legitimate single-key protocol.

**PASS (isolated stdlib parser smoke and source inspection); NOT VERIFIED**
for exact-new-HEAD GitHub Python 3.12/3.13 and nine required checks until
executed. No changes to normal SQL semantics, UID drop, root journal, signing,
release, production or rollback. Independent security review, original Gate A
#17/#57 and native Gate B #49 remain separate blockers.


### 2026-10-25 non-finite worker numeric IPC refusal (#17/#57)

**Scoped candidate hardening:** Python's permissive JSON decoder accepts
`NaN`/`Infinity` and converts exponent-overflowing `1e400` to infinity,
despite these not being valid finite JSON numbers. The privileged parent now
rejects both classes at the wire boundary, including nested values, and
refuses non-finite values in cursor rows even when injected directly.
Legitimate finite SQL floating-point results remain supported.

**PASS (isolated stdlib parser smoke):** five hostile wire-number forms
rejected; finite floating-point values accepted. **NOT VERIFIED:** exact
new PR HEAD Python 3.12/3.13 tests, all nine required GitHub contexts,
independent security review, original #17/#57 acceptance and native host
Gate B #49. No claim of worker authenticity, signer custody, real signed
candidate acceptance, production activation or release approval.


### 2026-10-26 decided-row metadata binding (scoped #17/#57 follow-up)

**Finding:** the root administrator's pending-list preflight previously compared
only a service-UID-controlled decided row's ID, state and version against the
protected decision receipt. A compromised intake SQLite database could retain
those values while changing stored OS, repositories or creation time; the
pending view would silently skip the row without detecting metadata drift.
The root receipt remained authoritative, but listing verification was incomplete.

**Candidate fix:** validate all seven decided-row fields and compare the exact
proposal metadata SHA-256 to the root-owned receipt under the existing journal
lock and one SQLite transaction. Keyset pages of at most 64 rows avoid
exceeding the 16 MiB service-worker response limit; reject duplicate/out-of-
order pages and more than the queue's 50,000-record limit. Three persisted
metadata-tamper tests and two hostile-worker pagination tests were added.

**Evidence:** PASS for source-level scope inspection; exact-new-HEAD Python
3.12/3.13 tests and nine mandatory GitHub checks **NOT VERIFIED** until runs
complete. This does not authenticate the intake-owned queue itself, prove
native SELinux/systemd, accept #17/#57 in full or satisfy #76 signing.
No endpoint, key, tag, release, production or rollback gate changed.
Independent security review and PR-specific merge permission remain pending.
