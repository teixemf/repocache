# v0.5.0: Privileged decision journal and recovery contract (#57)

**Development design; disabled-by-default; no production activation.**
This change implements Gate A's missing **root-authoritative** administrative
decision evidence. It does not modify the still-unmerged v0.4.0 candidate,
install a systemd service, change NGINX, or publish any submitted repository.

## Trust separation

| Object | Writer | Authoritative? |
| --- | --- | --- |
| Intake SQLite proposals / nonce / audit convenience rows | \`repocache-intake\` (service UID) | **No** |
| \`/var/lib/repocache/decisions/\` | Only UID 0, root-owned mode 0700 | **Yes for administrator decisions** |
| \`<proposal-id>.<revision>.json\` receipts | UID 0; mode 0600, O_EXCL publication | Yes while root boundary is trusted |
| \`.decision.lock\` | UID 0; mode 0600, exclusive flock | Serializes root review and backup |

Root-only directory provisioning is a **precondition**, never performed on
import, install or service startup. Its parent must also be root-owned and not
writable by other identities. The ordinary intake process may not read,
create, unlink or replace any file in the decision directory.

Receipts contain a random proposal ID, monotonically increasing revision,
review/reject/reopen, resulting state, local operator UID, Unix timestamp,
SHA-256 of the exact proposal metadata, the previous receipt digest and the
current receipt digest. They contain no repository URL, client secret, HTTP
request body or machine identifier. The hashes detect corruption **within
this protected root-controlled chain**; they do not supply independent
cryptographic attestation against UID 0 or offline whole-directory rollback.
On-host privileges/ACLs, SELinux policy and backup custody are Gate B #49.

## Transaction and recovery order

1. TUI lists PENDING items only after verifying exact proposal metadata,
   SQLite state/version and any existing root receipts. Without a trusted
   journal directory, review **fails closed**, not in a weak "legacy" mode.
2. On review/reject/reopen, root obtains the protected lock and an SQLite
   write transaction, checks \`expected_version\`, validates the receipt
   chain and binds the original stored proposal metadata digest.
3. A new immutable-in-place receipt is staged, fsynced, published
   **without replacement** via O_EXCL hardlink and the directory is fsynced.
   The corresponding SQLite state/version is then updated and committed.
4. If the root receipt write fails, **nothing changes in SQLite**.
   If SQLite fails after the receipt is durable, the operation returns an
   **error** and no "decision recorded" success notification is emitted.
   Subsequent decisions on that row are blocked until explicit reconciliation.
5. A root operator must investigate, prove the service inactive, and
   explicitly run \`/opt/repocache-cli/managed/current/bin/python -m repocache.submission_admin reconcile --id <proposal-id>
   --approve\`. Recovery validates the full root chain, exact proposal
   metadata and coherent prior SQLite version/state. A future/stale or
   forged version, altered metadata or corrupted receipt **fails closed**.
   No client can initiate reconciliation and nothing auto-approves.
6. \`/opt/repocache-cli/managed/current/bin/python -m repocache.submission_admin journal-verify\` verifies **all** surviving
   root chains. \`journal-backup --output-dir <new-empty-path> --approve\`
   snapshots all receipts to a new private root-controlled directory without
   overwriting existing backups. Keep this backup separate from the
   service-owned SQLite backup. Both are necessary for recoverable history.

These root-controlled commands are noninteractive and **must not** be exposed
through the unprivileged HTTP server or a remote client.

## Intentionally unperformed deployment steps

After Gate B #49's separate validation/approval, an operator could provision
the root-only journal directory by an idempotent equivalent of:

\`\`\`sh
install -d -o root -g root -m 0700 /var/lib/repocache/decisions
\`\`\`

Do not execute this on an active system solely because a PR merged. Check
the parent directory's root ownership, existing ACLs/mounts, SELinux file
context and service unit protections first. The protected directory must
not sit under the service-UID-writable proposal directory.

**Never restore a service-owned SQLite database alone and assume its audit
rows are authoritative.** A restored database behind the root journal will
refuse inconsistent review until a separately approved recovery operation.
Backup of root journal and service SQLite are distinct and must be managed
as a consistent recovery set. The root decision journal must not be
automatically purged by \`maintain\`, a backup rotation or a fresh install.

Real root/UID isolation, systemd, SELinux enforcing, disk-full conditions,
power-loss and restoration from off-host storage are **NOT VERIFIED** on
supported native platforms; they remain under #49. Python 3.12/3.13
synthetic tests must not be misrepresented as proof of those properties.

## Security review and acceptance

- **Code verification:** attempt to forge \`REVIEWED\` in intake SQLite,
  alter/delete service-writable audit rows, tamper with stored metadata,
  corrupt or remove protected receipt files, inject an SQLite failure
  between journal append and DB commit, replay stale versions, and restore
  an older service database. Expect fail-closed review and verifiable
  root history.
- **Backup verification:** verify all chains, snapshot to a new protected
  directory, reject overwrites, validate unchanged historical records,
  then explicitly reconcile a simulated stale proposal state.
- **TUI:** require root and two-step confirmation for both approval and
  rejection; no administrative success on incomplete transactions;
  redacted origin-only metadata and nonroot/corrupt-row refusal.
- **Gate A #17:** the exact final combined SHA, all acceptance criteria,
  security code review, required CI and explicit maintainer merge approval
  are mandatory. Issue #57 is not closed until every criterion is verified.
- **Gate B #49:** no TLS listener, host service, NGINX integration, real
  privilege separation, or production submission activation is approved.
