# Client repository transaction staging (non-applying)

**Tracking:** [#24](https://github.com/teixemf/repocache/issues/24), UC-01, UC-07, UC-11, UC-25, UC-26, UC-33.  
**Implementation:** `client/transaction_stage.py` — **experimental standalone module**, not wired into the installed client CLI or installer.  
**Targets:** Debian 13 and AlmaLinux 10 only; real-host acceptance **NOT VERIFIED**.

## Implemented boundary

The staging component validates an exact repository source file beneath a
supplied, owned root and an explicitly reviewed SHA-256 digest, then stages two
byte-for-byte snapshots in private state:

- `original.bin`: the actual local source content before the proposed
  change, including comments and any credentials.
- `proposed.bin`: a separately approved full-file candidate (the staging
  component does not generate or trust this candidate).
- `manifest.json`: exact relative source path, SHA-256 checksums and
  observed source inode, ownership, mode and timestamps.

State is kept under `/var/lib/repocache-client/staging/` relative to the
supplied root. Private directories require mode `0700` and owner matching
the invoking UID; files require `0600`. The persistent transaction lock
uses `flock(LOCK_EX | LOCK_NB)` to reject concurrent operations. An
individual stage is published by renaming a hidden, fsynced temporary
directory, then syncing the parent directory.

**Nothing in this implementation replaces, edits, chmods, unlinks or restores
APT/DNF source files.** The `stage()` and `inspect()` APIs are library
building blocks for later review and transaction work, not new CLI commands.
`repocache-client repos sync --apply` remains explicitly disabled.

## Fail-closed behavior

- Stage only known APT/DNF source paths: `/etc/apt/sources.list`,
  `/etc/apt/sources.list.d/*.list`, `*.sources`,
  `/etc/apt/mirrors/*`, and `/etc/yum.repos.d/*.repo`.
- Reject paths containing traversal, unsupported suffixes, untrusted parent
  ownership/permissions, symlinks and source hardlinks.
- Reject source contents larger than 1 MiB, unexpected digest changes and
  concurrent staging attempts. Identical candidate content is a no-op.
- Never overwrite a previously prepared original snapshot for the same
  source; a second stage is refused until deliberate administrative
  resolution.
- Reject unknown entries and interrupted `.partial` directories in the
  staging store. There is **no automatic deletion of uncertain state**.
- `inspect()` validates protected stage metadata and both checksums, then
  checks whether the local source still matches its previously observed
  inode/content/permissions/timestamps. Any change produces `drift`.
- The failure/diagnostic paths do not print original or candidate bytes and
  never include secrets. Staged backups are not uploaded or logged.

## Deliberately unimplemented

- No source writer, commit/abort CLI, repair, automatic rollback, deletion
  policy, durable managed-ID assignment, active-version recording,
  package-manager lock coordination, SELinux context preservation, ACL/xattr
  round-tripping or package-manager validation.
- Not yet safe to claim transactional *apply*, power-loss atomicity or
  reversible source edits. Incomplete staging after SIGKILL is refused for
  manual review, not silently rolled forward or back.
- The tested rootless filesystem does not prove system root permissions.
  Real Debian 13 / AlmaLinux 10 integration must explicitly verify
  root/non-root execution, package manager activity, selinux labels and
  symlink races. Path validation currently uses `lstat` plus
  `O_NOFOLLOW` on the source leaf; **it is not a full dirfd/openat2
  race-proof security boundary**, and may not be connected to a privileged
  apply path until proven safe against concurrent ancestor substitution.

## Mandatory follow-up acceptance gates

1. Prove a protected long-lived repository ownership manifest and stable IDs,
   including approved multi-entry file edits and external drift handling.
2. Add full-fidelity source parser and per-file diff validation. Stage only
   the affected entry while preserving unrelated content and file metadata.
3. Build secure dirfd/openat2-style path traversal and privileged
   filesystem-writing/atomic replacement and journal recovery, retaining
   ownership, ACLs, xattrs and SELinux labels. Add SIGKILL fault injection.
4. Verify real native APT/DNF package signature, TLS and fallback behavior,
   not just loopback HTTP metadata probing.
5. Reconcile with UC-43/44 uninstall preparation, native locks and
   two-snapshot retention rules before enabling the CLI write path.

**Status vocabulary:** The scope above may PASS synthetic tests; native
source-edit, recovery and security requirements remain **NOT VERIFIED**. No
PR merge without explicit maintainer approval and full scoped acceptance.
