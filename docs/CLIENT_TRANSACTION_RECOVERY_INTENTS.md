# Client transaction intent recovery — sandbox verification

**Issue:** [#24](https://github.com/teixemf/repocache/issues/24).  
**Implementation status:** read/write operations apply **only to explicitly marked private /tmp laboratory fixtures**.  
**Dependencies:** unmerged #131 (protected original snapshots), #132 (atomic sandbox), #133/#134 (Linux metadata checks), #135 (protected original ACL/xattr snapshots). This PR is stacked on #135 and **does not modify the installed REPOCACHE CLI**.

## Additional recovery invariants

A journalled intent records both `from_device/from_inode` and the intended destination `device/inode`. Upon restart under the staging `flock`, the sandbox writer inspects the exact pending source-directory temp name, **including content and supported xattrs**. The transaction can proceed only if its inode is the one recorded in the durable journal.

| Journal phase and source | Recovery decision |
| --- | --- |
| No journal, no pending temp | Report `no-intent`; do not modify source |
| No journal, unexpected pending temp | **Refuse**; retained for manual review |
| Install intent, original source inode still present, intended temp matches | Verify and remove only that own temp, then record `restored` |
| Install intent, original source inode present, no temp | Record `not-applied` after independent source verification |
| Install intent, new source inode already installed | Verify absence of an unexplained pending temp; restore the original through a new protected rollback intent |
| Restore intent, new source inode still installed, verified original-data temp present | **Resume the journalled rename** and record `restored` |
| Restore intent, original-data inode already restored | Verify no unexplained pending temp and record `restored` |
| Committed phase, source valid, no orphan temp | Report committed status, no write |
| Unknown temp, symlink, changed inode/content/xattrs or missing rollback temp | **Refuse**; do not delete/overwrite unknown state |

These states are tested with actual child-process `SIGKILL`, including termination **before rollback replacement**, which was a known unhandled state in the preceding experiment.

## Safety scope and limitations

- Test sources are disposable APT/DNF-like files, not active package repositories. The sandbox marker is not a production authorization token.
- This change fixes a test-lab recovery gap but **does not prove protection against a hostile same-UID process** modifying a pathname between `stat` and `os.replace`/`unlink`. A privileged helper must not use this lab as a race-proof write authority.
- The journal and checksum state are not signed, are not immutable against a privileged local attacker, and are not a production-quality ownership/authorization registry.
- Recovery remains incomplete for unjournalled temporary source files, unknown partial states, disk-full during cleanup, power loss, crash before all fsync boundaries, package-manager locks, non-native APT/DNF grammar and unverified fallback. These fail closed or require manual intervention.
- SELinux in enforcing mode on a **booted AlmaLinux 10 VM/host** is **NOT VERIFIED**, intentionally skipped in standard GitHub Actions container CI. No `security.selinux` attribute copying or production source apply is authorized on that basis.
- Real source editing and `repocache-client repos sync --apply` remain disabled. No merge, release or deployment without exact-head acceptance, required reviews and explicit maintainer approval.

The separate [helper design](CLIENT_PRIVILEGED_HELPER_CONTRACT.md) describes a future narrow privileged trust boundary; **there is no installed helper in this PR**.
