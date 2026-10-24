# Client metadata-aware shared-file transaction integration

**Tracking:** [issue #24](https://github.com/teixemf/repocache/issues/24).  
**Active review stack:** [#152](https://github.com/teixemf/repocache/pull/152) (`main`-based read-only foundations) → [#155](https://github.com/teixemf/repocache/pull/155) (sandbox approvals and atomic staging) → [#156](https://github.com/teixemf/repocache/pull/156) (metadata-aware recovery). Earlier [#138](https://github.com/teixemf/repocache/pull/138)/#140/#141/#142/#144/#146 are superseded for integration review, with original PR history and refs retained.  
**Source provenance:** [#134](https://github.com/teixemf/repocache/pull/134) and [#135](https://github.com/teixemf/repocache/pull/135) are already merged to `main`: preserve their laboratory ACL/xattr and staging implementations instead of duplicating or reverting them. [#137](https://github.com/teixemf/repocache/pull/137) has also been merged into `main`; the clean review must reuse its verified recovery-intent code without introducing a second divergent copy.  
**Already merged:** #131 protected transaction staging, #132 sandbox atomic writer, #133 dirfd preflight, #134 source ACL/xattr laboratory, #135 transaction metadata support and #137 recovery-intent hardening. The clean stack must reconcile with the latest `main` before any merge; it retains only scoped new per-entry functionality and sandbox-only integration.

## Changes, boundaries and trust

- A candidate selection refers to **one exact entry**, while atomic replacement and rollback operate on the **complete original file**. Validate the selected entry against explicit local test-only approval, source SHA-256/inode/metadata and an exact protected transaction stage. All sibling entry bytes must match the baseline; comments, suite, signature options and unrelated sections are unchanged.
- The stage-only adapter can prepare a proposed file even if the original contains supported Linux `user.*` attributes or a POSIX access ACL. Before disclosing the stage ID, it **must** capture a private, fsynced original-attribute snapshot; this is strictly tied to the original full-file hash and inode.
- The atomic sandbox engine checks the protected metadata and rejects any drift, unsupported attribute or broken snapshot before writing. A same-directory temporary target receives mode, bounded supported xattrs and POSIX access ACLs, and is fsynced and verified before its logged rename. Both explicit rollback and bounded interrupted-write recovery validate and preserve protected attributes.
- Unknown `security.*`, `trusted.*` or other unsupported namespaces, including `security.selinux`, **fail closed**. They are **not silently dropped, relabelled or treated as a green production readiness criterion**.
- With **no** attribute snapshot present, the previous safe behavior remains: an xattr-bearing file cannot be replaced. Missing, corrupt, duplicate or incomplete metadata records or orphaned temporaries block the affected transaction without forcibly cleaning unverified state.
- Refuse foreign inode, unknown temp, FIFO, changed content, changed attribute or changed source metadata. The hardened SIGKILL recovery from #137 can safely resume a journalled rollback intent only when the exact intended temporary inode/content/attributes match. Unprovable state requires manual intervention.

The only authorized writes in this integration are in a **marked, private, disposable test root under /tmp or /var/tmp**. Approval records and protected transaction state are likewise private **laboratory** data; no public CLI or installed privileged helper is registered or invoked. In particular `repocache-client repos sync --apply` continues to refuse production modifications.

## Test design

The workflows run exact-PR-head source, not an older dependency checkout, with OS Python in ephemeral **Debian 13** and **AlmaLinux 10** containers.

- `Client Shared Source Atomic Sandbox`: APT multi-line, deb822 multi-stanza and DNF multi-section source files. With real `setfacl` and `user.*` xattrs, an approved entry is changed atomically and rolled back. Verify the full original file, byte-identical unselected entries, ACL/xattr bytes, mode and approved stage. Negative scenarios verify post-stage and post-apply metadata drift.
- `Client Transaction Metadata Sandbox`: separate private-stage ACL/xattr snapshots, copy/rollback, SIGKILL-after-rename recovery, duplicate/corrupt/partial snapshot and unsupported security namespace refusal.
- `Client Metadata Sandbox`: source cloning roundtrip with real ACL/xattr support and unsupported metadata namespace refusals.
- Unit/CLI/security suites: include #131/#132/#133 regression tests as well as #134/#135/#137 fault injection and the #140–#144 entry-level tests.

## Known limitations and merge gate

**This is not a privileged production source writer.** These tests cannot prove atomic compare-and-swap against malicious processes with equal privileges, root-safe config mutation, power-loss durability on arbitrary filesystems, full native APT/DNF parser behavior, package-manager locking, signed GPG metadata/package verification, TLS/trusted CA handling, authentic upstream failover, or correct package install/upgrade/uninstall recovery.

The protected snapshots contain source bytes and **base64-encoded xattr values**, not encrypted secrets. Production use requires a reviewed ownership, retention, access, audit and cleanup design. A private filesystem directory does not protect metadata against its privileged owner.

**SELinux enforcing remains NOT VERIFIED.** Normal GitHub Actions containers do not demonstrate actual enforcing context correctness. The production acceptance gate still requires a booted AlmaLinux 10 host or VM with SELinux enforcing and verified label preservation. Until that is proven, unknown security namespaces must always refuse writes.

The clean integration review is **#152 → #155 → #156**, with each PR based on the immediately preceding reviewed branch; do not merge the superseded experimental PRs independently. Before any eventual mainline integration, reconcile the clean-stack divergence from current `main` and verify that already-merged #131/#132/#133/#134/#135/#137 code is not duplicated, reverted or weakened; obtain human/security reviews, run required exact-head CI after reconciliation and map every acceptance criterion to reproducible evidence. **Do not merge or activate apply under a partial PASS.**
