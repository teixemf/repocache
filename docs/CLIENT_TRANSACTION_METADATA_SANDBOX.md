# Protected sandbox transaction with POSIX ACL and xattr snapshots

**Tracking:** [#24](https://github.com/teixemf/repocache/issues/24).  
**Status:** experiment; **no production APT/DNF source-writing capability**.  
**Base:** metadata copier [PR #134](https://github.com/teixemf/repocache/pull/134), pending scoped integration.  
**Already merged on main:** protected staging [#131](https://github.com/teixemf/repocache/pull/131), atomic sandbox [#132](https://github.com/teixemf/repocache/pull/132) and read-only preflight [#133](https://github.com/teixemf/repocache/pull/133). No duplicated modules are carried by this PR; real source writes remain disabled.

## Implemented laboratory flow

1. Prepare a protected original/proposed source snapshot using `transaction_stage.stage`, exclusively inside a private, explicitly marked temporary root.
2. Before issuing any write intent, `transaction_metadata_sandbox.snapshot_sandbox` obtains supported source attrs by file descriptor and verifies original inode, SHA-256, ownership, mode and timestamps against the protected stage.
3. Persist `original-attributes.json` in private transaction state (`0600`, under `0700`), referencing the original source hash and inode. Attr values are **base64-encoded, not redacted or encrypted**; protection depends on private filesystem permissions. Never upload, log or include raw values in CLI results.
4. The sandbox atomic writer independently checks the protected snapshot, validates the exact xattrs on the current inode, clones supported attributes onto the same-directory temporary target, validates byte and inode correctness via the existing transaction checks, and records its durable intent before replacing the source.
5. The same checks apply to explicitly requested rollback and recovery after interrupted replacement. A foreign inode, changed attributes or broken snapshot refuses automatic overwrite.
6. If a protected attribute snapshot is missing while the source bears any supported or unsupported xattrs, the previous fail-closed refusal remains in effect. Incomplete `.partial` metadata staging blocks use of the transaction. No partial state is silently discarded.

Supported by this **synthetic sandbox**: bounded `user.*` attributes and `system.posix_acl_access` (POSIX access ACLs), retaining file content, mode, owner/group and attribute bytes. `security.*`, `trusted.*`, unsupported attribute namespaces, including **`security.selinux`**, are refused.

## Test evidence versus policy

Unit tests cover source and metadata roundtrip, combined POSIX ACL+user xattrs, rollback/recovery, external xattr drift, missing/corrupt/duplicate snapshots, interrupted metadata snapshot, SIGKILL immediately after atomic replace, plus negative SELinux label injection. Native disposable Debian 13 and AlmaLinux 10 Docker images exercise actual `setfacl` and xattr behavior using the OS Python and synthetic APT-like source files.

**SELinux enforcing validation is NOT run in ordinary GitHub Actions containers.** It remains a required separate **NOT VERIFIED** acceptance item for later testing on an appropriate booted AlmaLinux 10 VM or host with SELinux actually enforcing. Skipping that CI scenario is **not** waiving the production security requirement, nor an authorization to copy/drop `security.selinux` labels.

## Remaining production blockers

- This is a deliberately guarded **/tmp laboratory**, NOT a privileged helper, and neither the installed client nor its `repos sync --apply` command imports or invokes it.
- Current stage directory and journal designs remain experiments: they are not a complete, signed/independently trusted ownership manifest or crash/power-loss transaction engine. A SIGKILL can leave a hidden temporary source or incomplete state requiring manual recovery.
- These tests do not prove protection against all concurrent same-UID/root actors, metadata races, disk-full, filesystem replacement, ACL defaults, SELinux policy, Linux capabilities or all security namespace attributes.
- Protected snapshots contain sensitive source data and may contain credentials: implement a complete state retention, audit, rollback and secure cleanup policy, and review permissions on all paths before deployment.
- Package-manager locks, source parser preservation in shared multi-entry files, fallback for real signed packages, HTTPS and upstream availability remain separate unverified acceptance criteria.
- No PR merge, release, or production mutation without explicit maintainer approval and full relevant acceptance gates.

This experiment is intended to narrow the **remaining** metadata blockers, not to declare the full #24 apply feature ready.
