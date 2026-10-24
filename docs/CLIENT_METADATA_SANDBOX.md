# Client metadata preservation — sandbox experiment

**Scope:** experimental library `client/source_metadata_lab.py` for
[issue #24](https://github.com/teixemf/repocache/issues/24), building on
merged read-only preflight [PR #133](https://github.com/teixemf/repocache/pull/133).
**Production status: NOT VERIFIED — no privileged writes or `repos sync --apply`.**

## Supported experimental round trips

The `clone_sandbox_source(root, relative)` function uses the trusted,
allowlisted directory-descriptor preflight from #133. It accepts only
an explicitly marked **private temporary root beneath /tmp or /var/tmp**.
It opens one APT/DNF source by anchored directory descriptors and creates a
new, randomized, same-directory **clone**, never replacing the original name.

- Only regular single-linked source files owned by the invoking UID are
  supported. Group ownership and mode must be reproducible without
  privilege escalation; source/path identity and change times are
  rechecked before and after the clone.
- Supported Linux xattrs are `user.*` and `system.posix_acl_access`.
  Attributes are read through file descriptors and bounded to **32 names,
  8 KiB each, 64 KiB total**. POSIX access ACLs are applied after file mode
  to avoid silently rewriting the effective mask.
- The cloned file is fsynced, reopened through its directory descriptor,
  and independently verified for exact content SHA-256, content length,
  unchanged inode, POSIX mode, owner/group, exact xattr name/value tuples
  and matching ACL.
  On detectable errors, the incomplete clone is unlinked.
- Source file bytes and attribute **values** are never included in the
  result or diagnostic messages. The result always includes
  `production_apply_eligible: false`. Contents and xattrs only exist in
  process memory and within temporary private test roots.
- `security.selinux`, `security.*`, `trusted.*`, unsupported
  `system.*` or oversized attributes **fail closed**. SELinux context
  preservation is explicitly **NOT IMPLEMENTED**; a host with a SELinux
  label must not use this mechanism for production updates.

## Tests

`tests/test_client_source_metadata_lab.py` includes byte-preserving
APT/deb822 and DNF fixture cloning, `user.*` attrs including binary
values, POSIX access ACLs via `setfacl`, combined ACL+user attrs, invalid
root/paths, symlink/hardlink/writable sources, unknown security namespaces,
attribute bounds, concurrent xattr drift and cleanup after setxattr errors.

Native OS regression:
`.github/workflows/client-metadata-sandbox.yml` installs only `python3`
and `acl` **inside disposable Debian 13 and AlmaLinux 10 Docker
containers**. It runs `scripts/smoke_client_source_metadata.py` using the
OS Python, authentic Linux POSIX access ACLs and user xattrs on temporary
files, and asserts byte-for-byte equality. The GitHub checkout is mounted
read-only; no native package-source path is rewritten.

## Remaining requirements and explicit non-guarantees

- This is a **test-only copier**, not yet integrated with #131's protected
  journal, #132's atomic replacement/rollback or #133's installed client.
  There is no source writer under `/etc` and no helper authorization.
- ACL support is restricted to POSIX *access* ACLs on regular files.
  Default directory ACLs, security labels, SELinux enforcing policy,
  capabilities, file flags, device attributes and arbitrary xattrs are
  outside this scope and must not be silently discarded in production.
- `clone_sandbox_source` is not proof against a concurrent same-UID
  attacker: the source is rechecked for detectable drift, but no global
  operating-system/package-manager lock or fully race-free production
  authority exists. No safe journaling or hard-power-loss recovery is
  claimed; a SIGKILL can leave a hidden test clone.
- Metadata snapshot bytes are not yet bound to a protected transaction
  manifest. A future production writer must serialize metadata securely,
  revalidate after restart, preserve ownership/ACL/xattrs/SELinux as
  relevant and atomically commit or recover **without losing upstream**.
- Full native Debian 13/AlmaLinux 10 booted-host tests must cover SELinux
  enforcing, real root/non-root execution, ACLs on filesystems in use,
  package-manager activity, signature and TLS trust, inode conflicts,
  disk-full and interrupted writes before `--apply` can be exposed.

**Acceptance policy:** synthetic and native-container CI may establish
only the tested sandbox metadata-round-trip criteria. All production
requirements stay **NOT VERIFIED**. No merge without all scoped review
gates and explicit maintainer approval.
