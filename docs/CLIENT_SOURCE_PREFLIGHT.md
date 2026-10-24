# Client source security preflight — read-only privilege-boundary groundwork

**Status:** Experimental, read-only library; **not** a deployed privileged
helper or APT/DNF writer. [Issue #24](https://github.com/teixemf/repocache/issues/24).
**Targets:** Debian 13 and AlmaLinux 10; native checks run in disposable
containers, **not** on booted production hosts.

## Operation and trust boundary

The new `client/source_preflight.py` performs one operation:
`inspect_source(relative, root=Path("/"))`. With the default root
it requires effective UID **0**. It takes a strict, exact relative-path
allowlist for APT `sources.list`, `.list`, deb822 `.sources`, local APT
mirrorlists and DNF `.repo` files. It does not accept an arbitrary path
or an executable argument.

It opens the root and each path component using Linux directory descriptors
(`O_DIRECTORY|O_NOFOLLOW`) and opens the source with
`O_RDONLY|O_NOFOLLOW|O_NONBLOCK`. It rejects:

- Directory components not owned by the expected UID or writable by group/other;
  symbolic links are not followed.
- Source files that are symbolic links, nonregular, hardlinked, foreign-owned,
  group/world writable or larger than 1 MiB.
- Pathname/inode replacement and source size, ownership, mode or timestamp drift
  detected between the beginning and end of the read.
- Security attributes that cannot even be enumerated. Extended attributes
  are **detected, not dropped, copied or disclosed**.

Only the SHA-256 digest, bounded metadata and a fixed symbolic blocker are
returned. No source contents, key material or xattr **values** are logged or
returned. The return payload always has `write_eligible: false`, including
when the input passes all read-only checks; if any xattrs exist, the blocker
is `security-metadata-preservation-not-implemented`.

## Test fixtures and permissions

To keep rootless tests repeatable, `root` can point to an **explicitly
marked private test directory below /tmp or /var/tmp**. This requires a
`0700`, UID-owned root and a regular, single-linked `0600` marker with
the exact test magic. The fixture marker **is not an authorization to perform
privileged writes**; this library performs no writes. A missing, symlinked,
hardlinked, permissive or incorrect marker fails closed. Normal operation
never uses a mutable caller-supplied root; future privileged helpers must
hardcode the native root and must not expose a root override.

Unit tests: `tests/test_client_source_preflight.py`.

Native CI: `.github/workflows/client-source-preflight.yml`, running
`scripts/smoke_client_source_preflight.py` with native Python inside
`debian:trixie-slim` and `almalinux:10`. Tests operate exclusively on
temporary APT- and DNF-like files and run negative symlink/permission checks.
No host package sources are changed.

## Explicit limitations and missing production gates

1. The check is **read-only** and does not provide a privileged command,
   safe helper installation, owner manifest, logging or OS authorization.
   It is not imported by `client/repocache_client.py` or its installer.
2. Checking inode metadata before/after reading detects common drift but
   **does not create an exclusive write lock** or eliminate all same-UID
   concurrent modifications. Future helpers require precommit validation
   on durable dirfds, narrowly delegated root operations and native
   package-manager lock coordination.
3. ACL, xattr, SELinux and filesystem label metadata are not yet copied or
   restored. Successful read-only checks do not guarantee correct label
   preservation on AlmaLinux 10; any xattr-bearing source requires a
   separate, reviewed metadata-preservation implementation before writes.
4. Source content and authenticity are **not parsed or validated** here;
   it is a filesystem trust check only. A caller must independently
   validate APT/DNF grammar, repository signatures, TLS/CA trust, fallback
   and safe per-file transformations.
5. Real root-owned source files, non-root denial across an actual privilege
   boundary, booted systemd/SELinux enforcing machines, privileged rollback,
   power-loss durability, disk-full handling and attacker-controlled
   filesystem races remain **NOT VERIFIED**.
6. The merged [#131](https://github.com/teixemf/repocache/pull/131)
   non-applying staging and [#132](https://github.com/teixemf/repocache/pull/132)
   sandbox atomic-write experiment remain independent, isolated components.
   Neither may adopt this checker as a general write authorization.
7. [#64](https://github.com/teixemf/repocache/issues/64) governs separate
   server-side NGINX reload privilege delegation and must not be conflated
   with client package-source administration.

## Acceptance gate for this scoped PR

- Exact-head pytest, CLI conformance and security gates must run and PASS.
- Native disposable Debian 13 and AlmaLinux 10 source-preflight smoke must
  run and PASS; results do **not** prove real source editing.
- Review the final diff, existing PR dependencies and any failed or
  missing required CI. Mark unverified acceptance criteria honestly.
- No merge without explicit maintainer approval. `repos sync --apply`
  remains disabled until **full** issue #24 acceptance is verified.
