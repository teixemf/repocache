# Atomic mixed-entry source replacement — test sandbox only

**Tracking:** [issue #24](https://github.com/teixemf/repocache/issues/24).  
**Parent:** unmerged [PR #142](https://github.com/teixemf/repocache/pull/142), itself dependent on #141/#140/#138/#133.  
**Transactional dependency:** #131 protected staging and #132 atomic sandbox writer, now **merged into main**; native integration uses pinned commit `ff7c7a4e20d716f3d67c145de6dde0bcbeb7f269`, not copies of those implementations.

**This is NOT a production client feature.** No installed CLI/installer invocation, service, privileged helper, or live `/etc` path mutation is introduced. `repocache-client repos sync --apply` remains disabled.

## Proposed entry-to-stage binding

The standalone `client/entry_atomic_sandbox.py` library provides three non-CLI test functions:

- `apply_entry_sandbox(root, candidate_id, stage_id, new_https_url)`
- `rollback_entry_sandbox(root, candidate_id, stage_id, new_https_url)`
- `recover_entry_sandbox(root, candidate_id, stage_id, new_https_url)`

The adapter checks real effective UID 0, the two independently marked/private /tmp sandbox gates, the protected explicit entry approval from #142, candidate and stage IDs, original full-file SHA-256 and metadata, selected entry type/key/byte-span/digest, original and proposed stage bytes and absence of any modification to sibling entries. A caller cannot promote an arbitrary protected stage into an entry-approved stage merely by supplying its ID. The staging/atomic backend independently verifies live source inode and content before rename/rollback.

The proposal changes **only one selected URL token**; unrelated APT `.list` lines, deb822 stanzas, DNF `.repo` sections, comments and already existing signature options remain byte-identical. The complete file is always the atomic replacement unit. This avoids half-file writes and prohibits an old plan from overwriting a sibling modified by Ansible or an administrator.

The apply operation invokes #132's `apply_sandbox`, which fsyncs a new same-directory file, journals the expected source/target inodes, and atomically replaces the test source. Explicit rollback invokes `rollback_sandbox` and refuses a source externally edited since the transaction's install. Recovery invokes `recover_sandbox` only after independently revalidating that the protected original/proposed payload is exactly the one approved for that entry.

**Important limits:** these checks and `os.replace` are not a race-proof compare-and-swap for hostile same-UID/root actors. The original #132 laboratory does not preserve arbitrary extended attributes or SELinux contexts; if xattrs are present it deliberately **refuses the write**. The pending #135/#137 experiments must be reconciled and verified separately before ever considering a production source writer.

## Native regression evidence

`.github/workflows/client-shared-entry-atomic.yml` runs `scripts/smoke_client_entry_atomic.py` under Debian 13 and AlmaLinux 10 native Python in throwaway Docker containers. It exercises:

1. Actual sandbox atomic update and exact original rollback with independent byte comparisons of a preserved sibling for all three APT/DNF source formats.
2. Real root/non-root enforcement by dropping a child process to UID/GID 65534.
3. Rejection of a foreign stage ID or a stale whole-file baseline after an operator changes a sibling.
4. Rejection of rollback after post-install external edits.
5. Child-process SIGKILL after atomic replacement but before journal completion; recovery must restore the complete original shared file, including every unselected entry.
6. Refusal when the source contains an unsupported `user.*` xattr so metadata is never silently dropped.

These are **container-level sandbox proofs**, not installation, real package upgrade or SELinux enforcing validation.

## Explicit production and integration blockers

- Formal approved managed ownership lifecycle and revocation per repository entry, stored and audited as real protected root-only state rather than private test approvals.
- Native-complete APT/DNF parsing and signature/fallback validation, including the existing upstream, sensitive repositories, local mirrorlists/metalink, metadata and package verification, scoped HTTPS CA and safe failover.
- Privilege separation with a small installed helper, native package-manager locks, collision-safe source-file authority, durable transaction metadata, complete backup retention and power-loss/interrupt recovery.
- SELinux enforcing context handling on **booted AlmaLinux 10 VM/host** remains **NOT VERIFIED**. Do not claim test coverage from standard GitHub Actions containers.
- Human code/security review, #142 parent integration, reconciliation with pending #135/#137, and explicit maintainer merge authorization.

No merge, release, production changes or enablement of `repos sync --apply` is authorized by this experimental implementation.
