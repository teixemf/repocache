# Client privileged source-helper contract (design only)

**Status:** PROPOSED architecture, no executable privileged helper; [issue #24](https://github.com/teixemf/repocache/issues/24).  
**Scope:** Debian 13 and AlmaLinux 10 only.  
**Related:** protected staging #131, sandbox atomic recovery #132, source preflight #133, metadata #134, metadata-transaction integration #135. #131–#135 are merged into main. This document proposes a future helper only and does not grant production write authority.

## Security model

The interactive or scriptable `repocache-client` is unprivileged by default. A future *minimal, root-owned helper* should be invoked only through a narrow non-interactive command with explicit arguments, and only from a trusted installed binary/package. The helper, not the CLI, is the ultimate authority for a change. It must not accept an arbitrary file path, shell command, remote catalog payload, unchecked repository URI, user-supplied temporary-file path or unsigned write recipe.

**Proposed fixed operations** (not currently available):

| Operation | Authority and expected behavior |
| --- | --- |
| `status` | Read-only status; redact credentials and secret metadata |
| `validate` | Read protected owned manifest + exact transaction; check local sources, grammar, upstream fallback and signature/TLS policy without writing |
| `commit` | After validation, mutate only allowlisted, manifest-owned repository entries under a global transaction lock; use a validated, prepared and integrity-protected plan identifier, not arbitrary file bytes |
| `recover` | Inspect a journal after interruption, restore only when the current inode/digest/attrs provably belong to this transaction, otherwise refuse and retain evidence |
| `restore` | Administrator-authorized reversion, with the same validation gates, not a filesystem-wide force overwrite |

This table is a proposed logical interface, **not approved CLI syntax**; integrate with CLI v1 and UC-22/27 before implementing any executable contract.

## Trust boundaries and authorization

- Root-only mutation and private state owner; no implicit sudo/polkit escalation from script-friendly client commands. Do not create a network-facing daemon or delegate through NGINX.
- Use `openat2` resolution restrictions (or a thoroughly audited, equivalent dirfd strategy), strict allowlisted source directories, inode/type/owner/link/permission checks, anti-symlink/hardlink protections and bounded payload sizes.
- Manage stable ownership IDs independently of discovery hashes. Reject unknown or externally modified repositories. Confirm the exact original source content and all security metadata immediately before committing.
- Coordinate APT/DNF native locks and a REPOCACHE exclusive transaction lock. Fail fast with a script-stable nonzero exit code while package managers are active; do not block waiting or rewrite under package-manager activity.
- Store original and prior approved configuration, signatures, ownership and validated transactional states privately with strict retention and recovery policy. Never log or expose credentials, xattr values, tokens, private keys, or full original source bytes.
- Preserve original package verification (APT InRelease/Release GPG, DNF repo metadata and package policy), scoped TLS CA and native fallback; the helper must refuse changes if fallback and trust cannot be proven for the concrete repository.
- Treat `security.selinux` and unknown xattrs as a blocker until verified on a **booted AlmaLinux 10 enforcing environment**. Standard GitHub Actions containers do not provide this acceptance evidence. The CI enforcing test is deferred, the production security requirement is NOT WAIVED.
- For privileged commits, refuse disk/IO/memory exhaustion and uncertain recovery conditions without silently deleting snapshots. A clean rollback route and administrator-visible diagnostic state are mandatory.

## Recovery-specific invariants

Each intent must record the original and intended source (device, inode), content digest and normalized security metadata. The new temporary file must be fsynced before the journal intent is durable. On restart:

1. Observe exact source inode + bytes + metadata under trusted dirfds and the exclusive transaction lock.
2. If the original is still present, cancel an interrupted install only if the pending temp is demonstrably the journalled inode. Unknown temp => conflict, no deletion.
3. If the intended update is present, finish a safe rollback only when no external edit occurred; otherwise preserve it and report a conflict.
4. For interrupted rollback with the original bytes still staged as a journalled temporary file, verify temp inode/content/ACL/xattrs before resuming the pending replacement. Missing, symlinked or altered temp => conflict.
5. Never infer permission to overwrite from a matching SHA-256 alone, and never automatically remove unmatched temporary files.

The current sandbox laboratory tests some of these invariants under synthetic conditions. It does not guarantee Linux rename compare-and-swap semantics against a concurrent actor of equal privilege; **there is no general atomic CAS rename provided by `os.replace`**, and a precommit `stat` is not sufficient for a production race-proof writer.

## Acceptance evidence required before helper installation

The helper is **NOT IMPLEMENTED** and source edits remain blocked until all relevant evidence is PASS: protected ownership registry; real APT/DNF parser and multi-entry preservation; authentic package manager fallback and TLS/GPG tests under failure; root/non-root permission paths; fail-fast locks; race testing under hostile concurrent processes; complete fault injection including SIGKILL, disk-full and power failure; SELinux enforcing, ACLs and xattrs; signed clean-install/upgrade/recovery workflow; compatibility and migration; reviewed CI and security gates; explicit maintainer merge approval.

No production use and no `repos sync --apply` enablement follow from this design alone.
