# Atomic source replacement and recovery — sandbox experiment

**Issue:** [#24](https://github.com/teixemf/repocache/issues/24), UC-01/07/16/25/26/33.  
**Dependency:** [PR #131](https://github.com/teixemf/repocache/pull/131), protected non-applying staging; both remain unmerged.  
**Code:** `client/transaction_atomic_lab.py`; tests `tests/test_client_transaction_atomic_lab.py`.

## Critical security boundary

**This is NOT a production source writer.** The experiment is deliberately restricted to an explicitly marked temporary root beneath `/tmp` or `/var/tmp`, rejects the actual filesystem root, and is **not invoked** by `repocache-client`, `client/install.sh` or a privileged helper. The marker `.repocache-atomic-lab` must be private mode `0600` and contain the exact lab opt-in token; no production installation creates it.

Tests run on **synthetic APT/DNF files** and under the CI runner's current user. The pre-existing `repos sync --apply` refusal remains unchanged. The experiment cannot approve modifying an actual Debian 13 / AlmaLinux 10 configuration.

## What is implemented

- Reopen approved source directories through `O_DIRECTORY|O_NOFOLLOW` dirfds, refusing writable/foreign-owned components; open leaf with `O_NOFOLLOW` and compare pathname identity to the opened inode.
- Refuse source files with unexpected hardlinks or extended attributes, rather than discarding unhandled ACL/SELinux metadata.
- Compare the protected stage's exact original content, inode and ownership/mode/timestamps immediately before a replacement. Unknown external changes stop the transaction.
- Create a same-directory temporary source with mode `0600`, then preserve the staged mode, `fsync` its content, and persist an intent journal **before** `os.replace`; `fsync` the directory after replacement.
- Record the origin and destination inode/device pairs, not just hashes, and write a committed phase after the replacement. A second application of the same stage is refused, not silently repeated.
- Expose test-only `apply_sandbox`, `rollback_sandbox`, and `recover_sandbox`. Explicit rollback restores exact original bytes only when the installed inode and contents remain unchanged.
- Detect interrupted `SIGKILL` writes: if replacement did not happen, mark it non-applied; if the intended proposed inode reached the target, automatically revert it from the protected snapshot. An interrupted completed rollback can be recognized by its recorded destination inode.
- Fail closed on unexpected journal files or corrupt state. Never undo an externally replaced inode, even when it happens to contain the expected bytes.

## Important limitations / blockers

1. **Not complete crash safety.** Some interruptions leave source-directory temporary files; recovery refuses ambiguous state and can require a manual clean-up. Interrupted rollback before replacement is not guaranteed to resume. No actual power-loss durability has been demonstrated.
2. **No privilege isolation for deployment.** Same-UID concurrently writing actors and directory rename races across root anchors are not proven safe. The lab is not a hardened `openat2` privileged file writer or trusted root helper.
3. **No ACL, xattr or SELinux preservation.** Extended attributes are refused; custom ACL and SELinux behavior are NOT VERIFIED on real hosts. Ownership/group is accepted only when exactly compatible with the test actor.
4. **No package-manager coordination.** APT/DNF locks, parser correctness, comments in multi-entry files, signature trust, TLS and fallback policy validation remain separate mandatory acceptance gates.
5. **No stable managed repository ownership registry** and no complete two-backup retention / uninstall policy. The stage manifest is not evidence of entitlement to edit a source.
6. **No release/installation integration.** Do not add an option to bypass the sandbox guard or treat passing unit tests as authorization to enable `--apply`.

## Minimum reproducible acceptance

Execute `pytest -q tests/test_client_transaction_atomic_lab.py` on the exact PR head, with CI Python 3.12/3.13 regression and security checks. Tests verify atomic replacement, explicit rollback, source content/mode retention, broken/absent guard, external content and inode drift, unsupported xattrs, unexpected stage data, three real subprocess `SIGKILL` windows and refusal of uncertain state.

Before production apply, independently build a trusted fixed-path minimal-privilege helper, full source parser and bounded atomic changes, a complete safe recovery journal, exact native APT/DNF signature/TLS/fallback tests under authentic package installation, OS filesystem attributes/SELinux checks, root/non-root privilege tests and protected long-lived ownership/ID state. Mark any unavailable evidence **NOT VERIFIED**, not PASS.

No merge unless scoped acceptance criteria and security gates PASS and the maintainer explicitly approves.
