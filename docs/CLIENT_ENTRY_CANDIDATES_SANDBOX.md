# Client entry-level source boundaries and candidate identity

**Issue:** [#24](https://github.com/teixemf/repocache/issues/24).  
**Parent:** [PR #140](https://github.com/teixemf/repocache/pull/140) (protected *whole-file* candidate registry), depending on unmerged [#138](https://github.com/teixemf/repocache/pull/138) and [#133](https://github.com/teixemf/repocache/pull/133).  
**Status:** test-only, **no administrator-approved ownership and no source writer**.

## Motivation and security invariant

APT `.list` files may contain multiple `deb` entries, deb822 `.sources` files multiple stanzas, and DNF `.repo` files multiple sections. A source file is a **shared configuration container**, not proof that every contained repository belongs to REPOCACHE. UC-33 requires logically independent per-repository decisions while retaining file-scoped atomicity and recoverable backups. External tools (e.g., Ansible) must never be overwritten silently.

The read-only `client/source_entry_boundaries.py` identifies exact byte intervals for:
- Individual active `deb` / `deb-src` lines; preserve unrelated comments and blank lines.
- Individual deb822 stanzas separated by blank lines.
- Individual DNF `[repository-id]` sections; duplicate section names and malformed headers refuse the entire file.

This is **boundary discovery**, not full native APT/DNF parsing. Each entry has an exact SHA-256, a byte start/end offset, type and a conservative structure-subset eligibility flag. Unknown entry grammar may be inventoried with `structure_subset_pass=false`, **never accepted for candidate registration**; ambiguous boundaries refuse the entire file. Byte offsets and discovery ordering must **never** be used as durable write authority.

## Test-only per-entry candidate registry

`client/entry_candidate_sandbox.py` provides two **Python-library-only** operations:

- `register_entry_candidate_sandbox(root, relative, expected_file_sha256, chosen_entry_sha256)`: require a private, explicitly marked /tmp or /var/tmp fixture, verify complete source metadata and file digest via dirfd-anchored preflight, identify **exactly one** eligible entry by entry digest, and privately register a new random 128-bit candidate ID.
- `inspect_entry_candidate_sandbox(root, id)`: verify the protected candidate and reobserve all entries. Distinguish `intact` (file and entry unchanged), `file-drift` (selected entry still present, but shared file or its inode/metadata/position changed), `entry-drift` (selected entry changed, removed or ambiguous), and `conflict` (unsafe or unreadable source). Never silently rebaseline.

A protected `entry-<id>.json` binds a candidate to original entry and entire-file digests, source relative path, exact byte span, DNF section key where relevant, file inode/dev/owner/mode/timestamps and xattr presence. It explicitly records `state=candidate`, `ownership_granted=false`, `write_eligible=false`. These fields are **not mutable approval flags**; manually setting them to true invalidates the schema.

Storage uses a **separate** `var/lib/repocache-client/entry-candidates-lab/` namespace inside the marked private temporary root, with UID ownership, 0700 private directories, 0600 records, nonblocking exclusive flock and fsynced publication. The previous whole-file candidate namespace remains independent.

**Important:** Each successful candidate registration stores only metadata. It never rewrites the source, never contacts a catalog, never installs a helper, and does not authorize write operations. Matching a fingerprint or a valid local JSON record is NOT an administrator authorization, package-trust proof or source-writing capability.

## External changes and shared files

If an operator or Ansible edits an unrelated entry or merely adds a comment in the same file, the selected entry may still be recognized. Nevertheless, its enclosing **file baseline is dirty**. Any future file-scoped atomic commit must reject the old plan, re-read the complete file and require a new independently verified transaction before changing even the originally selected entry. This prevents using a stale whole-file snapshot to overwrite someone else's changes.

- A byte-identical replacement inode is also a file conflict.
- A changed selected entry is `entry-drift`, not an auto-approved baseline update.
- Duplicate identical entries or DNF duplicate section IDs are ambiguous.
- Corrupt, symlinked, unknown, partial or unauthorized private records block operations; unrelated valid entries do not grant permission to repair uncertain state.

## Test strategy and limitations

The unit tests cover mixed APT `.list` with comments, multi-stanza deb822, mixed DNF sections with a disabled sibling, two separate candidates from one source, sibling edits, target edits, same-byte inode changes, duplicate candidate selection, structural ambiguity, malformed/foreign state and lock contention.

[Native regression workflow](../.github/workflows/client-entry-candidates.yml) runs [disposable source fixtures](../scripts/smoke_client_entry_candidates.py) in **Debian 13** and **AlmaLinux 10** with OS Python, checking that sibling edits cannot authorize changes and that fixture sources remain byte-for-byte intact until deliberate test edits.

**NOT VERIFIED / production blockers:**
- Administrator-approved *managed ownership* and a stable entry-level lifecycle through legitimate edits, reordering, migration, addition/removal and uninstall.
- Full APT/DNF native parser, safe mixed-file byte patching, comment and attribute preservation, package GPG/metadata/trust, scoped TLS and verified upstream fallback.
- Privileged root helper, actual package-manager locks, hostile concurrent modification resistance, complete durable write journal, rollback and power-loss recovery.
- SELinux enforcing on a **booted AlmaLinux 10 VM/host**. Standard GitHub Actions containers are unsuitable: that scenario remains **NOT VERIFIED**, not waived.
- Independent code/security review and explicit merge authorization. A passing sandbox test does not satisfy full #24.

No public client CLI changes. `repocache-client repos sync --apply` remains disabled. No merge/release/production edit is authorized by this experiment.
