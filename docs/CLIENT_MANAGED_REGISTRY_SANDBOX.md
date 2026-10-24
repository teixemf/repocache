# Client candidate managed-ID registry — protected sandbox proof

**Issue:** [#24](https://github.com/teixemf/repocache/issues/24); functional UC-07, UC-25/26/27/29/30/33.  
**Dependencies:** unmerged read-only preflight [PR #133](https://github.com/teixemf/repocache/pull/133) and read-only helper [PR #138](https://github.com/teixemf/repocache/pull/138).  
**Status:** scoped local experiment, **NOT** a production managed-ownership authority or native source writer.

## Managed identity versus discovery identity

Discovery hashes from [PR #129](https://github.com/teixemf/repocache/pull/129) identify **observed repository descriptions** and may change when source file paths, URLs or suites change. They are useful for a read-only sync preview, but must never be the only authority to overwrite a repository.

This experiment assigns a random, opaque **candidate managed ID** independent of the source path, line number, URL, source order and hash. A private file records an initial **whole-file** baseline, but the record is explicitly `state: candidate`, `ownership_granted: false`, `write_eligible: false`. Even a passing candidate check **does not entitle REPOCACHE to manage or edit the file**. In production, managed IDs will need separate, explicit ownership approval, entry-level mappings, secure upgrades, and a transactional manifest update after every legitimate change.

No server catalog entry or user-supplied discovery ID can create or approve managed ownership implicitly.

## Experimental entry points

`client/managed_registry_sandbox.py` exposes **Python library functions only**, not public CLI commands:

- `register_candidate_sandbox(root, relative, expected_sha256)`: verify an explicitly supplied SHA-256 precondition against a single, safe local APT/DNF source, run a deliberately narrow structure check, then create a protected candidate record.
- `inspect_candidate_sandbox(root, candidate_id)`: verify the private registry and compare the current file's SHA-256, device/inode, mode, UID/GID, timestamps, xattr-presence and format against that baseline. Return only `intact` or `drift`, always without management authority.

The root must be a **private marked fixture beneath /tmp or /var/tmp**. No `/` root registration is permitted, even for an EUID 0 test process. There is no root override in the installed CLI. Registry files live under `var/lib/repocache-client/managed-candidates-lab/` *inside that disposable fixture*, with UID ownership, private `0700` directories, `0600` candidate JSON and a nonblocking exclusive `flock` for registration and checking. Writes use a uniquely named temporary private file, `fsync` and same-directory publication.

The registry refuses unknown entries, pending crash artifacts, symlinked state, malformed JSON, duplicate source candidates, an attempt to set `ownership_granted=true` and concurrent lock access. No raw repository source bytes, credentials, xattr values or complete URLs are stored; the private record nevertheless contains local source paths and hashes and must remain protected. A same-owner privileged attacker can modify private state: these laboratory files are **not signed or tamper-proof**.

## Deliberately conservative source structure check

`client/source_structure_subset.py` is a **pure, bounded syntax subset**, not a complete parser and not a trust verifier. It currently accepts only:

- One active, uncomplicated `deb` or `deb-src` entry per APT `.list`/sources.list file; limited architecture and external keyring selectors.
- One simple deb822 `.sources` stanza with one type, URI and suite; enabled, with required components for normal suites.
- One DNF `.repo` section with a single `baseurl`, `gpgcheck=1`, enabled, and no explicit disabled metadata signatures.

Unrecognised options, duplicate DNF sections, multiple source entries, multi-URI deb822, disabled sources, embedded credentials, `file://`, APT inline comments/folded deb822 fields and other ambiguous forms are **refused for candidature**, not rewritten or normalized. Mirrorlists, metalinks, complex local keyrings, multiple APT suites and multi-entry files require a complete native-validated parser and safe entry-level transformation before production.

A structure PASS means **only** that the example belongs to this restricted grammar. It does not prove APT/DNF accepts the file, that the repository is legitimate, that metadata/packages are signed, that TLS trust is correct, that a cache route exists, or that upstream failover is safe. All returned acceptance indicators for those capabilities remain false.

## Acceptance and testing

Synthetic tests exercise candidate registration, independent IDs, source-inode substitution with identical bytes, external content/permissions drift, malformed/unauthorized private state, duplicate candidature, lock contention, symlinked directories, xattr presence, and fail-closed supported/unsupported syntax.

[Native sandbox workflow](../.github/workflows/client-managed-registry.yml) runs [smoke script](../scripts/smoke_client_managed_registry.py) with the OS Python in disposable Debian 13 and AlmaLinux 10 images. The smoke uses only temporary APT/DNF-like file fixtures and demonstrates that one file can drift without silently changing unrelated candidates.

## Remaining production blockers

**NOT VERIFIED:** authoritative admin-approved managed ownership and stable entry-level IDs across valid upgrades/migrations; full native APT/DNF grammar and mixed-entry preservation; actual protected state on a clean installed system; safe privileged root writer, package-manager locks, no hostile path races, journalled crash/power-loss recovery, xattr/ACL/SELinux retention, signed package trust, scoped HTTPS and verified fallback.

SELinux enforcing validation remains deferred to an actual booted AlmaLinux 10 host/VM, **not waived**. The installed client, installer, public CLI, and `repocache-client repos sync --apply` remain untouched; source writes are still disabled.

No merge/release or production claim without the project acceptance gate and explicit maintainer approval.
