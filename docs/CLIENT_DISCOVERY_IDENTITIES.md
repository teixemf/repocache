# REPOCACHE Client — Read-only discovery identities and selection

**Status:** Planned integration, implemented only in the read-only inventory and `repos sync` preview.  
**Tracking:** [#24](https://github.com/teixemf/repocache/issues/24), UC-27 and [CLI v1](architecture/CLI_ARCHITECTURE.md).  
**Depends on:** the [read-only planner PR #122](https://github.com/teixemf/repocache/pull/122).  
**Supported targets for eventual source writes:** Debian 13 and AlmaLinux 10; native package-manager behavior **NOT VERIFIED**.

## Discovery ID versus managed repository ID

This change introduces *deterministic, opaque discovery IDs* as an input
for read-only selection:

```console
repocache-client repos list --json
repocache-client repos sync --json
repocache-client repos sync --repo apt-0123456789abcdef01234567 --json
repocache-client repos sync --repo apt-0123456789abcdef01234567 --repo dnf-fedcba9876543210fedcba98
```

The IDs in these examples are **illustrative**, not real inventory entries.

- APT `.list` identifiers derive from the relative file path, source kind
  (`deb`/`deb-src`), sanitized URI, suite, components and architecture
  selectors. Line numbers, comments, whitespace and line ordering do not
  define identity.
- APT deb822 `.sources` identifiers derive from the relative file path,
  normalized Types, original sanitized URIs, Suites, Components and
  Architectures. Stanza positions are deliberately excluded.
- DNF `.repo` identifiers derive from relative file path and exact INI
  section name, without relying on the order of sections or current URL.
- Each ID is an `apt-`/`dnf-` prefix and a 24-character SHA-256 hex digest
  over a versioned, JSON-encoded semantic descriptor. The descriptor is not
  emitted; credentials and URL parameters are removed **before** hashing.
- Identical descriptors within a file yield the same ID and are marked
  `identity_conflict`; a targeted preview of an ambiguous ID is refused,
  never silently mapped to the first match.

**These discovery IDs are not permanent managed-state identifiers.** They can
change when an APT URI, suite, architecture or source file path changes, or
when files are moved. A future management layer must use an explicitly
protected state/ownership manifest and independently allocated stable managed
IDs to survive REPOCACHE route changes, recovery, upgrades and intentional
source migrations. Do not persist a discovery hash as the sole authority to
replace host-managed files.

## Preview selection and safety

The optional, repeatable `--repo ID` flag is accepted only by
`repocache-client repos sync` and filters the read-only plan to exact,
unambiguous identifiers. Multiple flags select their union; without flags
all discovered sources are included. Order in output remains discovery order.

Invalid IDs, unknown IDs and ambiguous duplicate sources produce a nonzero
status without requesting the catalog. Input is not repeated in error
messages; this avoids accidentally logging credentials supplied as an ID.
Disabled sources stay skipped and all reported `apply_eligible` fields
remain `false`. **`repos sync --apply` still fails before requesting the
catalog, with or without `--repo`.**

The existing `name` field and the approved CLI entry points remain
unchanged. This is an additive read-only output/flag change, not an
authorization to alter APT/DNF sources or to add new catalog repositories.

## Acceptance limits and follow-up

Synthetic tests cover reorder and comments, deb822 stanza order, DNF section
order and changed mirrors, multiple selection, invalid/unknown/ambiguous IDs,
redaction and byte-for-byte nonmutation. Passing these tests does not
establish whether APT/DNF can fail over correctly.

Before enabling source writes, build protected managed IDs and ownership
manifests, validate complete APT/DNF source grammar, reject duplicates
and symlink drift, prove verified package-manager fallback on both
distributions and implement atomic backups, locking, recovery and
read-before-write revalidation. See [read-only planner](CLIENT_SYNC_PLAN.md)
and the [functional contract draft in PR #115](https://github.com/teixemf/repocache/pull/115) (not yet merged).

No merge or release until exact-head CI, review and explicit maintainer approval.
