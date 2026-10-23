# Release Operator CLI contract — issue #88

**Architecture source of truth:** [CLI_ARCHITECTURE.md](CLI_ARCHITECTURE.md),
v1.0, sections 2.3, 3, 6–9, 11–13. That file's **FROZEN DESIGN** controls
this contract. This document specializes its release-operator grammar; it
does not establish a competing CLI policy.

**Status:** **approved syntax design / implementation NOT VERIFIED**.
Command examples below are **target syntax**, **not installed help output**.
No release, tag, signature, Draft Release, merge or publication is authorized
by this document. The issue #88 original flat examples are superseded.

## 1. Executable ownership and hierarchy

\`\`\`text
repocache-release
├── environment
│   └── check
└── candidate
    ├── prepare VERSION
    ├── sign VERSION
    ├── stage VERSION
    ├── status VERSION
    └── publish VERSION

Future, not registered yet:
└── key
    └── check           [optional; no approved release target]
\`\`\`

The **separate** \`repocache-release\` program runs on the maintainer's
workstation, never as a server daemon or client runtime dependency. The
canonical grammar is **object → action → positional target → options**.
\`candidate\` is the singular resource object approved by the architecture;
do not add a plural alias without a design revision.

\`\`\`console
repocache-release environment check
repocache-release candidate prepare v0.5.0
repocache-release candidate sign v0.5.0 --passphrase-fd 3
repocache-release candidate stage v0.5.0
repocache-release candidate status v0.5.0 --json
repocache-release candidate publish v0.5.0
\`\`\`

**Migration of issue #88's provisional flat commands**:

| Former proposed invocation (never the final architecture) | Canonical v1.0 target |
| --- | --- |
| \`repocache-release doctor\` | \`repocache-release environment check\` |
| \`repocache-release prepare VERSION\` | \`repocache-release candidate prepare VERSION\` |
| \`repocache-release sign VERSION\` | \`repocache-release candidate sign VERSION\` |
| \`repocache-release stage VERSION\` | \`repocache-release candidate stage VERSION\` |
| \`repocache-release status VERSION\` | \`repocache-release candidate status VERSION\` |
| \`repocache-release publish VERSION\` | \`repocache-release candidate publish VERSION\` |

No flat compatibility aliases should be registered: the old names were
**unimplemented proposals**, not deprecated public stable commands.
If a publicly distributed release had shipped these entry points,
the architecture's two-*published-stable-release* deprecation rule would
apply instead.

## 2. Shared argument and output rules

- **Version** is a positional release identity, e.g. \`v0.5.0\`. Reject
  absent/malformed versions, unsupported release profiles, ambiguous tags,
  unsigned candidates and commits that do not match their successful
  reviewed Actions run. Never reinterpret "latest" as a version unless a
  separate signed selection policy is approved.
- **Global \`--json\`** must work **before the object** or **after the
  action and its operands**, with identical results:
  \`repocache-release --json candidate status v0.5.0\` and
  \`repocache-release candidate status v0.5.0 --json\`.
  Both successful and failed finite JSON commands emit exactly **one**
  JSON document on stdout; human diagnostics on stderr only. Semantic
  minimum: boolean \`ok\`, failure \`error.code\` (stable symbolic ID),
  failure \`error.message\` (redacted actionable text). The **exact**
  \`schema_version\`, result structure, error registry and numeric exit
  codes must be reconciled with the three-program cross-CLI contract before
  release. Never invent an independently incompatible numeric map.
- **Human output:** results on stdout, failures and warnings on stderr.
  The operator CLI must not prompt, spawn a TUI, elevate via \`sudo\`,
  ask for a passphrase implicitly, or echo credentials.
- **Object help:** \`repocache-release candidate\` or
  \`repocache-release environment\` displays contextual help with **no
  network login, filesystem modification or other side effect**.
  \`--help\` similarly performs no probes. Expose only operationally
  implemented commands in installed help.
- **\`--dry-run\`:** only add to a mutating handler once it is proven to
  perform **zero persistent local and remote mutations**, including state
  files, signatures, GitHub releases and audit records. It can perform
  documented read-only checks, never impersonates actual authorization
  or validates a publication as complete.
- No global \`--yes\` bypass, no automatic next-stage transition, no
  arbitrary \`--filter\` parser and no retry loop that silently publishes.
  Option placement and validation follow the server and client programs.

## 3. Operations and ownership boundaries

| Command | Required input / behavior | Writes and gate | Status |
| --- | --- | --- | --- |
| \`environment check\` | Check Git, \`gh\` read scopes, OpenSSL, Python support, host profile and approved Ed25519 public-key fingerprint; check signer key path owner/mode **without unlocking it** | Read-only diagnostics; no root or credential prompt | PLANNED |
| \`candidate prepare VERSION\` | Resolve reviewed tag, exact commit and successful owner-run Actions identity; fetch unsigned artifact, rebuild and compare source, signed policy and exact dependency-profile lock/digests | Safe idempotent restricted local cache/state only; **does not sign/stage/publish** | PLANNED |
| \`candidate sign VERSION --passphrase-fd FD\` | Validate local encrypted Ed25519 private key matches independently pinned public anchor; verify prepared candidate unchanged, sign manifest and provenance, verify signatures | **Explicit separate local owner action**; never read passphrase from argv, env, GitHub Secrets or logs | PLANNED |
| \`candidate stage VERSION\` | Verify the complete owner-signed exact asset set, tag/commit and manifest; create/reuse authorized GitHub **Draft Release** only on exact byte match | Explicit separate remote-write action; reject drift and unknown existing assets | PLANNED |
| \`candidate status VERSION\` | Read evidence from **#76/#78** for the exact signed candidate, both supported native OS matrices, asset digests, current gate verdicts and approvals | Read-only; report **PASS / FAIL / NOT VERIFIED** for each criterion, no synthetic PASS | PLANNED |
| \`candidate publish VERSION\` | Verify fresh completed acceptance for the **same exact** assets/commit/run, owner publication authorization and server immutability settings | **Separately invoked irreversible action**; refuse existing published release, changed draft assets or skipped checks; verify postpublication digest inventory | PLANNED |

The \`--passphrase-fd FD\` option is a **sign-only local-input adapter** to
be tested, not a way to save passwords. The descriptor must be a caller-owned
readable FD with bounds, one controlled read and memory-only lifetime.
Unexpected EOF, zero bytes, control sequences, symlinked/mispermissioned
private key, wrong signer and mismatched public fingerprint fail closed.
For use by a human, a **distinct approved interactive interface** may
request the secret; do not accidentally turn the noninteractive CLI into
that UI. The operator may use KeePassXC to hold an encrypted PEM and supply
its password at the point of signing. Never pass the PEM/key password to
Actions, GitHub, a server or a client.

No action is both a verifier and an automatic authorizer. Stage, sign and
publish are deliberately **separate**, and a successful preparation or
acceptance run never silently advances the next operation.

### Candidate state model (internal; independent of CLI encoding)

Use one release service backend for a future CLI/TUI, not scripts that
reimplement signature validation. Identify a candidate by:

- Canonical version and **signed dependency profile** (v0.5.0's legacy
  eight-asset wheelhouse and any *later* approved v0.6+ online profile).
- Exact reviewed source SHA, GitHub Actions run ID and attempt.
- Public publisher key ID and independently pinned fingerprint.
- Complete **byte SHA-256 inventory** of unsigned and signed files.
- Accepted checks, test run IDs and evidence tied to the same digest set.
- Last accepted stage and local/remote observed state (nonsecret only).

Persist resumable state under an owner-only directory using atomic writes
and restrictive permissions. A repeated \`prepare\` or \`stage\` with identical
verified inputs may report **unchanged**, while changed bytes must not be
silently adopted. Signing is always explicitly authorized, not an
automatic retry. Published immutable versions **must not be re-published**;
a repeat \`publish\` refuses before any API write (stricter one-time
publication policy from #88). A safe recovery path reports the already
published version and its immutable verified identity via \`status\`.

## 4. Integration with the current GitHub roadmap

- **#88:** command parser/UX shell, workstation packaging, resume state,
  validation adapters, human/manual approval boundaries and operator tests.
- **#76/#78, draft PR #77:** authoritative signed-candidate read-only
  prepublication acceptance engine; #88 **must call/reuse it**, not duplicate
  its manifest rules, parser or CI. Acceptance of a **real** owner-signed
  v0.5.0 candidate remains unverified until it actually runs.
- **#80/#82/#84:** versioned future signed source-only dependency profile;
  do not hard-code v0.5.0's eight assets into generic CLI grammar.
- **#36 and repository rulesets:** never authorize unreviewed/unmerged
  tags, bypass a protected main, sign via CI, or mutate published
  immutable versions.
- **CLI_ARCHITECTURE.md INT-01/INT-02:** numeric exit mapping and
  versioned JSON schema stay explicit integration dependencies.
- **All versions:** only supported Debian 13 and AlmaLinux 10 product
  targets; workstation environment diagnostics do not assert Linux
  server support on any other distro.

## 5. Executable acceptance tests required before enabling commands

| ID | Required test | Expected result |
| --- | --- | --- |
| REL-CLI-01 | Root \`--json\` and trailing \`--json\` | Identical one-document stdout; meaningful nonzero failures and redacted error codes |
| REL-CLI-02 | Object alone, each nested \`--help\`, version omitted | Side-effect-free help or usage error; no network or secret prompts |
| REL-CLI-03 | Old flat \`doctor/prepare/sign/stage/status/publish\` | Not accidentally exposed as competing public commands |
| REL-CLI-04 | Invalid version, tag mismatch, bad workflow run/head | Deterministic failure **before** signing, upload or publication |
| REL-CLI-05 | Missing/wrong/expired/corrupt signed manifest/provenance | Fail closed and preserve candidate bytes and state |
| REL-CLI-06 | Passphrase FD EOF, wrong key, wrong owner/mode | Fail closed, no interactive prompt, no secret output/log |
| REL-CLI-07 | Repeated prepare and exact-matching stage | No duplicated generation or asset upload; safe unchanged result |
| REL-CLI-08 | Changed draft asset, wrong acceptance run or stale CI | \`status\` NOT VERIFIED / FAIL, \`publish\` refused |
| REL-CLI-09 | \`--dry-run\` on any exposed command | No persistent local or remote mutation, including keys, tags and audits |
| REL-CLI-10 | Publish lacks separate approval or already exists | No write; prevent automatic transitions or overwrites |
| REL-CLI-11 | Main client/server CLI regression suite | Approved \`repocache-client\` anchors, \`repocache update list\`, TUI startup preserved |
| REL-CLI-12 | Native Debian 13 + AlmaLinux 10 signed candidate tests | Real accepted signature and OS-specific evidence, no fixture-only claims |
| REL-CLI-13 | Interrupted download/FD/API and resumed stages | Bounded, recoverable, digest-pinned, no credential leak |
| REL-CLI-14 | Source-only vs legacy dependency profile | Version-specific manifest validation, no fixed global asset count |

**Executed tests for this syntax-only document:** none. Syntax coverage,
runtime packaging, CI execution and published capabilities are
**NOT VERIFIED** until the implementation PR and independent acceptance
gates are complete. This command table is not an authorization to merge.

## 6. Explicit examples for a future validated implementation

\`\`\`console
# Read-only machine diagnostics, not an installation:
repocache-release environment check --json

# Preparation never signs anything:
repocache-release candidate prepare v0.5.0

# The key password is supplied through a caller-provided FD 3,
# not literally by any example shell variable or CLI argument:
repocache-release candidate sign v0.5.0 --passphrase-fd 3

# No implicit progression:
repocache-release candidate stage v0.5.0
repocache-release candidate status v0.5.0 --json

# Separate authorized publication on an unchanged, accepted candidate:
repocache-release candidate publish v0.5.0
\`\`\`

**Do not copy these commands into a production script** before the
workstation operator is actually implemented and verified. Existing
low-level \`scripts/offline_sign_release.py\` and the CI release workflow
remain distinct current mechanisms, not substitutes for this target
operator CLI.
