# Read-only client source-helper prototype

**Status:** experimental, **not installed or exposed as an approved public CLI**.  
**Tracking:** [issue #24](https://github.com/teixemf/repocache/issues/24), CLI architecture #107.  
**Dependency:** [PR #133](https://github.com/teixemf/repocache/pull/133) for the strictly read-only, dirfd-anchored source preflight. **PR #133 is already merged into `main`.**

## Narrow prototype interface

The standalone, non-installed `client/source_helper_preview.py` deliberately accepts only two read-only subcommands:

```console
python3 client/source_helper_preview.py --json status
python3 client/source_helper_preview.py inspect-source --source etc/apt/sources.list.d/example.sources --json
```

These commands are **development probes**, not user-facing `repocache-client`
commands. No installer, service, setuid binary, sudo rule, Polkit policy,
daemon, delegated root capability or new package entrypoint is created.

- `status`: returns static prototype capabilities, not a claim that a
  production helper is installed, and does not access the package sources.
- `inspect-source`: performs **filesystem-level preflight only** using
  the #133 path allowlist, Linux directory FDs, source inode/owner/mode and
  optional xattr presence. Against the native root, inspection requires
  effective UID 0. It does **not** elevate privileges. Errors are generic
  and redact caller-controlled names.
- No `--root`, arbitrary path, environment override or network argument
  exists on the standalone command. A private `_test_root` Python argument
  is accepted only by its internal test entrypoint; the preflight library
  independently requires a private, marked root beneath `/tmp` or
  `/var/tmp`. This is **never production authorization**.
- The finite JSON contract includes `schema_version`, `ok`,
  `operation`, `read_only`, `write_eligible: false` and, on errors,
  `error.code` and `error.message`. Failure messages never interpolate
  the supplied relative pathname, arbitrary arguments, source bytes,
  credentials, source digest, xattr names or values.
- `inspect-source` can report `filesystem_preflight: pass`, but its
  `repository_syntax_verified`, `package_signatures_verified`,
  `upstream_fallback_verified` and `managed_ownership_verified` fields
  remain **false**. A success exit status means **only** that the scoped
  filesystem inspection completed. It is not a complete `validate`
  operation or an apply gate.
- Invalid/unknown commands use prototype error category
  `INVALID_ARGUMENTS` (exit 2). Refused inspection uses
  `ROOT_REQUIRED` or `SOURCE_PREFLIGHT_REFUSED` (exit 3). These are
  **provisional private-helper values**, not the frozen project-wide exit
  code matrix, which remains an integration dependency.

The CLI v1 architecture distinguishes `validate` (configuration constraints)
from `check` and `inspect`-type read-only discovery. A public
`validate` operation is **reserved** until it actually proves source
grammar, managed ownership, GPG/TLS trust, native fallback and recovery
requirements; avoid labeling a mere inode check as completed validation.

## Security tests

`tests/test_client_source_helper_preview.py` verifies:

- Non-root `status` remains purely informational, no source access.
- `--json` works before or after an action and emits exactly one JSON
  document, including on usage and inspection failures.
- Allowed fixture inspection returns neither original contents nor
  credentials, path, digest or xattr values.
- Malformed URLs, traversal, Unicode abuse, arbitrary flags/root overrides,
  commit/recover/restore/validate verbs and missing required args fail closed.
- Root requirement and rootless private test fixture policy; parent
  symlink, hardlink and permissions are separately covered by #133 tests.
- No source mutation, no installed client CLI/installer references and
  explicit `repos sync --apply` refusal.

The native CI workflow
[`client-helper-preview.yml`](../.github/workflows/client-helper-preview.yml)
executes [a standalone smoke](../scripts/smoke_client_helper_preview.py) with
the OS Python in disposable Debian 13 and AlmaLinux 10 containers. It
performs a real UID/GID drop to 65534 before attempting native-root
inspection and expects a safe nonzero exit. It uses synthetic APT/DNF-like
files under `/tmp`, not native repository files.

## Mandatory remaining production requirements

**NOT VERIFIED / no implemented production helper:** secure installed
packaging and root authorization; stable protected managed IDs and
ownership; complete APT/DNF source grammar and safe multi-entry edits;
native APT/DNF lock coordination; race-proof writes; atomic commit/rollback
on real files with metadata preservation; complete power-loss recovery;
signed package metadata/payload and TLS fallback; clean-system installation,
upgrade/uninstall and migration; external security review.

**SELinux enforcing on a booted AlmaLinux 10 system remains NOT VERIFIED.**
It is deliberately not attempted in ordinary GitHub Actions containers,
as approved by the maintainer. This defers that unsuitable test environment,
**not** the mandatory production security gate. A real source writer must
never discard unknown `security.selinux` labels.

The draft helper operations in
[the standalone design on PR #137](https://github.com/teixemf/repocache/pull/137)
are design intentions only; this prototype intentionally offers no
production authority.

No PR merge, release, installed changes or activation of
`repocache-client repos sync --apply` is authorized by this work.
