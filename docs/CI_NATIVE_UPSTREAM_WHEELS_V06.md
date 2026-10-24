# GitHub Actions native upstream wheel compatibility gate

**Scope:** issues #83 and #85, independently layered on the current main
branch. The workflow native-upstream-wheels.yml uses disposable Debian 13 and
AlmaLinux 10 user spaces inside standard GitHub-hosted Ubuntu runners.

## What this proves

- APT/DNF installs each target's native Python (Debian 13: Python 3.13,
  AlmaLinux 10: Python 3.12) plus the required standard OS packages.
- As a dedicated non-root user, each target downloads exactly the versions
  listed in the existing reviewed legacy deps/runtime-wheels.lock from public
  PyPI. pip must choose a binary wheel and must not resolve transitives, select
  latest versions, use user configuration, build source or install globally.
- Every downloaded wheel must match the existing reviewed SHA-256 and embedded
  distribution identity. There is no fallback if the bytes or ABI differ.
- A fresh private native-Python virtual environment installs **all** locally
  staged binary wheel paths with --no-index, --no-deps, --require-hashes and
  --only-binary=:all:. After pip check, the complete installed runtime package
  inventory must exactly match the pins, except permitted pip bootstrap tools.
- An altered copy of a real wheel must be refused in a second fresh venv;
  successfully installed original bytes must remain untouched.
- A real Typer server CLI, Textual headless keyboard navigation and the
  standalone client read-only/help entry points run against the downloaded
  Python dependencies and the read-only REPOCACHE source tree. This is not a
  mock of Textual or PyPI; it is a native userspace compatibility probe.
- The checkout is mounted read-only, GitHub credentials are not persisted, no
  production system or GitHub release is changed, and every result is explicit
  PASS/FAIL. No release/signing keys are used.

## Deliberate scope boundaries

This is **NOT** a v0.6.0 owner-signed release acceptance gate. In particular,
the existing legacy wheel lock is NOT the future signed two-platform online
dependency lock. Hashes match reviewed bytes but do not authenticate the
publisher's release policy or independently establish upstream safety. The
REPOCACHE source tree is imported for CLI/TUI smoke instead of installing an
authenticated v0.6.0 first-party application wheel. A live index is only used
to acquire known pinned upstream wheels during this CI compatibility experiment.

The runner kernel remains Ubuntu, not a native Debian or AlmaLinux booted VM.
Bubblewrap containment, SELinux, systemd, malicious wheel execution, real
signed v0.4 -> v0.5 -> v0.6 migration, journaling, atomic activation,
same-version repair and rollback are **NOT VERIFIED** here. These remain
independent mandatory acceptance gates tracked by #83, #84, #85 and #112.
If downloading, hash verification, offline installation, Textual or CLI smoke
fails, the corresponding job must fail. A failing kernel namespace probe in
#112 may not be downgraded to a skip or replaced by unsandboxed activation.

The optional workflow_dispatch is available after GitHub recognizes the
workflow on the default branch. Pull requests changing the workflow, source,
wheel lock or smoke files trigger this matrix. CI results must always be
checked on the exact PR commit before assessing acceptance; do not infer PASS
from script existence.

## Reproducing in a disposable environment

Execute the same workflow steps shown in .github/workflows/native-upstream-wheels.yml
on an ephemeral GitHub Actions runner. The entry point runs with a read-only
/source repository and a private writable /work directory:

    /usr/bin/python3 /source/scripts/ci_native_upstream_wheels.py

The script intentionally refuses root and non-private workspaces. Neither
its output nor the legacy lock is suitable for signing or publishing a new
v0.6.0 release. Future work may replace this compatibility-only input with
genuinely authenticated version-specific target locks and the first-party
application wheel, after the separate policy/security acceptance gate.
