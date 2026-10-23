# Online candidate subprocess isolation: fail-closed prototype (v0.6+)

**Status: DRAFT / NON-ACTIVATING / NATIVE ISOLATION NOT VERIFIED.**
Tracks security issue #112 and blocks #83, #84, #85. Stacked above draft PR #106; no merge or release is authorized.

## Threat model and native boundary

The online candidate contains REPOCACHE-owned and hash-locked third-party wheels. Installing wheels and invoking pip, CLI or Textual can execute their code. The existing service UID owns the active generation and recovery metadata, so checking those files after a smoke test is insufficient: code may modify them and revert changes undetected.

This prototype uses native, non-setuid Linux Bubblewrap (/usr/bin/bwrap) **without an unsandboxed fallback**. It requires explicit user, PID, network, IPC and UTS namespaces, creates an empty filesystem namespace, and mounts only:
- OS runtime /usr and compatibility system libraries **read-only**; minimum read-only NSS/TLS system files
- private /proc, /dev and /tmp
- one writable, owner-private random staging workspace; the installed generation, updater journal and parent managed directory are NOT mounted
- a sanitized environment and /tmp as HOME

It rejects root execution, missing, insecure, symlinked, setuid or setgid executors, symlinked/shared workspaces, unapproved commands and absent mandatory namespaces. All third-party/owned offline pip install commands, pip metadata checks, CLI version/help and headless Textual smoke now pass through the executor. The trusted native Python venv bootstrap and signed, hash-verified network fetch happen outside it **before running downloaded code**.

**Security advisory / explicit package gate:** CVE-2026-87766 (symlink traversal during sandbox setup) requires at least **bubblewrap 0.12.0-1~deb13u1** on Debian 13 ([Debian DSA-6472-1](https://security-tracker.debian.org/tracker/DSA-6472-1)); the runtime compares the OS package using dpkg-query and native dpkg --compare-versions. On AlmaLinux 10, require the backport at **bubblewrap 0.10.0-5.el10_2** or an accepted newer package ([ALSA-2026:85308](https://errata.almalinux.org/10/ALSA-2026-85308.html)); the runtime queries the OS RPM database. These checks are fail-closed and performed before any wheel download. The runner also rejects setuid/setgid executables. Package metadata, a patched version and non-setuid **still do not prove native namespace isolation**; mandatory signed OS package provenance/SELinux and escape tests remain outstanding. Do not fall back to optional user namespaces.

No OS packages or root-owned launchers are modified by this draft. No Bubblewrap is installed automatically; missing or unsupported runtime causes early refusal BEFORE downloading wheels. Current legacy signed wheelhouse update remains unchanged.

## Acceptance and limitations

1. **PASS (unit policy only):** missing/symlinked/insecure/setuid helper rejected before network; command-generation tests confirm rootless namespace flags, minimal read-only runtime, one writable workspace, cleared environment and no host network.
2. **PASS (mocked transaction only):** all candidate pip and CLI/TUI subprocesses use the wrapper. Sandbox errors halt with no fallback and a temporary workspace is cleaned; no active generation is intentionally changed.
3. **NOT VERIFIED / BLOCKER:** actual bwrap/namespace runtime on Debian 13 and AlmaLinux 10 (including CVE-fixed packages, supported kernel user namespaces and SELinux), dynamic loader/library symlinks and a real installed full application + Textual headless smoke within the namespace.
4. **NOT VERIFIED / BLOCKER:** native attempted writes to current link/manifest, private files and outside staging, no network or host PID escape, no credential exposure; audit by an independent security reviewer. CLI output can itself leak details if untrusted code reads anything it should not.
5. **NOT VERIFIED / BLOCKER:** complete resource and process limits, fail-safe orphan recovery after forced termination and disk exhaustion, tested OS package provisioning for the executor. If secure rootless namespaces cannot work on a target, design a root-owned systemd transient sandbox with a separate UID; NEVER silently run unsandboxed.
6. **NOT VERIFIED / BLOCKER:** genuine publisher-key signed online eight-asset v0.6 candidate, full approved PyPI wheel closure, actual native runtime ABI, full CLI/TUI/client integration and all #83-#85 acceptances.
7. **NOT IMPLEMENTED / BLOCKER:** schema-2 online atomic activation, repair/downgrade policy, journal commit/rollback, SIGKILL/power-loss, external repository failover and native systemd/SELinux integration.

Sandboxed code is still untrusted; user namespaces increase kernel attack surface. The current symlink/manifest hash canary remains a secondary accidental-mutation detection check, NOT the isolation boundary. Existing staged environments are disposed of and report activated=false.

**Status: proposal with unit evidence only, not a security audit, not mergeable and not deployable.**

## Executed GitHub Actions userspace probe — 2026-10-23

The new [Native candidate sandbox probes](https://github.com/teixemf/repocache/actions/workflows/candidate-sandbox-native.yml) matrix runs Docker Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12 userspaces on the **Ubuntu GitHub-hosted runner kernel**. APT/DNF installs the official patched Bubblewrap. The scripts create a non-root repocache UID and a private managed directory, verify OS package versions and non-setuid permissions, then attempt to run production Bubblewrap arguments and restricted-filesystem/network/PID escape probes in a new user namespace.

### Exact-head observed results

- **PASS (real userspace preflight):** Debian 13 installed bubblewrap 0.12.0-1~deb13u1, root-owned/mode 755; AlmaLinux 10 installed bubblewrap 0.10.0-5.el10_2, root-owned/mode 755. Native OS/Python and patched package checks passed with the dedicated nonroot UID.
- **FAIL (kernel namespace startup):** [Debian probe run #40030945633](https://github.com/teixemf/repocache/actions/runs/40030945633) failed with "bwrap: Can't mount proc on /proc: Operation not permitted". The AlmaLinux probe in that same run failed with "bwrap: Can't mount proc on /newroot/proc: Operation not permitted".
- An earlier iteration of both probes failed at "bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted". On the disposable GitHub Actions Ubuntu VM only, loading the packaged narrow bwrap-userns-restrict AppArmor profile without disabling host-wide user namespace security, plus NET_ADMIN only in the disposable Docker test-container network namespace, progressed to the above independent /proc mount restriction.
- **NOT VERIFIED:** Because neither candidate process started, attempted writes to live managed paths, reads of private state, host PID isolation and network denial did NOT execute to completion. The new jobs are deliberately **FAILED**, not skipped or falsely reported as successful. Native Debian/Alma Linux kernel, systemd, SELinux and hostile-wheel execution remain unverified.
- **PASS (separate exact-head legacy CI):** [Tests #40030945658](https://github.com/teixemf/repocache/actions/runs/40030945658) 4/4, with 676 pytest plus 105 mandatory security tests passed per Python 3.12 and 3.13; [offline #40030945671](https://github.com/teixemf/repocache/actions/runs/40030945671) 3/3; [rootless legacy upgrade #40030945634](https://github.com/teixemf/repocache/actions/runs/40030945634) 2/2. **Nine legacy checks PASS, two new sandbox integration contexts FAIL.**

### Mandatory next environment

Provision reproducible isolated *full VMs* (or dedicated self-hosted GitHub Actions runners) with actual Debian 13 and AlmaLinux 10 kernels, patched native Bubblewrap, unprivileged user namespaces and native SELinux where applicable. Re-run the negative probes and real signed candidate CLI/TUI/venv only after successful namespace setup. Preserve explicit FAIL when missing, not an unsandboxed fallback. No unrestricted Docker privileged container, host-wide AppArmor disabling, host /proc bind or shared network can count as production isolation evidence. Require separate independent security review and full transactional activation/rollback acceptance before merge.

**This workflow proves an operating-system userspace prerequisite and a runner-specific kernel limitation, NOT a working v0.6 sandbox.**
