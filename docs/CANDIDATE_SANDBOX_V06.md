# Online candidate subprocess isolation: fail-closed prototype (v0.6+)

**Status: DRAFT / NON-ACTIVATING / GitHub Actions Ubuntu-kernel Docker namespace probes PASS; native Debian/AlmaLinux kernel and SELinux NOT VERIFIED.**
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


## 2026-11-03 — Approved Gate A / Gate B and bounded-output increment

The maintainer approved separating **implementation-only Gate A (#112/#113)** from mandatory **native operational/release Gate B (#149 and #83/#84/#85)**; the complete original issue acceptance history remains in #112. Neither green CI nor merged inert code allows production activation. Gate A still requires realistic resource containment, negative-path/recovery tests, an issue-specific independent security review, accepted prerequisite integration and separately authorized final-HEAD merge.

The candidate executor now drains subprocess stdout and stderr incrementally with a **combined 1 MiB bound** and a positive wall deadline (at most 300 seconds). Excessive output or a timeout refuses the candidate and terminates its own launcher process group. This prevents unbounded memory accumulation via \`subprocess.run(capture_output=True)\` in the trusted updater; it does **not** implement whole-tree CPU/RAM/PID limits, filesystem quota, global staging disk exhaustion handling, or native SELinux/kernel policy. All those remain **NOT VERIFIED** until their own targeted acceptance. The direct test commands for bounded capture use trusted stdlib Python; the live userspace CI runs the same guard with real Bubblewrap and a candidate emitting over 1 MiB.

**Pre-execution/integration status:** The source change must pass exact-HEAD CI on both userspaces and security assessment before any partial PASS is recorded. No merge, signing, release or online activation is authorized. GitHub milestone is v0.7.0; v0.6 wording in historical files is not release authority.


## 2026-11-03 — Private temporary filesystem disk cap (Gate A increment)

The production Bubblewrap invocation now uses \`--size 67108864 --tmpfs /tmp\`, enforcing a **64 MiB maximum for the candidate-private temporary filesystem per sandboxed command**. The option must immediately precede its \`--tmpfs\` mount. The real Debian 13 and AlmaLinux 10 **userspace** CI probe invokes a malicious candidate that attempts to write over 64 MiB into \`/tmp\`: only an actual \`ENOSPC\` and an unchanged active manifest count as PASS. An immutable command-shape regression prevents dropping/misplacing the limit. The trusted system Python venv bootstrap, staged wheel download and persistent candidate workspace are separate and not protected by this particular quota.

This is **not** a staging workspace filesystem quota, whole-process-tree memory/CPU/PID cgroup limit, guarantee against all disk-pressure paths, or native Debian/AlmaLinux/SELinux acceptance. Those Gate A/Gate B criteria remain NOT VERIFIED. This change does not enable activation or authorize merge.


## 2026-11-03 — Additional per-process Linux resource ceilings

The executor also requires root-owned, non-symlinked, non-setuid **\`/usr/bin/prlimit\`** from the OS util-linux package before any untrusted execution. Its exact argv sets soft **and** hard inherited limits on each launched Bubblewrap child: CPU time 60 seconds/process, virtual address space 2 GiB/process, tasks/processes 128 per real UID, open descriptors 256/process, maximum single-file size 512 MiB, and core dumps disabled. No shell or default policy fallback is allowed. Both target CI userspaces must demonstrate the limits inside a running sandbox rather than merely inspecting the command text.

**Scope caveat:** \`RLIMIT_AS\` and \`RLIMIT_CPU\` apply per process, \`RLIMIT_NPROC\` applies against the real UID across the host, and \`RLIMIT_FSIZE\` applies per individual file. These are **defense in depth**, NOT a per-candidate aggregate cgroup CPU/RAM/PID budget, nor a filesystem quota on the persistent staging bind. They cannot satisfy the full Gate A resource-containment requirement alone. Native provisioning and aggregate exhaustion/rollback remain NOT VERIFIED. Unsupported/missing OS helper refuses early; an independently commissioned security review is still required.

## Acceptance and limitations

1. **PASS (unit policy only):** missing/symlinked/insecure/setuid helper rejected before network; command-generation tests confirm rootless namespace flags, minimal read-only runtime, one writable workspace, cleared environment and no host network.
2. **PASS (mocked transaction only):** all candidate pip and CLI/TUI subprocesses use the wrapper. Sandbox errors halt with no fallback and a temporary workspace is cleaned; no active generation is intentionally changed.
3. **PARTIAL PASS (GitHub Ubuntu-kernel Docker only):** patched bwrap executed real sandbox child processes under Debian 13 and AlmaLinux 10 userspaces in #40110994376. Native target kernels, userns policy on installed hosts, SELinux and a real owner-signed full application/third-party wheel/Textual rehearsal remain **NOT VERIFIED / BLOCKING**.
4. **PARTIAL PASS (GitHub Ubuntu-kernel Docker only):** actual adversarial scripts tried forbidden writes/reads, outer loopback and PID access; all denied after synthetic root read-only fix, active state intact and staging cleaned. Native OS policy, arbitrary hostile wheel behavior, resource exhaustion, credential exposure analysis and independent review remain **NOT VERIFIED / BLOCKING**.
5. **NOT VERIFIED / BLOCKER:** complete resource and process limits, fail-safe orphan recovery after forced termination and disk exhaustion, tested OS package provisioning for the executor. If secure rootless namespaces cannot work on a target, design a root-owned systemd transient sandbox with a separate UID; NEVER silently run unsandboxed.
6. **NOT VERIFIED / BLOCKER:** genuine publisher-key signed online eight-asset v0.6 candidate, full approved PyPI wheel closure, actual native runtime ABI, full CLI/TUI/client integration and all #83-#85 acceptances.
7. **NOT IMPLEMENTED / BLOCKER:** schema-2 online atomic activation, repair/downgrade policy, journal commit/rollback, SIGKILL/power-loss, external repository failover and native systemd/SELinux integration.

Sandboxed code is still untrusted; user namespaces increase kernel attack surface. The current symlink/manifest hash canary remains a secondary accidental-mutation detection check, NOT the isolation boundary. Existing staged environments are disposed of and report activated=false.

**Status: prototype with CI container-kernel and unit evidence; native OS security acceptance, independent review and full signed activation remain NOT VERIFIED. Not mergeable or deployable.**

## Historical failed GitHub Actions userspace probe — 2026-10-23 (superseded by the passing 2026-10-24 run below)

The new [Native candidate sandbox probes](https://github.com/teixemf/repocache/actions/workflows/candidate-sandbox-native.yml) matrix runs Docker Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12 userspaces on the **Ubuntu GitHub-hosted runner kernel**. APT/DNF installs the official patched Bubblewrap. The scripts create a non-root repocache UID and a private managed directory, verify OS package versions and non-setuid permissions, then attempt to run production Bubblewrap arguments and restricted-filesystem/network/PID escape probes in a new user namespace.

### Exact-head observed results

- **PASS (real userspace preflight):** Debian 13 installed bubblewrap 0.12.0-1~deb13u1, root-owned/mode 755; AlmaLinux 10 installed bubblewrap 0.10.0-5.el10_2, root-owned/mode 755. Native OS/Python and patched package checks passed with the dedicated nonroot UID.
- **FAIL (kernel namespace startup):** [Debian probe run #40030945633](https://github.com/teixemf/repocache/actions/runs/40030945633) failed with "bwrap: Can't mount proc on /proc: Operation not permitted". The AlmaLinux probe in that same run failed with "bwrap: Can't mount proc on /newroot/proc: Operation not permitted".
- An earlier iteration of both probes failed at "bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted". On the disposable GitHub Actions Ubuntu VM only, loading the packaged narrow bwrap-userns-restrict AppArmor profile without disabling host-wide user namespace security, plus NET_ADMIN only in the disposable Docker test-container network namespace, progressed to the above independent /proc mount restriction.
- **NOT VERIFIED:** Because neither candidate process started, attempted writes to live managed paths, reads of private state, host PID isolation and network denial did NOT execute to completion. The new jobs are deliberately **FAILED**, not skipped or falsely reported as successful. Native Debian/Alma Linux kernel, systemd, SELinux and hostile-wheel execution remain unverified.
- **PASS (separate exact-head legacy CI):** [Tests #40030945658](https://github.com/teixemf/repocache/actions/runs/40030945658) 4/4, with 676 pytest plus 105 mandatory security tests passed per Python 3.12 and 3.13; [offline #40030945671](https://github.com/teixemf/repocache/actions/runs/40030945671) 3/3; [rootless legacy upgrade #40030945634](https://github.com/teixemf/repocache/actions/runs/40030945634) 2/2. **Nine legacy checks PASS, two new sandbox integration contexts FAIL.**

### Mandatory next environment

Provision reproducible isolated *full VMs* (or dedicated self-hosted GitHub Actions runners) with actual Debian 13 and AlmaLinux 10 kernels, patched native Bubblewrap, unprivileged user namespaces and native SELinux where applicable. Re-run the negative probes and real signed candidate CLI/TUI/venv only after successful namespace setup. Preserve explicit FAIL when missing, not an unsandboxed fallback. No unrestricted Docker privileged container, host-wide AppArmor disabling, host /proc bind or shared network can count as production isolation evidence. Require separate independent security review and full transactional activation/rollback acceptance before merge.

**This 2026-10-23 failed workflow was superseded by the 2026-10-24 passing Docker probe documented below. It did not establish an operating v0.6 sandbox.**


## 2026-10-24 — Working GitHub Actions Docker namespace probes; native gate remains separate

After [failed /proc tests #40031400116](https://github.com/teixemf/repocache/actions/runs/40031400116), the CI-only container launcher was adjusted to use `--security-opt systempaths=unconfined`: Docker's default masked/read-only `/proc` paths prevent rootless Bubblewrap from mounting its own separate procfs in a nested user/PID namespace. **This changes the security posture of the disposable outer CI container**, exposing previously masked kernel procfs paths. The CI runner also uses test-only `NET_ADMIN`, `seccomp=unconfined` and `apparmor=unconfined` for nested namespaces. It never uses Docker `--privileged`, host network, host PID or Docker socket; the repository source is mounted read-only, and a memory/PID limit is set. **Do not copy this outer Docker configuration into a deployed server.** A hardened CI runner is not equivalent to the inner sandbox security boundary or to a native target kernel.

The first actual successful sandbox startup exposed another defect: Bubblewrap's synthetic root is a writable anonymous tmpfs by default. An adversarial candidate could create a **sandbox-local** `/etc/repocache-forbidden-write` (not the host's `/etc`). The live negative test properly **FAILED** on both target userspaces in [run #40110678681](https://github.com/teixemf/repocache/actions/runs/40110678681). This is unacceptable under the intended "only workspace plus private temporary mounts writable" contract. The production invocation now applies `--remount-ro /` **after** all the filesystem mounts and the workspace bind, making the synthetic root read-only without remounting the separate candidate workspace or private `/tmp`. A unit regression checks this exact placement. We did not simply weaken the negative test.

The network/PID tests were also improved: compare real namespace identifiers against the outer CI container, test access to an **outer-container-only loopback socket** rather than probe a public Internet IP, reject visibility of an outer process, and check active manifest equality and final cleanup. The hostile code uses the same generated Bubblewrap mount/namespace flags as production, replacing only the allowlisted candidate command under the trusted test harness.

**Actual test results — code head `1ccb075a5814b3db6d376c240085a3ed1910cce1`:**

| Executed evidence | Verdict | Scope |
| --- | --- | --- |
| [Native candidate sandbox probes #40110994376](https://github.com/teixemf/repocache/actions/runs/40110994376) | **PASS 2/2** | Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12 userspaces in disposable Docker on Ubuntu GitHub-hosted VM kernel; both logs show patched root-owned non-setuid OS Bubblewrap, real candidate child startup, denied root/secret/state writes and reads, isolated network/PID, staging-only write and cleanup |
| [Tests #40110994328](https://github.com/teixemf/repocache/actions/runs/40110994328) | **PASS 4/4** | Python 3.12/3.13 unit/security and both source-bundle integrity checks |
| [Offline wheelchain #40110994339](https://github.com/teixemf/repocache/actions/runs/40110994339) | **PASS 3/3** | Legacy wheelhouse signing/build/install checks, **not** a genuine v0.6 online installation |
| [Rootless legacy upgrade #40110994335](https://github.com/teixemf/repocache/actions/runs/40110994335) | **PASS 2/2** | Legacy offline repair/rollback in disposable distro containers; **not** source-only v0.6 activation |

**Remaining NOT VERIFIED / mandatory merge and release blockers:** Debian 13 and AlmaLinux 10 *own booted kernels*, kernel/userns policy on those hosts, AlmaLinux SELinux enforcing, fully installed/maintained patched Bubblewrap in supported environments, realistic hostile-wheel execution and resource/DoS tests, native CLI/Textual with an owner-signed eight-asset online release, offline/online migration and real journaled activation/repair/rollback, required independent security review. GitHub-hosted runners are Ubuntu VMs, and their distro Docker containers share that Ubuntu kernel. These 11 passing contexts are meaningful but **do not close #112** or authorize release/merge. Full native-kernel tests may use disposable target-system VMs; GitHub-hosted nested VMs are an experimental possibility with no guarantee of nested-virtualization support. Preserve failure visibility and do not fall back to unsandboxed execution.


## 2026-10-24 — Real upstream wheel + installed original CLI/Textual under bwrap

**Integration change on #113 (non-activating, CI only):** `scripts/ci_candidate_sandbox_wheels.py` first checks the production `candidate_sandbox.require_executor()` gate, downloads the complete **legacy-reviewed** `deps/runtime-wheels.lock` packages from the real HTTPS PyPI index using native system Python pip in a disposable non-root workspace, verifies every exact binary wheel SHA-256 and package METADATA, then creates a private OS-native venv. There are **no wheel installs before the sandbox**. Offline locked wheel `pip install`, canonical original REPOCACHE application-wheel install, `pip check`, `pip list`, actual installed CLI version/help/update help and `RepoCacheApp.run_test` Textual navigation are dispatched through **the production `candidate_sandbox.run_isolated` executor**, not direct host pip or unsandboxed subprocesses. Stage is removed and the previous installed manifest remains byte-for-byte unchanged.

The first-party wheel is deterministically built in this **trusted CI fixture only** from checked-out v0.4.0 owned source using the stdlib source release builder. It is tested as v0.4.0, not misrepresented as an independently owner-signed v0.6.0 artifact. The upstream wheel versions/hashes are the existing legacy-reviewed pins from `deps/runtime-wheels.lock`, **not** signed v0.6.0 per-platform locks. Do not reuse these trust shortcuts for releases. No signing keys, release, privileged Docker, global Python installation or active-generation change.

**Executed exact code-head CI, commit `422a20ffd0758b5220640fe9a179686d8d2e72b4`:**

| Check | Result | Evidence |
| --- | --- | --- |
| Native candidate sandbox + live PyPI hash-locked installation, first-party wheel, CLI and Textual, real per-distro subprocess isolation and timeout/orphan canary | **PASS, 2/2** | [Sandbox workflow #40112457758](https://github.com/teixemf/repocache/actions/runs/40112457758). Both Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12 container-job logs inspected; real installed headless Textual navigation and previous-manifest preservation confirmed |
| Unit/security, package integrity and unsigned-source refusal | **PASS, 4/4** | [Tests #40112457909](https://github.com/teixemf/repocache/actions/runs/40112457909): 677 pytest passed, 1 warning plus 105 mandatory security tests per Python 3.12/3.13 |
| Existing legacy offline wheelchain | **PASS, 3/3** | [Offline #40112457730](https://github.com/teixemf/repocache/actions/runs/40112457730) |
| Existing legacy rootless upgrade/rollback | **PASS, 2/2** | [Upgrade #40112457728](https://github.com/teixemf/repocache/actions/runs/40112457728) |

**Important integration limit:** these are full actual candidate `pip`/CLI/Textual *commands*, but the candidate bytes are legacy-reviewed CI source/wheels and **not a genuinely publisher-signed eight-asset 0.6.0 candidate**. Test containers still use **Ubuntu GitHub-runner kernel**, with CI-only broadened outer-container Docker security settings; not the supported booted Debian/Alma kernels or SELinux enforcing. A complete signed release-index policy, independent native kernel/resource review and journaled atomic activation/recovery are **NOT VERIFIED**. Issue #112, #83, #84 and #85 remain open; PRs stay draft/unmerged.

**CI maintenance note:** independent main-based draft PR #143 already tests live upstream legacy pins without sandbox. The #113 workflow intentionally repeats these downloads to prove *execution of those wheels under the exact new sandbox*. Reconcile duplicate pin parsing/CLI smoke code once the underlying PR stack lands; do not merge #143 as a side-effect of this draft test.


## 2026-11-03 — Cgroup v2 delegated-resource admission contract (NOT YET A LAUNCHER)

Added \`src/repocache/candidate_cgroup.py\` as a **read-only, fail-closed kernel delegation preflight** plus exact leaf resource-controller write/readback contract, with negative tests in \`tests/test_candidate_cgroup.py\`. It is bundled with the v0.7 online-profile source archive. It is deliberately **not wired into the live candidate execution path** until the native supervised launcher can attach *before* untrusted exec, kill/drain the entire cgroup and guarantee staging disk space. Passing these *mock-filesystem* tests is **NOT evidence of actual cgroup containment**.

Provisioning required before any operational adoption (the stage remains non-activating):
- A root-managed, patched Debian 13 / AlmaLinux 10 systemd \`repocache-candidate.service\` with \`Delegate=cpu memory pids\`, and the manager process in the \`repocache-manager\` leaf (so the service root does not violate cgroup-v2's no-internal-process rule). The service must provision a dedicated empty \`repocache-candidates\` sibling subtree with controllers already enabled. A partially delegated, read-only or shared subtree fails admission; do not try to chmod/chown/enable controllers from untrusted application code.
- For **each separate candidate subprocess** (or, preferably, the full candidate rehearsal lifetime), create a fresh leaf and apply/read back \`cpu.max=200000 100000\` (two CPUs), \`memory.max=1073741824\` (1 GiB), \`memory.swap.max=0\`, \`pids.max=64\`. A resource-enforcing launcher must attach descendants before exec without a vulnerable move-after-spawn window, terminate residual tasks through \`cgroup.kill\`, and detect OOM/PID exhaustion from cgroup events. The source contract deliberately does not claim that this launcher exists.
- A separate **bounded persistent candidate staging filesystem quota** (not just the 64 MiB private \`/tmp\` and per-file RLIMIT_FSIZE), cleanup and disk-full recovery must be designed and executed. No runtime fallback to ungrouped candidate execution is permitted once cgroup enforcement is required.

**Gate A:** source-level delegation/limit-policy implementation and unit negatives can be assessed; **NOT VERIFIED:** complete safe attachment, group-level exhaustion, kill/drain, staging quotas, native package/service provisioning, independently commissioned issue-specific security review and exact-HEAD CI. **Gate B:** #149 booted native kernels/SELinux and #83/#84/#85 genuine signed candidate/activation/rollback remain mandatory. Do not close #112 or merge #113 on the strength of the preflight tests alone.

References for Linux controller semantics: Linux kernel cgroup v2 documentation and systemd CGROUP_DELEGATION guidance (see official upstream documentation). Native systemd integration requires a separate reviewed design and executable host evidence.

## 2026-11-03 — Trusted attach-before-exec cgroup bootstrap (source-level increment)

The new candidate_cgroup.entry_argv constructor requires a verified delegated cgroup, a fresh correctly named empty candidate leaf with exact cgroup controller limits already applied, a pinned root-owned system Python binary, and an explicit prlimit command. It builds a trusted OS Python invocation with isolated -I -S flags. The bootstrap writes 0 to cgroup.procs with O_NOFOLLOW, then execs prlimit and Bubblewrap. A missing, swapped or unwritable membership control terminates the bootstrap before candidate code executes. It avoids the unsafe Python Popen preexec_fn hook.

The CI negative integration test uses a normal temporary file as a stand-in for cgroup.procs and a harmless Python marker executable. It proves the source-level order and refusal after membership-file substitution, NOT actual kernel cgroup attachment, aggregate resource limits, or delegated systemd behavior.

IMPORTANT: This entry constructor is intentionally NOT yet wired to the deployed run_isolated executor. Full fresh-leaf lifecycle, group kill/drain and OOM/PID observation, persistent staging disk quota, native host provisioning and independently commissioned issue-specific security assessment remain NOT VERIFIED. No automatic fallback, production activation or merge authorization is created.

The pre-exec entry argv now also verifies the *canonical* inherited prlimit flag vector and Bubblewrap executable. Missing or altered limits, a shell replacement, or a different executable are refused before a child can be started. Mocked tests use a harmless system-Python payload substituted for the inner Bubblewrap command; no production sandbox policy is weakened.


## 2026-11-04 — Candidate leaf kill-and-drain cleanup (source-only increment)

The cgroup-v2 helper now includes `kill_and_drain_leaf()` to terminate all tasks in a specifically named, owned candidate leaf using the write-only `cgroup.kill` interface, wait up to a bounded deadline for `cgroup.events` to show `populated 0`, and remove **only the drained leaf** via cgroupfs `rmdir`. It refuses missing/symlinked kill controls, noncanonical paths, untrusted event status, timeout, or a failed `rmdir`; it never recursively deletes the host filesystem and never kills the service or candidate parent subtree. Unit tests use mock cgroup files and a simulated cgroupfs removal; they check negative paths and that no parent control is written.

**Gate A remains NOT VERIFIED:** this cleanup primitive is not yet bound to an exclusive fresh-leaf lifecycle or the live candidate executor, and no real cgroup kernel task has been terminated by these unit tests. Future native provisioning must ensure the cleanup supervisor itself lives outside the target leaf. Actual memory/CPU/PID exhaustion, staging filesystem quota, unexpected supervisor termination and independent security review remain pending. Gate B #149 still requires native booted Debian 13 / AlmaLinux 10 and SELinux enforcing. No merge or production-activation authorization is implied.

## 2026-11-07 — Exclusive candidate cgroup reservation and scoped cleanup

A source-only `candidate_leaf()` context manager now validates an already accepted delegation, opens the candidate-parent directory with `O_DIRECTORY|O_NOFOLLOW`, and creates a cryptographically unpredictable 128-bit candidate name using atomic `mkdir(dir_fd=..., mode=0700)` without reusing collisions. It applies and reads back the existing CPU/memory/PID ceilings before yielding the leaf. On normal exit, body failure or setup failure, it invokes the narrowly scoped `kill_and_drain_leaf` cleanup. Cleanup errors are **blocking**; the code never treats a leftover populated cgroup as a successful candidate. The entry/bootstrap and cleanup primitives remain separate from online candidate subprocess execution.

Unit tests mock cgroupfs virtual control files to verify exclusive reservation, no takeover on collision, invalid token or parent refusal, limits before yielding, cleanup on failure, and blocking cleanup errors. No test here exercises **kernel-backed systemd-delegated cgroup creation or actual resource exhaustion**; these remain NOT VERIFIED under Gate A and native host Gate B (#149). No production systemd service, real candidate, signature, publication, activation, branch protection or Merge Queue is modified.

Current GitHub-hosted Ubuntu CI compatibility: the `Native candidate sandbox probes` workflow verifies a package-owned vendor AppArmor `bwrap` profile before running the usual rootless Debian 13 / AlmaLinux 10 userspace probes; it does not disable `kernel.apparmor_restrict_unprivileged_userns` globally or provide native target-kernel evidence.
