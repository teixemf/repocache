# Stock NGINX eviction feasibility — issue #94 (v0.6.0)

**Scope:** disposable research only; no REPOCACHE installation, CLI, service, existing NGINX configuration, package-manager source, or production cache changes. Not approval to implement priority-aware eviction.

## Maintainer-approved research disposition — 2026-10-27

**Decision authority:** The maintainer explicitly authorized both decisions in the project conversation on 2026-10-27, now recorded at [issue #94](https://github.com/teixemf/repocache/issues/94). The approved direction is **NO-GO for building a custom global, multi-level cache priority/eviction engine**; use normal stock NGINX-managed `inactive`/`max_size`/`min_free` where supported, plus validated native per-repository policies where helpful. Native per-zone LRU **does not implement** a guaranteed cross-repository or metadata priority ranking.

**Concluded optional research:** This bounded rootless experimental investigation is accepted as the **final negative feasibility research deliverable**. Remaining *optional advanced-prioritization* experiments are discontinued, rather than represented as successful. This is a prospective, explicitly approved disposition of the #94 research scope; it does not erase the original seven acceptance criteria or convert any FAIL/NOT VERIFIED into PASS. The exact historical record remains **2 PASS / 1 FAIL for the tested undeclared-zone orphan-reclaim design / 4 NOT VERIFIED**. Those discontinued experiments are no longer prerequisites to the **bounded research-only artifact**, not a waiver of any security, compatibility or testing criterion applicable to future production work.

**Baseline remains mandatory and separately accepted:** #29 owns secure cache storage, isolation and persistence. #95 owns normal removal (withdraw route/catalog and retain eligible cached data without a removal-specific expiry, subject to native policy/pressure) plus fail-closed, ownership-verified force-cleanup. #97 owns native capacity/retention inheritance, limits, alerting, low-space recovery and safety. No unmanaged deletion of live NGINX cache objects is authorized. Supported Debian 13 / AlmaLinux 10 testing, SELinux, signed APT/DNF integrity and real fallback obligations remain mandatory **where applicable in these baseline issues**.

**Current artifact status:** The research-only PR #188 remains Draft, not merged. A separate independent technical assessment found former HEAD `8e17f1031ac97f04b3c3a85f29c78f6c0da4b7ed` technically adequate for the bounded deliverable (32/32 checks SUCCESS, Debian 13 18/18 lab unit tests); this documentation decision update changes the PR HEAD, so prior HEAD-specific review evidence requires an applicability check and any formal Option B acceptance must target the final exact HEAD. NO-GO and research scope decisions **do not** authorize Ready-for-review, merging, closing #94, release/signing, production activation or destructive operations.

The historical experimental sections below preserve what was originally measured and recommended before maintainer adoption.

---

## Documented behavior and hypotheses

Upstream reference: https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path

- NGINX cache keys are held in named shared-memory zones; bodies are stored in cache-path files. The inactive policy removes unaccessed objects regardless of freshness.
- Native max_size and (when available) min_free trigger least-recently-used eviction by the cache manager in iterations. These do not enforce a hard instantaneous quota.
- Stock NGINX does not document any global, multi-zone eviction ordering by repository demand, retired status or package metadata value. Separate paths/zones provide per-zone controls, not a guaranteed global ranking.
- The documented wildcard purge and cache purger require a commercial subscription; this investigation must not depend on those facilities.
- **Unproven hypothesis:** dropping a zone declaration leaves its existing on-disk files without a manager actively controlling that zone. Long-duration, restart, SELinux and pressure tests are necessary.

## Rootless, reversible harness

The script at scripts/spike_nginx_eviction_v06.py refuses UID 0, needs stock NGINX preinstalled and uses a unique temporary directory. Both fixture origin and proxy bind only to ephemeral loopback listeners. The dedicated test-only NGINX process receives explicit -p and -c sandbox paths, with private log, cache and temp paths; no systemd calls, global reloads, package installation or APT/DNF writes. It validates configurations before starting or sending SIGHUP only to its own test master. Cleanup terminates the spawned process and removes its temporary directory. The origin serves synthetic deterministic 48 KiB objects, **not** genuine signed APT/DNF metadata.

~~~bash
# On a disposable Debian 13 / AlmaLinux 10 host, as a non-root user:
python3 -m unittest -v tests/test_nginx_eviction_spike_v06.py
python3 scripts/spike_nginx_eviction_v06.py --mode both --objects 20 --settle-seconds 7 \
    > nginx-eviction-v06.json
~~~

The JSON contains NGINX version, OS ID, SELinux enforcing flag when readable, MISS/HIT samples, cache-file counts and bytes, and retired-route HTTP status. Neither file counts nor a short waiting interval constitute proof of object-level eviction order or pressure recovery. Command limits are 1–500 objects and 0–60 seconds of observation. Only run in disposable environments.

## Executed first-pass results, 2026-10-26

Environment: Debian GNU/Linux 13, Python 3.13.5, packaged NGINX 1.26.3. The real HTTP experiment ran as unprivileged user nobody. AlmaLinux and SELinux enforcing were **not** tested.

- **PASS in local sandbox:** four script unit guards passed, testing fixture determinism, private loopback config and zone retirement setup.
- **PASS in local sandbox:** for each warm synthetic repository and each cache mode, first request returned MISS, second returned HIT, with verified identical bytes.
- **PASS in local sandbox:** after the private configuration reload, removed route returned 404; remaining routes continued serving responses.
- **OBSERVED after 20 extra objects and 7 seconds:** shared zone occupancy rose from 149,177 bytes / 3 files to 1,143,674 bytes / 23 files, despite configured max_size=160k. No instantaneous storage cap may be inferred. This short window is **not** a claim that the manager never reclaims space.
- **OBSERVED in retired isolated zone:** zone removed from live NGINX configuration, but its disk path stayed at 49,728 bytes / 1 file across the same short observation. Active cold zone rose 49,725 → 348,078 bytes and hot zone 49,724 → 745,868 bytes. No assertion of safe automatic reclamation is justified.

Local measurements are provisional and still require evidence at the exact published feature-branch revision. These tests do not demonstrate genuine apt/dnf metadata integrity, valid package-manager fallback, long-lived cache manager/loader behavior, native SELinux, ENOSPC safety or object-level eviction ordering.

## Options and cost/security boundaries

| Architecture | Advantages | Limits / security consequences |
| --- | --- | --- |
| One shared stock cache zone | Simpler; stock zone-level LRU; no privileged custom sweeper | No repository priority classes or zone-specific quotas; retired objects compete with active objects |
| Separate native paths/zones per repository | Clearer ownership isolation and per-repository limits/inactivity | More shared-memory/configuration overhead; potential unmanaged retained files if zone is removed; no global priority |
| Custom priority-aware eviction agent | Could potentially rank objects across repositories | Opaque active NGINX file handling, concurrency/recovery, privilege and maintenance risks; not authorized |

**Historical preliminary recommendation (superseded by later decision proposal):** retain native eviction/pressure handling in issue #97 and avoid a custom deleting agent unless separately reviewed evidence demonstrates safe ownership, concurrency and recovery. The final GO / LIMITED GO / NO-GO disposition remains **NOT VERIFIED**. A NO-GO must not waive #95 normal-removal retention or safe explicitly authorized force cleanup.

## Original #94 acceptance matrix — initial snapshot (superseded below)

| Criterion | Status | Missing evidence |
| --- | --- | --- |
| Stock behavior study and two alternatives | **NOT VERIFIED (partial)** | Platform reproduction and reviewed config/version evidence |
| Ordering across repository classes | **NOT VERIFIED** | Object-level timed eviction traces under sustained pressure |
| Orphan reclamation after route removal | **NOT VERIFIED** | Prolonged native tests and explicit PASS/FAIL |
| Concurrency, ENOSPC, restart, integrity, availability | **NOT VERIFIED** | Negative workloads, APT/DNF metadata and actual fallback |
| Native Debian 13 and AlmaLinux 10 incl. SELinux | **NOT VERIFIED** | Booted/native AlmaLinux SELinux tests, representative systemd/cache |
| Overhead and operations cost | **NOT VERIFIED (partial)** | RAM/CPU/I/O, per-zone scaling and recovery analysis |
| GO / LIMITED GO / NO-GO | **NOT VERIFIED** | Final evidence-backed decision and maintainer review |

No merge, production activation, CLI redesign, change of milestone or release operation is authorized by this research.


## Extended manager / orphan observations — 2026-10-26

**Execution:** Debian 13 (trixie), NGINX 1.26.3, Python 3.13.5, non-root user nobody, only a bounded temporary loopback NGINX process. The extended script Git blob matches the locally executed bytes (SHA-1 blob 1dbe1adf222fe1f6868d880494de4698a22fb834). Six new unit tests plus the initial four passed locally (10/10). This is local evidence, not automatically accepted exact-HEAD GitHub CI.

The extended script compares (1) a shared zone with a reduced global limit, (2) an isolated zone retained without an exposed route with a lower limit, and (3) an isolated zone removed entirely from NGINX configuration. Three repositories received 12 stable 48-KiB objects each. All initial zone limits were 32 MiB. Following removal of the route, managed target limits were 128 KiB, and measurements were taken at 0, 10, 20, 30 and 40 seconds. The test used no direct cache-file deletion or commercial purge operation.

| Scenario | Before retirement | At t=0 following reload | At 10/20/30/40s | Interpretation |
| --- | ---: | ---: | ---: | --- |
| Shared zone; 128 KiB max_size | 1,790,130 bytes / 36 files | 99,452 bytes / 2 files | Unchanged | Native manager reclaimed bytes, without a repository-specific priority |
| Isolated zone kept, route removed; 128 KiB max_size | 596,738 bytes / 12 files | 99,457 bytes / 2 files | Unchanged | Unexposed but declared zone remains manageable |
| Isolated zone entirely dropped | 596,738 bytes / 12 files | 596,738 bytes / 12 files | Unchanged | No automatic reclamation observed in this 40-second window |

**PASS (narrow local experiment):** the retired route responded 404, the active route remained available and synthetic response bytes matched the origin fixture. The dropped-zone test then stopped only its disposable NGINX process, reattached the original cache zone and route, restarted its private NGINX and waited 70 seconds for cache loader activation. The first request for the previously cached object returned **HIT**, with expected bytes verified. This is a successful example of reattachment and reuse, **not** proof of automatic orphan-space reclaim while the zone is undeclared. Shrinkage in managed zones had already happened by the first post-reload snapshot; the interval is insufficient to measure convergence latency.

Upstream NGINX cache manager/loader behavior reference: https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path

### Reproduction

~~~bash
# Run without root privileges, only on disposable systems.
python3 -m unittest discover -s tests -p 'test_nginx_eviction_*v06.py' -v
for mode in shared isolated-keep isolated-drop; do
  python3 scripts/spike_nginx_eviction_extended_v06.py \
    --mode "$mode" --objects-per-repo 12 \
    --observe-seconds 40 --poll-seconds 10 \
    --recovery-loader-seconds 70
done
~~~

The isolated GitHub Actions workflow added to this branch runs the tests in a disposable Debian 13 userspace container. An optional AlmaLinux 10 job first checks the **container's own** /sys/fs/selinux/enforce and getenforce; if enforcing mode cannot be positively verified, it logs **NOT VERIFIED** and does **not** run the AlmaLinux experiment. A successfully skipped job must not be reported as AlmaLinux/SELinux PASS. There is no attempt to modify SELinux policy, use a privileged container, or alter the host. Even a container enforcing result is not a booted native AlmaLinux validation.

### Current original-issue acceptance status

- **PASS — local subtests only:** MISS/HIT integrity, retired route, controlled native managed-zone reclamation, short-term persistence of dropped zone and 70-second cache-loader recovery after reattachment.
- **NOT VERIFIED:** priority-class ordering, safe automatic reclaim for an **undeclared** zone, ENOSPC, true APT/DNF metadata integrity/fallback, resource-cost measurements, adversarial storage cases and full cross-platform native compatibility.
- **NOT VERIFIED:** AlmaLinux 10 enforcing SELinux on a native/booted target. The maintainer requests no SELinux test when GitHub Actions containers cannot support enforcing; this does not amend the original criterion or convert a skip to PASS.
- **NOT VERIFIED:** final GO / LIMITED GO / NO-GO recommendation and full issue #94 acceptance. The working hypothesis favors native cache-manager limits with explicitly retained zone declarations over custom opaque-cache file deletion, subject to further integration review with #95/#97.

No runtime, release, v0.5.0 integration, production deployment or protected operation is approved by these experiments.


## Engineering evidence supporting the adopted NO-GO (original proposal)

**Original engineering recommendation, adopted by maintainer on 2026-10-27: NO-GO for a custom multi-level eviction engine.** Continue ordinary stock-NGINX cache manager configuration through baseline #97, with data-ownership and lifecycle design in #29/#95. Do **not** introduce a privileged sweeper, delete live opaque cache files, fork NGINX, rely on NGINX Plus purging, or infer per-package demand from incomplete metrics. The adopted architecture does not authorize PR merge or #94 closure.

Evidence supporting this engineering decision:
1. A shared native zone applies its eviction policy across all objects without a repository-class priority guarantee. Separate zones enforce independent `max_size`/`inactive` controls; they do not create a global ordering between retired, low-demand, cold, hot and metadata objects. Per-object native LRU is *recency*, not a proven measure of request frequency, repository demand or metadata value.
2. With the route removed but the zone still declared, reducing that zone's `max_size` caused native reclamation in disposable Debian 13 experiments. This was **pressure applied explicitly to that zone**, not automatic priority by global free-space level. A finite `inactive` can also expire retained cache data without pressure, so the default-preserve semantics of #95 cannot be claimed from this alone.
3. With the zone declaration dropped entirely, bytes remained on disk in the observed 40s window, and a controlled private restart/zone reattachment recovered a cached object after the loader ran. While the zone was undeclared, **no automatic pressure-driven reclamation was observed**. Neither this observation nor the upstream docs proves safe unattended reclaim of unmanaged orphan paths.
4. Both techniques require a correct, explicitly approved ownership model to avoid deleting or exhausting another repository's or a pre-existing NGINX installation's data. #95 safe force-cleanup is a separate, explicitly authorized operation; #94 must not circumvent it.

### Bounded follow-up: object recency, concurrent clients and origin outage

The new self-contained script `scripts/spike_nginx_priority_availability_v06.py` extends the **shared-zone** control only, without introducing any REPOCACHE production logic. It warms eight 48-KiB synthetic package objects in a large native zone, reinforces one hot object's recency, then changes its private zone `max_size` to 128 KiB and records file count/bytes every five seconds. Subsequent HTTP hot/cold status probes are labelled as **intrusive** because a MISS can repopulate objects and change LRU. It performs eight concurrent requests for an identical synthetic object with `proxy_cache_lock on`, checking byte integrity, and then warms a dedicated cached object, turns off only its disposable origin server, and checks whether that object remains readable from NGINX while an uncached request gets HTTP 502. Tests use the initial NGINX package available in the **Debian 13 GitHub Actions userspace container**, run as UID 65534 and never modify system or production config.

~~~bash
# Rootless disposable environment, NGINX already packaged:
python3 -m unittest discover -s tests -p 'test_nginx_priority_availability_v06.py' -v
python3 scripts/spike_nginx_priority_availability_v06.py --wait-seconds 15 --workers 8
~~~

This is **not** true ENOSPC, a full package-manager failover, a concurrency stress test of NGINX's cache-file lifecycle, or a test of APT/DNF signed metadata. All those original criteria remain **NOT VERIFIED**. GitHub Actions job results, object observations and request statuses must be inspected **at the new exact PR HEAD**, not inferred from test creation. AlmaLinux 10 SELinux enforcing was unavailable in GitHub Actions; the optional job must continue to preflight and skip with `NOT VERIFIED` rather than attempt an unsupported test.

### Operational cost and design comparison

| Property | Native shared-zone control | Native per-repo paths/zones | Custom ranking engine |
| --- | --- | --- | --- |
| Additional per-zone shared-memory allocation | One zone; lab requests 1 MiB of shared keys memory | N zones; lab requests 1 MiB **per** zone (100 zones => 100 MiB nominal reserved zone declarations, not measured RSS) | Additional service/runtime state; not implemented |
| Max-size / inactive | One shared LRU/expiry policy | Separate LRU/expiry; no global cross-zone ranking | Would need object ownership, trustworthy per-object demand and locking |
| Retired data without exposure | Still competes with active entries | Keep unexposed zone managed, or drop it leaving unmanaged files | Requires protected ownership-aware cleanup |
| Configuration/maintenance | Low; limited per-repo controls | N paths/zones and related validation/reload/recovery complexity | High; privilege, concurrency and upgrade hazards |
| Native crash/recovery & SELinux validation | Only scoped synthetic observations available | Only scoped synthetic observations available | None |
| Per-repo/metadata priority promise | **Not supported by demonstrated control** | Best effort per-zone budgets only | **NOT VERIFIED; unsafe design not justified** |

The memo does **not** endorse a particular lifecycle representation (parked NGINX zone vs removed zone). That design belongs to #18/#28/#29/#95/#97; whichever is chosen must preserve accepted normal-removal/cache-retention semantics and native baseline eviction without pretending undocumented automatic orphan cleanup exists. The maintainer adopted the NO-GO and bounded research disposition on 2026-10-27; PR acceptance and any final-HEAD independent-review substitution remain separate.

### Acceptance summary for #94 (after preparing decision)

| Original criterion | Status | Basis / blocker |
| --- | --- | --- |
| Native study and at least two configuration alternatives | **PASS (bounded design study)** | Documented NGINX behavior plus exact-configuration disposable shared/isolated runs; this does not certify platforms |
| Multi-level eviction ordering under pressure | **NOT VERIFIED** | Native zone-wide LRU observed; no demonstrated global hierarchy across repos/packages/metadata; new hot/cold probes are intentionally nondeterministic |
| Normal removed-repo preservation and automatic pressure reclaim | **FAIL for dropped-zone configuration tested** | 40s observation retained 12 unmanaged objects despite other zone activity; cannot demonstrate safe automatic reclaim. Kept-zone can reclaim after independent explicit quota shrink, but may violate unlimited no-removal-deadline behavior |
| Safety/availability/negative paths, metadata | **NOT VERIFIED** | New concurrency/outage synthetic test is a limited subset; ENOSPC, signed metadata, client failover, hostile dirs and interruption remain untested |
| Debian 13 and AlmaLinux 10 with SELinux enforcing | **NOT VERIFIED** | Debian container passes targeted studies; Alma enforcing not available in allowed container and no native booted-host test |
| Cost/performance/operational burden | **NOT VERIFIED (qualitative cost assessed)** | Nominal zone sizes/config complexity explained; measured CPU/RAM/I/O and native scale not executed |
| Written GO / LIMITED GO / NO-GO outcome | **PASS as documented recommendation** | Engineering NO-GO was subsequently adopted on 2026-10-27; this does not close issue #94 or imply full acceptance |

**Current disposition:** NO-GO and end of optional research approved on 2026-10-27, with original incomplete acceptance statuses preserved. #94 remains OPEN and PR #188 DRAFT; PR-specific independent-review acceptance, current-HEAD CI, branch freshness, merge and issue closure are separate gates. No v0.5.0 impact.

## Review-response addendum — 2026-10-27

A separate read-only independent AI-assisted technical assessment reviewed PR #188 at its former HEAD 73fd2e0d112b562ea98098099b6f92ed5fba4794. It recommended NO-GO for a custom multi-level priority engine while classifying the PR as BLOCKED. It is not a formal human GitHub approval, nor an accepted review-criterion substitution or merge authorization. The amended head requires its own independent assessment.

Findings and corrections:
- S-04 (private subprocess startup): The extended harness now terminates and reaps its newly spawned private NGINX child when listener readiness raises before the caller receives the process. A negative test starts a disposable child, forces a listener timeout, and checks the child exited.
- F-04 (concurrency): The shared-cache fixture counts origin requests by key and checks the expected eight-client observation (one MISS, seven HITs, one origin request). This is bounded NGINX proxy_cache_lock behavior, not a proof of generalized concurrent eviction or storage safety.
- S-03 (metrics and symlinks): Synthetic cache statistics now avoid following symlinks, reject a linked cache root and have negative unit coverage. Statistics are read-only; this is not production deletion/cleanup logic.
- F-03 (timing): The extended harness records the monotonic time from sending the private SIGHUP to the first cache snapshot. The first sample follows retired-route and active-route HTTP checks. Neither file counts nor apparent bytes establish allocated blocks, global free-space recovery or instantaneous eviction latency.
- F-01 (ordering): Synthetic hot HIT/cold MISS probes modify the recency/access history, and do not prove the requested repository-class or metadata priority hierarchy.
- F-02 (orphan pressure): The dropped-zone study never applied true global filesystem pressure, ENOSPC or min_free. The unmanaged retained bytes during 40 seconds do not demonstrate an impossible universal reclaim algorithm. However the tested dropped-zone setup provides no identified running NGINX cache manager controlling that orphaned path and is FAIL for the original safe automatic pressure-reclaim requirement *in that tested design*.
- S-01 (reproducibility): The GitHub Actions image tags and package repositories are mutable. The executed Debian job recorded nginx/1.26.3; immutable container image digests/package snapshots and corresponding provenance are NOT VERIFIED. The package installation phase runs in the disposable container, whereas experiment NGINX refuses UID 0.
- S-02 (reload/rollback): nginx -t and later route tests are partial private-reload checks, not an atomic NGINX activation/rollback algorithm. Nothing in these scripts is authorized for the server provisioner.

Original #94 acceptance following independent review:
1. Stock shared/per-zone behavior study: PASS as a bounded research comparison, not full platform validation.
2. Full priority ordering: NOT VERIFIED.
3. Default-preserve plus safe automatic reclaim: FAIL for the tested *undeclared-zone* design; no actual global disk-pressure test was performed.
4. Full negative/concurrency/ENOSPC/recovery/metadata/fallback safety: NOT VERIFIED (small synthetic subsets PASS only).
5. Debian 13 plus AlmaLinux 10 including native SELinux enforcing: NOT VERIFIED; Alma enforcing was unavailable in the allowed GitHub Actions container and was not exercised or waived.
6. CPU/RAM/I/O and operational overhead measurement: NOT VERIFIED; qualitative complexity comparison exists.
7. Written GO/LIMITED GO/NO-GO: PASS only as a documented NO-GO proposal. Adoption and issue closure require separate maintainer decisions.

The NO-GO recommendation leaves #29 storage ownership, #95 normal-removal preservation and safe force-cleanup, and #97 native cache management fully mandatory. Do not infer full issue acceptance, merge readiness or deployment permission from experimental evidence. The earlier 34/34 SUCCESS CI checks and original independent assessment refer to the old HEAD 73fd2e0; amended-head tests must be inspected anew.

### Follow-up assessment C-01 — 2026-10-27

A second, independently commissioned read-only assessment of former HEAD `cab49fcc89211a98832968824d423a89d3cf8cde` found that the read-only `cache_stats()` guard rejected a symlink in the final cache path only, but could traverse a symlinked **parent**. The reviewed fix walks every lexical component of the absolute selected path without resolving links, fails closed if any existing component is a symlink, and rejects explicit `..` path traversal. The negative test constructs a symlinked intermediate `cache` directory leading to an external directory containing a synthetic file, and checks that the measurement refuses to traverse it. The original final-component and internal-symlink tests are retained.

This is a **bounded research-only check**. Checking ancestry before `os.walk()` is subject to time-of-check/time-of-use races if another actor can mutate directory entries. A real production cleanup or security-enforced ownership boundary requires descriptor-relative no-follow traversal and independent review; neither is implemented or authorized here. No file deletion is performed.

The separate review also identified C-02: ephemeral loopback-port allocation and HTTP 404 readiness probes cannot cryptographically bind the listener to the spawned process. This is a **LOW, outstanding measurement-confidence limitation** in a disposable, unprivileged sandbox; the experiment checks for premature NGINX exit, but does not claim socket ownership attestation. No changes to system or production NGINX are authorized.

All original issue #94 criteria remain at the same level: **2 PASS / 1 FAIL (tested dropped-zone reclamation) / 4 NOT VERIFIED**. Any CI result recorded before these changes applies only to its historical HEAD, not the newly amended source. No review waiver, merge, issue closure or architecture decision has been made.
