# Stock NGINX eviction feasibility — issue #94 (v0.6.0)

**Scope:** disposable research only; no REPOCACHE installation, CLI, service, existing NGINX configuration, package-manager source, or production cache changes. Not approval to implement priority-aware eviction.

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

**Preliminary recommendation only:** retain native eviction/pressure handling in issue #97 and avoid a custom deleting agent unless separately reviewed evidence demonstrates safe ownership, concurrency and recovery. The final GO / LIMITED GO / NO-GO disposition remains **NOT VERIFIED**. A NO-GO must not waive #95 normal-removal retention or safe explicitly authorized force cleanup.

## Original #94 acceptance matrix

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
