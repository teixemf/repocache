# Native client metadata-fallback experimental test matrix

**Status:** executable CI experiment, not production acceptance and not a
complete failover proof.  
**Tracking:** [#24](https://github.com/teixemf/repocache/issues/24),
UC-02/UC-16/UC-34/UC-35.  
**Targets:** Debian 13 `debian:trixie-slim` and AlmaLinux 10
`almalinux:10`.  
**Entrypoints:**
[probe script](../scripts/ci_client_native_fallback.py),
[GitHub Actions workflow](../.github/workflows/client-native-fallback.yml).

## Why these tests exist

The Debian APT mirror transport supports local `mirror+file:` lists and
`priority:N` metadata. It explicitly says that mirrors **without** a priority
may be selected at random. A literal cache URL followed by an upstream URL,
without priorities, is therefore insufficient evidence that the cache is
preferred. See
[apt-transport-mirror(1), Debian 13](https://manpages.debian.org/trixie/apt/apt-transport-mirror.1.en.html).

DNF documents `baseurl` as an ordered list of URLs, but this is not a
guarantee for each failure mode or each repository configuration. See
[DNF5 configuration reference](https://dnf5.readthedocs.io/en/stable/dnf5.conf.5.html).

## Test fixtures and trust boundaries

The workflow prepares dependencies inside **disposable containers**, then
starts two loopback HTTP endpoints hosting the same intentionally synthetic
repository. One endpoint acts as REPOCACHE, the other as the upstream.
The tests operate on private source files, metadata caches and trust files in
a temporary directory. They do **not** mutate host APT/DNF repository sources.

- For APT, an ephemeral OpenPGP key signs an isolated `InRelease`. A
  dedicated `Signed-By` keyring verifies metadata without weakening the
  system's repository-signature configuration or globally installing trust.
- For DNF, `createrepo_c` generates metadata for an empty repository.
  `gpgcheck=1` remains set. The test does not install any RPM and metadata
  signatures are not tested, so **DNF package/metadata authentication is
  NOT VERIFIED** by this experiment.
- Both probes use **HTTP loopback only**. They therefore do not test
  external HTTPS certificate validation, private CAs, DNS failure,
  redirects, metadata tampering, package download or interrupted writes.
- Each operation uses a fresh metadata cache and records per-backend
  request counts; a successful exit without requests to the expected backend
  is *not* sufficient to pass.

## Executed scenarios

| Scenario | Primary cache | Upstream | Expected observation |
| --- | --- | --- | --- |
| Preferred cache | Healthy | Healthy | Native metadata update succeeds; requests primary, not upstream |
| Primary outage | HTTP 503 | Healthy | Native metadata update succeeds; requests both primary and upstream |
| Cache recovery | Healthy again | Healthy | A subsequent fresh metadata update selects primary again |
| Complete outage | HTTP 503 | HTTP 503 | Native metadata update fails; both sources have been attempted |

No scenario removes package signatures or claims source rewrite capability.

## Remaining mandatory acceptance gates

**NOT VERIFIED** until separate targeted tests PASS:

- Production-like **HTTPS** with certificate errors, timeouts, 404, 5xx,
  DNS failure, redirects and CA/private-CA paths, without weakening TLS.
- Signed Debian metadata and authentic signed RPM package downloads
  through both cache and upstream, including mismatch and tampering failure.
- Real package-manager behavior with authentic Debian 13 and AlmaLinux 10
  repository formats, `mirrorlist`, `metalink`, multiple suites, components,
  architectures, and mixed external distributions.
- Clean booted systems with systemd, AlmaLinux SELinux, OS package-manager
  locks, root/non-root privilege enforcement and real protected source paths.
- REPOCACHE client transactional write/rollback, reboot/power-loss recovery,
  drift detection, original-source preservation and uninstall preparation.

If any native metadata probe fails, the result is a **FAIL** of this exact
tested combination; do not silently downgrade it to a warning or fall back
to an unsigned repository. Keep `repos sync --apply` disabled under the
UC-16 fallback gate until the supported combinations have passed real tests.
