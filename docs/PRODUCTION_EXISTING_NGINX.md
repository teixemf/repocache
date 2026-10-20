# v0.4.0: Production frontend on an existing NGINX server

## Supported deployment contract

REPOCACHE v0.4.0 is intended to be a **production CLI/TUI management and
diagnostics frontend** for a Linux package repository caching service already
deployed and configured by the operator using NGINX. It **does not install,
configure, or take ownership of NGINX**. Automated NGINX deployment, TLS setup,
cache provisioning and reversible APT/DNF source configuration belong to later
milestones; they are not prerequisites implemented by the v0.4.0 installer.

The management frontend is not the repository-serving data plane. Existing
NGINX routes must continue serving repository traffic if the REPOCACHE CLI/TUI
fails or is stopped. Client upstream fallback is an independently tested
deployment responsibility, not a capability automatically activated by this
frontend release.

**Supported hosts:** Debian 13 with its OS-provided Python 3.13 and AlmaLinux
10 with its OS-provided Python 3.12. Earlier OS versions, upgrades from
pre-public REPOCACHE installations, automatic NGINX provisioning and
unverified downgrades are unsupported.

## Before installation

On an already configured server, the operator must verify **without changing
production state**:

1. NGINX and its existing proxy/cache routes are installed, configured and
   serving package repositories. Record current package manager upstream
   fallback and recovery procedures independently.
2. NGINX configuration passes `nginx -t` under an appropriately privileged
   **operator session**. Do not loosen TLS-key or configuration permissions so
   that the REPOCACHE service account can read private keys.
3. The cache directory and optional NDJSON request-metrics log exist. Their
   defaults are `/var/cache/nginx/repos` and
   `/var/log/nginx/repocache-metrics.log`. An unavailable log is **not**
   proof of zero requests; metrics may report unavailable or sample-limited.
4. The root-owned launcher and trusted recovery helper are installed only
   using the separately verified rootless bootstrap, and public Ed25519
   verification key material is provisioned **independently** of an untrusted
   downloaded release. Use only signed source and native hash-pinned offline
   dependency artifacts. The source-only v0.4.0 `install.sh` flow is rejected
   by design.
5. Keep existing NGINX configuration, certificates, caches and APT/DNF source
   files backed up using the site's normal operational process. The frontend
   installer must not rewrite them.

## Frontend smoke/acceptance on a representative preconfigured host

The following commands are operator-executed checks, **not claims of CI or
production-machine tests already performed**. Run them on a suitable disposable
or staging server first. Capture sanitized output, exit code, distribution,
Python version and installed signed-release fingerprint.

```sh
repocache --version
repocache status --json
repocache repos list --json
repocache health --json
repocache config check
repocache cache stats --json
repocache metrics --json
repocache update check --json
repocache update list --json
```

Expected behaviour:

- Commands are non-interactive and terminate; a missing metrics log or
  insufficient NGINX config permissions is reported transparently, not
  misreported as validated. `nginx -T` can require elevated permissions
  depending on TLS certificate paths. Do not relax system permissions merely
  to make a dashboard green.
- Repository route discovery must match actual reviewed NGINX `proxy_pass`
  locations. `status` and `metrics` are read-only; sampled history is not
  a full retention or billing-grade log.
- Run `repocache` **without arguments** in an interactive terminal to check
  Textual. It must not prompt when invoked by a script/non-TTY.
- A failed REPOCACHE frontend command must not interrupt live NGINX or
  package-manager access to previously configured upstreams.
- The default read-only `repocache-client repos sync` cannot change APT/DNF
  sources; applying client rewrites is not part of v0.4.0.

NGINX reload is an **explicit operational action**, not part of normal
frontend deployment or update:

```sh
repocache service reload             # Refuses non-interactively; no change
repocache service reload --yes       # Requires existing privileges; nginx -t first
```

The second command is reserved for an operator who has separately authorized
an NGINX reload. The CLI does not obtain new privileges to perform it. Do not
run it as part of a read-only smoke check on a live server.

## Updates, failure boundaries and recovery

- Install/upgrade the CLI/TUI using an independently authenticated signed
  release and hash-verified offline native wheelhouse. Service-account work
  must never execute as root. A same-version retry **rebuilds** a fresh
  managed generation instead of trusting mutable existing runtime bytes.
- An incompatible or unsigned release, an unsupported legacy installation,
  untrusted dependency set, unsafe installation path, or failed preflight
  must be refused without changing NGINX, TLS, caches or APT/DNF sources.
- The updater's root-owned lock and trusted startup recovery coordinator are
  separate from NGINX. Preserve previous manifest and active CLI on failures
  using journal recovery; use offline recovery instructions instead of
  executing suspected compromised application code.
- Do not assume a frontend upgrade rolls back NGINX configuration, client
  source files or an operator's own changes. Those remain externally managed
  in v0.4.0.
- Real booted systemd/SELinux tests and physical power-loss testing are **NOT
  TESTED** in CI; this residual risk is documented. Operator validation and
  issue reports are required before claiming tested compatibility with a
  particular real deployment.

## Release acceptance and publication

The v0.4.0 **production deployment contract is the frontend-only scope above**
and not a promise of complete NGINX setup. Acceptance still requires the
relevant functional, fundamental-security and defensive tests, reviewed
dependency rights, exact-head CI, signed publishing provenance, and explicit
approval for each merge, promotion and publication.

**Publication is not equivalent to testing on every production installation.**
Record post-release staging validation of the actual published signed asset,
CLI/TUI operation against an existing NGINX service and package-manager
traffic unaffected by frontend failures. Do not include internal network
identifiers, sensitive logs or actionable vulnerabilities in public issues:
use GitHub private vulnerability reporting.
