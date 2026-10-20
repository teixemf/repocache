# Changelog

## v0.4.0 (unreleased candidate)

First planned public REPOCACHE release, based on a selectively sanitized source snapshot, with a new Git history. Release acceptance and publication are **not complete**. This is the first standalone public release: migration from pre-public installations (including v0.3.0) is **not supported**. The public v0.4.0 release policy has no previous-version compatibility allowlist; the historical migration prototype is not shipped in release archives.

Planned work includes Debian 13/AlmaLinux 10 native Python support, non-interactive update discovery and selection, Ed25519 authenticated releases, hash-pinned offline dependencies, rootless updater hardening and durable recovery. Implemented code is not the same as verified release behavior; consult CI and PR acceptance evidence.

**Security hardening (#35):** Explicit same-version update no longer returns `already-installed` based on a matching service-owned manifest or existing executable. Publisher identity is checked again and authenticated offline assets are installed into a new generation. Refuse symlink, hardlink, incorrect owner and unsafe mode drift on active/staged runtime paths and protected launcher ancestors. This approach does not attest an existing environment against a compromised service UID; recovery must not execute a suspect installed CLI.

Earlier private-development versions are **not republished** or automatically licensed by the new public repository.
