# Read-only client repository synchronization plan

**Status:** Phase-1 draft implementation for [#24](https://github.com/teixemf/repocache/issues/24); **NOT** an APT/DNF apply engine.  
**Targets:** Debian 13 and AlmaLinux 10; native behavior remains NOT VERIFIED.  
**Interface:** `repocache-client repos sync` (read-only). `repos sync --apply` remains explicitly refused.

## Output and security contract

When a current, HTTPS-validated server catalog is available, sync inventories the local package sources and emits an *advisory* plan. Each entry keeps existing fields (`name`, `type`, `source`, `urls`, `enabled`, `route`, `supported`) and adds:

```json
{
  "plan": {
    "status": "candidate",
    "reason": "native-fallback-and-trust-not-verified",
    "action": "none",
    "apply_eligible": false
  }
}
```

The response also contains `dry_run: true`, `planned_changes: 0` and `plan_summary` status counts. **A candidate is not approved for a write**: APT/DNF fallback, package signature policy, authentication context, TLS scope, file ownership and drift still require verification.

| Status | Meaning |
| --- | --- |
| `skipped` | Disabled locally or absent from approved server catalog; leave unchanged. |
| `blocked` | Known unsafe/ambiguous source (credentials or URL parameters, weak signature/TLS policy, invalid URL, or cache-only source without verified fallback). |
| `review` | Existing mixed cache/upstream route, but mere presence of both addresses is not evidence that native fallback works. |
| `candidate` | Direct source appears in active catalog. Eligible for further checks **only**, never for mutation. |

Only sanitized URLs are emitted; private source URLs or DNF credentials must not be logged. Other credentials can be stored out of band (e.g., APT auth.conf, DNF shared configuration), so the absence of an explicit credential marker **does not prove** that a source is public. The current parser is advisory, not a trusted full-fidelity source writer.

The current implementation intentionally does **not**:

- Write APT/DNF source files or mirrorlists, even with `--apply`.
- Establish package authenticity or native fallback guarantees.
- Change local trust anchors, SSL verification or package signature checking.
- Claim a full stable repository identifier contract or accept per-repository mutation targets.
- Activate remote Repository Requests or infer that catalog inclusion authorizes addition of new system package repositories.

## Tests, acceptance and follow-up

- Synthetic tests: single-line APT sources, deb822 `.sources`, DNF `.repo`, disabled sections, credential-bearing URLs, weak signature configuration, existing mixed routes, malformed/unknown sources, repeatable nonmutation and early apply refusal.
- This PR must pass the exact-head CI parser inventory and all required security/smoke workflows.
- Before **any** future `--apply`: define stable IDs, independently validate APT/DNF source grammar and configurations, preserve comments/ownership, prove supported fallback combinations on native Debian 13/AlmaLinux 10, and add transactional backups, locking, drift detection, interruption recovery and rollback. Failure means the source stays direct.
- Coordinate CLI changes with [#107](https://github.com/teixemf/repocache/issues/107) and authenticated submissions with [#22](https://github.com/teixemf/repocache/issues/22)/draft PR #46.
