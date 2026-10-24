# CLI JSON and exit-status contract v1

**Authority:** [CLI Architecture v1.0](CLI_ARCHITECTURE.md) · [CLI conformance](CLI_CONFORMANCE.md) · issue #107.

**Scope:** The three executables `repocache`, `repocache-client`, and the independent workstation-only `repocache-release`. This is a **compatibility-preserving implementation contract** for currently shipped command behavior, not an assertion that every planned CLI command is implemented.

## JSON v1 on finite commands

All finite commands which accept `--json` must emit **exactly one JSON object on stdout** for an ordinary success or required failure, never terminal markup. Success objects include the additive fields:

```json
{"schema_version":1,"ok":true}
```

Failure objects have at least:

```json
{"schema_version":1,"ok":false,"error":{"code":"INVALID_ARGUMENT","message":"An argument is missing."}}
```

Further operation-specific fields (`status`, `performed`, `retryable`, `exit_code`, `checks`, `repositories`, `result`) are retained when already present. The `error.code` identifier must be stable, uppercase snake case; `error.message` is human-readable, actionable and must not contain credentials. Human-facing errors in text mode go to stderr. JSON parsing failures are rejected before host or network operations; object-only help remains nonmutating. Plain `--help` remains human-readable. Streaming `logs follow --json` remains explicitly unavailable; it cannot be silently represented as one finite JSON document.

The new versioned envelope is an **intentional one-time compatibility migration** from v0.4.0's unversioned successes and some string-valued `error` fields, before the v1 interface becomes a stable release contract. Consumers should use `schema_version` and `error.code`, not parse human text. Do not remove operation-specific existing fields merely for visual consistency. Future schema changes require versioning, compatibility evidence and the published stable-release deprecation policy.

## Exact observed exit statuses — freeze existing public behavior

| Code | Present behavior / contract | Notes |
| --- | --- | --- |
| `0` | Successful operation or safe idempotent no-op | Shared across all three executables |
| `1` | Required diagnostic/runtime failure | Server diagnostics, client `check` with failed required connectivity; workstation release operation failures |
| `2` | Invalid CLI arguments or refused operation in existing compatibility paths | Server updater may return 2 for signature/compatibility/offline refusal; client disabled submit/sync and IO refusals return 2. **Do not silently rewrite these already-published paths.** |
| `3` | Client `check`: enabled repository configuration invalid while required connectivity checks passed | Preserved approved client-specific diagnostic distinction; not a universal batch failure |
| `75` | Signed updater transaction busy/locked | Preserve existing retryable semantics |

No other numeric status is assigned to planned commands by this version. A new command must choose from the established meanings; if additional categories are essential, amend the registry with explicit version/compatibility review rather than inventing a number. **The same number is not sufficient to classify an error**: scripts should use `error.code` together with the process return code. In particular, status 2 contains intentionally retained legacy update refusals, not only argument errors.

## Minimum stable symbolic codes

- `INVALID_ARGUMENT`: parser syntax, unknown action/option, missing required argument.
- `OPERATION_FAILED`: existing client/runtime refusal or unclassified required operation failure; no credentials in message.
- `REPOSITORY_INVALID`: client `check` exit 3.
- `REQUIRED_CHECK_FAILED`: client `check` exit 1.
- `REPOSITORY_NOT_FOUND`, `REPOSITORY_LOOKUP_UNAVAILABLE`, `UNSUPPORTED_OUTPUT_MODE`: server's established error identifiers.
- `BUSY`, `OFFLINE`, `AUTHENTICATION_REQUIRED`: signed update retry/availability classification where the existing updater explicitly provides that status.
- Workstation-only operational error identifiers (e.g. `INVALID_RELEASE`, `UNSAFE_SIGNER`, `BUILD_NOT_VERIFIED`) are preserved; no silent renaming.

Do not turn a failed required check into `ok: true` merely because producing the JSON response succeeded. A JSON parser failure must not probe NGINX, APT/DNF sources, server networking or signing keys, and must return exit 2. Versioned JSON is an API surface: review redaction, failure channels, option placement and backwards compatibility with every change.

## Regression gates

`tests/test_cli_error_contract.py` executes the parser and symbolic/exit matrix for all three executable frontends. `tests/test_cli_interface_contract.py` maintains command inventory and previously approved command anchors. Both are mandatory on Python 3.12 and 3.13 via `.github/workflows/tests.yml`; the release operator remains a workstation-only separately distributed executable. The v1 update-install tests in PR #114 must be reconciled to this envelope before integration.

**Platform limitation:** These parser tests do not imply an owner-signed production candidate was installed or rolled back on native Debian 13 / AlmaLinux 10, or satisfy #85. Do not use this scope to bypass #114's existing native acceptance or separate merge approval.
