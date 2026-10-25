# Contributing to REPOCACHE

REPOCACHE is licensed under [Apache License 2.0](LICENSE). Development uses English for code, documentation, reviews, issues, CLI output and releases.

Check existing public issues before proposing changes. File a focused issue with acceptance criteria, compatibility, safety implications and reproduction steps. Keep each PR focused and describe tests actually executed, unverified behavior and operational risks.

## AI-assisted contributions

REPOCACHE uses generative AI extensively in code, documentation and review proposals. Disclose substantive AI assistance in PR descriptions. Do not present an AI-generated review or an unexecuted test as independently verified. The contributor and maintainer remain responsible for license compliance, safe implementation and verifiable acceptance evidence.

## Review and security

Review policy candidate: [Choice C risk-tiered review](docs/PR_INDEPENDENT_REVIEW_POLICY.md) (issue #176). A separate workstream approved a conflicting Choice B. **PROPOSED; NOT ACTIVE until reconciled.** Preserve the existing independent review/acceptance and explicit owner merge approval gates. An AI-assisted technical report is not a formal human GitHub approval.


- Only Debian 13 and AlmaLinux 10 are currently targeted. Do not assert untested compatibility.
- Preserve APT/DNF failover, rollback, non-interactive CLI output and configuration safety.
- Never add private credentials, internal domain names, operational logs or deployment identifiers.
- For code changes, add appropriate regression, privilege-boundary and failure-path tests.
- Use a feature branch and a PR. **No merge without all relevant criteria PASS, inspected CI outcomes and explicit maintainer approval.**
- Report vulnerabilities privately via [SECURITY.md](SECURITY.md), never through a public issue.
