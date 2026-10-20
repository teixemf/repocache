# Security Policy

REPOCACHE is under active development. **There is no approved public v0.4.0 release yet.** Debian 13 and AlmaLinux 10 are the targeted supported platforms. Do not assume a draft branch passed independent security auditing or live-system validation.

## Reporting vulnerabilities

Do **not** create public issues or PRs containing actionable exploits, private keys, credentials, private network information or vulnerable production logs.

Use GitHub's **Security → Advisories → Report a vulnerability** private reporting workflow. The repository owner confirmed Private Vulnerability Reporting enabled and, on 2026-10-20, **personally verified using a GitHub account without repository administrator permissions that the private reporter form opens**. No synthetic or real private vulnerability was submitted; an end-to-end report-delivery test remains **NOT TESTED**. If the option is unexpectedly unavailable, use a previously established private contact channel rather than publishing technical details. The project does not claim a guaranteed response SLA.

## Security model and AI disclosure

Generative AI contributes substantially to this project, including proposed source code, tests and security reviews. AI-generated review is **not an independent security audit**, and unexecuted tests must not be represented as PASS.

Release authenticity requires independently provisioned Ed25519 public keys and offline maintainer custody of private signing keys; source hashes, public repository rulesets and GitHub access alone are insufficient. Preserve privilege separation, safe downloads, filesystem protections, signed provenance, verified offline dependencies and rollback behavior. Never share private signing keys via GitHub Actions or public discussions.
