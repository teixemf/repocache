# Roadmap

The initial public milestone is **v0.4.0**: establish a clean Apache-2.0 public source tree, enforce safe GitHub branch/tag rules, verify CI on the exact reviewed head, fix security blockers, rehearse isolated upgrade/rollback for Debian 13 and AlmaLinux 10, and publish an independently signed release **only after explicit maintainer approval**.

Future work includes complete server provisioning, richer client repository submission/review, operational observability and additional tested recovery scenarios.

The historic private project's issue/PR numbers are deliberately **not mirrored** here. Public issues will be created with new acceptance criteria and identifiers.

## Current work coordination

The description above records the initial public-release plan; it is not a
live issue-state ledger. Check [GitHub milestones](https://github.com/teixemf/repocache/milestones)
and current issue acceptance criteria for release ownership and status.

Contributors and AI-assisted sessions should start with [AGENTS.md](AGENTS.md)
and [the development workflow](docs/DEVELOPMENT_WORKFLOW.md).
For v0.5.0, consult the [scope and acceptance ledger](docs/RELEASE_SCOPE_V0.5.0.md);
its proposed freeze and scope corrections are **not adopted decisions** until
explicitly approved and integrated. The binding candidate and publication gates
remain in [the release acceptance policy](docs/RELEASE_ACCEPTANCE_POLICY.md).
