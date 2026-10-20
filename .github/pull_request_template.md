## Summary

Explain the change and the user-facing impact in English.

## Linked Issue

Closes #

## Implementation notes

Describe design choices, API/CLI compatibility, and any changes to NGINX, repository sources or stored metrics.

## Verification

- [ ] `PYTHONPATH=src python -m pytest -q` passes.
- [ ] Tested on supported Python versions or documented what could not be tested.
- [ ] Release-bundle/installer tests were run where applicable.
- [ ] English documentation and user-facing text were updated as needed.

**Test evidence:**

## Safety and rollout

- [ ] The default behaviour remains read-only/non-destructive, unless explicitly reviewed.
- [ ] No tokens, keys, private hostnames, logs or client identifiers are included.
- [ ] Changes to privileged configuration have a documented rollout and rollback plan, if applicable.
- [ ] Existing stable commands/JSON consumers remain compatible, or migrations are described.

**Deployment plan:**

**Rollback plan:**

## Reviewer notes

List known limitations, follow-up Issues and any maintainer decision needed. Do not merge until approved.
