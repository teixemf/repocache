"""Offline unit/regression tests for PR milestone governance (#145)."""

import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / ".github/scripts/assign_pr_milestone.py"
_spec = importlib.util.spec_from_file_location("assign_pr_milestone", SCRIPT)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def issue(n, milestone, *, pr=False, state="open", title="", body=""):
    return {
        "number": n,
        "milestone": None if milestone is None else {"number": milestone},
        "state": state,
        "title": title,
        "body": body,
        **({"pull_request": {"url": "https://example.invalid"}} if pr else {}),
    }


def test_single_issue_title_reference():
    primary, linked = mod.references("fix(client): safe sync (#24)", "See #102, parent PR #133")
    assert (primary, linked) == (None, (24,))
    assert mod.choose_milestone(primary, linked, lambda n: issue(n, 4)) == 4


def test_multiple_issues_same_milestone():
    _, refs = mod.references("ci: tests (#83 #85)", "")
    assert refs == (83, 85)
    assert mod.choose_milestone(None, refs, lambda n: issue(n, 3)) == 3


def test_conflicting_issue_milestones_are_blocked():
    _, refs = mod.references("build: signed profile (#84 #80)", "")
    with pytest.raises(mod.MilestonePolicyError, match="Milestone conflict"):
        mod.choose_milestone(None, refs, lambda n: issue(n, {84: 3, 80: 2}[n]))


def test_explicit_primary_must_not_hide_conflicting_closing_issue():
    primary, refs = mod.references("work (#84)", "Primary issue: #84\nCloses #80")
    with pytest.raises(mod.MilestonePolicyError, match="conflict"):
        mod.choose_milestone(primary, refs, lambda n: issue(n, {84: 3, 80: 2}[n]))


def test_conflicting_primary_issue_declarations_rejected():
    with pytest.raises(mod.MilestonePolicyError, match="Conflicting"):
        mod.references("work", "Primary issue: #83\nPrimary issue: #84")


def test_missing_issue_link_and_milestone_rejected():
    with pytest.raises(mod.MilestonePolicyError, match="Missing primary"):
        mod.choose_milestone(None, (), lambda n: issue(n, 3))
    with pytest.raises(mod.MilestonePolicyError, match="no valid milestone"):
        mod.choose_milestone(83, (), lambda n: issue(n, None))


def test_references_to_pr_not_issue_are_rejected():
    with pytest.raises(mod.MilestonePolicyError, match="not an issue"):
        mod.choose_milestone(24, (), lambda n: issue(n, 4, pr=True))


def test_pr_reference_in_prose_does_not_override_title_issue():
    primary, refs = mod.references("test (#24)", "The implementation builds on PR #132 and PR #133")
    assert (primary, refs) == (None, (24,))


def test_explicit_primary_issue_body_marker():
    primary, refs = mod.references("feat(cli): new command", "Primary issue: #107\nRelated to #83")
    assert (primary, refs) == (107, ())
    assert mod.choose_milestone(primary, refs, lambda n: issue(n, 2)) == 2


def test_reconcile_updates_only_empty_pr_milestone():
    calls = []

    def request(url, token, method="GET", payload=None):
        calls.append((url, method, payload))
        if method == "PATCH":
            assert payload == {"milestone": 4}
            return issue(110, 4, pr=True)
        return issue(110, None, pr=True, title="fix (#24)") if url.endswith("/110") else issue(24, 4)

    assert mod.reconcile("teixemf/repocache", 110, "fake", request) == "Assigned milestone #4 to PR #110"
    assert len([c for c in calls if c[1] == "PATCH"]) == 1


def test_reconcile_preserves_existing_milestone_without_issue_fetch():
    calls = []

    def request(url, token, method="GET", payload=None):
        calls.append((url, method))
        return issue(110, 2, pr=True, title="work (#24)")

    assert mod.reconcile("teixemf/repocache", 110, "fake", request) == "Preserved manually assigned milestone #2"
    assert calls == [("https://api.github.com/repos/teixemf/repocache/issues/110", "GET")]


def test_reconcile_skips_closed_pr():
    def request(url, token, method="GET", payload=None):
        return issue(110, None, pr=True, state="closed")

    assert mod.reconcile("teixemf/repocache", 110, "fake", request) == "Skipped closed PR"


def test_invalid_issue_response_or_repository_are_blocked():
    with pytest.raises(mod.MilestonePolicyError, match="Invalid repository"):
        mod.reconcile("teixemf/bad/other", 123, "fake")
    with pytest.raises(mod.MilestonePolicyError, match="Unexpected issue response"):
        mod.reconcile("teixemf/repocache", 123, "fake", lambda *args: issue(999, 4, pr=True))
