"""Docs/template contract for proposed independent PR review governance (#176).

These tests protect disclosure and pre-merge evidence requirements only.
They do NOT prove human review, governance adoption or live GitHub rules.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "docs/PR_INDEPENDENT_REVIEW_POLICY.md"
TEMPLATE = ROOT / ".github/pull_request_template.md"
CONTRIBUTING = ROOT / "CONTRIBUTING.md"


def test_policy_explicitly_not_adopted_without_owner_decision() -> None:
    text = POLICY.read_text(encoding="utf-8")
    assert "PROPOSED / NOT ADOPTED" in text
    assert "Choose and record ONE enforceable policy" in text
    assert "required_approving_review_count: 0" in text
    assert "are strictly historical, PR-specific decisions" in text
    assert "not an amendment of the live rulesets" in text


def test_policy_preserves_nonnegotiable_merge_and_security_gates() -> None:
    text = POLICY.read_text(encoding="utf-8")
    for phrase in (
        "PASS", "FAIL", "NOT VERIFIED",
        "required status context", "explicit merge authorization",
        "separate, explicit merge authorization",
        "pull_request_target", "event=push", "Ed25519",
        "#158", "#170", "#171",
    ):
        assert phrase.lower() in text.lower(), phrase


def test_pull_request_template_exposes_review_and_acceptance_evidence() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")
    for phrase in (
        "Exact HEAD/base SHAs",
        "PASS / FAIL / NOT VERIFIED",
        "Review evidence",
        "PR-specific substitution",
        "Explicit separate merge authorization",
        "post-merge verification",
    ):
        assert phrase in text, phrase
    assert "external AI technical evidence" in text


def test_contributing_discloses_proposal_status() -> None:
    text = CONTRIBUTING.read_text(encoding="utf-8")
    assert "docs/PR_INDEPENDENT_REVIEW_POLICY.md" in text
    assert "PROPOSED" in text
    assert "explicit owner merge approval" in text
