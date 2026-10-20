"""Release-integration workflow contract (issue #12).

GitHub still enforces rulesets and job status externally. These tests detect
accidental changes to the tracked CI/publishing policy; they do not substitute
for verifying effective repository settings through GitHub.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def test_test_workflow_covers_release_branch_main_and_untrusted_prs():
    workflow = (WORKFLOWS / "tests.yml").read_text(encoding="utf-8")
    assert "on:\n  push:\n    branches: [main, release/v0.4.0]\n  pull_request:" in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert "'3.12'" in workflow and "'3.13'" in workflow
    assert "'debian13'" in workflow and "'almalinux10'" in workflow
    assert "scripts/smoke_release_bundle.sh" in workflow


def test_publication_workflow_has_no_unreviewed_push_or_secret_publisher():
    workflow = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    assert "on:\n  workflow_dispatch:\n" in workflow
    assert "\n  push:" not in workflow
    assert "\n  release:" not in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert "startsWith(github.ref, 'refs/tags/v')" in workflow
    assert "github.actor == 'teixemf'" in workflow
    assert "compare/${GITHUB_SHA}...main" in workflow
    assert "unsigned-release-candidate" in workflow
    assert "sign_release.py" not in workflow
    assert "offline_sign_release.py" not in workflow


def test_release_docs_require_each_approval_and_true_acceptance_evidence():
    path = ROOT / "docs" / "RELEASE_INTEGRATION.md"
    doc = path.read_text(encoding="utf-8")
    for gate in ("PASS", "FAIL", "NOT VERIFIED", "explicit",
                 "release/v0.4.0", "main", "NGINX", "rollback"):
        assert gate in doc
    assert "No automatic merge" in doc


def test_native_offline_installed_wheels_execute_headless_tui():
    verifier = (ROOT / "scripts/ci_offline_wheels.py").read_text(encoding="utf-8")
    native = (ROOT / "scripts/build_release_wheels.sh").read_text(encoding="utf-8")
    smoke = (ROOT / "scripts/smoke_tui.py").read_text(encoding="utf-8")
    assert 'run(py, "/src/scripts/smoke_tui.py", env=poison)' in verifier
    assert "Installed native Textual UI smoke did not complete" in verifier
    assert "--network none" in native
    assert '"/src/scripts/ci_offline_wheels.py verify --release"' not in native
    assert 'ci_offline_wheels.py verify --release' in native
    assert "async with app.run_test" in smoke
    assert 'tui.snapshot = lambda' in smoke  # No production NGINX is touched
