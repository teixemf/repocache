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
    assert (
        "on:\n  push:\n    branches: "
        "[main, release/v0.4.0, integration/v0.5.0, integration/v0.6.0]"
        "\n  pull_request:"
    ) in workflow
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


def test_mandatory_release_security_matrix_is_explicitly_executed():
    workflow = (WORKFLOWS / "tests.yml").read_text(encoding="utf-8")
    required = (
        "tests/test_public_release_transport_defensive.py",
        "tests/test_hostile_archive_defensive.py",
        "tests/test_complete_bundle_identity.py",
        "tests/test_release_integration_contract.py",
    )
    assert "Required release security regression gate (issues 37 38 39)" in workflow
    assert "python -m pytest -q" in workflow
    for path in required:
        assert (ROOT / path).is_file(), path
        assert path in workflow, path
    # Fail if signed native artifact CI silently stops executing hostile TAR
    # probes against the installed release (not merely the checked-out tree).
    verifier = (ROOT / "scripts/ci_offline_wheels.py").read_text(encoding="utf-8")
    native = (ROOT / "scripts/ci_hostile_archive.py").read_text(encoding="utf-8")
    assert 'run(py, "/src/scripts/ci_hostile_archive.py", env=poison)' in verifier
    assert "Native hostile archive regression did not execute" in verifier
    assert "installed native release/wheelhouse hostile archive refusal" in native
    assert '("--network none"' not in verifier  # Container isolation enforced by caller.
    assert "--network none" in (ROOT / "scripts/build_release_wheels.sh").read_text(
        encoding="utf-8")
    runbook = (ROOT / "docs/RELEASE_0.4.0_GATES.md").read_text(encoding="utf-8")
    for issue in ("#37", "#38", "#39"):
        assert issue in runbook
    for requirement in ("asset fingerprint", "NOT VERIFIED", "PASS", "FAIL"):
        assert requirement in runbook


def test_native_public_transport_security_gate_cannot_be_omitted():
    smoke = (ROOT / "scripts/smoke_release_bundle.sh").read_text(encoding="utf-8")
    native = (ROOT / "scripts/ci_native_public_transport.py").read_text(encoding="utf-8")
    assert "ci_native_public_transport.py,target=/tmp/ci_native_public_transport.py,readonly" in smoke
    assert "PYTHONPATH=./src /usr/bin/python3 /tmp/ci_native_public_transport.py" in smoke
    assert "PASS: native public GitHub transport refuses unsafe redirects and credentials" in native
    assert "urllib.request.build_opener = lambda *_: f" in native
    assert "Legacy asset token accepted" in native
    assert "Chained CDN redirect accepted" in native


def test_rootless_rollback_checks_run_for_every_pr_main_and_release_branch_commit():
    # Required status contexts must not silently disappear for docs-only PRs.
    workflow = (WORKFLOWS / "upgrade-distros.yml").read_text(encoding="utf-8")
    assert (
        "  pull_request:\n  push:\n    branches: "
        "[main, release/v0.4.0, integration/v0.5.0, integration/v0.6.0]"
        "\n  workflow_dispatch:"
    ) in workflow
    trigger = workflow.partition("  pull_request:")[2].partition("permissions:")[0]
    assert "paths:" not in trigger
    assert "Synthetic rootless update and rollback" in workflow
    assert "debian:trixie-slim" in workflow and "almalinux:10" in workflow


def test_governed_integration_push_retains_complete_offline_and_upstream_gates():
    """Preserve nine mandatory unfiltered push contexts across all four lanes."""
    exact = "branches: [main, release/v0.4.0, integration/v0.5.0, integration/v0.6.0]"
    for name in ("tests.yml", "offline-wheelhouse.yml", "upgrade-distros.yml"):
        text = (WORKFLOWS / name).read_text(encoding="utf-8")
        assert exact in text, name
        assert "  pull_request:" in text
        assert "permissions:\n  contents: read" in text
    upstream = (WORKFLOWS / "native-upstream-wheels.yml").read_text(encoding="utf-8")
    assert "branches: [main, integration/v0.5.0, integration/v0.6.0]" in upstream
    assert "  pull_request:" in upstream
    assert "      - 'deps/runtime-wheels.lock'" in upstream
    assert 'target=/source,readonly' in upstream
    assert "runuser -u repocacheci" in upstream
    assert "permissions:\n  contents: read" in upstream
    release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    assert "\n  push:" not in release
