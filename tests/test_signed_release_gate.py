"""Release gating tests: only a read-only candidate may run on GitHub Actions."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_release_requires_offline_wheelhouse_and_prohibits_ci_signing():
    ci = (ROOT / ".github/workflows/release.yml").read_text()
    assert "scripts/build_release_wheels.sh" in ci
    assert "unsigned-release-candidate" in ci
    assert "contents: write" not in ci
    assert "secrets.REPOCACHE_RELEASE_SIGNING_KEY_B64" not in ci
    assert "gh release create" not in ci
    assert "  sign:" not in ci and "  publish:" not in ci
    local = (ROOT / "scripts/offline_sign_release.py").read_text()
    assert "getpass.getpass" in local
    assert "validate_public_key" in local
    assert "verify_candidate" in local
    assert "sign_manifest" in local
    assert "sign_provenance" in local
    assert "validate_candidate_identity" in local


def test_release_bundle_distributes_verifier():
    content = (ROOT / "scripts/build_release.py").read_text()
    assert '"src/repocache/signatures.py"' in content
    cli = (ROOT / "src/repocache/cli.py").read_text()
    assert '"--manifest"' in cli and '"--signature"' in cli
