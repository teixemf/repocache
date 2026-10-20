"""License evidence inventory only; a human must review legal obligations (#6)."""
import importlib.util
import io
import json
from pathlib import Path
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "wheel_licenses", ROOT / "scripts/audit_wheel_licenses.py")
licenses = importlib.util.module_from_spec(spec)
spec.loader.exec_module(licenses)


def make_wheel(tmp_path, name="example-1.0-py3-none-any.whl",
               metadata="Name: example\nVersion: 1.0\nLicense-Expression: MIT\n",
               notices=None):
    dest = tmp_path / name
    with zipfile.ZipFile(dest, "w") as output:
        output.writestr("example-1.0.dist-info/METADATA", metadata)
        if notices:
            for path, body in notices.items():
                output.writestr("example-1.0.dist-info/licenses/" + path, body)
    return dest


def test_metadata_license_expression_is_evidence_not_legal_approval(tmp_path):
    path = make_wheel(tmp_path)
    review = licenses.audit_wheel(path)
    assert review["name"] == "example"
    assert review["license_expression"] == "MIT"
    assert review["sha256"]
    assert review["legal_compatibility"] == "NOT VERIFIED"
    inventory = licenses.inventory([path])
    assert inventory["review_state"].startswith("NOT VERIFIED")
    assert len(inventory["components"]) == 1
    assert json.loads(licenses.format_inventory([path])) == inventory


@pytest.mark.parametrize("metadata", [
    "Name: example\nVersion: 1.0\n",
    "Name: other\nVersion: 1.0\nLicense: MIT\n",
    "Name: example\nVersion: 1.1\nLicense: MIT\n",
    "Name: example\nVersion: 1.0\nLicense: UNKNOWN\n",
    "Not-Name: example\nVersion: 1.0\nLicense: MIT\n",
])
def test_no_license_evidence_or_mismatched_identity_fails(tmp_path, metadata):
    path = make_wheel(tmp_path, metadata=metadata)
    with pytest.raises(licenses.LicenseEvidenceError):
        licenses.audit_wheel(path)


def test_legacy_classifiers_count_as_evidence_not_approval(tmp_path):
    path = make_wheel(tmp_path, metadata=(
        "Name: example\nVersion: 1.0\n"
        "Classifier: License :: OSI Approved :: Apache Software License\n"))
    assert licenses.audit_wheel(path)["license_classifiers"] == [
        "License :: OSI Approved :: Apache Software License"]


def test_bundled_notice_file_counts_as_evidence_but_needs_human_review(tmp_path):
    path = make_wheel(tmp_path, metadata="Name: example\nVersion: 1.0\n",
                      notices={"LICENSE": "Synthetic notice, not a real license"})
    item = licenses.audit_wheel(path)
    assert item["notice_files"] == ["example-1.0.dist-info/licenses/LICENSE"]
    assert item["legal_compatibility"] == "NOT VERIFIED"


def test_oversized_metadata_and_broken_zip_fail_closed(tmp_path):
    path = make_wheel(tmp_path, metadata=(
        "Name: example\nVersion: 1.0\nLicense: MIT\n" + "X" * 200000))
    with pytest.raises(licenses.LicenseEvidenceError, match="bounded"):
        licenses.audit_wheel(path)
    path.write_bytes(b"not a wheel")
    with pytest.raises(licenses.LicenseEvidenceError):
        licenses.audit_wheel(path)


def test_duplicate_or_symlinked_wheel_and_missing_inventory_refused(tmp_path):
    path = make_wheel(tmp_path)
    with pytest.raises(licenses.LicenseEvidenceError, match="Duplicate"):
        licenses.inventory([path, path])
    with pytest.raises(licenses.LicenseEvidenceError):
        licenses.inventory([])
    link = tmp_path / "linked.whl"
    link.symlink_to(path)
    with pytest.raises(licenses.LicenseEvidenceError):
        licenses.audit_wheel(link)


def test_native_wheel_verification_always_runs_rights_audit():
    script = (ROOT / "scripts/ci_offline_wheels.py").read_text(encoding="utf-8")
    assert "from audit_wheel_licenses import format_inventory" in script
    assert 'print("CI BUILD LICENSE EVIDENCE: " +' in script
    assert 'format_inventory(sorted(build_tools.glob("*.whl")))' in script
    assert 'print("CI LICENSE EVIDENCE: " + format_inventory(files).strip()' in script
    assert "verified_extract(tarpath.read_bytes(), digest" in script
