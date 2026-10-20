"""Public source disclosure gate: no historical internal hostnames or private URLs.

This is a structural regression check, not a full credential leak scanner.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REVIEWED = (
    "README.md", "CONTRIBUTING.md", "SECURITY.md", "SUPPORT.md",
    "ROADMAP.md", "CHANGELOG.md", "pyproject.toml",
    "client", "src", "scripts", "docs", ".github",
)


def test_no_private_repository_references_in_public_code():
    # Construct the historical repository suffix rather than putting its URL
    # or private issue numbers in the public source tree.
    obsolete_name = "repocache" + "-priv"
    for name in REVIEWED:
        root = ROOT / name
        files = (root.rglob("*") if root.is_dir() else (root,))
        for file in files:
            if (not file.is_file() or file.is_symlink() or
                    file.suffix not in {".py", ".sh", ".md", ".toml", ".yaml", ".yml", ".json", ".txt"}):
                continue
            data = file.read_text(encoding="utf-8")
            assert obsolete_name not in data.lower(), file


def test_no_realistic_private_lan_names_in_public_files():
    # The private DNS naming convention must not leak to the first release.
    domain = re.compile(r"\b[a-z][a-z0-9.-]*\.lan\.[a-z]{2,}\b", re.I)
    for top in (ROOT / "src", ROOT / "client", ROOT / "scripts", ROOT / "docs"):
        for file in top.rglob("*"):
            if (not file.is_file() or file.is_symlink() or
                    file.suffix not in {".py", ".sh", ".md", ".toml", ".yaml", ".yml", ".json", ".txt"}):
                continue
            assert domain.search(file.read_text(encoding="utf-8")) is None, file


def test_public_license_and_ai_disclosure_are_explicit():
    readme = (ROOT / "README.md").read_text()
    assert "Apache-2.0" in readme
    assert "generative AI" in readme
    assert (ROOT / "LICENSE").is_file()
    assert "independent security audit" in (ROOT / "SECURITY.md").read_text()
