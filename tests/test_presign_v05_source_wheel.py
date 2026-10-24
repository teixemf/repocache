"""Fail-closed v0.4 source-TAR / v0.5 signed-wheel signing boundary (#76).

These fixtures do NOT use the owner private key or claim a genuine release.
They exercise real wheelhouse and first-party-wheel parsers against bytes
that could otherwise be rehashed after the CI wheel build.
"""
from __future__ import annotations

import hashlib
import importlib
import io
import json
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def checked_source(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(REPO / "scripts"))
    checker = importlib.import_module("verify_release_candidate")
    root = tmp_path / "reviewed"
    package = root / "src/repocache"
    package.mkdir(parents=True)
    modules = {
        "repocache/__init__.py": b'__version__ = "0.5.0"\n',
        "repocache/cli.py": b'def cli(): return "reviewed"\n',
        "repocache/submissions.py": b'def intake(): return "reviewed"\n',
    }
    for name, data in modules.items():
        dest = root / "src" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    (root / "THIRD_PARTY_NOTICES.md").write_bytes(b"approved notices\n")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "repocache-control"\nversion = "0.5.0"\n'
    )
    deps = root / "deps"
    deps.mkdir()
    (deps / "build-wheels.lock").write_text(
        "setuptools 80.0.0 " + "a" * 64 + "\n"
        "wheel 0.45.0 " + "b" * 64 + "\n"
    )
    monkeypatch.setattr(checker, "ROOT", root)

    def rebuild(dest: Path):
        assert dest.is_dir()  # production verifier created its secure tempdir
        path = dest / "repocache-v0.5.0.tar.gz"
        path.write_bytes(b"reviewed source archive fixture")
        return path, dest / (path.name + ".sha256")

    monkeypatch.setattr(checker, "build_release", rebuild)
    return checker, root, modules


def file_zip(modules: dict[str, bytes], *, duplicate=False,
             symlink=False, oversized_metadata=False,
             alien_metadata=False) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in modules.items():
            if name == "repocache/submissions.py" and symlink:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, b"repocache/__init__.py")
            else:
                z.writestr(name, data)
        z.writestr("repocache_control-0.5.0.dist-info/METADATA",
                   "Metadata-Version: 2.3\nName: repocache-control\n"
                   "Version: 0.5.0\n\n")
        if alien_metadata:
            z.writestr("repocache_control-9.9.9.dist-info/entry_points.txt",
                       b"[console_scripts]\nunsafe=repocache.cli:app\n")
        if oversized_metadata:
            # A tiny compressed ZIP member can expand beyond safe pre-signing
            # memory bounds even though the outer wheelhouse is hash-locked.
            z.writestr("repocache_control-0.5.0.dist-info/UNREVIEWED",
                       b"X" * 50_000_001)
        if duplicate:
            with pytest.warns(UserWarning, match="Duplicate name"):
                z.writestr("repocache/submissions.py", b"shadowed")
    return stream.getvalue()


def build_fixture(tmp_path, checked_source, *, attack=None) -> Path:
    _, root, reviewed = checked_source
    output = tmp_path / "candidate"
    output.mkdir()
    archive = output / "repocache-v0.5.0.tar.gz"
    archive.write_bytes(b"reviewed source archive fixture")

    candidate = dict(reviewed)
    if attack == "missing":
        del candidate["repocache/submissions.py"]
    if attack == "modified":
        candidate["repocache/submissions.py"] = b"def intake(): return 'modified'\n"
    if attack == "oversized-module":
        candidate["repocache/submissions.py"] = b"X" * 1_000_000
    if attack == "extra":
        candidate["repocache/unreviewed.py"] = b"print('unreviewed')\n"
    if attack == "extra-path":
        candidate["evil.pth"] = b"import unreviewed\n"
    app = file_zip(candidate, duplicate=attack == "duplicate",
                   symlink=attack == "symlink",
                   oversized_metadata=attack == "oversized-metadata",
                   alien_metadata=attack == "alien-dist-info")
    app_name = "repocache_control-0.5.0-py3-none-any.whl"
    dep_name = "typer-1.0.0-py3-none-any.whl"
    dep = b"inert dependency fixture"
    (root / "deps/runtime-wheels.lock").write_text(
        "typer 1.0.0 " + sha(dep) + "\n"
    )
    wheels = {app_name: app, dep_name: dep}
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"version": "0.5.0"},
                         "tools": {"components": [
                             {"name": "setuptools", "version": "80.0.0",
                              "hashes": [{"content": "a" * 64}]},
                             {"name": "wheel", "version": "0.45.0",
                              "hashes": [{"content": "b" * 64}]},
                         ]}},
            "components": [
                {"type": "library", "name": n.split("-")[0],
                 "version": n.split("-")[1],
                 "hashes": [{"alg": "SHA-256", "content": sha(v)}],
                 "properties": [{"name": "repocache:wheel-file", "value": n}]}
                for n, v in wheels.items()
            ]}
    lock = "".join(f"./wheels/{name} --hash=sha256:{sha(data)}\n"
                   for name, data in wheels.items()).encode("ascii")
    assets = {
        "requirements.lock": lock,
        "sbom.json": (json.dumps(sbom) + "\n").encode(),
        "THIRD_PARTY_NOTICES.md": (root / "THIRD_PARTY_NOTICES.md").read_bytes(),
        **{"wheels/" + n: v for n, v in wheels.items()},
    }
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for name, raw in assets.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(raw)
            entry.mode = 0o600
            archive.addfile(entry, io.BytesIO(raw))
    (output / "repocache-v0.5.0.tar.gz.wheelhouse.tar.gz").write_bytes(
        data.getvalue())
    return output


def test_real_verifier_accepts_exact_reviewed_first_party_wheel(
        tmp_path, checked_source, capsys):
    checker, _, _ = checked_source
    checker.verify(build_fixture(tmp_path, checked_source))
    assert "PASS: rebuilt release" in capsys.readouterr().out


@pytest.mark.parametrize("attack", [
    "missing", "modified", "extra", "extra-path", "duplicate", "symlink",
    "oversized-module", "oversized-metadata", "alien-dist-info",
])
def test_real_verifier_rejects_rehashed_unreviewed_wheel(
        tmp_path, checked_source, attack):
    checker, _, _ = checked_source
    output = build_fixture(tmp_path, checked_source, attack=attack)
    # The wheelhouse lock/SBOM and archive SHA all match the ATTACKED wheel;
    # the independent checkout-module comparison must still fail closed.
    with pytest.raises(ValueError, match="first-party wheel differs"):
        checker.verify(output)


def test_offline_owner_signer_refuses_unreviewed_wheel_before_key_access(
        tmp_path, checked_source, monkeypatch):
    checker, _, _ = checked_source
    signer = importlib.import_module("offline_sign_release")
    output = build_fixture(tmp_path, checked_source, attack="modified")
    monkeypatch.setattr(signer, "verify_candidate", checker.verify)
    monkeypatch.setattr(signer, "validate_public_key", lambda *_a:
                        pytest.fail("Owner private key must not be accessed"))
    bundle = output / "repocache-v0.5.0.tar.gz"
    with pytest.raises(ValueError, match="first-party wheel differs"):
        signer.sign_candidate(
            bundle, tmp_path / "unavailable-owner-private.pem",
            commit="a" * 40, run_id="1", attempt="1", password=b"test-only",
            check_github=False,
        )


@pytest.mark.parametrize("attack", ["untracked", "missing"])
def test_owner_signer_requires_exact_git_tracked_module_set_before_github(
        checked_source, monkeypatch, attack):
    """Local bytes matching a tampered wheel are not proof of reviewed Git code."""
    _, root, modules = checked_source
    signer = importlib.import_module("offline_sign_release")
    monkeypatch.setattr(signer, "ROOT", root)
    if attack == "untracked":
        (root / "src/repocache/unreviewed.py").write_text(
            "def unaudited(): return True\n")
    else:
        (root / "src/repocache/submissions.py").unlink()

    def fake_command(argv, **_kw):
        # Fail if GitHub is contacted before locally refusing the source drift.
        if argv[0] != "git":
            pytest.fail("Unreviewed source must not trigger GitHub API reads")
        if "rev-parse" in argv:
            return b"a" * 40 + b"\n"
        if "status" in argv:
            return b""
        if "ls-files" in argv:
            return b"\x00".join(
                p.replace("repocache/", "src/repocache/", 1).encode()
                for p in sorted(modules)
            ) + b"\x00"
        pytest.fail("Unexpected Git subcommand")

    monkeypatch.setattr(signer, "_read_only_command", fake_command)
    with pytest.raises(signer.OfflineSigningError,
                       match="differ from the reviewed Git commit"):
        signer.validate_candidate_identity(
            root / "repocache-v0.5.0.tar.gz", "a" * 40, "1", "1"
        )
