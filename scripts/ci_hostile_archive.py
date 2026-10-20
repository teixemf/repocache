#!/usr/bin/env python3
"""Small deterministic native hostile-archive test, using installed package.

CI only. Run after authenticated offline wheelhouse installation with network
disabled. This is neither random unbounded fuzzing nor a production probe.
"""
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile

from repocache import upgrade, wheelhouse


def make(name, type=tarfile.REGTYPE):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz") as tar:
        member = tarfile.TarInfo(name)
        member.type = type
        if type == tarfile.REGTYPE:
            member.size = 5
            tar.addfile(member, io.BytesIO(b"probe"))
        else:
            member.linkname = "fixture"
            tar.addfile(member)
    return result.getvalue()


def main():
    with tempfile.TemporaryDirectory(prefix="native-archive-") as tmp:
        home = Path(tmp)
        names = [
            ("repocache-v0.4.0/../escape", tarfile.REGTYPE),
            ("repocache-v0.4.0/release-policy.json", tarfile.SYMTYPE),
            ("repocache-v0.4.0/release-policy.json", tarfile.LNKTYPE),
            ("repocache-v0.4.0/foreign", tarfile.REGTYPE),
        ]
        for idx, (path, kind) in enumerate(names):
            data = make(path, kind)
            try:
                upgrade._extract_verified(
                    data, "0.4.0", home / ("source" + str(idx)),
                    {"version": "0.0.0"}, {"ID": "debian", "VERSION_ID": "13"})
            except upgrade.UpgradeError:
                pass
            else:
                raise RuntimeError("Untrusted source archive accepted")
        for idx, path in enumerate(("../escape", "/outside", "wheels/../bad.whl")):
            data = make(path)
            try:
                wheelhouse.verified_extract(
                    data, hashlib.sha256(data).hexdigest(),
                    home / ("deps" + str(idx)))
            except wheelhouse.WheelhouseError:
                pass
            else:
                raise RuntimeError("Untrusted wheelhouse accepted")
        if (home / "escape").exists() or (home / "outside").exists():
            raise RuntimeError("Archive extraction escaped staging")
    print("PASS: installed native release/wheelhouse hostile archive refusal")


if __name__ == "__main__":
    main()
