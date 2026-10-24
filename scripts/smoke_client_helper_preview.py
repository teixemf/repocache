#!/usr/bin/env python3
"""Disposable Debian 13 / AlmaLinux 10 smoke for read-only helper prototype.

Native /etc is NEVER inspected or altered by this smoke. The only native-root
attempt deliberately runs after dropping UID/GID and must be denied.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


CLIENT = Path(__file__).resolve().parents[1] / "client"
sys.path.insert(0, str(CLIENT))
import source_helper_preview as helper  # noqa: E402
import source_preflight as pre  # noqa: E402

RELATIVE = "etc/yum.repos.d/synthetic.repo"
DATA = b"[synthetic]\nbaseurl=https://upstream.invalid/repo\ngpgcheck=1\n"


def invoke(args, root=None):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = helper.main(args, _test_root=root)
    document = json.loads(output.getvalue())
    assert document["read_only"] is True
    assert document["write_eligible"] is False
    return code, document


def main():
    with tempfile.TemporaryDirectory(prefix="repocache-helper-preview-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        marker = root / pre.MARKER
        marker.write_bytes(pre.TEST_MAGIC)
        marker.chmod(0o600)
        source = root / RELATIVE
        source.parent.mkdir(parents=True)
        source.write_bytes(DATA)
        before = source.stat()

        code, status = invoke(["status", "--json"])
        assert code == 0 and status["ok"] and not status["installed"]
        code, verified = invoke(
            ["inspect-source", "--source", RELATIVE, "--json"], root)
        assert code == 0 and verified["filesystem_preflight"] == "pass"
        assert verified["repository_syntax_verified"] is False
        assert verified["package_signatures_verified"] is False
        assert verified["upstream_fallback_verified"] is False
        assert RELATIVE not in json.dumps(verified)
        assert source.read_bytes() == DATA
        assert source.stat().st_ino == before.st_ino

        code, bad = invoke(["--json", "inspect-source",
                            "--source", "https://user:secret@example.org/"], root)
        assert code != 0 and bad["error"]["code"] == "SOURCE_PREFLIGHT_REFUSED"
        assert "secret" not in json.dumps(bad)

        code, denied = invoke(["--json", "commit", "--source", RELATIVE], root)
        assert code == 2 and denied["error"]["code"] == "INVALID_ARGUMENTS"

        if os.geteuid() == 0:
            worker = r"""
import json, os, sys
os.setgroups([])
os.setgid(65534)
os.setuid(65534)
sys.path.insert(0, sys.argv[1])
import source_helper_preview as helper
code = helper.main(["--json", "inspect-source",
                    "--source", "etc/apt/sources.list"])
raise SystemExit(code)
"""
            result = subprocess.run(
                [sys.executable, "-c", worker, str(CLIENT)],
                check=False, capture_output=True, text=True, timeout=15,
            )
            assert result.returncode == 3, result.stderr
            doc = json.loads(result.stdout)
            assert doc["error"]["code"] == "ROOT_REQUIRED"
            assert doc["write_eligible"] is False
        else:
            raise AssertionError("Native privilege smoke requires isolated container root")

        assert source.read_bytes() == DATA
        assert source.stat().st_ino == before.st_ino
        print("PASS: read-only helper prototype, redaction, real non-root denial")


if __name__ == "__main__":
    main()
