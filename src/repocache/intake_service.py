"""Explicit local-only intake service runner.

Installing the Python package does not install, enable or start the service.
The optional systemd example is also disabled unless an operator deploys it.
"""
from __future__ import annotations

import argparse
import os
import pwd
import signal
import stat
import threading
from pathlib import Path

from repocache.intake import SubmissionIntake, load_keyring, make_loopback_server
from repocache.submissions import SubmissionError, SubmissionQueue

DEFAULT_STORE = Path("/var/lib/repocache/submissions/queue.sqlite3")
DEFAULT_KEYRING = Path("/etc/repocache-intake/keyring.json")
ENABLE_MARKER = Path("/etc/repocache-intake/enable-local-intake")
SERVICE_USER = "repocache-intake"
PORT = 8765


def check_enable_marker(path: Path = ENABLE_MARKER) -> None:
    try:
        stat_info = path.lstat()
    except OSError as exc:
        raise SubmissionError("listener_disabled", 403) from exc
    # Root-controlled opt-in marker, non-world-writable, never a symlink.
    if (not stat.S_ISREG(stat_info.st_mode) or stat_info.st_uid != 0
            or stat_info.st_mode & 0o022):
        raise SubmissionError("listener_disabled", 403)


def require_service_identity() -> None:
    try:
        user = pwd.getpwnam(SERVICE_USER)
    except KeyError as exc:
        raise SubmissionError("service_account_missing", 503) from exc
    if os.geteuid() == 0 or os.geteuid() != user.pw_uid:
        raise SubmissionError("service_identity_required", 403)


def build_intake() -> SubmissionIntake:
    check_enable_marker()
    require_service_identity()
    return SubmissionIntake(
        SubmissionQueue(DEFAULT_STORE),
        load_keyring(DEFAULT_KEYRING),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="repocache-intake")
    parser.add_argument("--enable-local-only", action="store_true",
                        help="Require controlled marker and dedicated service identity")
    parser.add_argument("--check-config", action="store_true",
                        help="Validate without binding or starting a listener")
    args = parser.parse_args(argv)

    if not args.enable_local_only:
        print("ERROR: Intake remains disabled without explicit local-only opt-in")
        return 2
    try:
        intake = build_intake()
        if args.check_config:
            print("Local intake configuration valid; listener not started")
            return 0
        server = make_loopback_server(intake, enabled=True, port=PORT)
        # shutdown must run in another thread; calling it in the serving
        # thread's signal handler deadlocks HTTPServer. Stop gracefully.
        def shutdown(_signum, _frame):
            threading.Thread(target=server.shutdown, daemon=True).start()
        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)
        try:
            server.serve_forever(poll_interval=0.25)
        finally:
            server.server_close()
        return 0
    except (SubmissionError, OSError) as exc:
        # No credentials, paths, IP addresses or request bodies in diagnostics.
        code = exc.code if isinstance(exc, SubmissionError) else "local_service_unavailable"
        print("ERROR: " + code)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
