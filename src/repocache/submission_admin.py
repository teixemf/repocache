"""Root-only, non-interactive controls for optional submissions state.

These commands neither configure nor activate NGINX, systemd or the intake.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from repocache.submission_recovery import restore_offline
from repocache.submissions import SubmissionError, SubmissionQueue

STORE = Path("/var/lib/repocache/submissions/queue.sqlite3")
UNIT = "repocache-intake.service"


def intake_is_inactive() -> bool:
    """Fail closed if systemd is absent, inconsistent or running the intake."""
    try:
        proc = subprocess.run(
            ["/usr/bin/systemctl", "is-active", UNIT],
            text=True, capture_output=True, check=False, timeout=5,
        )
        return proc.returncode == 3 and proc.stdout.strip() == "inactive"
    except (OSError, subprocess.TimeoutExpired):
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="repocache-submissions-admin")
    actions = parser.add_subparsers(dest="command", required=True)
    backup = actions.add_parser("backup")
    backup.add_argument("--output", type=Path, required=True)
    backup.add_argument("--approve", action="store_true", required=True)
    restore = actions.add_parser("restore")
    restore.add_argument("--input", type=Path, required=True)
    restore.add_argument("--approve", action="store_true", required=True)
    maintain = actions.add_parser("maintain")
    maintain.add_argument("--retention-days", type=int, required=True)
    maintain.add_argument("--approve", action="store_true", required=True)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("ERROR: operator_required", file=sys.stderr)
        return 3
    try:
        if args.command == "restore":
            # No restore while the intake is running, or when systemd cannot
            # prove it is stopped. Existing DB remains until the backup is
            # validated and the rollback inode has been durably recorded.
            rollback = restore_offline(
                STORE, args.input, approved=args.approve,
                service_stopped=intake_is_inactive,
            )
            print("Restore completed; previous database preserved at " + str(rollback))
        elif args.command == "backup":
            if not args.approve:
                raise SubmissionError("operator_approval_required", 403)
            SubmissionQueue(STORE).backup(args.output)
            print("Backup created")
        else:
            if not args.approve:
                raise SubmissionError("operator_approval_required", 403)
            result = SubmissionQueue(STORE).maintain(
                approved=True, decided_retention_days=args.retention_days)
            print("Maintenance completed: decided=%d, expired_nonces=%d" %
                  (result["purged_decided"], result["purged_nonces"]))
        return 0
    except (SubmissionError, OSError) as exc:
        error = exc.code if isinstance(exc, SubmissionError) else "operation_unavailable"
        print("ERROR: " + error, file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
