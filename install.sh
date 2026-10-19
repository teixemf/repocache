#!/usr/bin/env bash
# Install from a GitHub Release bundle; Git is not required.
set -Eeuo pipefail
if [[ "$(id -u)" -eq 0 || "$(id -un)" != "repocache" ]]; then
  echo 'Run as the dedicated repocache service account after rootless bootstrap; never as root.' >&2
  exit 1
fi
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -x /usr/bin/python3 ]]; then
  echo 'REPOCACHE requires the OS-provided /usr/bin/python3' >&2
  exit 1
fi
/usr/bin/python3 -I "$HERE/platform_check.py"
PYTHONPATH="$HERE/src" /usr/bin/python3 - "$HERE" <<'PY'
import sys
from pathlib import Path
from repocache.updater import install_source
result = install_source(Path(sys.argv[1]))
print("REPOCACHE installed:", result["version"])
print("Test: repocache --version && repocache repos list")
PY
