#!/usr/bin/env bash
# REPOCACHE Managed Client — no daemon or pip dependencies.
set -Eeuo pipefail
if [[ "$EUID" -ne 0 ]]; then
  echo "Run as root: sudo ./client/install.sh --server https://cache.example.org" >&2
  exit 1
fi
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -x /usr/bin/python3 ]]; then
  echo 'REPOCACHE requires the OS-provided /usr/bin/python3' >&2
  exit 1
fi
/usr/bin/python3 -I "$HERE/../platform_check.py"
SERVER="https://cache.example.org"
while (($#)); do
  case "$1" in
    --server)
      [[ $# -ge 2 ]] || { echo "--server requires a value" >&2; exit 2; }
      SERVER="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
SOURCE="$HERE/repocache_client.py"
TARGET_DIR="/opt/repocache-client"
CONFIG_DIR="/etc/repocache-client"
LAUNCHER="/usr/local/bin/repocache-client"
PYTHON="/usr/bin/python3"

"$PYTHON" - "$SERVER" <<'PY'
import sys
from urllib.parse import urlsplit
value = sys.argv[1]
u = urlsplit(value)
if u.scheme != "https" or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ("", "/"):
    raise SystemExit("Invalid server: use https://hostname")
PY

[[ -f "$SOURCE" ]] || { echo "Incomplete client bundle" >&2; exit 1; }
"$PYTHON" --version >/dev/null
if [[ -L "$LAUNCHER" ]] || [[ -e "$LAUNCHER" && ! -f "$LAUNCHER" ]]; then
  echo "Incompatible executable at $LAUNCHER; aborting" >&2
  exit 1
fi
if [[ -f "$LAUNCHER" ]] && ! grep -q '^# REPOCACHE-CLIENT MANAGED$' "$LAUNCHER"; then
  echo "Executable at this path is not managed by REPOCACHE: $LAUNCHER" >&2
  exit 1
fi

install -d -m 0755 "$TARGET_DIR"
install -d -m 0755 "$CONFIG_DIR"
install -m 0644 "$SOURCE" "$TARGET_DIR/repocache_client.py"
"$PYTHON" - "$SERVER" "$CONFIG_DIR/config.json" <<'PY'
import json, os, sys, tempfile
from pathlib import Path
server, dest = sys.argv[1:]
directory = Path(dest).parent
fd, temp = tempfile.mkstemp(dir=directory, prefix=".config-")
try:
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump({"server": server.rstrip("/")}, stream)
        stream.write("\n")
    os.chmod(temp, 0o644)
    os.replace(temp, dest)
finally:
    if os.path.exists(temp):
        os.unlink(temp)
PY
cat > "$LAUNCHER.tmp" <<'SH'
#!/bin/sh
# REPOCACHE-CLIENT MANAGED
exec /usr/bin/python3 /opt/repocache-client/repocache_client.py "$@"
SH
chmod 0755 "$LAUNCHER.tmp"
mv -f "$LAUNCHER.tmp" "$LAUNCHER"
echo "REPOCACHE Client installed (managed, no daemon)."
echo "Try: repocache-client repos list"
echo "Then:    repocache-client check"
