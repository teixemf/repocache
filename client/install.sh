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
# BEGIN SERVER_ARGUMENT_PREFLIGHT
# Pure argument and TLS-origin validation; no managed filesystem writes.
# UC-10: a server must be supplied explicitly; never install a placeholder.
SERVER=""
while (($#)); do
  case "$1" in
    --server)
      [[ $# -ge 2 && -n "$2" ]] || { echo "--server requires a HTTPS origin" >&2; exit 2; }
      [[ -z "$SERVER" ]] || { echo "--server may only be provided once" >&2; exit 2; }
      SERVER="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$SERVER" ]] || {
  echo "Missing required --server HTTPS_ORIGIN (example: --server https://cache.example.org)" >&2
  exit 2
}
/usr/bin/python3 - "$SERVER" <<'PY'
import ipaddress
import re
import sys
from urllib.parse import urlsplit

value = sys.argv[1]
try:
    origin = urlsplit(value)
    port = origin.port
except ValueError:
    raise SystemExit("Invalid server: malformed HTTPS origin")

if (origin.scheme != "https" or not origin.hostname
        or origin.username is not None or origin.password is not None
        or origin.path not in ("", "/") or origin.query or origin.fragment
        or port == 0 or origin.netloc.endswith(":")
        or any(ord(ch) < 33 or ord(ch) > 126 for ch in value)
        or "\\" in value or "%" in value
        or "?" in value or "#" in value):
    raise SystemExit("Invalid server: use a canonical HTTPS origin")

hostname = origin.hostname
try:
    ipaddress.ip_address(hostname)
except ValueError:
    # Reject ambiguous numeric/hex IPv4 abbreviations and DNS label tricks.
    labels = hostname.split(".")
    numeric = re.compile(r"(?:[0-9]+|0[xX][0-9A-Fa-f]+)\Z", re.ASCII)
    dns_label = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z", re.ASCII)
    if (len(hostname) > 253 or len(labels) < 2
            or all(numeric.fullmatch(label) for label in labels)
            or any(not dns_label.fullmatch(label) for label in labels)):
        raise SystemExit("Invalid server: use a canonical HTTPS origin")
PY
# END SERVER_ARGUMENT_PREFLIGHT

# Installation paths remain fixed and are initialized before the first write.
SOURCE="$HERE/repocache_client.py"
TARGET_DIR="/opt/repocache-client"
CONFIG_DIR="/etc/repocache-client"
LAUNCHER="/usr/local/bin/repocache-client"
PYTHON="/usr/bin/python3"

# All filesystem-writing tools must exist before the first managed write.
# Fail closed on an incompletely provisioned OS rather than installing partly.
for required in /usr/bin/install /usr/bin/mv /usr/bin/chmod /usr/bin/grep /usr/bin/mktemp /usr/bin/rm; do
  [[ -x "$required" ]] || {
    echo "Missing client installer prerequisite: $required" >&2
    exit 1
  }
done
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

# BEGIN MANAGED_PATH_PREFLIGHT
# Refuse symlinked managed directories and unsafe destination file types
# before the first filesystem write. Never adopt a redirected third-party path.
for directory in "$TARGET_DIR" "$CONFIG_DIR"; do
  if [[ -L "$directory" || ( -e "$directory" && ! -d "$directory" ) ]]; then
    echo "Unsafe client managed directory: $directory" >&2
    exit 1
  fi
done
for path in "$TARGET_DIR/repocache_client.py" "$CONFIG_DIR/config.json"; do
  if [[ -L "$path" || ( -e "$path" && ! -f "$path" ) ]]; then
    echo "Unsafe client managed file: $path" >&2
    exit 1
  fi
done
# END MANAGED_PATH_PREFLIGHT

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
# Stage the launcher under a unique O_EXCL-created filename rather than
# following a predictable .tmp symlink. Clean up on interrupted installs.
LAUNCHER_TEMP="$(/usr/bin/mktemp "${LAUNCHER}.XXXXXXXX")"
trap 'if [[ -n "${LAUNCHER_TEMP:-}" ]]; then /usr/bin/rm -f -- "$LAUNCHER_TEMP"; fi' EXIT
cat > "$LAUNCHER_TEMP" <<'SH'
#!/bin/sh
# REPOCACHE-CLIENT MANAGED
exec /usr/bin/python3 /opt/repocache-client/repocache_client.py "$@"
SH
chmod 0755 "$LAUNCHER_TEMP"
mv -f -- "$LAUNCHER_TEMP" "$LAUNCHER"
LAUNCHER_TEMP=""
echo "REPOCACHE Client installed (managed, no daemon)."
echo "Try: repocache-client repos list"
echo "Then:    repocache-client check"
