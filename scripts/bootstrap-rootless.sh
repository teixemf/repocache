#!/usr/bin/env bash
# Privileged one-time filesystem bootstrap only; never imports package Python.
# REQUIRES an independently authenticated script/launcher and reviewed digest.
set -Eeuo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
if [[ $(id -u) -ne 0 || $# -ne 4 || "$1" != "--launcher-sha256" ||
      ! "$2" =~ ^[a-fA-F0-9]{64}$ || "$3" != "--recovery-sha256" ||
      ! "$4" =~ ^[a-fA-F0-9]{64}$ ]]; then
  echo "Usage (root): bootstrap-rootless.sh --launcher-sha256 VERIFIED_LAUNCHER_SHA256 --recovery-sha256 VERIFIED_RECOVERY_SHA256" >&2
  exit 2
fi
# Verify the system environment before creating any users or directories.
# Only OS-owned Python and embedded stdlib code execute while privileged.
# Do not import Python from an untrusted REPOCACHE source tree.
if [[ ! -x /usr/bin/python3 ]]; then
  echo 'Missing OS-provided /usr/bin/python3' >&2
  exit 1
fi
/usr/bin/python3 -I - <<'PY'
import re
import sys
from pathlib import Path

values = {}
for raw in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
    row = raw.strip()
    if not row or row.startswith("#") or "=" not in row:
        continue
    key, value = row.split("=", 1)
    if key in ("ID", "VERSION_ID"):
        if key in values:
            raise SystemExit("Duplicate platform identifier")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[key] = value
version = values.get("VERSION_ID", "")
if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", version):
    raise SystemExit("Invalid OS version")
expected = {("debian", "13"): (3, 13), ("almalinux", "10"): (3, 12)}.get(
    (values.get("ID", ""), version.split(".")[0]))
if expected is None or sys.version_info[:2] != expected:
    raise SystemExit("Unsupported OS/native Python: Debian 13 / 3.13 or AlmaLinux 10 / 3.12 required")
PY
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
launcher="$here/repocache-launcher.sh"
recovery="$here/../src/repocache/recovery.py"
[[ -f "$recovery" && ! -L "$recovery" ]] || { echo 'Invalid trusted recovery helper source' >&2; exit 1; }
printf '%s  %s\n' "$4" "$recovery" | sha256sum -c --status ||
  { echo "Recovery helper differs from independently verified fingerprint" >&2; exit 1; }
[[ -f "$launcher" && ! -L "$launcher" ]] || { echo 'Invalid launcher source' >&2; exit 1; }
printf '%s  %s\n' "$2" "$launcher" | sha256sum -c --status ||
  { echo "Launcher hash differs from independently verified fingerprint" >&2; exit 1; }
# Reject missing OS-owned command prerequisites before useradd or any filesystem
# mutation. An incomplete util-linux/coreutils/shadow-utils install is not a
# valid target; never attempt best-effort privileged bootstrap.
for required in /usr/sbin/runuser /usr/sbin/useradd /usr/bin/install /usr/bin/stat /usr/bin/sha256sum /usr/bin/grep /usr/bin/id; do
  [[ -x "$required" && ! -L "$required" ]] || {
    echo "Missing or unsafe OS-owned bootstrap prerequisite: $required" >&2
    exit 1
  }
done
for path in /opt /opt/repocache-cli /usr/local /usr/local/bin /usr/local/libexec; do
  [[ ! -L "$path" ]] || { echo "Unsafe symlinked system path: $path" >&2; exit 1; }
done
# Root must own every ancestor leading to the service-visible lock location.
# A writable /opt would let another UID rename even a root-owned child dir.
for trusted in / /opt; do
  [[ -d "$trusted" && ! -L "$trusted" &&
      "$(stat -c %u "$trusted")" = 0 ]] ||
    { echo "Untrusted system path: $trusted" >&2; exit 1; }
  mode="$(stat -c %a "$trusted")"
  if (( (8#$mode & 0022) != 0 )); then
    echo "Writable trusted ancestor: $trusted" >&2
    exit 1
  fi
done

if [[ -e /usr/local/bin/repocache || -L /usr/local/bin/repocache ]]; then
  if [[ ! -f /usr/local/bin/repocache || -L /usr/local/bin/repocache ]] ||
      ! grep -Fq 'REPOCACHE ROOTLESS LAUNCHER' /usr/local/bin/repocache; then
    echo "Unmanaged or pre-public launcher detected; in-place migration is unsupported in v0.4.0; refusing overwrite" >&2
    exit 1
  fi
fi
if [[ -e /usr/bin/repocache || -L /usr/bin/repocache ]]; then
  echo "Pre-public /usr/bin/repocache detected; in-place migration to v0.4.0 is unsupported" >&2
  exit 1
fi
if ! id repocache >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /var/lib/repocache \
    --shell /usr/sbin/nologin --no-create-home repocache
fi
[[ "$(id -u repocache)" != "0" ]] || { echo 'Unsafe service identity' >&2; exit 1; }
install -d -o root -g root -m 0755 /opt/repocache-cli
install -d -o repocache -g repocache -m 0700 /opt/repocache-cli/managed
# Trusted, persistent root-owned lock: an unprivileged updater may take a
# read-only exclusive flock but cannot replace the pathname or its inode.
# Never truncate or replace an existing inode during re-bootstrap.

/usr/bin/python3 -I - <<'PY'
import os
import pwd
import stat
from pathlib import Path

parent = Path("/opt/repocache-cli")
directory = parent.stat(follow_symlinks=False)
if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0
        or stat.S_IMODE(directory.st_mode) & 0o022):
    raise SystemExit("Unsafe root-owned updater lock directory")
group = pwd.getpwnam("repocache").pw_gid
rootfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    try:
        fd = os.open(".updater.lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_CLOEXEC | os.O_NOFOLLOW, 0o400, dir_fd=rootfd)
    except FileExistsError:
        pass
    else:
        try:
            os.fchown(fd, 0, group)
            os.fchmod(fd, 0o440)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(rootfd)
    fd = os.open(".updater.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                 dir_fd=rootfd)
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0
                or meta.st_gid != group or meta.st_nlink != 1
                or stat.S_IMODE(meta.st_mode) != 0o440):
            raise SystemExit("Invalid persistent updater lock ownership")
    finally:
        os.close(fd)
finally:
    os.close(rootfd)
PY

install -d -o repocache -g repocache -m 0700 /var/lib/repocache
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0644 "$recovery" /usr/local/libexec/repocache-recover.py
install -o root -g root -m 0755 "$launcher" /usr/local/bin/repocache
echo "Rootless filesystem bootstrap complete. No release has been installed."
echo "Next: independently verify a publisher-signed release and its hash-pinned offline dependencies."
