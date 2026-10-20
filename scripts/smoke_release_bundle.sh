#!/usr/bin/env bash
# Isolated release-bundle smoke test; never use on a production host.
set -Eeuo pipefail
if [[ $# -ne 3 || ! "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Usage: smoke_release_bundle.sh vX.Y.Z debian13|almalinux10 DIR" >&2
  exit 2
fi
version="$1"
case "$2" in
  debian13) image="debian:13-slim"; python="3.13";;
  almalinux10) image="almalinux:10"; python="3.12";;
  *) echo "Unsupported target: $2" >&2; exit 2;;
esac
work="$(realpath "$3")"
archive="repocache-$version.tar.gz"
test -f "$work/$archive" && test -f "$work/$archive.sha256"
(cd "$work" && sha256sum -c "$archive.sha256")
suite="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker run --rm --pull=always \
  --mount "type=bind,source=$work,target=/artifacts,readonly" \
  --mount "type=bind,source=$suite/smoke_tui.py,target=/tmp/smoke_tui.py,readonly" \
  -e "REPOCACHE_VERSION=$version" -e "REPOCACHE_PYTHON=$python" \
  "$image" /bin/sh -eu -c '
case "$(cat /etc/os-release)" in
  *"ID=debian"*)
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      python3 python3-venv python3-pip util-linux ca-certificates
    ;;
  *)
    dnf -y -q install python3 python3-pip util-linux shadow-utils ca-certificates
    ;;
esac
/usr/bin/python3 -c "import os,sys; assert sys.version_info[:2] == tuple(map(int,os.environ[\"REPOCACHE_PYTHON\"].split(\".\")))"
cd /artifacts
sha256sum -c "repocache-$REPOCACHE_VERSION.tar.gz.sha256"
mkdir -p /tmp/repocache-smoke && cd /tmp/repocache-smoke
tar -xzf "/artifacts/repocache-$REPOCACHE_VERSION.tar.gz"
cd "repocache-$REPOCACHE_VERSION"
test -f LICENSE && test -f src/repocache/recovery.py
test -f docs/PRODUCTION_EXISTING_NGINX.md
test ! -e .git && test ! -e tests
# Test the actual OS-native interpreter and reject unsupported fixture pairs.
# Everything below runs inside the disposable native Docker image.
/usr/bin/python3 -I platform_check.py
/usr/bin/python3 - <<PY
import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("native_preflight", "platform_check.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.validate(Path("/etc/os-release").read_text(encoding="utf-8"),
                sys.version_info[:2])
cases = (
    ("ID=debian\nVERSION_ID=12\n", (3, 13)),
    ("ID=almalinux\nVERSION_ID=9\n", (3, 12)),
    ("ID=debian\nVERSION_ID=13\n", (3, 12)),
    ("ID=almalinux\nVERSION_ID=10\n", (3, 13)),
    ("ID=ubuntu\nVERSION_ID=24.04\n", (3, 12)),
)
for descriptor, version_tuple in cases:
    try:
        module.validate(descriptor, version_tuple)
    except module.PlatformError:
        continue
    raise AssertionError("Unsupported OS/native Python pair accepted")
print("PASS: native OS/Python preflight and five unsupported platform pairs")
PY
# Invalid client setup must fail before creating global launchers or state.
if /bin/bash client/install.sh --server http://not-https.invalid > /tmp/rejected-client-server.log 2>&1; then
  echo "Invalid client server unexpectedly accepted" >&2
  exit 1
fi
test ! -e /opt/repocache-client
test ! -e /etc/repocache-client
test ! -e /usr/local/bin/repocache-client
echo "PASS: invalid native client preflight refused before writing managed state"
launcher_sha="$(sha256sum scripts/repocache-launcher.sh | cut -d " " -f1)"
recovery_sha="$(sha256sum src/repocache/recovery.py | cut -d " " -f1)"
/bin/bash scripts/bootstrap-rootless.sh --launcher-sha256 "$launcher_sha" --recovery-sha256 "$recovery_sha"
# The service UID must never unlink or replace this root-owned inode.
lock=/opt/repocache-cli/.updater.lock
test "$(stat -c %u "$lock")" = 0
test "$(stat -c %a "$lock")" = 440
test "$(stat -c %h "$lock")" = 1
inode_before="$(stat -c %d:%i "$lock")"
if /usr/sbin/runuser -u repocache -- rm -f "$lock"; then
  echo "Service UID replaced the trusted update lock" >&2
  exit 1
fi
test "$(stat -c %d:%i "$lock")" = "$inode_before"
/usr/sbin/runuser -u repocache -- /usr/bin/python3 -I -c '\''import os,fcntl
fd=os.open("/opt/repocache-cli/.updater.lock",os.O_RDONLY|os.O_NOFOLLOW)
fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
fcntl.flock(fd,fcntl.LOCK_UN)
os.close(fd)
'\''
# A second root bootstrap must retain the existing inode.
/bin/bash scripts/bootstrap-rootless.sh --launcher-sha256 "$launcher_sha" --recovery-sha256 "$recovery_sha"
test "$(stat -c %d:%i "$lock")" = "$inode_before"

# The trusted recovery coordinator must refuse owner, group and mode drift
# before accessing managed state. Mutations are confined to this disposable
# image and reset immediately; they are never applied to a real host.
probe_lock() {
  /usr/sbin/runuser -u repocache -- /usr/bin/python3 -I \
    /usr/local/libexec/repocache-recover.py > /tmp/lock-probe.log 2>&1
}
refuse_lock() {
  if probe_lock; then
    echo "Tampered updater lock was accepted: $1" >&2
    exit 1
  fi
  grep -F "Recovery refused:" /tmp/lock-probe.log >/dev/null || {
    cat /tmp/lock-probe.log >&2
    exit 1
  }
  echo "PASS: tampered updater lock refused ($1)"
}
probe_lock

chown repocache:repocache "$lock"
refuse_lock "wrong owner"
chown root:repocache "$lock"

chown root:root "$lock"
refuse_lock "wrong group"
chown root:repocache "$lock"

chmod 0660 "$lock"
refuse_lock "writable inode"
chmod 0440 "$lock"

lock_parent_mode="$(stat -c %a /opt/repocache-cli)"
chmod 0777 /opt/repocache-cli
refuse_lock "writable lock parent"
chmod "$lock_parent_mode" /opt/repocache-cli

opt_mode="$(stat -c %a /opt)"
chmod 0777 /opt
refuse_lock "writable system ancestor"
chmod "$opt_mode" /opt

test "$(stat -c %d:%i "$lock")" = "$inode_before"
probe_lock
echo "PASS: root-owned updater lock survives negative ownership and path probes"

# First-public releases must not distribute the unsupported historical migrator.
test ! -e scripts/migrate_v030.py

# Source-only v0.4.0 installs are deliberately forbidden: the audited
# release path must use independently authenticated offline dependencies.
chown -R repocache:repocache .
if /usr/sbin/runuser -u repocache -- /bin/bash install.sh > /tmp/rejected-source.log 2>&1; then
    echo "Unsigned source-only installation unexpectedly succeeded." >&2
    exit 1
fi
grep -F "authenticated, hash-pinned offline release dependencies" /tmp/rejected-source.log
test ! -e /opt/repocache-cli/managed/current
# Independently exercise the stand-alone client without configuring repositories.
/usr/bin/python3 -m py_compile client/repocache_client.py src/repocache/upgrade.py
/bin/bash client/install.sh --server https://cache.example.org
repocache-client --json repos list > /tmp/client-repos.json
/usr/local/bin/repocache-client check --help > /dev/null
/usr/local/bin/repocache-client repos submit --help > /dev/null
/usr/local/bin/repocache-client repos sync --help > /dev/null
if /usr/local/bin/repocache-client repos sync --apply > /tmp/client-apply-rejected.log 2>&1; then
  echo "Unsafe client source rewrite unexpectedly accepted" >&2
  exit 1
fi
echo "PASS: installed client command contract and sync --apply refusal"
/usr/bin/python3 -c "import json; assert isinstance(json.load(open(\"/tmp/client-repos.json\"))[\"repositories\"],list)"

echo "PASS: disposable native $REPOCACHE_VERSION bundle layout, unsigned-source refusal and client smoke"
'
