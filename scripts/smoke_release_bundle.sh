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
test ! -e .git && test ! -e tests
launcher_sha="$(sha256sum scripts/repocache-launcher.sh | cut -d " " -f1)"
recovery_sha="$(sha256sum src/repocache/recovery.py | cut -d " " -f1)"
/bin/bash scripts/bootstrap-rootless.sh --launcher-sha256 "$launcher_sha" --recovery-sha256 "$recovery_sha"
chown -R repocache:repocache .
/usr/sbin/runuser -u repocache -- /bin/bash install.sh
repocache --version | grep -F "${REPOCACHE_VERSION#v}"
repocache status --json >/tmp/status.json
/usr/bin/python3 -c "import json; d=json.load(open(\"/tmp/status.json\")); assert isinstance(d.get(\"repos\"),list)"
# An unsigned artifact and checksum must not authorize an upgrade.
if repocache update --version "${REPOCACHE_VERSION#v}" \
  --bundle "/artifacts/repocache-$REPOCACHE_VERSION.tar.gz" \
  --checksum "/artifacts/repocache-$REPOCACHE_VERSION.tar.gz.sha256" \
  --json >/tmp/unsigned.json; then
  echo "Unsigned upgrade unexpectedly accepted" >&2
  exit 1
fi
/usr/sbin/runuser -u repocache -- /opt/repocache-cli/managed/current/bin/python -I /tmp/smoke_tui.py
/bin/bash client/install.sh --server https://cache.example.org
repocache-client --json repos list >/tmp/client-repos.json
/usr/bin/python3 -c "import json; assert isinstance(json.load(open(\"/tmp/client-repos.json\"))[\"repositories\"],list)"
echo "PASS: disposable native $REPOCACHE_VERSION smoke"
'
