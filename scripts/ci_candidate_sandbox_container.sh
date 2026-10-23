#!/usr/bin/env bash
# Disposable native USERSPACE Bubblewrap probes on GitHub-hosted runner kernel.
# No --privileged, no production hosts, no external network inside candidate.
set -Eeuo pipefail
if [[ $# != 1 ]]; then
  echo "Usage: $0 debian13|almalinux10" >&2
  exit 2
fi
case "$1" in
  debian13) image="debian:13-slim";;
  almalinux10) image="almalinux:10";;
  *) echo "Unsupported distro $1" >&2; exit 2;;
esac
repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
printf 'OS userspace: %s\nKernel: GitHub runner (NOT native distro kernel)\n' "$image"
# GitHub Docker's user namespace syscalls must be exposed. This is scoped
# to a disposable test-only container, not a REPOCACHE production host.
# Never use --privileged, host networking or the Docker socket. Test-only
# CAP_NET_ADMIN is scoped to this disposable container network namespace
# to let bwrap set up loopback; it does not grant host network access.
docker run --rm --pull=always \
  --cap-add NET_ADMIN \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  --mount "type=bind,source=$repo,target=/source,readonly" \
  "$image" /bin/sh -eu -c '
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
case "$(sed -n "s/^ID=//p" /etc/os-release | tr -d "\"")" in
  debian)
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      bubblewrap python3 python3-venv ca-certificates util-linux passwd
    ;;
  almalinux)
    dnf -y -q install bubblewrap python3 python3-pip shadow-utils util-linux ca-certificates
    dnf -y -q update bubblewrap
    ;;
  *) echo "Unexpected Linux distribution" >&2; exit 1;;
esac

echo "Installed OS package evidence:"
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W bubblewrap
else
  rpm -q bubblewrap
fi
stat -c "bubblewrap path=%n owner=%u mode=%a" /usr/bin/bwrap
id repocache >/dev/null 2>&1 ||
  useradd --system --user-group --home-dir /var/lib/repocache \
          --shell /usr/sbin/nologin --no-create-home repocache
mkdir -p /opt/repocache-cli/managed /var/lib/repocache
chown repocache:repocache /opt/repocache-cli/managed /var/lib/repocache
chmod 0700 /opt/repocache-cli/managed /var/lib/repocache
printf "verified-old-release\n" > /opt/repocache-cli/managed/installed.json
printf "isolated secret\n" > /var/lib/repocache/ci-private-secret
chown repocache:repocache /opt/repocache-cli/managed/installed.json \
                           /var/lib/repocache/ci-private-secret
chmod 0600 /opt/repocache-cli/managed/installed.json \
           /var/lib/repocache/ci-private-secret
ln -s /opt/repocache-cli/managed/legacy-in-use \
      /opt/repocache-cli/managed/current
exec runuser -u repocache -- /usr/bin/python3 \
     /source/scripts/ci_candidate_sandbox_native.py
'
