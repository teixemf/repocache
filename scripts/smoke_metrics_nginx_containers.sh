#!/usr/bin/env bash
# Ephemeral source-mounted, rootless, network-isolated real NGINX for #14.
set -Eeuo pipefail
case "${1-}" in
  debian:trixie-slim|almalinux:10) os_image="$1" ;;
  *) echo 'Expected debian:trixie-slim or almalinux:10' >&2; exit 2 ;;
esac
repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
tag="repocache-nginx-metrics-${RANDOM}-${RANDOM}"
trap 'docker image rm -f "$tag" >/dev/null 2>&1 || :; rm -rf -- "$work"' EXIT
cat > "$work/Dockerfile" <<'DOCKERFILE'
ARG OS_IMAGE=debian:trixie-slim
FROM ${OS_IMAGE}
RUN if command -v apt-get >/dev/null 2>&1; then \
      apt-get update -qq && \
      DEBIAN_FRONTEND=noninteractive apt-get install -qq -y --no-install-recommends nginx python3 ca-certificates; \
    else \
      dnf -y -q install nginx python3 ca-certificates; \
    fi
USER 10001:10001
WORKDIR /src
DOCKERFILE
docker build --pull --build-arg "OS_IMAGE=$os_image" -t "$tag" "$work"
docker run --rm --network none --read-only \
  --security-opt no-new-privileges --cap-drop ALL --pids-limit 64 \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --mount "type=bind,source=$repo,target=/src,readonly" \
  "$tag" /usr/bin/python3 /src/scripts/ci_metrics_nginx_runtime.py
