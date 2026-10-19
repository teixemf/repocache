#!/usr/bin/env bash
set -Eeuo pipefail
case "$1" in debian:trixie-slim|almalinux:10) image="$1";; *) exit 2;; esac
repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
chmod 0755 "$work"
mkdir -m 0777 "$work/artifacts"
tag="repocache-deps-$RANDOM"
# Privilege is used only for cleanup of the isolated runner-owned test directory.
# No downloaded package, source hook or Python executes as root.
trap 'docker image rm -f "$tag" >/dev/null 2>&1 || :; sudo rm -rf -- "$work"' EXIT
cat > "$work/Dockerfile" <<'EOF'
ARG OS_IMAGE=debian:trixie-slim
FROM $OS_IMAGE
RUN if command -v apt-get >/dev/null 2>&1; then \
      apt-get update -qq && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        python3 python3-venv python3-pip python3-setuptools python3-wheel ca-certificates; \
    else \
      dnf -y -q install python3 python3-pip python3-devel python3-setuptools python3-wheel ca-certificates; \
    fi
USER 10001:10001
WORKDIR /tmp
EOF
docker build --pull --build-arg "OS_IMAGE=$image" -t "$tag" "$work"
docker run --rm \
  --mount "type=bind,source=$repo,target=/src,readonly" \
  --mount "type=bind,source=$work/artifacts,target=/artifacts" \
  "$tag" /usr/bin/python3 /src/scripts/ci_offline_wheels.py build
docker run --rm --network none \
  --mount "type=bind,source=$repo,target=/src,readonly" \
  --mount "type=bind,source=$work/artifacts,target=/artifacts,readonly" \
  "$tag" /usr/bin/env -i PATH=/usr/bin:/bin HOME=/tmp PYTHONPATH=/src/src \
    /usr/bin/python3 /src/scripts/ci_offline_wheels.py verify
# Negative supply-chain test: a changed build-backend hash must fail
# before the application build hook can execute.
mkdir -m 0777 "$work/poisoned"
if docker run --rm \
  --mount "type=bind,source=$repo,target=/src,readonly" \
  --mount "type=bind,source=$work/poisoned,target=/artifacts" \
  "$tag" /usr/bin/python3 /src/scripts/ci_offline_wheels.py \
  build --simulate-poisoned-backend > "$work/poisoned.log" 2>&1; then
  echo "ERROR: poisoned build-tool hash was accepted" >&2
  exit 1
fi
if ! grep -Fq 'Build backend dependency SHA-256 mismatch' "$work/poisoned.log"; then
  tail -35 "$work/poisoned.log" >&2
  echo "ERROR: poisoned-build test failed for an unrelated reason" >&2
  exit 1
fi
echo "PASS: hash-mutated build backend refused before source execution ($image)"
echo "PASS: native offline wheelchain $image"
