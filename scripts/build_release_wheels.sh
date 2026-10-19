#!/usr/bin/env bash
# Disposable native-wheel publisher rehearsal; never on production systems.
set -Eeuo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
out="$(realpath -m "$1")"
mkdir -p "$out"
work="$(mktemp -d)"
chmod 0755 "$work"
mkdir -m 0777 "$work/artifacts"
trap 'docker image rm -f "repocache-debian-wheels-$$" "repocache-alma-wheels-$$" >/dev/null 2>&1 || :; sudo rm -rf -- "$work"' EXIT
for image in 'debian:trixie-slim' 'almalinux:10'; do
  if [[ "$image" == 'debian:trixie-slim' ]]; then tag="repocache-debian-wheels-$$"; else tag="repocache-alma-wheels-$$"; fi
  mkdir -p "$work/$tag"
  cat > "$work/$tag/Dockerfile" <<'DOCKERFILE'
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
DOCKERFILE
  docker build --pull --build-arg "OS_IMAGE=$image" -t "$tag" "$work/$tag"
done
# Debian produces a pure Python wheelhouse; Alma verifies the identical archive.
docker run --rm \
  --mount "type=bind,source=$repo,target=/src,readonly" \
  --mount "type=bind,source=$work/artifacts,target=/artifacts" \
  "repocache-debian-wheels-$$" /usr/bin/python3 /src/scripts/ci_offline_wheels.py build --release
for tag in "repocache-debian-wheels-$$" "repocache-alma-wheels-$$"; do
  docker run --rm --network none \
    --mount "type=bind,source=$repo,target=/src,readonly" \
    --mount "type=bind,source=$work/artifacts,target=/artifacts,readonly" \
    "$tag" /usr/bin/env -i PATH=/usr/bin:/bin HOME=/tmp PYTHONPATH=/src/src \
      /usr/bin/python3 /src/scripts/ci_offline_wheels.py verify --release
done
find "$work/artifacts" -maxdepth 1 -type f -name 'repocache-v*.tar.gz.wheelhouse.tar.gz*' \
  -exec cp -- {} "$out/" \;
echo 'PASS: version-bound wheelhouse independently installed without network on both native OS'
