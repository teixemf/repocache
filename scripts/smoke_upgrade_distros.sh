#!/usr/bin/env bash
# Run only in disposable GitHub Actions containers; never on production hosts.
set -Eeuo pipefail
case "${1:-}" in
  debian:trixie-slim|almalinux:10) image="$1" ;;
  *) echo "Unsupported disposable Linux image" >&2; exit 2 ;;
esac
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
tag="repocache-wheel-rehearsal-$RANDOM"
trap 'docker image rm -f "$tag" >/dev/null 2>&1 || :; sudo rm -rf -- "$work"' EXIT
mkdir -p "$work/artifacts" "$work/legacy" "$work/next"
# This is a synthetic *test-only* old-version fixture generated from the
# current reviewed code. It is NOT the historical v0.3.0 release.
for target in "$work/legacy" "$work/next"; do
  cp -a "$repo/README.md" "$repo/CHANGELOG.md" "$repo/LICENSE" "$repo/pyproject.toml" \
    "$repo/install.sh" "$repo/platform_check.py" "$repo/release-policy.json" \
    "$repo/src" "$repo/client" "$repo/scripts" "$repo/deps" "$target/"
done
python3 - "$work/legacy" <<'PY'
import json
import sys
from pathlib import Path
root = Path(sys.argv[1])
for filename in ("pyproject.toml", "src/repocache/__init__.py"):
    path = root / filename
    data = path.read_text()
    count = data.count("0.4.0")
    assert count == 1, (filename, count)
    path.write_text(data.replace("0.4.0", "0.3.0"))
policy = root / "release-policy.json"
data = json.loads(policy.read_text())
assert data["version"] == "0.4.0"
data["version"] = "0.3.0"
policy.write_text(json.dumps(data, indent=2) + "\n")
PY
python3 "$work/legacy/scripts/build_release.py" --tag v0.3.0 --output "$work/artifacts"
# The target version uses the actual public v0.4.0 sources.

python3 "$work/next/scripts/build_release.py" --tag v0.4.0 --output "$work/artifacts"
(cd "$work/artifacts" && sha256sum -c repocache-v0.3.0.tar.gz.sha256 &&
 sha256sum -c repocache-v0.4.0.tar.gz.sha256)
# Build the real, hash-pinned, platform-native source wheels before
# signing. They are not installed from PyPI by the target updater.
mkdir -p "$work/builder"
cat > "$work/builder/Dockerfile" <<'DOCKERFILE'
ARG BASE_IMAGE=debian:trixie-slim
FROM $BASE_IMAGE
RUN if command -v apt-get >/dev/null 2>&1; then \
      apt-get update -qq && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        python3 python3-venv python3-pip python3-setuptools python3-wheel ca-certificates openssl util-linux passwd; \
    else \
      dnf -y -q install python3 python3-pip python3-devel python3-setuptools python3-wheel ca-certificates openssl util-linux util-linux-user shadow-utils; \
    fi
USER 10001:10001
WORKDIR /tmp
DOCKERFILE
docker build --pull --build-arg "BASE_IMAGE=$image" -t "$tag" "$work/builder"
for version in 0.3.0 0.4.0; do
  mkdir -m 0777 "$work/wheel-$version"
  if [[ "$version" == 0.3.0 ]]; then source="$work/legacy"; else source="$work/next"; fi
  docker run --rm \
    --mount "type=bind,source=$source,target=/src,readonly" \
    --mount "type=bind,source=$work/wheel-$version,target=/artifacts" \
    "$tag" /usr/bin/python3 /src/scripts/ci_offline_wheels.py build --release
  cp "$work/wheel-$version/repocache-v$version.tar.gz.wheelhouse.tar.gz" \
    "$work/artifacts/repocache-v$version.tar.gz.wheelhouse.tar.gz"
done
# These ephemeral CI keys do not represent actual publisher custody (#54).
# The private key never enters either disposable target container or release.
openssl genpkey -algorithm Ed25519 -out "$work/ephemeral-private.pem"
chmod 0600 "$work/ephemeral-private.pem"
openssl pkey -in "$work/ephemeral-private.pem" -pubout -out "$work/ephemeral-public.pem"
for version in 0.3.0 0.4.0; do
  python3 "$repo/scripts/sign_release.py" \
    --bundle "$work/artifacts/repocache-v${version}.tar.gz" \
    --private-key "$work/ephemeral-private.pem" \
    --key-id "ci-fixture" --commit "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    --expires-at "$(date -u -d '+24 hours' +%s)" \
    --wheelhouse-sha256 "$(sha256sum "$work/artifacts/repocache-v$version.tar.gz.wheelhouse.tar.gz" | cut -d' ' -f1)"
done
echo "Running isolated upgrade/rollback exercise inside $image"
# All Python install/upgrade operations below run in a DIFFERENT target
# process with the entire network namespace disabled. OS prerequisites were
# installed in the disposable image build before any bundle was trusted.
docker run --rm --network none --user 0:0 \
  --mount "type=bind,source=$work/artifacts,target=/artifacts,readonly" \
  --mount "type=bind,source=$work/ephemeral-public.pem,target=/tmp/ci-publisher.pem,readonly" \
  --mount "type=bind,source=$repo/scripts/upgrade_e2e.py,target=/tmp/upgrade_e2e.py,readonly" \
  "$tag" /usr/bin/python3 /tmp/upgrade_e2e.py
