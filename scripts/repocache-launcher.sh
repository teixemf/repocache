#!/bin/sh
# Trusted launcher installed by the privileged bootstrap, not by the package.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

BASE=/opt/repocache-cli
if [ -e "$BASE/.migration-v030.json" ] || [ -L "$BASE/.migration-v030.json" ]; then
    printf '%s\n' 'REPOCACHE migration requires recovery before execution.' >&2
    exit 70
fi

uid=$(/usr/bin/id -u)
if [ "$uid" -eq 0 ]; then
    # Do not execute the managed package as root.
    exec /usr/sbin/runuser -u repocache -- /usr/bin/env -i \
        HOME=/var/lib/repocache PATH=/usr/local/bin:/usr/bin:/bin \
        LANG=C.UTF-8 PYTHONNOUSERSITE=1 PYTHONSAFEPATH=1 \
        /usr/local/bin/repocache "$@"
fi

if [ "$(/usr/bin/id -un)" != repocache ]; then
    echo 'Run via sudo or as the repocache service account.' >&2
    exit 77
fi

# Invoke only the separately installed, root-owned recovery coordinator.
# Fail closed if recovery is not possible.
if ! /usr/bin/env -i HOME=/var/lib/repocache \
        PATH=/usr/local/bin:/usr/bin:/bin LANG=C.UTF-8 \
        PYTHONNOUSERSITE=1 PYTHONSAFEPATH=1 \
        /usr/bin/python3 -I /usr/local/libexec/repocache-recover.py >/dev/null; then
    echo 'REPOCACHE recovery coordinator refused launch.' >&2
    exit 70
fi

exec /usr/bin/env -i HOME=/var/lib/repocache \
    PATH=/usr/local/bin:/usr/bin:/bin LANG=C.UTF-8 \
    PYTHONNOUSERSITE=1 PYTHONSAFEPATH=1 \
    "$BASE/managed/current/bin/repocache" "$@"
