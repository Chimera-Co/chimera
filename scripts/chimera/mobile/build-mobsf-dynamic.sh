#!/bin/bash
# Build localhost/chimera-mobsf-dynamic:4.5.3 from the static MobSF image and the verified frida-server download.
#   sudo scripts/chimera/mobile/build-mobsf-dynamic.sh
# Then scripts/chimera/static-vm/build-image.sh --images copies it into the VM image store.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
XZ=/var/lib/chimera-mobile/downloads/frida-server-17.18.0-android-x86_64.xz
XZ_SHA256=c2bd76f2a26330f8d0c104d104cec7fe91a6f607dc930902ffeed68ba1a37b7b # GitHub's asset digest
echo "$XZ_SHA256  $XZ" | sha256sum -c --quiet
CTX=$(mktemp -d /tmp/chimera-mobsf-dyn.XXXX)
trap 'rm -rf "$CTX"' EXIT
xz -dc "$XZ" >"$CTX/frida-server-17.18.0-android-x86_64"
chmod 755 "$CTX/frida-server-17.18.0-android-x86_64"
cp "$HERE/Containerfile" "$CTX/Containerfile"
# --network=host: a plain podman build adds a netavark FORWARD rule above CHIMERA_GUARD (see the build guide).
podman build --network=host -t localhost/chimera-mobsf-dynamic:4.5.3 "$CTX"
