#!/bin/bash
# Build the CHIMERA Android guest: Android-x86 9.0-r2 (API 28, x86_64, userdebug) as a Xen HVM disk, without the
# interactive installer. Xen boots the ISO's kernel and initrd directly; the disk holds the rest:
#
#   /android-9.0-r2/{ramdisk.img, system/ (a writable directory, as MobSF needs), data/}
#
#   sudo scripts/chimera/mobile/build-android-image.sh [path/to/android-x86_64-9.0-r2.iso]
#
# Output in /var/lib/chimera-mobile: android-kernel, android-initrd.img, android-base.img (raw, one partition) and
# adbkey/adbkey.pub (the only key adbd accepts). first-boot.py then boots it once so Android builds /data, and
# turns it into the golden image (android-golden.qcow2) every analysis starts from.
set -euo pipefail
OUT=/var/lib/chimera-mobile
ISO=${1:-$OUT/downloads/android-x86_64-9.0-r2.iso}
ISO_MD5=e9ba997cede7bf3514d2ba3e624ff767 # SourceForge's published hash of android-x86_64-9.0-r2.iso
MOBSF_IMAGE=${MOBSF_IMAGE:-localhost/chimera-mobsf:4.5.3}
SRC=android-9.0-r2
DISK=$OUT/android-base.img
ISO_MNT=$(mktemp -d /tmp/chimera-android-iso.XXXX)
SFS_MNT=$(mktemp -d /tmp/chimera-android-sfs.XXXX)
SYS_MNT=$(mktemp -d /tmp/chimera-android-sys.XXXX)
DST=$(mktemp -d /tmp/chimera-android-dst.XXXX)
LOOP=

cleanup() {
    for m in "$DST" "$SYS_MNT" "$SFS_MNT" "$ISO_MNT"; do
        umount "$m" 2>/dev/null || true
        rmdir "$m" 2>/dev/null || true
    done
    if [ -n "$LOOP" ]; then losetup -d "$LOOP" 2>/dev/null || true; fi
}
trap cleanup EXIT

echo "$ISO_MD5  $ISO" | md5sum -c --quiet
install -d -m 700 "$OUT"

mount -o loop,ro "$ISO" "$ISO_MNT"
mount -o loop,ro "$ISO_MNT/system.sfs" "$SFS_MNT"
mount -o loop,ro "$SFS_MNT/system.img" "$SYS_MNT"
install -m 644 "$ISO_MNT/kernel" "$OUT/android-kernel"
install -m 644 "$ISO_MNT/initrd.img" "$OUT/android-initrd.img"

truncate -s 0 "$DISK.new"
truncate -s 8G "$DISK.new"
printf 'label: dos\n,,83,*\n' | sfdisk -q "$DISK.new"
LOOP=$(losetup -f --show -P "$DISK.new")
mkfs.ext4 -q -F -L android "${LOOP}p1"
mount "${LOOP}p1" "$DST"
install -d "$DST/$SRC/data"
install -m 644 "$ISO_MNT/ramdisk.img" "$DST/$SRC/ramdisk.img"
cp -a "$SYS_MNT" "$DST/$SRC/system"

# adbd listens on TCP 5555 from boot; MobSF reaches it from the mobile VM on the same bridge.
cat >>"$DST/$SRC/system/build.prop" <<'EOF'

# CHIMERA
service.adb.tcp.port=5555
persist.adb.tcp.port=5555
persist.sys.usb.config=adb
ro.setupwizard.mode=DISABLED
persist.sys.timezone=UTC
EOF

# The adb key MobSF uses (adb's own format, made by the adb in the MobSF image, no network). first-boot.py puts
# the public half into /data/misc/adb/adb_keys, so no on-screen "allow USB debugging" prompt is needed.
if [ ! -f "$OUT/adbkey" ]; then
    KEYDIR=$(mktemp -d /tmp/chimera-adbkey.XXXX)
    chmod 777 "$KEYDIR"
    podman run --rm --network none --entrypoint adb -v "$KEYDIR:/out" "$MOBSF_IMAGE" keygen /out/adbkey >/dev/null
    install -m 600 "$KEYDIR/adbkey" "$OUT/adbkey"
    install -m 644 "$KEYDIR/adbkey.pub" "$OUT/adbkey.pub"
    shred -u "$KEYDIR/adbkey" "$KEYDIR/adbkey.pub"
    rmdir "$KEYDIR"
fi
sync
mv "$DISK.new" "$DISK"
echo "built $DISK; next: first-boot.py"
