#!/usr/bin/env bash
# Build a minimal inert guest initramfs exclusively from distro busybox-static.
# Run at install time as root; no network, untrusted images, or guest disks.
set -Eeuo pipefail
umask 022
output="/usr/local/lib/slipcage/microguest.cpio.gz"
busybox="$(command -v busybox)"
[[ -x "$busybox" ]] || { echo "busybox-static is required" >&2; exit 1; }
command -v cpio >/dev/null || { echo "cpio is required" >&2; exit 1; }
[[ "$EUID" == 0 ]] || { echo "Must run as root" >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/root/bin" "$work/root/dev"
cp -- "$busybox" "$work/root/bin/busybox"
chmod 0755 "$work/root/bin/busybox"
ln -s busybox "$work/root/bin/sh"
mknod -m 0600 "$work/root/dev/console" c 5 1
cat > "$work/root/init" <<'GUEST_INIT'
#!/bin/sh
echo SLIPCAGE_MICROGUEST_OK > /dev/console
exec /bin/busybox poweroff -f
GUEST_INIT
chmod 0755 "$work/root/init"
tmp="$(mktemp /usr/local/lib/slipcage/.microguest.XXXXXXXX)"
trap 'rm -rf -- "$work"; rm -f -- "$tmp"' EXIT
(
  cd "$work/root"
  find . -print0 | LC_ALL=C sort -z | cpio --null -o --format=newc --quiet | gzip -n > "$tmp"
)
chmod 0644 "$tmp"
mv -f -- "$tmp" "$output"
echo "Built vetted, diskless, networkless Slipcage microguest initramfs"
