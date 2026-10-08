#!/usr/bin/env bash
# Construct a deterministic, inert experiment guest using distro busybox-static.
# No downloaded guest images, guest disk, networking, or arbitrary guest payloads.
set -Eeuo pipefail
umask 022
[[ "$EUID" == 0 ]] || { echo "Root needed to create the console device node" >&2; exit 1; }
busybox="$(command -v busybox)"
[[ -x "$busybox" ]] || { echo "busybox-static is required" >&2; exit 1; }
command -v cpio >/dev/null || { echo "cpio is required" >&2; exit 1; }

destination="/usr/local/lib/slipcage/experiment-v1.cpio.gz"
work="$(mktemp -d)"
temporary=""
cleanup() {
  rm -rf -- "$work"
  if [[ -n "$temporary" ]]; then rm -f -- "$temporary"; fi
}
trap cleanup EXIT

mkdir -p "$work/root/bin" "$work/root/dev"
cp -- "$busybox" "$work/root/bin/busybox"
chmod 0755 "$work/root/bin/busybox"
ln -s busybox "$work/root/bin/sh"
mknod -m 0600 "$work/root/dev/console" c 5 1
cat > "$work/root/init" <<'GUEST_INIT'
#!/bin/sh
# Fixed, harmless arithmetic and SHA-256 known-answer check. No outside inputs.
set -eu
n=1
total=0
squares=0
while [ "$n" -le 1000 ]; do
    total=$((total + n))
    squares=$((squares + n * n))
    n=$((n + 1))
done
if [ "$total" -ne 500500 ] || [ "$squares" -ne 333833500 ]; then
    echo SLIPCAGE_EXPERIMENT_V1_ARITHMETIC_FAIL > /dev/console
    exec /bin/busybox poweroff -f
fi
actual="$(printf abc | /bin/busybox sha256sum)"
expected="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -"
if [ "$actual" != "$expected" ]; then
    echo SLIPCAGE_EXPERIMENT_V1_SHA256_FAIL > /dev/console
    exec /bin/busybox poweroff -f
fi
echo SLIPCAGE_EXPERIMENT_V1_SUM=500500 > /dev/console
echo SLIPCAGE_EXPERIMENT_V1_SQUARES=333833500 > /dev/console
echo SLIPCAGE_EXPERIMENT_V1_SHA256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad > /dev/console
echo SLIPCAGE_EXPERIMENT_V1_OK > /dev/console
exec /bin/busybox poweroff -f
GUEST_INIT
chmod 0755 "$work/root/init"
temporary="$(mktemp /usr/local/lib/slipcage/.experiment-v1.XXXXXXXX)"
(
  cd "$work/root"
  find . -print0 | LC_ALL=C sort -z | cpio --null -o --format=newc --quiet | gzip -n > "$temporary"
)
chmod 0644 "$temporary"
mv -f -- "$temporary" "$destination"
temporary=""
echo "Built fixed arithmetic and SHA-256 experiment guest (no network or disks)"
