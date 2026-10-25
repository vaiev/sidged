#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
#
# build-vm-disk.sh: build static musl release binaries (`vaikor`, `vaikor-tui`),
# verify zero RFC 8032 test keys are embedded, and package:
#   1. dist/vaikor-linux-amd64-musl.tar.gz (portable rootfs overlay bundle)
#   2. dist/vaikor-vm-rootfs.ext4          (hardened ext4 VM disk / appliance image,
#                                           built rootlessly with mke2fs -d)
#   3. dist/SHA256SUMS                     (reproducible artifact digests)
#
# Usage: scripts/build-vm-disk.sh [--out-dir dist]
set -euo pipefail

out_dir="dist"
if [[ "${1:-}" == "--out-dir" ]]; then
  out_dir="${2:?missing directory after --out-dir}"
  shift 2
fi
[[ $# -eq 0 ]] || { echo "usage: $0 [--out-dir <dir>]" >&2; exit 2; }

src=$(cd "$(dirname "$0")/.." && pwd)
export PATH="$HOME/.cargo/bin:$PATH"

target="x86_64-unknown-linux-musl"
sha=$(git -C "$src" rev-parse HEAD)
export VAIKOR_GIT_SHA="$sha"
export CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-gcc}"

echo "==> Building static musl dist binaries ($target, git $sha)..."
cargo build --manifest-path "$src/runtime/Cargo.toml" \
  --profile dist --locked --target "$target" \
  -p vaikor-guard -p vaikor-tui

vaikor_bin="$src/runtime/target/$target/dist/vaikor"
tui_bin="$src/runtime/target/$target/dist/vaikor-tui"
[[ -x "$vaikor_bin" && -x "$tui_bin" ]] || { echo "missing dist binaries" >&2; exit 1; }

mkdir -p "$src/$out_dir"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

rootfs="$stage/rootfs"
install -d -m 0755 \
  "$rootfs/sbin" \
  "$rootfs/proc" \
  "$rootfs/sys" \
  "$rootfs/dev" \
  "$rootfs/run" \
  "$rootfs/usr/local/bin" \
  "$rootfs/usr/local/share/vaikor/systemd" \
  "$rootfs/usr/local/share/vaikor/ui" \
  "$rootfs/etc/systemd/system" \
  "$rootfs/etc/sysusers.d" \
  "$rootfs/etc/tmpfiles.d"
install -d -m 0700 \
  "$rootfs/var/lib/vaikor" \
  "$rootfs/var/lib/vaikor/scenarios" \
  "$rootfs/var/lib/vaikor/audit" \
  "$rootfs/var/lib/vaikor/credentials"

cat > "$rootfs/sbin/init" <<'INIT'
#!/bin/sh
# Minimal Vaikor VM appliance init for direct Linux kernel boot (e.g. Linux 7.3 + QEMU/KVM).
export PATH=/usr/local/bin:/usr/bin:/bin:/sbin
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t tmpfs -o size=16m,mode=0755 tmpfs /run 2>/dev/null || true
mkdir -p -m 2750 /run/vaikor/approval
export VAIKOR_LOCAL=1
echo "Vaikor Appliance VM booted: $(/usr/local/bin/vaikor --version)"
exec /usr/local/bin/vaikor --version
INIT
chmod 0755 "$rootfs/sbin/init"

install -m 0555 "$vaikor_bin" "$rootfs/usr/local/bin/vaikor"
install -m 0555 "$tui_bin" "$rootfs/usr/local/bin/vaikor-tui"
install -m 0644 "$src/deploy/systemd/vaikor-run@.service" "$rootfs/etc/systemd/system/vaikor-run@.service"
install -m 0644 "$src/deploy/systemd/vaikor-run@.service.d/egress.conf.example" "$rootfs/usr/local/share/vaikor/systemd/egress.conf.example"
install -m 0644 "$src/deploy/systemd/vaikor.sysusers.conf" "$rootfs/etc/sysusers.d/vaikor.conf"
install -m 0644 "$src/deploy/systemd/vaikor.tmpfiles.conf" "$rootfs/etc/tmpfiles.d/vaikor.conf"
install -m 0644 "$src/deploy/README-host.md" "$rootfs/usr/local/share/vaikor/README-host.md"
install -m 0644 "$src/ui/shell/index.html" "$src/ui/shell/shell.css" "$src/ui/shell/shell.js" "$rootfs/usr/local/share/vaikor/ui/"

echo "==> Scanning staged rootfs for RFC 8032 test keys..."
python3 "$src/scripts/check-no-test-keys.py" "$rootfs"

cp -f "$vaikor_bin" "$src/$out_dir/vaikor"
cp -f "$tui_bin" "$src/$out_dir/vaikor-tui"
chmod 0555 "$src/$out_dir/vaikor" "$src/$out_dir/vaikor-tui"

tarball="$src/$out_dir/vaikor-linux-amd64-musl.tar.gz"
tar --sort=name --mtime="@0" --owner=0 --group=0 --numeric-owner \
  -C "$rootfs" -czf "$tarball" .

disk_img="$src/$out_dir/vaikor-vm-rootfs.ext4"
rm -f "$disk_img"
/usr/sbin/mke2fs -q -t ext4 -L "vaikor-rootfs" -d "$rootfs" -E root_owner=0:0 "$disk_img" 64M

(
  cd "$src/$out_dir"
  sha256sum vaikor vaikor-tui vaikor-linux-amd64-musl.tar.gz vaikor-vm-rootfs.ext4 > SHA256SUMS
)

echo "==> Built artifacts in $src/$out_dir:"
cat "$src/$out_dir/SHA256SUMS"
