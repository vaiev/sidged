#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
#
# build-vm-disk.sh: build static musl release binaries (`sidged`, `sidged-tui`),
# verify zero RFC 8032 test keys are embedded, and package:
#   1. dist/sidged-linux-amd64-musl.tar.gz (portable rootfs overlay bundle)
#   2. dist/sidged-vm-rootfs.ext4          (hardened ext4 VM disk / appliance image,
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
export SIDGED_GIT_SHA="$sha"
export CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-gcc}"

echo "==> Building static musl dist binaries ($target, git $sha)..."
cargo build --manifest-path "$src/runtime/Cargo.toml" \
  --profile dist --locked --target "$target" \
  -p sidged-guard -p sidged-tui

sidged_bin="$src/runtime/target/$target/dist/sidged"
tui_bin="$src/runtime/target/$target/dist/sidged-tui"
[[ -x "$sidged_bin" && -x "$tui_bin" ]] || { echo "missing dist binaries" >&2; exit 1; }

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
  "$rootfs/usr/local/share/sidged/systemd" \
  "$rootfs/usr/local/share/sidged/ui" \
  "$rootfs/etc/systemd/system" \
  "$rootfs/etc/sysusers.d" \
  "$rootfs/etc/tmpfiles.d"
install -d -m 0700 \
  "$rootfs/var/lib/sidged" \
  "$rootfs/var/lib/sidged/scenarios" \
  "$rootfs/var/lib/sidged/audit" \
  "$rootfs/var/lib/sidged/credentials"

cat > "$rootfs/sbin/init" <<'INIT'
#!/bin/sh
# Minimal Sidged VM appliance init for direct Linux kernel boot (e.g. Linux 7.3 + QEMU/KVM).
export PATH=/usr/local/bin:/usr/bin:/bin:/sbin
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t tmpfs -o size=16m,mode=0755 tmpfs /run 2>/dev/null || true
mkdir -p -m 2750 /run/sidged/approval
export SIDGED_LOCAL=1
echo "Sidged Appliance VM booted: $(/usr/local/bin/sidged --version)"
exec /usr/local/bin/sidged --version
INIT
chmod 0755 "$rootfs/sbin/init"

install -m 0555 "$sidged_bin" "$rootfs/usr/local/bin/sidged"
install -m 0555 "$tui_bin" "$rootfs/usr/local/bin/sidged-tui"
install -m 0644 "$src/deploy/systemd/sidged-run@.service" "$rootfs/etc/systemd/system/sidged-run@.service"
install -m 0644 "$src/deploy/systemd/sidged-run@.service.d/egress.conf.example" "$rootfs/usr/local/share/sidged/systemd/egress.conf.example"
install -m 0644 "$src/deploy/systemd/sidged.sysusers.conf" "$rootfs/etc/sysusers.d/sidged.conf"
install -m 0644 "$src/deploy/systemd/sidged.tmpfiles.conf" "$rootfs/etc/tmpfiles.d/sidged.conf"
install -m 0644 "$src/deploy/README-host.md" "$rootfs/usr/local/share/sidged/README-host.md"
install -m 0644 "$src/ui/shell/index.html" "$src/ui/shell/shell.css" "$src/ui/shell/shell.js" "$rootfs/usr/local/share/sidged/ui/"

echo "==> Scanning staged rootfs for RFC 8032 test keys..."
python3 "$src/scripts/check-no-test-keys.py" "$rootfs"

cp -f "$sidged_bin" "$src/$out_dir/sidged"
cp -f "$tui_bin" "$src/$out_dir/sidged-tui"
chmod 0555 "$src/$out_dir/sidged" "$src/$out_dir/sidged-tui"

tarball="$src/$out_dir/sidged-linux-amd64-musl.tar.gz"
tar --sort=name --mtime="@0" --owner=0 --group=0 --numeric-owner \
  -C "$rootfs" -czf "$tarball" .

disk_img="$src/$out_dir/sidged-vm-rootfs.ext4"
rm -f "$disk_img"
/usr/sbin/mke2fs -q -t ext4 -L "sidged-rootfs" -d "$rootfs" -E root_owner=0:0 "$disk_img" 64M

(
  cd "$src/$out_dir"
  sha256sum sidged sidged-tui sidged-linux-amd64-musl.tar.gz sidged-vm-rootfs.ext4 > SHA256SUMS
)

echo "==> Built artifacts in $src/$out_dir:"
cat "$src/$out_dir/SHA256SUMS"
