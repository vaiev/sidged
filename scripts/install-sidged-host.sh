#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
#
# install-sidged-host.sh: build and install Sidged on a Debian 13 or
# Ubuntu 24.04 host (turnkey WP c). Run it from a checkout as your admin user
# (not as root); privileged steps use sudo.
#
# What it does:
#   1. checks the distribution; installs only build dependencies
#      (build-essential pkg-config git ca-certificates, and the distro rustup
#      package unless a cargo >= 1.89 is already installed);
#   2. builds `sidged` with the toolchain pinned in rust-toolchain.toml
#      (cargo build --profile dist --locked) as the invoking user;
#   3. installs /usr/local/bin/sidged (0755 root:root);
#   4. creates the system users sidged (Core) and sidged-approver (0004 R9c)
#      via sysusers.d, and the approval directory via tmpfiles.d;
#   5. creates /var/lib/sidged (0700 sidged:sidged) and generates the audit
#      log key as the sidged user with `sidged keygen`;
#   6. installs the hardened oneshot template sidged-run@.service and the
#      egress profile example. Nothing is enabled or started.
#
# What it never does: download and run an installer script, install a
# container engine, open or configure any listener, enable a unit.
#
# Usage: scripts/install-sidged-host.sh [--dry-run]
set -euo pipefail

dry_run=0
case "${1:-}" in
  "") ;;
  --dry-run) dry_run=1 ;;
  *) echo "usage: $0 [--dry-run]" >&2; exit 2 ;;
esac

die() { echo "install-sidged-host: $*" >&2; exit 1; }
run() {
  echo "+ $*"
  if (( ! dry_run )); then "$@"; fi
}

if [[ ${EUID} -eq 0 ]]; then
  die "run this as your admin user, not as root; privileged steps use sudo"
fi

[[ -r /etc/os-release ]] || die "/etc/os-release not found"
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  debian:13 | ubuntu:24.04 | ubuntu:26.04 | ubuntu:26.10) ;;
  *) die "supported: Debian 13, Ubuntu 24.04, Ubuntu 26.04, Ubuntu 26.10 (found ${ID:-?} ${VERSION_ID:-?})" ;;
esac

src=$(cd "$(dirname "$0")/.." && pwd)
[[ -f $src/runtime/Cargo.toml && -f $src/rust-toolchain.toml ]] \
  || die "run from a sidged checkout (runtime/Cargo.toml not found)"

prefix=/usr/local
state=/var/lib/sidged
units=/etc/systemd/system
share=$prefix/share/sidged

# 1. Build dependencies only.
packages=(build-essential pkg-config git ca-certificates)
cargo_ok=0
if command -v cargo >/dev/null; then
  # cargo 1.89 or newer satisfies rust-toolchain.toml without rustup.
  ver=$(cargo --version | sed -nE 's/^cargo ([0-9]+)\.([0-9]+).*/\1 \2/p')
  if [[ -n $ver ]] && read -r major minor <<<"$ver" && (( major > 1 || minor >= 89 )); then
    cargo_ok=1
  fi
fi
if (( ! cargo_ok )) && ! command -v rustup >/dev/null; then
  packages+=(rustup)
fi
run sudo apt-get update
run sudo apt-get install -y --no-install-recommends "${packages[@]}"

# 2. Build as the invoking user. rustup reads rust-toolchain.toml (1.89.0)
#    and verifies what it downloads; no installer script is piped to a shell.
if command -v rustup >/dev/null || (( dry_run )); then
  run rustup show active-toolchain
fi
run cargo build --manifest-path "$src/runtime/Cargo.toml" --profile dist --locked -p sidged-guard -p sidged-tui
bin=$src/runtime/target/dist/sidged
tui_bin=$src/runtime/target/dist/sidged-tui
(( dry_run )) || [[ -x $bin ]] || die "build did not produce $bin"
(( dry_run )) || [[ -x $tui_bin ]] || die "build did not produce $tui_bin"

# 3. Binaries.
run sudo install -D -m 0755 -o root -g root "$bin" "$prefix/bin/sidged"
run sudo install -D -m 0755 -o root -g root "$tui_bin" "$prefix/bin/sidged-tui"

# 4. Users and the approval directory (0004 R9c).
run sudo install -D -m 0644 -o root -g root "$src/deploy/systemd/sidged.sysusers.conf" /etc/sysusers.d/sidged.conf
run sudo systemd-sysusers /etc/sysusers.d/sidged.conf
run sudo install -D -m 0644 -o root -g root "$src/deploy/systemd/sidged.tmpfiles.conf" /etc/tmpfiles.d/sidged.conf
run sudo systemd-tmpfiles --create /etc/tmpfiles.d/sidged.conf

# 5. State directory and the audit log key, generated as the core user.
run sudo install -d -m 0700 -o sidged -g sidged "$state" "$state/scenarios" "$state/audit" "$state/credentials"
if (( ! dry_run )) && sudo test -e "$state/log-key"; then
  echo "log key directory $state/log-key exists; kept"
else
  run sudo -u sidged "$prefix/bin/sidged" keygen "$state/log-key"
fi

# 6. Units: installed, not enabled, not started.
run sudo install -D -m 0644 -o root -g root "$src/deploy/systemd/sidged-run@.service" "$units/sidged-run@.service"
run sudo install -D -m 0644 -o root -g root "$src/deploy/systemd/sidged-run@.service.d/egress.conf.example" "$share/systemd/egress.conf.example"
run sudo install -D -m 0644 -o root -g root "$src/deploy/README-host.md" "$share/README-host.md"
run sudo systemctl daemon-reload

if (( dry_run )); then
  echo "dry run: nothing was changed"
  exit 0
fi
cat <<EOF

Installed. Nothing is enabled or running, and nothing listens.
Next steps (see $share/README-host.md):
  - put a scenario into $state/scenarios/<name>/ and grant keys into
    $state/keys/ (sudo -u sidged $prefix/bin/sidged keygen $state/keys);
  - run once in local mode:  sudo systemctl start sidged-run@<name>
  - verify the audit log:    sidged log verify $state/audit/<name>.log --public <hex>
EOF
