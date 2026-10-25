#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
# install_check.sh: static checks for the host install script and the systemd
# files (turnkey WP c). Run by `cargo test` (vaikor-guard/tests/deploy_scripts.rs)
# and standalone: bash scripts/tests/install_check.sh
#
# Fails on: a wildcard bind, a curl/wget download piped into a shell, a unit
# that runs as the login user, a missing hardening directive, an enable/start,
# a container engine or SQLite/OpenSSL dev package, an [Install] section, a
# URL in the script, and a bash syntax error. Runs systemd-analyze verify on
# a copy of the unit when systemd-analyze is installed (skipped otherwise).
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
script=$root/scripts/install-vaikor-host.sh
unit=$root/deploy/systemd/vaikor-run@.service
egress=$root/deploy/systemd/vaikor-run@.service.d/egress.conf.example
sysusers=$root/deploy/systemd/vaikor.sysusers.conf
tmpfiles=$root/deploy/systemd/vaikor.tmpfiles.conf

fail=0
bad() { echo "install_check: FAIL: $*" >&2; fail=1; }

for f in "$script" "$unit" "$egress" "$sysusers" "$tmpfiles"; do
  [[ -f $f ]] || { bad "missing $f"; }
done
if (( fail )); then exit 1; fi

bash -n "$script" || bad "bash -n $script"
if command -v shellcheck >/dev/null; then
  shellcheck "$script" "$0" || bad "shellcheck"
else
  echo "install_check: shellcheck not installed; skipped"
fi

all=("$script" "$unit" "$egress" "$sysusers" "$tmpfiles")
# Wildcard or public listeners, HTTP serving.
if grep -nE '0\.0\.0\.0|\[::\]|--bind|vaikor serve|ListenStream|ListenDatagram' "${all[@]}"; then
  bad "wildcard bind, listener or serve"
fi
# Downloads piped into a shell.
if grep -nE '(curl|wget)[^|#]*\|[[:space:]]*(sudo[[:space:]]+)?([a-z]*sh)\b' "${all[@]}"; then
  bad "download piped into a shell"
fi
if grep -nE '\b(curl|wget)\b' "$script"; then
  bad "script downloads with curl/wget"
fi
# No URLs at all in the script (no remote hosts, no installers).
if grep -nE 'https?://' "$script"; then
  bad "URL in the install script"
fi
# Never the login user, never DynamicUser (R9c needs a stable core uid).
if grep -nE '^User=\$|^User=\$\{?USER|DynamicUser=yes' "$unit" "$egress"; then
  bad "unit runs as the login user or DynamicUser"
fi
grep -qx 'User=vaikor' "$unit" || bad "unit must run as User=vaikor"
grep -qx 'Type=oneshot' "$unit" || bad "unit must be Type=oneshot"
if grep -nE '^\[Install\]' "$unit" "$egress"; then
  bad "unit has an [Install] section (must not be enableable by default)"
fi
# No enable/start, no container engine, no unneeded dev packages.
# The closing `cat <<EOF` block only prints hints for the operator.
if sed '/<<EOF$/,/^EOF$/d' "$script" \
  | grep -nE 'systemctl[[:space:]]+(--now[[:space:]]+)?(enable|start|restart)|--now'; then
  bad "script enables or starts a unit"
fi
if grep -nE '\b(podman|docker|libsqlite3-dev|libssl-dev)\b' "$script" "$unit" "$egress"; then
  bad "container engine or SQLite/OpenSSL dev package"
fi
if grep -nE 'rustup-init|sh\.rustup\.rs' "$script"; then
  bad "rustup installer script"
fi
# Hardening directives (0010 R3/R4; Inv. 2, 8).
for d in \
  'NoNewPrivileges=yes' 'CapabilityBoundingSet=' 'AmbientCapabilities=' \
  'ProtectSystem=strict' 'ProtectHome=yes' 'PrivateTmp=yes' 'PrivateDevices=yes' \
  'PrivateNetwork=yes' 'RestrictAddressFamilies=AF_UNIX' 'IPAddressDeny=any' \
  'RestrictNamespaces=yes' 'RestrictSUIDSGID=yes' 'LockPersonality=yes' \
  'MemoryDenyWriteExecute=yes' 'SystemCallArchitectures=native' \
  'SystemCallFilter=@system-service' 'ProtectKernelTunables=yes' \
  'ProtectKernelModules=yes' 'ProtectKernelLogs=yes' 'ProtectControlGroups=yes' \
  'ProtectClock=yes' 'ProtectHostname=yes' 'RemoveIPC=yes' 'UMask=0077' \
  'StateDirectory=vaikor' 'StateDirectoryMode=0700' 'Environment=VAIKOR_LOCAL=1'; do
  grep -qx "$d" "$unit" || bad "unit lacks $d"
done
grep -qE '^ExecStart=/usr/local/bin/vaikor guard .* --local( |$)' "$unit" \
  || bad "default ExecStart must be a local guard run"
# The egress profile opens only what egress needs and keeps the rest.
grep -qx 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' "$egress" \
  || bad "egress profile must add only AF_INET/AF_INET6"
grep -qx 'PrivateNetwork=no' "$egress" || bad "egress profile must lift PrivateNetwork"
grep -qx 'ReadWritePaths=/run/vaikor/approval' "$egress" || bad "egress profile needs the approval dir"
if grep -nE -- '--local( |$)|VAIKOR_LOCAL=1' "$egress" | grep -v '^[0-9]*:#'; then
  bad "egress profile still sets local mode"
fi
# 0004 R9c provisioning.
grep -qE '^d /run/vaikor/approval 2750 vaikor vaikor-approver -' "$tmpfiles" \
  || bad "tmpfiles must create /run/vaikor/approval 2750 vaikor:vaikor-approver"
grep -qE '^u vaikor ' "$sysusers" || bad "sysusers must create the core user vaikor"
grep -qE '^u vaikor-approver ' "$sysusers" || bad "sysusers must create vaikor-approver"
if grep -nE '^m (vaikor-approver vaikor|vaikor vaikor-approver)\b' "$sysusers"; then
  bad "core and approver must not share a group"
fi
# The script refuses root, checks the distro and never writes 0.0.0.0 configs.
grep -q 'EUID' "$script" || bad "script must refuse to run as root"
grep -q '/etc/os-release' "$script" || bad "script must check the distribution"

# Credential storage is separate from mutable scenario state.
# shellcheck disable=SC2016
grep -Fq '"$state/credentials"' "$script" || bad "missing credential directory"
grep -Fq '/var/lib/vaikor/credentials/' "$root/deploy/README-host.md" || bad "document credential location"
grep -q 'nologin system account' "$root/deploy/README-host.md" || bad "document approver nologin account"

# systemd-analyze verify on a copy whose ExecStart points at /bin/true.
if command -v systemd-analyze >/dev/null; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  sed 's#^ExecStart=/usr/local/bin/vaikor #ExecStart=/bin/true #' "$unit" > "$tmp/vaikor-run@check.service"
  if ! out=$(systemd-analyze verify "$tmp/vaikor-run@check.service" 2>&1); then
    echo "$out" >&2
    bad "systemd-analyze verify"
  elif grep -iE 'unknown (key|section)|invalid|failed to parse' <<<"$out"; then
    bad "systemd-analyze verify reported problems"
  fi
else
  echo "install_check: systemd-analyze not installed; skipped"
fi

if (( fail )); then exit 1; fi
echo "install_check: OK"
