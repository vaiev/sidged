#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
#
# open-sidged-app.sh: open the Sidged UI in a Chromium-family browser window
# in app mode (turnkey WP e).
#
# Usage: scripts/open-sidged-app.sh [--print] [URL]
#   (no URL)  opens the local offline shell ui/shell/index.html via file://
#   URL       only http:// + a loopback IP literal (127.x.y.z or [::1]) + an
#             explicit port, with an optional plain path. No hostname (not even
#             localhost: name resolution is not trusted, cf. 0007 R3), no
#             userinfo, no query, no fragment, no percent-encoding. Anything
#             else exits 2.
#   --print   print the browser command instead of starting it.
#
# The temporary profile is removed when the browser process returns.
# Forking launchers (snap/flatpak wrappers) may lose it while the browser runs.
# A successful return within 2 s warns about this possible launcher fork.
# --print uses <temporary-profile-dir> instead of a disposable path.
#
# Nothing here opens a listener; a URL is only useful if something on this
# machine already serves the shell on loopback.
set -euo pipefail

print=0
args=()
for arg in "$@"; do
  case "$arg" in
    --print) print=1 ;;
    *) args+=("$arg") ;;
  esac
done
if (( ${#args[@]} > 1 )); then
  echo "usage: $0 [--print] [URL]" >&2
  exit 2
fi

refuse() { echo "open-sidged-app: refused: $1 (only http://<loopback IP literal>:<port>[/path])" >&2; exit 2; }

# 0007 R3 by analogy: loopback IP literals only.
check_url() {
  local url=$1 addr port rest
  [[ $url =~ ^http://(\[::1\]|[0-9]{1,3}(\.[0-9]{1,3}){3}):([0-9]{1,5})(/[A-Za-z0-9._~/-]*)?$ ]] \
    || refuse "not http:// with a loopback IP literal and a port"
  addr=${BASH_REMATCH[1]}
  port=${BASH_REMATCH[3]}
  rest=${BASH_REMATCH[4]:-}
  if [[ $addr != "[::1]" ]]; then
    local IFS=.
    # shellcheck disable=SC2206
    local octets=($addr)
    [[ ${octets[0]} == 127 ]] || refuse "host is not a loopback address"
    local o
    for o in "${octets[@]}"; do
      if ! [[ $o =~ ^(0|[1-9][0-9]{0,2})$ ]] || (( o > 255 )); then
        refuse "invalid IPv4 literal"
      fi
    done
  fi
  if ! [[ $port =~ ^[1-9][0-9]{0,4}$ ]] || (( port > 65535 )); then
    refuse "port must be 1-65535"
  fi
  [[ $rest != *..* ]] || refuse "path must not contain .."
}

if (( ${#args[@]} == 1 )); then
  url=${args[0]}
  check_url "$url"
else
  shell=$(cd "$(dirname "$0")/.." && pwd)/ui/shell/index.html
  if (( ! print )) && [[ ! -f $shell ]]; then
    echo "open-sidged-app: $shell not found (the offline UI shell)" >&2
    exit 1
  fi
  url=file://$shell
fi

browser=
for candidate in chromium chromium-browser google-chrome google-chrome-stable microsoft-edge; do
  if command -v "$candidate" >/dev/null; then
    browser=$candidate
    break
  fi
done

profile='<temporary-profile-dir>'
if (( ! print )); then
  profile=$(mktemp -d)
fi
trap 'if (( ! print )); then rm -rf -- "$profile"; fi' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cmd=("${browser:-chromium}" "--app=$url" "--user-data-dir=$profile" --no-first-run --no-default-browser-check "--window-size=1340,880")
if (( print )); then
  printf '%s\n' "${cmd[*]}"
  exit 0
fi
if [[ -z $browser ]]; then
  echo "open-sidged-app: no Chromium-family browser found; open $url yourself" >&2
  exit 3
fi
started=$SECONDS
status=0
"${cmd[@]}" || status=$?
elapsed=$((SECONDS - started))
rm -rf -- "$profile"
if (( status == 0 && elapsed < 2 )); then
  echo "open-sidged-app: warning: launcher forked and the temporary profile was removed (possible: browser returned within 2 s)" >&2
fi
exit "$status"
