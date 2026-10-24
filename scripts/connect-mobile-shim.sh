#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
#
# connect-mobile-shim.sh: connect a smartphone (Termux / SSH) or remote laptop
# to a Sidged VM/Host over SSH without exposing any public ports (0010 §3).
#
# Modes:
#   approve <approver@host> [socket]   Attach sidged-tui to the host approval socket (SO_PEERCRED preserved)
#   pull-view <user@host>:<remote.json> <local.json>  Fetch a Core-emitted A2UI view JSON for ui/shell
set -euo pipefail

mode="${1:-}"
case "$mode" in
  approve)
    target="${2:?missing approver@host}"
    sock="${3:-/run/sidged/approval/control.sock}"
    exec ssh -t "$target" /usr/local/bin/sidged-tui approve --socket "$sock"
    ;;
  pull-view)
    src="${2:?missing user@host:/path/to/view.json}"
    dst="${3:-view.json}"
    exec scp -q "$src" "$dst"
    ;;
  *)
    echo "usage: $0 {approve <approver@host> [socket] | pull-view <user@host:/path/view.json> [local.json]}" >&2
    exit 2
    ;;
esac
