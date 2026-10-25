#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
# companion_ui_check.sh: static checks for the companion canvas webview (WP 7).
#   bash scripts/tests/companion_ui_check.sh [app-dir]
#
# The canvas renders Core-built surfaces and talks only through the single `companion`
# IPC command: no network, no HTML injection, no eval, no browser storage, no dialog
# (consequential steps are confirmed in the Core Trusted UI, never in the webview).
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
app=${1:-$root/companion/vaikor-companion-app}
ui=$app/ui
fail=0
bad() { echo "companion_ui_check: FAIL: $*" >&2; fail=1; }

for f in "$ui/index.html" "$ui/canvas.js" "$ui/canvas.css" "$app/tauri.conf.json" \
         "$app/capabilities/default.json" "$app/build.rs"; do
  [[ -f $f ]] || bad "missing $f"
done
if (( fail )); then exit 1; fi

# The vendored design system must be byte-identical to ui/vaiev-ui (one source of truth).
for f in tokens/tokens.css tokens/components.css tokens/fonts.css vaikor-theme.css fonts/OFL-LICENSE.txt \
         fonts/ibm-plex-mono-latin-400-normal.woff2 fonts/ibm-plex-mono-latin-500-normal.woff2 \
         fonts/ibm-plex-sans-latin-400-normal.woff2 fonts/ibm-plex-sans-latin-500-normal.woff2 \
         fonts/ibm-plex-sans-latin-600-normal.woff2; do
  cmp -s "$root/ui/vaiev-ui/$f" "$ui/vendor/$f" || bad "ui/vendor/$f differs from ui/vaiev-ui/$f"
done

# The only URL allowed in the webview sources is the Tauri IPC origin (the font licence text is not loaded).
if grep -rnoE --exclude=OFL-LICENSE.txt 'https?://[^ "'"'"';]+|wss?://[^ "'"'"';]+' "$ui" | grep -v 'http://ipc\.localhost'; then
  bad "URL in companion ui/"
fi
if grep -nE 'fetch\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts|new Worker|serviceWorker|RTCPeerConnection|window\.open|location\s*=' "$ui/canvas.js"; then
  bad "network API in canvas.js"
fi
if grep -nE 'innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|setTimeout\(\s*["'"'"']' "$ui/canvas.js"; then
  bad "HTML injection or eval in canvas.js"
fi
if grep -nE 'localStorage|sessionStorage|indexedDB|document\.cookie' "$ui/canvas.js"; then
  bad "browser storage"
fi
if grep -niE '<dialog|showModal|\bapprove\b|<iframe|<object|<embed|<script>' "$ui/index.html" "$ui/canvas.js"; then
  bad "dialog, embedding or inline script"
fi
if grep -nE 'url\(|@import' "$ui/canvas.css"; then
  bad "url() or @import in canvas.css"
fi

# CSP: identical connect-src (IPC only) and no unsafe sources, in the page and the app config.
for f in "$ui/index.html" "$app/tauri.conf.json"; do
  csp=$(grep -oE "default-src[^\"]*" "$f" | head -1)
  [[ $csp == *"connect-src ipc: http://ipc.localhost;"* ]] || bad "$f: connect-src must be exactly ipc: http://ipc.localhost"
  [[ $csp == *"script-src 'self';"* ]] || bad "$f: script-src must be 'self'"
  [[ $csp != *unsafe* ]] || bad "$f: unsafe CSP source"
done

# Exactly one app command, and the window may call nothing else.
grep -q '\.commands(&\["companion"\])' "$app/build.rs" || bad "build.rs must declare only the companion command"
python3 -I - "$app/capabilities/default.json" <<'EOF' || bad "capability must grant only allow-companion"
import json, sys
cap = json.load(open(sys.argv[1]))
sys.exit(0 if cap.get("permissions") == ["allow-companion"] else 1)
EOF

if (( fail )); then exit 1; fi
echo "companion_ui_check: OK"
