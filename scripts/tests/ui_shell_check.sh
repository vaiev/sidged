#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
# ui_shell_check.sh: static checks for the offline UI shell (turnkey WP d).
# Run by `cargo test` (sidged-guard/tests/ui_shell.rs) and standalone:
#   bash scripts/tests/ui_shell_check.sh [ui-dir]
#
# The shell must make zero network requests and show only real data or a
# labelled empty state: no URL, no network API, no font download, no inline
# script/style/handler (CSP), no fake identities or signatures, no storage
# claims, no approval dialog (0004 R5, R12: Trusted UI belongs to the Core).
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
ui=${1:-$root/ui/shell}
html=$ui/index.html
css=$ui/shell.css
js=$ui/shell.js
fail=0
bad() { echo "ui_shell_check: FAIL: $*" >&2; fail=1; }

for f in "$html" "$css" "$js" "$ui/TOKENS-SOURCE.md"; do
  [[ -f $f ]] || bad "missing $f"
done
if (( fail )); then exit 1; fi

# Zero external requests: no URL of any scheme that loads something.
if grep -rnE 'https?:|wss?:|ftp:|//[a-z0-9.-]+\.[a-z]{2,}/' "$ui"; then
  bad "URL in ui/"
fi
if grep -rniE 'googleapis|gstatic|cdn|unpkg|jsdelivr|@import' "$ui"; then
  bad "font/CDN reference or @import"
fi
# No font files shipped and @font-face only with local().
if find "$ui" -type f \( -iname '*.woff' -o -iname '*.woff2' -o -iname '*.ttf' -o -iname '*.otf' \) | grep -q .; then
  bad "font files in ui/ (use the system stack or local())"
fi
if grep -nE 'url\(' "$css"; then
  bad "url() in CSS"
fi
# No network APIs.
if grep -nE 'fetch\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts|new Worker|SharedWorker|serviceWorker|RTCPeerConnection|window\.open|location\s*=|\.src\s*=|\.href\s*=' "$js"; then
  bad "network API in shell.js"
fi
if grep -niE '<iframe|<object|<embed|<form[^>]*action|<link[^>]*rel="?(preconnect|prefetch|dns-prefetch|preload)' "$html"; then
  bad "embedding or preloading element"
fi
# No fake identities, signatures, keys or storage claims.
for word in 'ed25519' 'did:key' 'sqlite' 'bereit' 'persistent' 'grok' 'swarm' 'xai-' 'AIza'; do
  if grep -rniF -- "$word" "$html" "$css" "$js"; then
    bad "forbidden string: $word"
  fi
done
# No approval UI and no local-mode toggle (0004 R5, R12; 0007 R2).
if grep -niE '<dialog|showModal|\bapprove\b|type="?checkbox|role="?switch' "$html" "$js"; then
  bad "approval dialog or toggle in the page"
fi
if grep -nE 'localStorage|sessionStorage|indexedDB|document\.cookie' "$js"; then
  bad "browser storage"
fi
# CSP: exact policy, no inline script/style/handlers, scripts by relative path.
csp="default-src 'none'; style-src 'self'; script-src 'self'; font-src 'self'; img-src 'self'; connect-src 'none'; form-action 'none'; base-uri 'none'"
grep -qF "<meta http-equiv=\"Content-Security-Policy\" content=\"$csp\">" "$html" || bad "CSP meta missing or different"
if grep -nE '<script>|<script [^>]*>[^<]' "$html"; then bad "inline script"; fi
if grep -nE '<style|[[:space:]]style=' "$html"; then bad "inline style"; fi
if grep -nE '[[:space:]]on[a-z]+=' "$html"; then bad "inline event handler"; fi
grep -qE '<script src="shell.js" defer></script>' "$html" || bad "shell.js must be loaded by relative path"
grep -qE '<link rel="stylesheet" href="shell.css">' "$html" || bad "shell.css must be loaded by relative path"
if grep -nE 'innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function' "$js"; then
  bad "HTML injection sink in shell.js"
fi
# English content and the registry CountdownWidget mapping.
grep -qF '<html lang="en">' "$html" || bad "English shell must declare lang=en"
if grep -nF 'vv-countdown-pill' "$html" "$css"; then bad "custom countdown class"; fi
grep -qF 'class="vv-chip vv-chip--primary vv-mono vv-countdown" title="CountdownWidget"' "$html" || bad "countdown must use primary chip and mono token"
if grep -nE '^\.vv-chip--primary[[:space:]]*\{[^}]*border-radius' "$css"; then
  bad "primary chip must not set border-radius"
fi
grep -qF '.vv-countdown { border-radius: var(--vv-shape-full); }' "$css" || bad "pill shape must be scoped to countdown"
# One glass layer; 48 px targets; reduced motion/transparency honoured (0004 R7).
[[ $(grep -c 'vv-glass' "$html") -eq 1 ]] || bad "exactly one .vv-glass element"
grep -q -- '--vv-touch-target: 48px' "$css" || bad "48 px target token missing"
grep -q 'prefers-reduced-motion' "$css" || bad "prefers-reduced-motion not handled"
grep -q 'prefers-reduced-transparency' "$css" || bad "prefers-reduced-transparency not handled"
grep -q 'prefers-contrast' "$css" || bad "prefers-contrast not handled"
# Pinned upstream names only; every shell variable must resolve locally.
fixture=$root/ui/shell/vaiev-ui-0bb03ba-token-names.txt
while IFS= read -r name; do
  grep -qxF -- "$name" "$fixture" || bad "token absent from vaiev/ui 0bb03ba: $name"
done < <(grep -oE -- '--[a-zA-Z0-9_-]+[[:space:]]*:' "$css" | sed 's/[[:space:]]*:$//' | sort -u)
while IFS= read -r name; do
  grep -qE -- "${name}[[:space:]]*:" "$css" || bad "undefined shell token: $name"
done < <(grep -rhoE -- 'var\([[:space:]]*--vv-[a-zA-Z0-9_-]+' "$ui" | sed 's/var([[:space:]]*//' | sort -u)
if grep -rnE -- '--vv-glass-bg|--vv-motion-(fast|base|slow)|--vv-target|Vv Sans|Vv Mono' "$ui"; then
  bad "invented token or font name"
fi
# The audit view never claims verification.
grep -q 'sidged log verify' "$html" || bad "audit view must point to sidged log verify"

if (( fail )); then exit 1; fi
echo "ui_shell_check: OK"
