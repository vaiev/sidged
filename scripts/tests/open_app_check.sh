#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
# open_app_check.sh: checks for scripts/open-sidged-app.{sh,ps1} (turnkey WP e).
# Run by `cargo test` (sidged-guard/tests/open_app.rs) and standalone.
#
# The opener opens the local shell file by default. An optional URL must be
# http:// + a loopback IP literal + an explicit port (no localhost, no other
# host, no userinfo, no query/fragment); anything else exits 2. `--print`
# shows the browser command instead of starting a browser (used here).
# The PowerShell cases run only when pwsh is installed.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
sh_opener=$root/scripts/open-sidged-app.sh
ps_opener=$root/scripts/open-sidged-app.ps1
fail=0
bad() { echo "open_app_check: FAIL: $*" >&2; fail=1; }

for f in "$sh_opener" "$ps_opener"; do
  [[ -f $f ]] || bad "missing $f"
done
if (( fail )); then exit 1; fi
bash -n "$sh_opener" || bad "bash -n"
if command -v shellcheck >/dev/null; then
  shellcheck -S style "$sh_opener" "$0" || bad "shellcheck"
else
  echo "open_app_check: shellcheck not installed; skipped"
fi

# Static: no remote host parameter, no default network URL, no hostnames.
# Match the literal PowerShell variable name.
# shellcheck disable=SC2016
if grep -niE 'VmHost|RemoteHost|\$Host\b|-Host\b' "$sh_opener" "$ps_opener"; then
  bad "remote host parameter"
fi
# A hostname URL, or an IP literal URL that is not 127.x.
if grep -nE 'https?://[A-Za-z]' "$sh_opener" "$ps_opener" \
  || grep -nE 'https?://[0-9]' "$sh_opener" "$ps_opener" | grep -vE 'https?://127\.'; then
  bad "URL to a host other than a loopback literal"
fi
if grep -nE '0\.0\.0\.0|--bind|\blisten\b' "$sh_opener" "$ps_opener"; then
  bad "listener or wildcard address"
fi

good=(
  "http://127.0.0.1:8080"
  "http://127.0.0.1:8080/"
  "http://127.1.2.3:9000/app/view"
  "http://[::1]:8080"
)
refused=(
  "http://192.0.2.1:8080"
  "http://10.0.0.1:8080"
  "http://localhost:8080"
  "http://LOCALHOST:8080"
  "http://user@127.0.0.1:8080"
  "http://user:pw@127.0.0.1:8080"
  "https://example.invalid"
  "https://127.0.0.1:8080"
  "http://127.0.0.1"
  "http://127.0.0.1:0"
  "http://127.0.0.1:65536"
  "http://127.0.0.1:08080"
  "http://127.0.0.256:80"
  "http://127.0.0.1.example.invalid:80"
  "http://[::ffff:127.0.0.1]:80"
  "http://127.0.0.1:8080/?next=x"
  "http://127.0.0.1:8080/#frag"
  "http://127.0.0.1:8080/%2e%2e"
  "file:///etc/passwd"
  "javascript:alert(1)"
  ""
)

run_sh() { bash "$sh_opener" --print "$@"; }

out=$(run_sh) || bad "default (file) mode failed"
grep -qF -- '--user-data-dir=<temporary-profile-dir>' <<<"$out" || bad "print must use profile placeholder"
grep -qE -- "--app=file://$root/ui/shell/index.html( |$)" <<<"$out" || bad "default must open file://.../ui/shell/index.html in app mode: $out"
for url in "${good[@]}"; do
  out=$(run_sh "$url") || { bad "refused good URL $url"; continue; }
  grep -qF -- "--app=$url" <<<"$out" || bad "good URL not passed through: $url -> $out"
done
for url in "${refused[@]}"; do
  set +e
  run_sh "$url" >/dev/null 2>&1
  rc=$?
  set -e
  [[ $rc -eq 2 ]] || bad "URL not refused with exit 2: '$url' (exit $rc)"
done
set +e
bash "$sh_opener" --print "http://127.0.0.1:8080" extra >/dev/null 2>&1
rc=$?
set -e
[[ $rc -eq 2 ]] || bad "extra argument not refused (exit $rc)"

# A fake browser records its profile and returns immediately, or fails.
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
cat >"$fixture/chromium" <<'BROWSER'
#!/usr/bin/env bash
for arg in "$@"; do
  case "$arg" in --user-data-dir=*) printf '%s\n' "${arg#*=}" >"$PROFILE_RECORD" ;; esac
done
exit "${BROWSER_STATUS:-0}"
BROWSER
chmod +x "$fixture/chromium"
export PROFILE_RECORD="$fixture/profile"
out=$(PATH="$fixture:$PATH" bash "$sh_opener" 2>&1) || bad "fake browser failed"
grep -qF 'launcher forked and the temporary profile was removed' <<<"$out" || bad "missing fast launcher warning"
[[ ! -d $(cat "$PROFILE_RECORD") ]] || bad "profile not removed"
set +e
out=$(PATH="$fixture:$PATH" BROWSER_STATUS=7 bash "$sh_opener" 2>&1)
rc=$?
set -e
[[ $rc -eq 7 ]] || bad "browser failure status lost"
[[ $out != *'launcher forked'* ]] || bad "failed browser reported as forked"
[[ ! -d $(cat "$PROFILE_RECORD") ]] || bad "failed browser profile not removed"

if command -v pwsh >/dev/null; then
  out=$(pwsh -NoProfile -File "$ps_opener" -Print) || bad "ps1 default failed"
  grep -qF -- '--user-data-dir=<temporary-profile-dir>' <<<"$out" || bad "ps1 print must use profile placeholder"
  grep -qF -- "--app=file://" <<<"$out" || bad "ps1 default must open the shell file: $out"
  for url in "${good[@]}"; do
    pwsh -NoProfile -File "$ps_opener" -Print -Url "$url" >/dev/null || bad "ps1 refused good URL $url"
  done
  for url in "${refused[@]}"; do
    [[ -z $url ]] && continue
    set +e
    pwsh -NoProfile -File "$ps_opener" -Print -Url "$url" >/dev/null 2>&1
    rc=$?
    set -e
    [[ $rc -eq 2 ]] || bad "ps1 URL not refused with exit 2: '$url' (exit $rc)"
  done
else
  echo "open_app_check: pwsh not installed; PowerShell cases skipped"
fi

if (( fail )); then exit 1; fi
echo "open_app_check: OK"
