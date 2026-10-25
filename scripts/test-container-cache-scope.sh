#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
# Cache trust split fixtures (no podman needed): cache mounts only for pull-request
# scopes, never in the committed (trusted/release) Containerfile; per-run
# build label and label-scoped cleanup.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
gen=scripts/containerfile-scope.sh

# 1. The committed Containerfile is the trusted build: no cache mounts.
check "committed Containerfile has no cache mount" "! grep -q 'type=cache' Containerfile"
check "committed build drops target/ in the build RUN" "grep -q '^ && rm -rf runtime/target$' Containerfile"

# 2. Empty scope (trusted): output identical to the input.
if "$gen" "" Containerfile "$t/trusted" >"$t/out" 2>&1 && cmp -s Containerfile "$t/trusted"; then
  ok "empty scope keeps the file as is"
else bad "empty scope"; cat "$t/out"; fi

# 3. PR scope: literal per-PR ids (no build-time variable expansion needed).
if "$gen" pr42 Containerfile "$t/pr" >"$t/out" 2>&1; then
  check "pr42 mounts the PR registry cache" "grep -q 'id=vaikor-cargo-reg-pr42,' '$t/pr'"
  check "pr42 mounts the PR target cache" "grep -q 'id=vaikor-cargo-target-pr42,' '$t/pr'"
  check "pr42 has exactly two cache mounts" "[ \"\$(grep -c 'type=cache' '$t/pr')\" = 2 ]"
  check "pr42 has no unscoped id" "! grep -Eq 'id=vaikor-(cargo-registry|target)[,[:space:]]' '$t/pr'"
  check "pr42 keeps target/ (it is the cache mount)" "! grep -q 'rm -rf runtime/target' '$t/pr'"
else bad "pr42 generation"; cat "$t/out"; fi

# 4. Anything but pr<N> is refused (fail closed).
for scope in main pr pr0 pr4x 'pr1 ' '../x' 'pr1,id=x' trusted; do
  if "$gen" "$scope" Containerfile "$t/x" >/dev/null 2>&1; then bad "scope '$scope' refused"; else ok "scope '$scope' refused"; fi
done

# 5. A Containerfile without the marker lines is refused for a PR scope.
printf 'FROM scratch\nRUN true\n' > "$t/nomarker"
if "$gen" pr1 "$t/nomarker" "$t/x" >/dev/null 2>&1; then bad "missing marker refused"; else ok "missing marker refused"; fi

# 6. container-test.sh: per-run label, no kept layers, scoped file, trusted
#    builds without layer cache. A fake podman records the build arguments.
mkdir -p "$t/bin"
cat > "$t/bin/podman" <<'F'
#!/usr/bin/env bash
# Every call is logged (storage trust split), then global store flags are
# stripped so the subcommand can be dispatched.
[ -z "${FAKE_CALLS:-}" ] || printf '%s\n' "$*" >> "$FAKE_CALLS"
while [ "${1:-}" = --root ] || [ "${1:-}" = --runroot ]; do shift 2; done
if [ "$1" = build ]; then
  printf '%s\n' "$@" > "$FAKE_LOG"
  while [ $# -gt 0 ]; do [ "$1" = -f ] && cp "$2" "$FAKE_LOG.file"; shift; done
  exit 1
fi
exit 0
F
chmod +x "$t/bin/podman"
run_ct() { # scope log
  PATH="$t/bin:$PATH" FAKE_LOG="$2" VAIKOR_CACHE_SCOPE="$1" VAIKOR_CI_RUN=77-2 \
    VAIKOR_GIT_SHA=unknown scripts/container-test.sh linux/amd64 >/dev/null 2>&1 || true
}
run_ct pr9 "$t/prlog"
check "PR build labels the run" "grep -qx -- '--label' '$t/prlog' && grep -qx 'vaikor.ci.run=77-2' '$t/prlog'"
check "PR build keeps no intermediate layers" "grep -qx -- '--layers=false' '$t/prlog'"
check "PR build uses the pr9-scoped file" "grep -q 'id=vaikor-cargo-target-pr9,' '$t/prlog.file'"
check "PR build may use the layer cache" "! grep -qx -- '--no-cache' '$t/prlog'"
run_ct "" "$t/trlog"
check "trusted build has no cache mount" "! grep -q 'type=cache' '$t/trlog.file'"
check "trusted build ignores the layer cache" "grep -qx -- '--no-cache' '$t/trlog'"
check "trusted build labels the run" "grep -qx 'vaikor.ci.run=77-2' '$t/trlog'"

# 6b. Test-key scan builds follow the same split (it rebuilds what ships).
run_scan() { # scope log
  PATH="$t/bin:$PATH" FAKE_LOG="$2" VAIKOR_CACHE_SCOPE="$1" VAIKOR_CI_RUN=77-2 \
    VAIKOR_GIT_SHA=unknown scripts/scan-shipped-test-keys.sh linux/amd64 >/dev/null 2>&1 || true
}
run_scan pr9 "$t/sprlog"
check "PR scan labels the run, keeps no layers" "grep -qx 'vaikor.ci.run=77-2' '$t/sprlog' && grep -qx -- '--layers=false' '$t/sprlog'"
check "PR scan uses the pr9-scoped file" "[ -f '$t/sprlog.file' ] && grep -q 'id=vaikor-cargo-target-pr9,' '$t/sprlog.file'"
run_scan "" "$t/strlog"
check "trusted scan: no cache mount, no layer cache" "[ -f '$t/strlog.file' ] && ! grep -q 'type=cache' '$t/strlog.file' && grep -qx -- '--no-cache' '$t/strlog'"

# 6c. Compose: the image is built by podman build under the same
#     split, then compose only starts it (never builds).
cat > "$t/bin/fake-compose" <<'F'
#!/usr/bin/env bash
printf 'VAIKOR_TAG=%s %s\n' "${VAIKOR_TAG:-}" "$*" >> "$FAKE_COMPOSE_LOG"
# Like podman-compose: every engine call goes through --podman-path.
pp=podman
while [ $# -gt 0 ]; do [ "$1" = --podman-path ] && pp="$2"; shift; done
"$pp" ps -q >/dev/null
exit 0
F
chmod +x "$t/bin/fake-compose"
run_up() { # scope log
  : > "$2.compose"
  PATH="$t/bin:$PATH" FAKE_LOG="$2" FAKE_COMPOSE_LOG="$2.compose" ENGINE_COMPOSE="$t/bin/fake-compose" \
    VAIKOR_CACHE_SCOPE="$1" VAIKOR_CI_RUN=77-2 VAIKOR_GIT_SHA=unknown \
    scripts/compose-up.sh proj >/dev/null 2>&1 || true
}
# The fake podman fails builds; compose-up must then not start compose.
run_up pr9 "$t/cprlog"
check "compose PR build: run label, no layers, pr9 file" "grep -qx 'vaikor.ci.run=77-2' '$t/cprlog' && grep -qx -- '--layers=false' '$t/cprlog' && grep -q 'id=vaikor-cargo-target-pr9,' '$t/cprlog.file'"
check "compose PR build: per-run image tag" "grep -qx 'localhost/vaikor-core:ci-77-2' '$t/cprlog'"
check "compose not started after a failed build" "[ ! -s '$t/cprlog.compose' ]"
run_up_trusted() { # log
  : > "$1.compose"
  PATH="$t/bin:$PATH" FAKE_LOG="$1" FAKE_COMPOSE_LOG="$1.compose" ENGINE_COMPOSE="$t/bin/fake-compose" \
    VAIKOR_CACHE_SCOPE="" VAIKOR_CI_RUN=77-2 VAIKOR_GIT_SHA=unknown RUNNER_TEMP="$t/rt" \
    bash -c '. scripts/podman-store.sh; vaikor_store_open; scripts/compose-up.sh proj; rc=$?; vaikor_store_close; exit $rc' >/dev/null 2>&1 || true
}
mkdir -p "$t/rt"
run_up_trusted "$t/ctrlog"
check "compose trusted build: no cache mount, --no-cache" "! grep -q 'type=cache' '$t/ctrlog.file' && grep -qx -- '--no-cache' '$t/ctrlog' && grep -qx 'vaikor.ci.run=77-2' '$t/ctrlog'"
# With a succeeding build, compose runs up --no-build and never build.
sed -i 's/^  exit 1$/  exit 0/' "$t/bin/podman"
run_up pr9 "$t/cuplog"
check "compose up --no-build, no compose build" "grep -q -- 'up -d --no-build' '$t/cuplog.compose' && ! grep -Eq '(^| )build( |$)' '$t/cuplog.compose'"
check "compose up starts the per-run tag" "grep -q -- '^VAIKOR_TAG=ci-77-2 .*-p proj up -d --no-build' '$t/cuplog.compose'"
check "compose-test.sh delegates to compose-up.sh" "grep -q 'scripts/compose-up.sh' scripts/compose-test.sh && ! grep -Eq 'ENGINE_COMPOSE[^#]* build\b' scripts/compose-test.sh"
sed -i 's/^  exit 0$/  exit 1/' "$t/bin/podman"

# 6d. Storage trust split: trusted runs use a throwaway podman store under
#     $RUNNER_TEMP on every podman call; PR runs keep the shared store.
mkdir -p "$t/rt"
store_calls() { # label calls-file
  if [ ! -s "$2" ]; then bad "$1: no podman calls"; return; fi
  if grep -Ev -- "--root $t/rt/vaikor-store\.[^ /]+/root --runroot $t/rt/vaikor-store\.[^ /]+/run( |$)" "$2" | grep -q .; then
    bad "$1: every podman call uses the throwaway store"; grep -Ev -- '--root' "$2" | head -3
  else ok "$1: every podman call uses the throwaway store"; fi
  check "$1: store removed afterwards" "! ls -d '$t/rt'/vaikor-store.* >/dev/null 2>&1"
}
no_store() { # label calls-file
  check "$1: shared store (no --root/--runroot)" "[ -s '$2' ] && ! grep -Eq -- '--(root|runroot)( |=)' '$2'"
  check "$1: no throwaway store" "! ls -d '$t/rt'/vaikor-store.* >/dev/null 2>&1"
}
run_store() { # scope calls-file cmd...
  local scope=$1 calls=$2; shift 2; : > "$calls"
  PATH="$t/bin:$PATH" FAKE_LOG="$calls.build" FAKE_CALLS="$calls" RUNNER_TEMP="$t/rt" \
    VAIKOR_CACHE_SCOPE="$scope" VAIKOR_CI_RUN=77-2 VAIKOR_GIT_SHA=unknown "$@" >/dev/null 2>&1 || true
}
run_store "" "$t/ct-trusted" scripts/container-test.sh linux/amd64
store_calls "container-test trusted" "$t/ct-trusted"
# podman cannot pull tag+digest, so the pin is pulled as name@digest.
while read -r ref; do
  if grep -qF -- " pull " "$t/ct-trusted" && grep -F -- " pull " "$t/ct-trusted" | grep -qF -- "$ref"; then ok "container-test trusted pulls ${ref%%@*} by digest"
  else bad "container-test trusted pulls ${ref%%@*} by digest"; fi
done < <(sed -nE 's/^FROM +(--[^ ]+ +)*([^ ]+@sha256:[0-9a-f]{64}).*/\2/p' Containerfile | sed -E 's/:[^:@/]+@/@/' | sort -u)
run_store pr9 "$t/ct-pr" scripts/container-test.sh linux/amd64
no_store "container-test PR" "$t/ct-pr"
run_store "" "$t/bi-trusted" scripts/check-base-index.sh
store_calls "check-base-index trusted" "$t/bi-trusted"
run_store pr9 "$t/bi-pr" scripts/check-base-index.sh
no_store "check-base-index PR" "$t/bi-pr"
run_store "" "$t/sc-trusted" scripts/scan-shipped-test-keys.sh linux/amd64
store_calls "scan trusted" "$t/sc-trusted"
run_store pr9 "$t/sc-pr" scripts/scan-shipped-test-keys.sh linux/amd64
no_store "scan PR" "$t/sc-pr"
# 6e. Storage trust split for compose: compose-test.sh owns the trusted
#     store; compose-up.sh and podman-compose (--podman-path) use it.
run_up_store() { # scope calls-file [inherit]
  local scope=$1 calls=$2 inherit=${3:-yes}; : > "$calls"; : > "$calls.compose"
  local cmd='scripts/compose-up.sh proj'
  # shellcheck disable=SC2016 # code for bash -c, expanded there
  [ "$inherit" = yes ] && cmd='. scripts/podman-store.sh; vaikor_store_open; rc=0; scripts/compose-up.sh proj || rc=$?; vaikor_store_close; exit $rc'
  PATH="$t/bin:$PATH" FAKE_LOG="$calls.build" FAKE_CALLS="$calls" FAKE_COMPOSE_LOG="$calls.compose" \
    ENGINE_COMPOSE="$t/bin/fake-compose" RUNNER_TEMP="$t/rt" VAIKOR_CACHE_SCOPE="$scope" \
    VAIKOR_CI_RUN=77-2 VAIKOR_GIT_SHA=unknown bash -c "$cmd" >/dev/null 2>&1 || true
}
sed -i 's/^  exit 1$/  exit 0/' "$t/bin/podman"
run_up_store "" "$t/cu-trusted"
store_calls "compose-up trusted" "$t/cu-trusted"
check "compose trusted: podman-compose gets --podman-path to the store wrapper" \
  "grep -Eq -- '--podman-path $t/rt/vaikor-store\.[^ /]+/podman ' '$t/cu-trusted.compose'"
check "compose trusted: compose's podman calls carry the store flags" "grep -Eq -- '--root [^ ]+ --runroot [^ ]+ ps' '$t/cu-trusted'"
run_up_store "" "$t/cu-orphan" no
check "compose-up refuses a trusted run without an inherited store" \
  "! grep -q ' build ' '$t/cu-orphan' && [ ! -s '$t/cu-orphan.compose' ] && ! ls -d '$t/rt'/vaikor-store.* >/dev/null 2>&1"
run_up_store pr9 "$t/cu-pr" no
no_store "compose-up PR" "$t/cu-pr"
check "compose PR: no --podman-path" "[ -s '$t/cu-pr.compose' ] && ! grep -q -- '--podman-path' '$t/cu-pr.compose'"
sed -i 's/^  exit 0$/  exit 1/' "$t/bin/podman"
# compose-test.sh / compose-init.sh: every podman and compose call after the
# store opens goes through $PODMAN / --podman-path (static; the full script
# needs pyyaml and a real engine).
check "compose-test opens and closes the store" "grep -q 'vaikor_store_open' scripts/compose-test.sh && grep -q 'vaikor_store_close' scripts/compose-test.sh"
check "compose-test: ps/wait/init via \$PODMAN" "grep -q 'engine=\"\$PODMAN\"' scripts/compose-test.sh && grep -q 'ENGINE=\"\$PODMAN\" COMPOSE_PROJECT' scripts/compose-test.sh"
check "compose-test: logs and down via the store-aware compose" "! grep -Eq '\\\$ENGINE_COMPOSE -f docker-compose.yml -p' scripts/compose-test.sh && grep -q 'compose_cmd' scripts/compose-test.sh"
check "compose-check: unshare through the engine wrapper" "grep -q 'engine.endswith(\"/podman\")' scripts/compose-check.py && grep -q '\[engine, \"unshare\"' scripts/compose-check.py"
check "compose-init: unshare through the engine wrapper" "! grep -q 'then podman unshare' scripts/compose-init.sh"

check "workflow sweeps leftover stores in always()" "grep -q 'vaikor-store\.\*' .github/workflows/container.yml"

# 6f. Scratch files podman reads or writes (the scoped Containerfile, the
#     build output) live in a directory the script creates under
#     $RUNNER_TEMP, never in /tmp, and are removed afterwards: rootless
#     podman runs in the mount namespace of its pause process, whose /tmp
#     need not be the caller's.
rm -rf "$t/rt" "$t/tmp"; mkdir -p "$t/rt" "$t/tmp"
scratch() { # label scope build-log cmd...
  local label=$1 scope=$2 log=$3; shift 3
  rm -f "$log" "$log.file"
  PATH="$t/bin:$PATH" FAKE_LOG="$log" RUNNER_TEMP="$t/rt" TMPDIR="$t/tmp" \
    ENGINE_COMPOSE="$t/bin/fake-compose" FAKE_COMPOSE_LOG=/dev/null \
    VAIKOR_CACHE_SCOPE="$scope" VAIKOR_CI_RUN=77-2 VAIKOR_GIT_SHA=unknown "$@" >/dev/null 2>&1 || true
  check "$label: -f in a script-made dir under \$RUNNER_TEMP" \
    "[ -s '$log.file' ] && grep -A1 -x -- '-f' '$log' | tail -1 | grep -Eq '^$t/rt/vaikor-[a-z]+\.[^/]+/[^/]+$'"
  check "$label: scratch removed, nothing in \$TMPDIR" "[ -z \"\$(ls -A '$t/rt' '$t/tmp' | grep -v ':$')\" ]"
}
scratch "container-test trusted" "" "$t/sf-ct" scripts/container-test.sh linux/amd64
scratch "container-test PR" pr9 "$t/sf-ctpr" scripts/container-test.sh linux/amd64
scratch "scan trusted" "" "$t/sf-sc" scripts/scan-shipped-test-keys.sh linux/amd64
check "scan: build output in a script-made dir under \$RUNNER_TEMP" \
  "grep -A1 -x -- '-o' '$t/sf-sc' | tail -1 | grep -Eq '^type=local,dest=$t/rt/vaikor-[a-z]+\.[^/]+/musl$'"
scratch "compose-up PR" pr9 "$t/sf-cu" scripts/compose-up.sh proj
scratch "context scan" "" "$t/sf-cx" scripts/check-no-test-keys.sh --context
check "context scan: build output in a script-made dir under \$RUNNER_TEMP" \
  "grep -A1 -x -- '-o' '$t/sf-cx' | tail -1 | grep -Eq '^type=local,dest=$t/rt/vaikor-[a-z]+\.[^/]+/fs$'"

# 6g. container-test.sh passes on a podman that succeeds, also when a long
#     image list follows the instance it looks for: no reader in a pipeline
#     may exit early, or pipefail turns the writer's SIGPIPE into exit 141.
mkdir -p "$t/okbin" "$t/empty"
cat > "$t/okbin/podman" <<'F'
#!/usr/bin/env bash
while [ "${1:-}" = --root ] || [ "${1:-}" = --runroot ]; do shift 2; done
case "$1 ${2:-}" in
  "manifest inspect") echo '{"manifests":[{"digest":"sha256:feed","platform":{"os":"linux","architecture":"amd64"}}]}' ;;
  # One writer process that dies of SIGPIPE, as podman does.
  "images "*) exec awk 'BEGIN { print "sha256:feed 1d"; for (i = 0; i < 200000; i++) print "sha256:0ther 2d" }' ;;
  "image inspect")
    case "$*" in *Architecture*) echo amd64 ;; *Config.User*) echo 65532:65532 ;; *) echo PATH=/bin ;; esac ;;
  "create "*) echo cid1 ;;
  "export -o") tar -C "$FAKE_EMPTY" -cf "$3" . ;;
  "export "*) tar -C "$FAKE_EMPTY" -cf - . ;;
  "run "*) echo "vaikor 0.2.0 (unknown)" ;;
esac
exit 0
F
chmod +x "$t/okbin/podman"
for scope in pr9 ""; do
  PATH="$t/okbin:$PATH" FAKE_EMPTY="$t/empty" RUNNER_TEMP="$t/rt" VAIKOR_CACHE_SCOPE="$scope" \
    VAIKOR_CI_RUN=77-2 VAIKOR_GIT_SHA=unknown scripts/container-test.sh linux/amd64 >"$t/out" 2>&1; rc=$?
  if [ "$rc" = 0 ] && grep -qx 'PASS: linux/amd64' "$t/out"; then ok "container-test passes on a working podman (scope '${scope}')"
  else bad "container-test passes on a working podman (scope '${scope}', exit $rc)"; tail -3 "$t/out"; fi
done
mkdir -p "$t/keyed/keys"; : > "$t/keyed/keys/log-key.key"
PATH="$t/okbin:$PATH" FAKE_EMPTY="$t/keyed" RUNNER_TEMP="$t/rt" VAIKOR_CACHE_SCOPE=pr9 \
  VAIKOR_CI_RUN=77-2 VAIKOR_GIT_SHA=unknown scripts/container-test.sh linux/amd64 >"$t/out" 2>&1; rc=$?
check "container-test still refuses a key file in the image" "[ $rc != 0 ] && grep -q 'secret-like file baked in: ./keys/log-key.key' '$t/out'"
check "container-test leaves no scratch behind" "[ -z \"\$(ls -A '$t/rt')\" ]"

# 6h. The throwaway store's runroot holds the rootless network namespace.
#     Podman 5 opens it with pasta, which the Debian/Ubuntu AppArmor profile
#     lets read only under /tmp and /run/user/<uid>; so on 5.x the runroot is
#     a fresh directory under $XDG_RUNTIME_DIR (else /tmp), linked from the
#     store. Podman 4.9 (slirp4netns) keeps it inside the store. Both are
#     removed with the store, also by the sweep for a killed step.
mkdir -p "$t/vbin" "$t/xdg"; rm -rf "$t/rt"; mkdir -p "$t/rt"
cat > "$t/vbin/podman" <<'F'
#!/usr/bin/env bash
while [ "${1:-}" = --root ] || [ "${1:-}" = --runroot ]; do shift 2; done
# Only the client flag: `podman version` may write to the store's runroot.
[ "$1" = --version ] && echo "podman version $FAKE_VERSION"
[ "$1" = version ] && exit 3
exit 0
F
chmod +x "$t/vbin/podman"
store_probe() { # version xdg cmd
  PATH="$t/vbin:$PATH" FAKE_VERSION="$1" XDG_RUNTIME_DIR="$2" RUNNER_TEMP="$t/rt" \
    VAIKOR_CACHE_SCOPE="" VAIKOR_CI_RUN=77-2 bash -c ". scripts/podman-store.sh; $3"
}
# shellcheck disable=SC2016 # code for bash -c, expanded there
open_show='vaikor_store_open; s="${PODMAN%/podman}"; grep -q -- "--runroot $s/run " "$PODMAN" && echo wrapper; [ -L "$s/run" ] && readlink "$s/run"; [ -d "$s/run" ] && echo dir'
out="$(store_probe 5.4.2 "$t/xdg" "$open_show; vaikor_store_close")"
check "podman 5: runroot is a fresh dir under \$XDG_RUNTIME_DIR, linked from the store" \
  "grep -qx wrapper <<<\"\$out\" && grep -Eqx '$t/xdg/vaikor-run\.[A-Za-z0-9]{6}' <<<\"\$out\" && grep -qx dir <<<\"\$out\""
check "podman 5: close removes the store and its runroot" \
  "! ls -d '$t/rt'/vaikor-store.* >/dev/null 2>&1 && [ -z \"\$(ls -A '$t/xdg')\" ]"
out="$(store_probe 5.4.2 "" "$open_show; vaikor_store_close")"
check "podman 5 without \$XDG_RUNTIME_DIR: runroot under /tmp, removed" \
  "grep -Eqx '/tmp/vaikor-run\.[A-Za-z0-9]{6}' <<<\"\$out\" && [ ! -e \"\$(grep '^/tmp/' <<<\"\$out\")\" ]"
# shellcheck disable=SC2034 # read by the check below (eval)
out="$(store_probe 4.9.3 "$t/xdg" "$open_show; vaikor_store_close")"
check "podman 4.9: runroot stays inside the store" \
  "grep -qx wrapper <<<\"\$out\" && ! grep -q '^/' <<<\"\$out\" && grep -qx dir <<<\"\$out\" && [ -z \"\$(ls -A '$t/xdg')\" ]"
store_probe 5.4.2 "$t/xdg" 'vaikor_store_open' >/dev/null
store_probe 4.9.3 "$t/xdg" 'vaikor_store_open' >/dev/null
# shellcheck disable=SC2016 # code for bash -c, expanded there
store_probe 5.4.2 "$t/xdg" 'for d in "$RUNNER_TEMP"/vaikor-store.*; do vaikor_store_remove "$d"; done'
check "sweep removes leftover stores of both kinds and the linked runroot" \
  "[ -z \"\$(ls -A '$t/rt' '$t/xdg' | grep -v ':$')\" ]"
mkdir -p "$t/rt/vaikor-store.evil1A/root" "$t/victim/vaikor-run.abcdef"; : > "$t/victim/vaikor-run.abcdef/keep"
ln -s "$t/victim/vaikor-run.abcdef" "$t/rt/vaikor-store.evil1A/run"
# shellcheck disable=SC2016 # code for bash -c, expanded there
store_probe 5.4.2 "$t/xdg" 'vaikor_store_remove "$RUNNER_TEMP/vaikor-store.evil1A"'
check "sweep never follows a runroot link outside \$XDG_RUNTIME_DIR or /tmp" \
  "[ -f '$t/victim/vaikor-run.abcdef/keep' ] && [ ! -e '$t/rt/vaikor-store.evil1A' ]"
check "workflow sweeps through vaikor_store_remove" \
  "[ \"\$(grep -c 'do vaikor_store_remove ' .github/workflows/container.yml)\" = 3 ] && ! grep -q 'unshare rm' .github/workflows/container.yml"
rm -rf "$t/rt"; mkdir -p "$t/rt"

# 7. Workflow: scope only from the PR number, cleanup only by run label.
wf=.github/workflows/container.yml
want_scope="VAIKOR_CACHE_SCOPE: \${{ github.event_name == 'pull_request' && format('pr{0}', github.event.pull_request.number) || '' }}"
want_scope="${want_scope//\\/}"
if [ "$(grep -cF "$want_scope" "$wf")" -ge 2 ] && [ "$(grep -c 'VAIKOR_CACHE_SCOPE:' "$wf")" = "$(grep -cF "$want_scope" "$wf")" ]; then ok "workflow scopes caches by PR number only (both image jobs)"
else bad "workflow scopes caches by PR number only (both image jobs)"; fi
check "workflow has no unfiltered image prune" "! grep -Eq 'podman image prune -f *(>|\$|\\|)' $wf"
check "workflow cleans up by run label" "grep -q 'label=vaikor.ci.run=' $wf"

# 8. Every script the container workflow runs or sources is shellcheck-clean
#    (following sources). Skipped, as in scripts/tests, without shellcheck.
lint=(scripts/check-base-index.sh scripts/test-check-base-index.sh scripts/test-container-cache-scope.sh
      scripts/container-test.sh scripts/compose-test.sh scripts/compose-up.sh scripts/compose-init.sh
      scripts/scan-shipped-test-keys.sh scripts/test-check-no-test-keys.sh scripts/check-no-test-keys.sh
      scripts/containerfile-scope.sh scripts/podman-store.sh)
if command -v shellcheck >/dev/null; then
  if shellcheck -x "${lint[@]}" >"$t/sc" 2>&1; then ok "container scripts are shellcheck-clean"
  else bad "container scripts are shellcheck-clean"; grep -E '^In |SC[0-9]+' "$t/sc" | head -20; fi
else echo "skip container scripts shellcheck: shellcheck not installed"; fi

[ "$fail" = 0 ] && echo "PASS: container cache scope"
exit "$fail"
