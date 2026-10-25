#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
# ci-local.sh: run locally what .github/workflows/{rust-ci,validate}.yml run in CI,
# plus a fmt check. Run before handing a SHA over for push.
#
# Certifies HEAD only: a dirty worktree is refused, and all steps run in a clean
# detached export of HEAD (git worktree add --detach), removed afterwards.
# Every step runs; each status is collected; exit 1 if ANY step failed.
# No step can be skipped by env. actionlint is optional (not part of CI).
# The whole run (disk guard, clean, build, tests) holds one exclusive flock.
#
# Env:
#   CI_LOCAL_BASE     base for the fmt scope only (default origin/main). Must be a
#                     proper ancestor of HEAD; empty or HEAD is refused.
#                     gitleaks and DCO always scan merge-base(origin/main)..HEAD.
#   FMT_FULL=1        cargo fmt --all -- --check. Default: only .rs files changed vs
#                     CI_LOCAL_BASE. Main is not fmt-clean yet; the full fmt PR
#                     follows the merge train, then FMT_FULL=1 becomes the default.
#   CI_LOCAL_JOBS     cargo -j (default 2)
#   CARGO_TARGET_DIR  default: $VAIEV_ROOT/target if VAIEV_ROOT is set, else
#                     <worktree>/runtime/target. Lock: $VAIEV_ROOT/target.lock or
#                     <target>.lock.
#   VAIEV_MIN_FREE_GB required free GiB on the target filesystem, measured after the
#                     export is created (default 6). Below: staged clean
#                     (incremental, musl, cargo clean); still below: exit 3.
#   CI_LOCAL_VENV     prebuilt venv with spec/validate/requirements.txt (default
#                     $VAIEV_TOOLS/venv-validate). Never installed during the run;
#                     missing = schema FAIL.
#   GITLEAKS          gitleaks binary (default: gitleaks from PATH)
#
# Exit: 0 green, 1 a step failed, 2 bad base/args, 3 disk, 4 dirty tree.
set -euo pipefail

src=$(git rev-parse --show-toplevel)
cd "$src"
if [[ -n $(git status --porcelain --untracked-files=normal) ]]; then
  echo "ci-local: REFUSE: worktree is dirty; commit or stash first (certifies HEAD only)" >&2
  git status --short >&2; exit 4
fi

head_sha=$(git rev-parse HEAD)
base_ref=${CI_LOCAL_BASE-origin/main}
if [[ -z $base_ref || $base_ref == HEAD ]]; then
  echo "ci-local: REFUSE: CI_LOCAL_BASE must not be empty or HEAD" >&2; exit 2
fi
base_sha=$(git rev-parse --verify -q "${base_ref}^{commit}") || { echo "ci-local: REFUSE: base $base_ref not found" >&2; exit 2; }
if [[ $base_sha == "$head_sha" ]] || ! git merge-base --is-ancestor "$base_sha" "$head_sha"; then
  echo "ci-local: REFUSE: base $base_ref ($base_sha) is not a proper ancestor of HEAD" >&2; exit 2
fi
main_sha=$(git merge-base origin/main HEAD) || { echo "ci-local: REFUSE: no merge-base with origin/main" >&2; exit 2; }

jobs=${CI_LOCAL_JOBS:-2}
manifest=runtime/Cargo.toml
venv=${CI_LOCAL_VENV:-${VAIEV_TOOLS:+$VAIEV_TOOLS/venv-validate}}
min_free_gb=${VAIEV_MIN_FREE_GB:-6}
if [[ -n ${VAIEV_ROOT:-} ]]; then
  export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$VAIEV_ROOT/target}
  lock=$VAIEV_ROOT/target.lock
else
  export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$src/runtime/target}
  lock=${CARGO_TARGET_DIR%/}.lock
fi
target_dir=$CARGO_TARGET_DIR

# One exclusive lock for the whole run (shared with the weekly cleanup).
exec 9>>"$lock"
if ! flock -n 9; then echo "ci-local: waiting for lock $lock"; flock 9; fi

# Clean export of HEAD.
tmp=$(mktemp -d "${TMPDIR:-/tmp}/ci-local.XXXXXX")
cleanup() { git -C "$src" worktree remove --force "$tmp/src" >/dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT
git worktree add -q --detach "$tmp/src" "$head_sha"
echo "ci-local: export $(du -sh "$tmp/src" | cut -f1) at $tmp/src"
cd "$tmp/src"

# Disk guard (after the export, so its size counts).
free_kb() { local d=$1; while [[ ! -d $d ]]; do d=$(dirname "$d"); done; df -Pk "$d" | awk 'NR==2 {print $4}'; }
enough() {
  local kb; kb=$(free_kb "$target_dir")
  echo "ci-local: free $(awk -v k="$kb" 'BEGIN{printf "%.2f", k/1048576}') GiB on target fs (min ${min_free_gb})"
  awk -v k="$kb" -v m="$min_free_gb" 'BEGIN{exit !(k >= m*1048576)}'
}
ok=0; enough && ok=1
if (( !ok )); then
  echo "ci-local: stage 1: remove incremental caches"
  find "$target_dir" -mindepth 2 -maxdepth 3 -type d -name incremental -prune -exec rm -rf {} + 2>/dev/null || true
  enough && ok=1
fi
if (( !ok )); then
  echo "ci-local: stage 2: remove musl targets"
  rm -rf "$target_dir/x86_64-unknown-linux-musl" "$target_dir/aarch64-unknown-linux-musl"
  enough && ok=1
fi
if (( !ok )); then
  echo "ci-local: stage 3: empty the target dir (keeps the dir, its group and mode)"
  find "$target_dir" -mindepth 1 -delete 2>/dev/null || true
  enough && ok=1
fi
if (( !ok )); then
  echo "ci-local: REFUSE: less than ${min_free_gb} GiB free after all clean stages" >&2; exit 3
fi
mkdir -p "$target_dir"

declare -a names=() results=() times=()
failed=0
run_step() { # name, command...; subshell with errexit; status collected explicitly
  local name=$1; shift
  local t0=$SECONDS rc
  echo "==> [$name] $*"
  set +e
  ( set -euo pipefail; "$@" )
  rc=$?
  set -e
  names+=("$name"); times+=($((SECONDS - t0)))
  if [[ $rc -eq 0 ]]; then results+=("PASS"); else results+=("FAIL($rc)"); failed=1; fi
}
skip_step() { echo "==> [$1] SKIPPED: $2"; names+=("$1"); results+=("SKIP"); times+=(0); }

echo "ci-local: HEAD $head_sha, fmt base $base_sha, scan range $main_sha..$head_sha, cargo -j$jobs"

crate_edition() { # edition from the nearest Cargo.toml (or workspace.package)
  local d e; d=$(dirname "$1")
  while [[ $d != . && $d != / ]]; do
    if [[ -f $d/Cargo.toml ]]; then
      e=$(sed -nE 's/^edition *= *"([0-9]+)".*/\1/p' "$d/Cargo.toml" | head -1)
      [[ -z $e ]] && e=$(sed -nE 's/^edition *= *"([0-9]+)".*/\1/p' "$manifest" | head -1)
      [[ -n $e ]] && { echo "$e"; return 0; }
      return 1
    fi
    d=$(dirname "$d")
  done
  return 1
}
edition_for() { # the file's crate, else the crate of a #[path] module that includes it; none = fail
  local inc p
  crate_edition "$1" && return 0
  while IFS=: read -r inc p; do
    p=${p#*\"}; p=${p%%\"*}
    if [[ $(realpath -m "$(dirname "$inc")/$p") == "$(realpath -m "$1")" ]]; then
      crate_edition "$inc" && return 0
    fi
  done < <(git grep -e '#\[path = "' -- '*.rs')
  echo "fmt: no edition found for $1 (no crate, no #[path] includer)" >&2; return 1
}
fmt_changed() {
  local list f ed rc=0 n=0
  list=$(git diff --name-only --diff-filter=ACMR "${base_sha}...${head_sha}" -- '*.rs')
  while IFS= read -r f; do
    [[ -n $f && -f $f ]] || continue
    n=$((n + 1))
    ed=$(edition_for "$f") || { rc=1; continue; }
    rustfmt --check --edition "$ed" "$f" || rc=1
  done <<< "$list"
  echo "fmt: $n changed .rs file(s) checked"
  return $rc
}
if [[ ${FMT_FULL:-0} == 1 ]]; then
  run_step fmt cargo fmt --manifest-path "$manifest" --all -- --check
else
  run_step fmt fmt_changed
fi

# rust-ci.yml "test and clippy"
run_step test   cargo test --manifest-path "$manifest" --workspace --locked -j "$jobs"
run_step clippy cargo clippy --manifest-path "$manifest" --workspace --all-targets --locked -j "$jobs" -- -D warnings
run_step test-experimental cargo test --manifest-path "$manifest" -p vaikor-cli -p vaikor-guard --features experimental --locked -j "$jobs"
# validate.yml "runtime crates"
run_step test-default cargo test --manifest-path "$manifest" --locked -j "$jobs"
# The vaikor.com verifier module is its own workspace (rust-ci.yml "site verifier test and clippy").
site() {
  cargo test --manifest-path site/Cargo.toml --locked -j "$jobs" &&
    cargo clippy --manifest-path site/Cargo.toml --all-targets --locked -j "$jobs" -- -D warnings
}
run_step site site

# rust-ci.yml "companion core test and clippy" and "companion canvas static checks"
companion() {
  cargo test --manifest-path companion/Cargo.toml -p vaikor-companion-core --locked -j "$jobs" &&
    cargo clippy --manifest-path companion/Cargo.toml -p vaikor-companion-core --all-targets --locked -j "$jobs" -- -D warnings &&
    bash scripts/tests/companion_ui_check.sh
}
run_step companion companion

# validate.yml "validate"
schema() {
  [[ -n $venv && -x $venv/bin/python ]] || { echo "schema: venv '${venv}' missing (no install during run; fail closed)"; return 1; }
  "$venv/bin/python" spec/validate/validate.py --quiet
  "$venv/bin/python" -m unittest discover -s spec/validate -v
}
run_step schema schema

# validate.yml "validate": no private issue references, plus the guard's fixtures
private_refs() {
  bash scripts/check-no-private-refs.sh
  bash scripts/tests/private_refs_check.sh
}
run_step private-refs private_refs

# validate.yml "musl": the binary must be rebuilt in this run
musl() {
  local bin=$target_dir/x86_64-unknown-linux-musl/release/vaikor stamp
  command -v musl-gcc >/dev/null || { echo "musl-gcc missing"; return 1; }
  rm -f "$bin"; stamp=$(mktemp)
  cargo build --manifest-path "$manifest" --locked --release -j "$jobs" \
    --target x86_64-unknown-linux-musl -p vaikor-guard
  [[ $bin -nt $stamp ]] || { rm -f "$stamp"; echo "musl: $bin not rebuilt in this run"; return 1; }
  rm -f "$stamp"
  ldd "$bin" 2>&1 | grep -q 'statically linked'
}
run_step musl musl

# rust-ci.yml "gitleaks"
gl=${GITLEAKS:-gitleaks}
leaks() {
  command -v "$gl" >/dev/null || { echo "gitleaks not found (mandatory)"; return 1; }
  "$gl" git --redact --verbose --exit-code 1 --log-opts="-m ${main_sha}..${head_sha}" .
}
run_step gitleaks leaks

# validate.yml "dco"
dco() {
  local s=0 sha shas
  shas=$(git rev-list "${main_sha}..${head_sha}")
  for sha in $shas; do
    git log -1 --format=%B "$sha" | grep -q '^Signed-off-by: ' || { echo "Commit $sha has no Signed-off-by line"; s=1; }
  done
  return $s
}
run_step dco dco

if command -v actionlint >/dev/null; then run_step actionlint actionlint
else skip_step actionlint "actionlint not installed (not part of CI)"; fi

echo; echo "ci-local summary for $head_sha"
for i in "${!names[@]}"; do printf '  %-13s %-9s %4ss\n' "${names[$i]}" "${results[$i]}" "${times[$i]}"; done
if [[ $failed -ne 0 ]]; then echo "ci-local: RED"; exit 1; fi
echo "ci-local: GREEN"
