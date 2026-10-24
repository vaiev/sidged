# Sidged companion (WP 7): `sidged-desktop` and `sidged-android`

Status: v0.2 scaffold. Both nodes embed the Rust Core in-process through Tauri v2; there is no fixed app view.
A surface is assembled from the `@vaiev/ui` v4 catalog ([`../ui/a2ui-catalog.v4.json`](../ui/a2ui-catalog.v4.json))
and the data it shows:

| Source | Surface |
|---|---|
| capability `input_schema` (SDG-L1) | `input`: header, flow badge, `FormSurface` generated from the schema |
| capability result + `output_schema` | `output`: the first primitive whose catalog `binds` match the schema shape (`StepTimeline`, `DataTable`, `FormSurface` readonly) |
| linguist envelope with missing slots | `clarification`: the catalog question as header, one field per intent slot |
| signed artifact `ResultSurface` | `output`: `IntentHeader`, `FlowBadge`, `ArtifactCard`, `StepTimeline` |

Every surface is validated against the primitives' `props_schema` before it reaches the webview. The webview renders
surfaces; it never builds one.

## Layout

- `sidged-companion-core/`: pure Rust, no GUI dependency, fully tested in CI-like environments.
  - `catalog.rs`: catalog loading, `binds` matching, surface validation.
  - `schema.rs`: JSON Schema subset validator; unknown keywords fail closed.
  - `surface.rs`: the composer.
  - `commands.rs`: the IPC allowlist (`catalog.describe`, `node.status`, `node.init`, `intent.list`,
    `intent.run`, `linguist.prompt`, `linguist.run`, `linguist.verify`, `surface.capability_input`, `surface.capability_output`,
    `surface.input_submit`, `surface.clarification_submit`). No command approves, pairs or sends, and no command
    confirms a consequential step. `intent.run` runs a complete, Core-verified intent's catalog plan on this node
    (`sidged_cli::turnkey::run_verified_intent`, the same path as `sidged task`): consequential steps are denied, no
    capability token is checked yet, step outcomes are audited after the run, and the result record is signed. It
    writes workspace state: executor files and state under the workspace, the audit chain, the result record and
    surface, and the device time zone in `config.json`.
    `surface.input_submit` only validates and returns a `pending-plan` invocation for plan verification and the
    Core-owned Trusted UI. `node.init` is the initialization command: on first run it turns the app's data directory into
    a Sidged workspace (`sidged_cli::turnkey::bootstrap_workspace`), returns only public identifiers, and refuses once a
    node exists.
- `sidged-companion-app/`: Tauri v2 shell. One app crate, two products: `tauri.conf.json` (`sidged-desktop`) and
  `tauri.android.conf.json` (`sidged-android`). The webview may call exactly one command, `companion`
  (`build.rs` app manifest + `capabilities/default.json`). CSP: `connect-src ipc: http://ipc.localhost` only.
  `ui/` is plain JavaScript without a bundler; `scripts/tests/companion_ui_check.sh` enforces no network APIs, no
  HTML injection, no storage and no dialogs.

## Design and flow

The canvas uses @vaiev/ui v4 with the Sidged theme (accent "Sodium", dark only), the same files sidged.com serves
([`../ui/vaiev-ui`](../ui/vaiev-ui/SOURCE.md), copied to `ui/vendor/` and checked to be identical). Content is flat and
tonal; the navigation pill and the dock in the thumb zone are the one glass layer.

1. **Onboarding** (first run, no node yet): the black stage with a sodium glow and one glass card in three steps:
   what Sidged is, creating the local node (`node.init`), and the node's public owner identity.
2. **Home**: when the node has a local model endpoint, an intent bar asks Model -1 (`linguist.run`); the Core keeps
   only language, intent and slots and asks for what is missing in the detected language. Below it, one tile per intent of the intent catalog. A tile opens the clarification surface for its slots; when
   every required slot is given, the Core returns the canonical English intent and its route as a ready surface.
   "Run on this node" calls `intent.run`; consequential steps are denied there, because the webview is not a
   Trusted UI.
3. **Tools** (dock): the capabilities of a valid SDG-L1 workspace catalog, each with its schema-built form.

This workspace is separate from `runtime/`, so the runtime lock file and CI never depend on GUI toolchains. Tauri is
held at 2.11.x, the last line that builds with the repository toolchain (rustc 1.89).

## Toolchain (user-local, no sudo)

```
bash scripts/setup-companion-toolchain.sh --accept-android-licenses
. ~/.local/share/sidged-toolchain/env.sh
```

Installs a pinned, checksum-verified JDK 17, Android command-line tools, platform 35, build-tools 35.0.0, NDK r28c,
the Rust Android targets and `tauri-cli` 2.11.5. The Linux desktop build additionally needs WebKitGTK from the
distribution (the script prints the `apt` command).

## Model -1 on the desktop node

```
bash scripts/setup-companion-toolchain.sh --with-llama          # llama.cpp v0.6.0, commit-pinned, CPU
bash scripts/serve-local-linguist.sh <sidged-linguist-q8_0.gguf> \
    --workspace ~/.local/share/com.sidged.companion/workspace
cargo run --manifest-path companion/Cargo.toml -p sidged-companion-core --example ask -- \
    <workspace> "$XDG_RUNTIME_DIR/sidged/linguist.sock" "Erinner mi morn am achti a de Zahnarzttermin"
```

The desktop app starts the model itself when `<app data>/models/linguist.gguf` exists, using `SIDGED_LLAMA_SERVER` or
the toolchain's llama-server (same checks as on the phone, below). Started by hand, the server listens on a private
AF_UNIX socket only; `config.json` gets `model.endpoint` (`unix:<socket>`, uid), `model.output` from the GGUF and
mode 0600. Create the node first (onboarding or `node.init`). An AF_UNIX model endpoint with the peer-uid check is not
egress (0004 R9d), so it needs no local-mode latch.

## Model -1 on the phone (sidged-android)

```
PATH=<venv with cmake>/bin:$PATH bash scripts/build-android-linguist.sh   # libllama_server.so into jniLibs
cd companion/sidged-companion-app && cargo tauri android build --debug --apk --target aarch64
# weights (not bundled): a Q4_K_M GGUF of the deployed linguist, about 400 MB
adb push sidged-linguist-q4_k_m.gguf /data/local/tmp/linguist.gguf
adb shell 'run-as com.sidged.companion mkdir -p models && run-as com.sidged.companion cp /data/local/tmp/linguist.gguf models/linguist.gguf'
adb shell 'run-as com.sidged.companion chmod 700 models && run-as com.sidged.companion chmod 600 models/linguist.gguf'
adb shell rm /data/local/tmp/linguist.gguf      # run-as cp leaves the copy world-writable: hence the chmod
# optional pin: models/linguist.gguf.sha256 holds the expected SHA-256; a mismatch refuses to start
```

Install a GGUF exported by `local-training/release_gate.sh` (or stamped with `local-training/gguf_output_form.py`): the
weights declare the output form they were trained on in the metadata key `sidged.linguist.output` (0017 L3b, `compact`
or `full`; absent means full), so the pin covers it. Check before copying:
`python3 -I local-training/gguf_output_form.py read <model.gguf>`. A compact GGUF exported before the key (run 12 and
earlier) reads as full: stamp it with `gguf_output_form.py stamp --form compact <model.gguf>`, which changes its
SHA-256, then write the new pin.

At start the app checks the weights' SHA-256 (cached by size and mtime), runs the bundled server from its native
library directory on `<app data>/run/linguist.sock` (0700, no TCP port) and, once it answers, writes `model.endpoint`,
the app's uid, `model.digest` and `model.output` (from the key; left out for full) into the workspace `config.json`. A
GGUF that declares any other form is not started. The canvas shows the intent bar as soon as
`node.status` reports the model. Without weights the app offers the intent tiles only. A start error is kept in
`models/last-error.txt`.

Measured on a Galaxy S25-class phone with the run 6 weights: the socket is up 17 s after the first start (most of it the
one-time SHA-256 of 397 MB), then 1.2 to 1.7 s per utterance at about 65 generated tokens/s. The APK declares no
`INTERNET` permission (removed even if a library merges it in); the bundled canvas does not need it.

## Build and test

```
cargo test --manifest-path companion/Cargo.toml -p sidged-companion-core
bash scripts/tests/companion_ui_check.sh
cd companion/sidged-companion-app
cargo tauri dev                                            # desktop (needs WebKitGTK)
cargo tauri android build --debug --apk --target aarch64   # sidged-android
```

The node shows the capabilities in `catalog.json` of the workspace named by `SIDGED_WORKSPACE` (for example one made
by `sidged init --workspace <dir>`), or of `<app data>/workspace`.

## Not in this scaffold

Signed distribution of the weights (WP 25), hardware-bound approval (Android Keystore /
StrongBox, desktop OS credential gate), the mobile capabilities `mobile.camera.qr_scan`,
`mobile.audio.ptt_utterance` and `mobile.share.intake`, and the blind relay transport are later work packages.
