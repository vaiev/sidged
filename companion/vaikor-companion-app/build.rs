// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
fn main() {
    // The webview may call exactly one app command; see capabilities/default.json.
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(&["companion"])),
    )
    .expect("tauri build script");
}
