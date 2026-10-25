// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
// Prevents an additional console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    vaikor_companion_app_lib::run();
}
