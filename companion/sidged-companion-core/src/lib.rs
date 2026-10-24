// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Sidged companion core (WP 7): the pure-Rust part of the desktop and Android nodes.
//!
//! There is no fixed app view. A surface is assembled from the `@vaiev/ui` v4 catalog
//! (`ui/a2ui-catalog.v4.json`) and the data it shows: capability `input_schema` and
//! `output_schema`, intent-catalog slots for a clarification, or a signed artifact
//! record. The Tauri shells only forward the allowlisted commands of [`commands`].

pub mod catalog;
pub mod commands;
/// The JSON Schema subset validator lives in the runtime (`sidged-capability::schema`).
pub use sidged_capability::schema;
pub mod surface;
