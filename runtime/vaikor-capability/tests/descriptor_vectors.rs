// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! The Core's registry against the shared descriptor vectors (0001 R1-R11, R20): a descriptor
//! the vectors refuse must not load.

use std::path::PathBuf;

use serde_json::{json, Value};
use vaikor_capability::Registry;

#[test]
fn shared_descriptor_vectors_match() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/test-vectors/capability/descriptor.json");
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for vector in file["vectors"].as_array().unwrap() {
        let loaded = Registry::from_descriptors(&json!([vector["input"]["descriptor"]]));
        let result = if loaded.is_ok() { "accept" } else { "refuse" };
        assert_eq!(
            result,
            vector["expected"]["result"],
            "{} {:?}",
            vector["id"],
            loaded.err()
        );
    }
}
