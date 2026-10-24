// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Mutation fuzzing of capability tokens: structure, attenuation, signatures and holder
//! binding (SDG-L2), seeded from the shared token and signature vectors
//! (`runtime/fuzz/mutate.rs`). A presented token is untrusted input from another device.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;
use sidged_grant::{accept_presented, parse_rfc3339_z, resolve_did_key, structural_token};

#[path = "../../fuzz/mutate.rs"]
mod mutate;

fn seeds() -> Vec<Value> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors");
    let mut seeds = Vec::new();
    for file in [
        "tokens/narrowing.json",
        "tokens/lifetime.json",
        "tokens/budget-constraints.json",
        "signatures/token-chain.json",
    ] {
        let text = std::fs::read_to_string(root.join(file)).unwrap();
        let vectors: Value = serde_json::from_str(&text).unwrap();
        for vector in vectors["vectors"].as_array().unwrap() {
            seeds.push(vector["input"]["token"].clone());
        }
    }
    seeds
}

fn root_of(token: &Value) -> Option<&str> {
    token["chain"][0]["iss"].as_str().or(token["iss"].as_str())
}

#[test]
fn mutated_tokens_are_checked_without_panicking() {
    let seeds = seeds();
    assert!(seeds.len() > 5);
    mutate::run(
        mutate::iterations(5000),
        Duration::from_secs(1),
        |case, rng| {
            let mut token = seeds[case % seeds.len()].clone();
            mutate::mutate(&mut token, rng);
            token
        },
        |token| {
            let _ = structural_token(token);
            let roots: Vec<&str> = root_of(token).into_iter().collect();
            let _ = accept_presented(token, "2026-10-21T00:00:00Z", &roots);
        },
    );
}

#[test]
fn mutated_identifiers_and_times_are_parsed_without_panicking() {
    let seeds = [
        "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
        "2026-10-21T00:00:00Z",
        "2026-02-28T23:59:60Z",
    ];
    mutate::run(
        mutate::iterations(20000),
        Duration::from_secs(1),
        |case, rng| mutate::mutate_text(seeds[case % seeds.len()], rng),
        |text| {
            let _ = resolve_did_key(text);
            let _ = parse_rfc3339_z(text);
        },
    );
}
