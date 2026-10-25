// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Mutation fuzzing of the 0012 dCBOR codec and signed-record checks, seeded from the shared
//! record vectors (`runtime/fuzz/mutate.rs`).

use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;
use vaikor_record::{decode, encode, Record};

#[path = "../../fuzz/mutate.rs"]
mod mutate;

fn vectors() -> Vec<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/test-vectors/records/records.json");
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    file["vectors"].as_array().unwrap().clone()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// Canonical encodings of every vector value, plus the decode inputs.
fn byte_seeds() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    for vector in vectors() {
        if let Some(text) = vector["input"]["hex"].as_str() {
            seeds.push(hex(text));
        }
        for value in [&vector["input"]["value"], &vector["input"]["record"]] {
            if let Ok(bytes) = encode(value) {
                seeds.push(bytes);
            }
        }
    }
    seeds
}

#[test]
fn mutated_bytes_decode_only_to_their_own_canonical_form() {
    let seeds = byte_seeds();
    mutate::run(
        mutate::iterations(20000),
        Duration::from_secs(1),
        |case, rng| {
            let mut bytes = seeds[case % seeds.len()].clone();
            mutate::mutate_bytes(&mut bytes, rng);
            bytes
        },
        |bytes| {
            if let Ok(value) = decode(bytes) {
                assert_eq!(
                    &encode(&value).unwrap(),
                    bytes,
                    "accepted a non-canonical form"
                );
            }
        },
    );
}

#[test]
fn mutated_trees_round_trip_or_are_refused() {
    let seeds: Vec<Value> = vectors()
        .iter()
        .flat_map(|v| [v["input"]["value"].clone(), v["input"]["record"].clone()])
        .filter(|v| !v.is_null())
        .collect();
    mutate::run(
        mutate::iterations(20000),
        Duration::from_secs(1),
        |case, rng| {
            let mut value = seeds[case % seeds.len()].clone();
            mutate::mutate(&mut value, rng);
            value
        },
        |value| {
            if let Ok(bytes) = encode(value) {
                assert_eq!(
                    &decode(&bytes).unwrap(),
                    value,
                    "round trip changed the tree"
                );
            }
        },
    );
}

#[test]
fn nesting_beyond_the_limit_is_refused_without_recursing_into_it() {
    // 100 000 nested one-element arrays, then null: refused at depth 129, not a stack overflow.
    let mut bytes = vec![0x81; 100_000];
    bytes.push(0xf6);
    assert!(decode(&bytes).is_err());
    // A length prefix far beyond the input is refused before any allocation.
    assert!(decode(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
    assert!(decode(&[0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
}

#[test]
fn mutated_records_are_checked_without_panicking() {
    let seeds: Vec<Value> = vectors()
        .iter()
        .filter(|v| v["operation"] == "record-check")
        .map(|v| v["input"].clone())
        .collect();
    mutate::run(
        mutate::iterations(4000),
        Duration::from_secs(1),
        |case, rng| {
            let mut input = seeds[case % seeds.len()].clone();
            mutate::mutate(&mut input, rng);
            input
        },
        |input| {
            let keys: Vec<String> = input["trusted_core_keys"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|k| k.as_str().map(str::to_string))
                .collect();
            if let Ok(record) = Record::check(input["record"].clone(), &keys) {
                let _ = (record.digest(), record.resource(), record.expired());
            }
            let _ = Record::parse(input["record"].clone());
        },
    );
}
