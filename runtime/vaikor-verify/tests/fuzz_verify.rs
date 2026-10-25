// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Mutation fuzzing of the stored-plan parser, the VKR-L3 verifier and the Cedar flow stage,
//! seeded from every shared plan vector (`runtime/fuzz/mutate.rs`).

use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;
use vaikor_verify::flow::{check_json_plan_flows, CedarFlowPolicy};
use vaikor_verify::{stored, DeferToCedar, DenySensitive};

#[path = "../../fuzz/mutate.rs"]
mod mutate;

fn seeds() -> Vec<Value> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors/plan/verify.json");
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    file["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|vector| vector["input"].clone())
        .collect()
}

#[test]
fn mutated_plans_and_catalogs_never_panic_the_verifier() {
    let seeds = seeds();
    let flow = CedarFlowPolicy::default_set();
    mutate::run(
        mutate::iterations(4000),
        Duration::from_secs(2),
        |case, rng| {
            let mut input = seeds[case % seeds.len()].clone();
            mutate::mutate(&mut input, rng);
            input
        },
        |input| {
            let _ =
                check_json_plan_flows(&input["plan"], &input["catalog"], "did:key:z6Mkfuzz", &flow);
            let _ = stored::plan_digest(&input["plan"]);
            let (Ok(plan), Ok(catalog)) = (
                stored::parse_plan(&input["plan"]),
                stored::parse_catalog(&input["catalog"]),
            ) else {
                return;
            };
            let _ = vaikor_verify::verify(&plan, &catalog, &DenySensitive);
            let _ = vaikor_verify::verify(&plan, &catalog, &DeferToCedar);
        },
    );
}
