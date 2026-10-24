// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Mutation fuzzing of the surface validator (0017 C1/C2), the gate before a webview renders
//! anything. Seeded from the surfaces the companion builds for every capability and intent
//! (`runtime/fuzz/mutate.rs`). Whatever the validator accepts must still be within the
//! catalog's node and depth limits.

use std::time::Duration;

use serde_json::Value;
use sidged_cli::linguist::{IntentCatalog, Ordered};
use sidged_cli::turnkey::default_catalog;
use sidged_companion_core::catalog::A2uiCatalog;
use sidged_companion_core::surface;

#[path = "../../../runtime/fuzz/mutate.rs"]
mod mutate;

fn seeds(catalog: &A2uiCatalog) -> Vec<Value> {
    let intents = IntentCatalog::builtin().unwrap();
    let mut seeds = Vec::new();
    for descriptor in default_catalog().as_array().unwrap() {
        seeds.extend(surface::capability_input(catalog, descriptor).ok());
    }
    for entry in &intents.intents {
        let none = Ordered(Vec::new());
        let envelope = intents.derive("gsw", Some(&entry.intent), &none).unwrap();
        let verified = intents
            .verify_proposal(&serde_json::to_string(&envelope).unwrap())
            .unwrap();
        seeds.extend(surface::clarification(catalog, &intents, &verified).ok());
        seeds.extend(surface::intent_ready(catalog, &intents, &verified).ok());
    }
    seeds
}

fn depth_and_count(nodes: &Value, depth: usize, count: &mut usize) -> usize {
    let mut deepest = depth;
    for node in nodes.as_array().into_iter().flatten() {
        *count += 1;
        deepest = deepest.max(depth_and_count(&node["children"], depth + 1, count));
    }
    deepest
}

#[test]
fn mutated_surfaces_are_validated_without_panicking() {
    let catalog = A2uiCatalog::builtin().unwrap();
    let seeds = seeds(&catalog);
    assert!(seeds.len() > 10, "{} seeds", seeds.len());
    for seed in &seeds {
        assert!(
            catalog.validate_surface(seed).is_empty(),
            "seed rejected: {seed}"
        );
    }
    let limits: Value =
        serde_json::from_str(include_str!("../../../ui/a2ui-catalog.v4.json")).unwrap();
    let max_nodes = limits["limits"]["max_nodes"].as_u64().unwrap() as usize;
    let max_depth = limits["limits"]["max_depth"].as_u64().unwrap() as usize;
    mutate::run(
        mutate::iterations(5000),
        Duration::from_secs(2),
        |case, rng| {
            let mut surface = seeds[case % seeds.len()].clone();
            mutate::mutate(&mut surface, rng);
            surface
        },
        |surface| {
            if catalog.validate_surface(surface).is_empty() {
                let mut count = 0;
                let depth = depth_and_count(&surface["nodes"], 0, &mut count);
                assert!(
                    count <= max_nodes && depth <= max_depth,
                    "limits passed: {surface}"
                );
            }
        },
    );
}
