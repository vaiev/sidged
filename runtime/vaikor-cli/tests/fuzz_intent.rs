// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Mutation fuzzing of the untrusted model boundary: linguist replies (0017 L2-L7), the
//! intent plans the Core builds from them (§2b) and the node's time and duration readers
//! (X6). Seeded from the hand-written probes (`runtime/fuzz/mutate.rs`).

use std::path::PathBuf;
use std::time::Duration;

use chrono::{TimeZone, Utc};
use serde_json::Value;
use vaikor_cli::intent_plan::plan_for_intent;
use vaikor_cli::linguist::{IntentCatalog, Ordered};
use vaikor_cli::node_exec::duration_seconds;
use vaikor_cli::turnkey::default_catalog;
use vaikor_cli::when;
use vaikor_verify::flow::CedarFlowPolicy;

#[path = "../../fuzz/mutate.rs"]
mod mutate;

const OWNER: &str = "did:key:z6MkwSD8dBdqcXQzKJZQFPy2hh2izzxskndKCjdmC2dBpfME";

/// (utterance, Core-derived envelope) for every probe with an intent.
fn seeds(catalog: &IntentCatalog) -> Vec<(String, Value)> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../local-training/linguist_probes.json");
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut seeds = Vec::new();
    for probe in file["probes"].as_array().unwrap() {
        let utterance = probe["u"].as_str().unwrap().to_string();
        let slots = Ordered(
            probe["slots"]
                .as_object()
                .into_iter()
                .flatten()
                // A null slot is unchecked by the probe (free text): not part of the seed.
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                .collect(),
        );
        if let Ok(envelope) = catalog.derive("gsw", probe["intent"].as_str(), &slots) {
            seeds.push((utterance, serde_json::to_value(envelope).unwrap()));
        }
    }
    seeds
}

#[test]
fn mutated_linguist_replies_are_verified_and_planned_without_panicking() {
    let catalog = IntentCatalog::builtin().unwrap();
    let capabilities = default_catalog();
    let flow = CedarFlowPolicy::default_set();
    let seeds = seeds(&catalog);
    assert!(seeds.len() > 20);
    mutate::run(
        mutate::iterations(3000),
        Duration::from_secs(2),
        |case, rng| {
            let (utterance, mut envelope) = seeds[case % seeds.len()].clone();
            mutate::mutate(&mut envelope, rng);
            let mut raw = envelope.to_string();
            if rng.below(4) == 0 {
                raw = mutate::mutate_text(&raw, rng);
            }
            let utterance = if rng.below(2) == 0 {
                mutate::mutate_text(&utterance, rng)
            } else {
                utterance
            };
            (utterance, raw)
        },
        |(utterance, raw)| {
            let _ = catalog.verify_proposal(raw);
            if let Ok(verified) = catalog.verify_proposal_for(utterance, raw) {
                if !verified.envelope.clarification_needed {
                    let _ = plan_for_intent(&catalog, &verified, &capabilities, &flow, OWNER);
                }
            }
        },
    );
}

#[test]
fn mutated_time_and_duration_words_are_read_or_refused() {
    let words = [
        "morn am füfi",
        "hüt am Aabe",
        "am Mäntigmorge",
        "inere haube Stund",
        "tomorrow at 8",
        "morgen um halb neun",
        "in 10 Minuten",
        "um viertel vor 8",
        "am Friitig am 9i",
        "next Monday at 5pm",
        "speter am 20:15",
        "10 Minuten",
        "e haubi Stund",
        "PT1H30M",
        "1 Stunde und 30 Minuten",
        "zwo Stund",
        "an hour and a half",
    ];
    let tz = when::parse_timezone("Europe/Zurich").unwrap();
    let now = Utc.with_ymd_and_hms(2026, 10, 25, 0, 30, 0).unwrap();
    mutate::run(
        mutate::iterations(20000),
        Duration::from_secs(1),
        |case, rng| mutate::mutate_text(words[case % words.len()], rng),
        |text| {
            if let Some(due) = when::resolve(text, now, tz) {
                assert!(
                    due.with_timezone(&Utc) > now,
                    "{text:?} resolved into the past"
                );
            }
            let _ = duration_seconds(text);
            let _ = when::parse_timezone(text);
        },
    );
}
