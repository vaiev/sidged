// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Runner for the shared intent vectors (`spec/test-vectors/intent/linguist.json`, 0017 L1-L7,
//! PL1-PL5, X6). `SIDGED_REGEN_VECTORS=1` writes the actual results as `expected` (review the
//! diff before committing it); otherwise every vector must match.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sidged_cli::intent_plan::{check_plan, plan_for_intent};
use sidged_cli::linguist::IntentCatalog;
use sidged_cli::node_exec::duration_seconds;
use sidged_cli::turnkey::default_catalog;
use sidged_cli::when;
use sidged_verify::flow::CedarFlowPolicy;

const OWNER: &str = "did:key:z6MkwSD8dBdqcXQzKJZQFPy2hh2izzxskndKCjdmC2dBpfME";

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors/intent/linguist.json")
}

fn raw_reply(input: &Value) -> String {
    match input.get("reply_text").and_then(Value::as_str) {
        Some(text) => text.to_string(),
        None => input["reply"].to_string(),
    }
}

fn actual(catalog: &IntentCatalog, vector: &Value) -> Value {
    let input = &vector["input"];
    let verify = || match input["utterance"].as_str() {
        Some(utterance) => catalog.verify_proposal_for(utterance, &raw_reply(input)),
        None => catalog.verify_proposal(&raw_reply(input)),
    };
    match vector["operation"].as_str().unwrap() {
        "linguist-verify" => match verify() {
            Ok(verified) => json!({"value": {
                "envelope": verified.envelope,
                "corrections": verified.corrections,
            }}),
            Err(_) => json!({"result": "refuse"}),
        },
        "intent-plan" => {
            let Ok(verified) = verify() else {
                return json!({"value": {"verdict": "refuse", "stage": "envelope"}});
            };
            let capabilities = default_catalog();
            let flow = CedarFlowPolicy::default_set();
            let checked = match input.get("plan") {
                Some(plan) => check_plan(
                    plan.clone(),
                    catalog,
                    &verified,
                    &capabilities,
                    &flow,
                    OWNER,
                ),
                None => plan_for_intent(catalog, &verified, &capabilities, &flow, OWNER),
            };
            match checked {
                Ok(plan) => json!({"value": {"verdict": "accept", "plan_digest": plan.digest}}),
                Err(refusal) => json!({"value": {"verdict": "refuse", "stage": refusal.stage}}),
            }
        }
        "time-resolve" => {
            let now: DateTime<Utc> = input["now"].as_str().unwrap().parse().unwrap();
            let tz = when::parse_timezone(input["tz"].as_str().unwrap()).unwrap();
            let instant = when::resolve(input["text"].as_str().unwrap(), now, tz);
            json!({"value": instant.map(|t| t.to_rfc3339())})
        }
        "duration-read" => json!({"value": duration_seconds(input["text"].as_str().unwrap())}),
        other => panic!("unknown operation {other}"),
    }
}

#[test]
fn shared_intent_vectors_match() {
    let catalog = IntentCatalog::builtin().unwrap();
    let mut file: Value = serde_json::from_str(&std::fs::read_to_string(path()).unwrap()).unwrap();
    let regen = std::env::var_os("SIDGED_REGEN_VECTORS").is_some();
    for vector in file["vectors"].as_array_mut().unwrap() {
        let got = actual(&catalog, vector);
        if regen {
            // Keep the file's member order: expected goes before status.
            let status = vector["status"].take();
            let note = vector["note"].take();
            let object = vector.as_object_mut().unwrap();
            object.remove("status");
            object.remove("note");
            object.insert("expected".into(), got);
            object.insert("status".into(), status);
            object.insert("note".into(), note);
        } else {
            assert_eq!(got, vector["expected"], "{}", vector["id"]);
        }
    }
    if regen {
        let text = serde_json::to_string_pretty(&file).unwrap() + "\n";
        std::fs::write(path(), text).unwrap();
    }
}
