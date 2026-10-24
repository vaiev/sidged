// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! `sidged task` end to end on a bootstrapped node: catalog plans on the real executors,
//! and a signed record of exactly what happened.

use std::fs;
use std::path::PathBuf;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sidged-turnkey-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Recorded Model -1 answers: each utterance maps to the envelope the model gave for it.
/// The Core re-derives everything except lang, intent and slots, so the test exercises the
/// real catalog path without a model process.
struct RecordedLinguist {
    replies: Vec<(&'static str, String)>,
}

impl sidged_cli::linguist::LinguistModel for RecordedLinguist {
    fn propose(&self, _system: &str, user: &str) -> Result<String, String> {
        let utterance = user
            .rsplit_once("\nUtterance: ")
            .map(|(_, u)| u)
            .unwrap_or("");
        self.replies
            .iter()
            .find(|(u, _)| *u == utterance)
            .map(|(_, reply)| reply.clone())
            .ok_or_else(|| format!("no recorded reply for {utterance:?}"))
    }
}

fn recorded(lang: &str, intent: Option<&str>, slots: &[(&str, &str)]) -> String {
    use sidged_cli::linguist::{IntentCatalog, Ordered};
    let slots = Ordered(
        slots
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    );
    let envelope = IntentCatalog::builtin()
        .unwrap()
        .derive(lang, intent, &slots)
        .unwrap();
    serde_json::to_string(&envelope).unwrap()
}

#[test]
fn turnkey_task_runs_catalog_plans_on_real_executors_and_signs_only_real_outcomes() {
    use sidged_cli::turnkey::{
        bootstrap_workspace, execute_turnkey_task, execute_turnkey_task_with,
    };

    let dir = scratch("wp5-turnkey");
    let manifest = bootstrap_workspace(&dir).unwrap();
    assert!(
        manifest.worker_dids.is_empty(),
        "a new node enrolls no edges by itself"
    );

    // Without a configured Model -1 there is no keyword fallback.
    let err = execute_turnkey_task(&dir, "schick es", false).unwrap_err();
    assert!(err.starts_with("model-not-configured"), "{err}");

    let model = RecordedLinguist {
        replies: vec![
            ("schick es", recorded("gsw", None, &[])),
            (
                "Schreib eine E-Mail an Anna mit dem Architektur-Update",
                recorded(
                    "de",
                    Some("messaging.send"),
                    &[("recipient", "Anna"), ("topic", "Architektur-Update")],
                ),
            ),
            (
                "Create a Rust parser module and unit tests",
                recorded(
                    "en",
                    Some("task.code"),
                    &[
                        ("description", "a parser module with unit tests"),
                        ("language", "Rust"),
                    ],
                ),
            ),
            (
                "Stell en Timer uf 10 Minute für de Tee",
                recorded(
                    "gsw",
                    Some("timer.set"),
                    &[("duration", "10 minutes"), ("label", "the tea")],
                ),
            ),
        ],
    };

    // An ambiguous utterance asks locally in the user's language and wakes nothing:
    let clarify = execute_turnkey_task_with(&dir, "schick es", false, &model).unwrap();
    assert!(clarify.clarification_needed);
    assert_eq!(
        clarify.clarification_question.as_deref(),
        Some("Was genau söll ich mache?")
    );
    assert_eq!(clarify.steps_executed, 0);

    // A complete mail intent is planned from the catalog (draft, then send). This node has no
    // local generator model, so the draft step refuses honestly and the send never runs;
    // the signed record says exactly that.
    let mail_task = execute_turnkey_task_with(
        &dir,
        "Schreib eine E-Mail an Anna mit dem Architektur-Update",
        false,
        &model,
    )
    .unwrap();
    assert!(!mail_task.clarification_needed);
    assert_eq!(
        mail_task.canonical_intent,
        "Send a message to Anna about Architektur-Update"
    );
    assert_eq!(mail_task.steps_executed, 0);
    let statuses: Vec<&str> = mail_task.steps.iter().map(|s| s.status.as_str()).collect();
    assert_eq!(statuses, ["refused", "skipped"]);
    assert!(mail_task.steps[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("generator"));
    // The record is the store's immutable dCBOR entry (ROADMAP 11g).
    let record = sidged_record::decode(&fs::read(mail_task.record_path.unwrap()).unwrap()).unwrap();
    assert_eq!(
        record["content"]["summary"],
        "0 of 2 steps completed on this node"
    );

    // A local intent runs for real: the timer is in the node state with its end time.
    let timer_task = execute_turnkey_task_with(
        &dir,
        "Stell en Timer uf 10 Minute für de Tee",
        false,
        &model,
    )
    .unwrap();
    assert_eq!(timer_task.steps_executed, 1);
    let timers: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.join("timers.json")).unwrap()).unwrap();
    assert_eq!(timers[0]["duration"], "10 minutes");
    assert_eq!(timers[0]["label"], "the tea");
    let surface_text = fs::read_to_string(timer_task.surface_path.unwrap()).unwrap();
    let surface: serde_json::Value = serde_json::from_str(&surface_text).unwrap();
    assert_eq!(surface["component"], "ResultSurface");
    assert_eq!(surface["props"]["primitives"].as_array().unwrap().len(), 4);

    // There is no pretend cloud planning: --hybrid refuses until model-planned intents exist.
    let err = execute_turnkey_task_with(
        &dir,
        "Create a Rust parser module and unit tests",
        true,
        &model,
    )
    .unwrap_err();
    assert!(err.starts_with("hybrid-planning-unavailable"), "{err}");

    let _ = fs::remove_dir_all(dir);
}
