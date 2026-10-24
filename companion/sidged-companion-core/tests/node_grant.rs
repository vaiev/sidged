// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! `intent.run` runs a plan only under the node's owner mandate (invariant 2, 0002 §6a,
//! ROADMAP 11f): a node without one, or with one that does not allow the plan, runs no step.

use serde_json::json;
use sidged_cli::turnkey::{issue_workspace_mandate, MANDATE_FILE};
use sidged_companion_core::commands::CompanionCore;

fn decisions(dir: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(dir.join("logs").join("audit.log"))
        .unwrap()
        .lines()
        .map(|line| {
            let payload: serde_json::Value =
                serde_json::from_str(line.splitn(3, ' ').nth(2).unwrap()).unwrap();
            payload["decision"].as_str().unwrap().to_string()
        })
        .collect()
}

#[test]
fn intent_run_refuses_without_a_mandate_or_outside_it_and_runs_inside_it() {
    let dir = std::env::temp_dir().join(format!("sidged-companion-grant-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let core = CompanionCore::with_workspace(dir.clone()).unwrap();
    core.dispatch("node.init", &json!({})).unwrap();
    let mandate = std::fs::read(dir.join(MANDATE_FILE)).unwrap();
    let timer = json!({"lang": "en", "intent": "timer.set",
                       "slots": {"duration": "10 minutes", "label": "the tea"}});

    std::fs::remove_file(dir.join(MANDATE_FILE)).unwrap();
    let err = core.dispatch("intent.run", &timer).unwrap_err();
    assert!(err.contains("no owner mandate"), "{err}");
    assert!(!dir.join("timers.json").exists(), "a timer was started");
    assert!(!dir.join("records/latest-record.json").exists());
    assert_eq!(decisions(&dir), ["deny"]);

    // A mandate that allows only notes does not cover the timer.
    issue_workspace_mandate(
        &dir,
        vec![json!({"action": "notes.append",
                    "resource": "urn:sidged:capability:notes.append"})],
        json!({"messages": 10}),
        &sidged_gateway::utc_stamp(),
        3600,
    )
    .unwrap();
    let err = core.dispatch("intent.run", &timer).unwrap_err();
    assert!(err.contains("the mandate does not allow"), "{err}");
    assert!(!dir.join("timers.json").exists(), "a timer was started");
    assert_eq!(decisions(&dir), ["deny", "deny"]);

    // The owner's mandate from init lets it run, reserved before the effect.
    std::fs::write(dir.join(MANDATE_FILE), mandate).unwrap();
    let run = core.dispatch("intent.run", &timer).unwrap();
    assert_eq!(run["summary"]["steps_executed"], 1, "{run}");
    assert!(dir.join("timers.json").exists());
    assert_eq!(
        decisions(&dir),
        ["deny", "deny", "allow", "spend", "allow", "completed"]
    );
    let _ = std::fs::remove_dir_all(&dir);
}
