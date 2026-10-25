// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! `intent.run` audits before it acts (invariant 9, ROADMAP 11e): with an audit log that
//! does not verify, the companion refuses the run and the node state stays untouched.

use serde_json::json;
use vaikor_companion_core::commands::CompanionCore;

#[test]
fn intent_run_with_a_corrupt_audit_log_refuses_before_the_first_effect() {
    let dir = std::env::temp_dir().join(format!("vaikor-companion-audit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let core = CompanionCore::with_workspace(dir.clone()).unwrap();
    core.dispatch("node.init", &json!({})).unwrap();
    let log = dir.join("logs").join("audit.log");
    let bad = format!("{} {} {{}}\n", "0".repeat(64), "ab".repeat(64));
    std::fs::write(&log, &bad).unwrap();

    let timer = json!({"lang": "en", "intent": "timer.set",
                       "slots": {"duration": "10 minutes", "label": "the tea"}});
    let err = core.dispatch("intent.run", &timer).unwrap_err();
    assert!(err.contains("signature"), "{err}");
    assert!(!dir.join("timers.json").exists(), "a timer was started");
    assert!(!dir.join("records/latest-record.json").exists());
    assert_eq!(std::fs::read_to_string(&log).unwrap(), bad);

    // A verifying log lets the same intent run, and it is audited.
    std::fs::write(&log, "").unwrap();
    let run = core.dispatch("intent.run", &timer).unwrap();
    assert_eq!(run["summary"]["steps_executed"], 1, "{run}");
    assert!(dir.join("timers.json").exists());
    let text = std::fs::read_to_string(&log).unwrap();
    let decisions: Vec<String> = text
        .lines()
        .map(|line| {
            let payload: serde_json::Value =
                serde_json::from_str(line.splitn(3, ' ').nth(2).unwrap()).unwrap();
            payload["decision"].as_str().unwrap().to_string()
        })
        .collect();
    // The task token's acceptance and the step's reservation precede its decision (0002 §6a).
    assert_eq!(decisions, ["allow", "spend", "allow", "completed"]);
    let _ = std::fs::remove_dir_all(&dir);
}
