// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Audit before effect on the `sidged task` / companion path (invariant 9, ROADMAP 11e):
//! the audit chain is opened and verified before the first step, each step's decision is
//! appended before its effect and its outcome after it. A log that cannot be written stops
//! the run before anything happens. Every check looks at the node's state on disk.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sidged_cli::linguist::{IntentCatalog, LinguistModel, Ordered, VerifiedIntent};
use sidged_cli::turnkey::{bootstrap_workspace, execute_turnkey_task_with, run_verified_intent};
use sidged_log::Chain;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sidged-audit-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    bootstrap_workspace(&dir).unwrap();
    dir
}

fn envelope(intent: &str, slots: &[(&str, &str)]) -> String {
    let slots = Ordered(
        slots
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    );
    let envelope = IntentCatalog::builtin()
        .unwrap()
        .derive("en", Some(intent), &slots)
        .unwrap();
    serde_json::to_string(&envelope).unwrap()
}

fn verified(intent: &str, slots: &[(&str, &str)]) -> VerifiedIntent {
    IntentCatalog::builtin()
        .unwrap()
        .verify_proposal(&envelope(intent, slots))
        .unwrap()
}

fn timer() -> VerifiedIntent {
    verified(
        "timer.set",
        &[("duration", "10 minutes"), ("label", "the tea")],
    )
}

fn note() -> VerifiedIntent {
    verified("task.note", &[("content", "buy milk")])
}

fn run(
    dir: &Path,
    intent: &VerifiedIntent,
) -> Result<sidged_cli::turnkey::TurnkeyTaskSummary, String> {
    run_verified_intent(dir, &IntentCatalog::builtin().unwrap(), intent)
}

fn log_path(dir: &Path) -> PathBuf {
    dir.join("logs").join("audit.log")
}

fn log_seed(dir: &Path) -> [u8; 32] {
    let text = fs::read_to_string(dir.join("keys/log.key")).unwrap();
    let text = text.trim();
    let mut seed = [0u8; 32];
    for (i, slot) in seed.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap();
    }
    seed
}

/// Nothing a step could have done is on disk: no timer, no note, no record of a run.
fn assert_no_effects(dir: &Path) {
    assert!(!dir.join("timers.json").exists(), "a timer was started");
    assert!(
        !dir.join("files/notes/inbox.md").exists(),
        "a note was written"
    );
    assert!(
        !dir.join("records/latest-record.json").exists(),
        "a run record was signed"
    );
}

struct OneReply(String);

impl LinguistModel for OneReply {
    fn propose(&self, _system: &str, _user: &str) -> Result<String, String> {
        Ok(self.0.clone())
    }
}

#[test]
fn a_locked_audit_log_refuses_the_task_before_the_first_effect() {
    let dir = scratch("locked");
    let held = Chain::open(&log_path(&dir), &log_seed(&dir)).unwrap();

    let err = run(&dir, &timer()).unwrap_err();
    assert!(err.contains("locked"), "{err}");
    let err = run(&dir, &note()).unwrap_err();
    assert!(err.contains("locked"), "{err}");
    // `sidged task` goes the same way.
    let model = OneReply(envelope("timer.set", &[("duration", "10 minutes")]));
    let err = execute_turnkey_task_with(&dir, "set a timer", false, &model).unwrap_err();
    assert!(err.contains("locked"), "{err}");
    assert_no_effects(&dir);

    drop(held);
    assert_eq!(fs::read_to_string(log_path(&dir)).unwrap(), "");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_corrupt_audit_log_refuses_the_task_before_the_first_effect() {
    let dir = scratch("corrupt");
    let bad = format!("{} {} {{}}\n", "0".repeat(64), "ab".repeat(64));
    fs::write(log_path(&dir), &bad).unwrap();

    let err = run(&dir, &timer()).unwrap_err();
    assert!(err.contains("signature"), "{err}");
    let err = run(&dir, &note()).unwrap_err();
    assert!(err.contains("signature"), "{err}");
    assert_no_effects(&dir);
    // The log stays as it was found: nothing is appended to a chain that does not verify.
    assert_eq!(fs::read_to_string(log_path(&dir)).unwrap(), bad);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn an_unwritable_audit_log_directory_refuses_the_task_before_the_first_effect() {
    let dir = scratch("unwritable");
    let logs = dir.join("logs");
    fs::remove_file(log_path(&dir)).unwrap();
    fs::set_permissions(&logs, fs::Permissions::from_mode(0o500)).unwrap();
    // A process that ignores directory permissions (root) cannot exercise this case.
    let probe = logs.join("probe");
    if fs::write(&probe, "").is_ok() {
        let _ = fs::remove_file(probe);
        fs::set_permissions(&logs, fs::Permissions::from_mode(0o700)).unwrap();
        let _ = fs::remove_dir_all(dir);
        eprintln!("skipped: directory permissions are not enforced for this user");
        return;
    }

    let result = run(&dir, &timer());
    let note_result = run(&dir, &note());
    fs::set_permissions(&logs, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err(), "{result:?}");
    assert!(note_result.is_err(), "{note_result:?}");
    assert_no_effects(&dir);
    assert!(!log_path(&dir).exists());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn every_executed_step_has_its_decision_before_its_outcome_in_a_verifying_log() {
    let dir = scratch("order");
    fs::create_dir_all(dir.join("files")).unwrap();
    fs::write(dir.join("files/report.md"), "quarterly numbers").unwrap();

    let summary = run(&dir, &timer()).unwrap();
    assert_eq!(summary.steps_executed, 1);
    assert!(dir.join("timers.json").exists());
    let noted = run(&dir, &note()).unwrap();
    // share.offer: the read runs, the send is consequential and `sidged task` has no
    // Trusted UI, so it is denied and audited as a denial, with no outcome.
    let share = run(
        &dir,
        &verified(
            "share.offer",
            &[("item", "report.md"), ("recipient", "Anna")],
        ),
    )
    .unwrap();
    let statuses: Vec<&str> = share.steps.iter().map(|s| s.status.as_str()).collect();
    assert_eq!(statuses, ["completed", "denied"]);

    let public = sidged_log::public_key(&log_seed(&dir));
    let count = sidged_log::verify_file(&log_path(&dir), &public).unwrap();
    let events = sidged_log::read_events(&log_path(&dir), &public).unwrap();
    assert_eq!(count, events.len());
    let kinds: Vec<(&str, &str, &str)> = events
        .iter()
        .map(|e| {
            (
                e.capability.trim_start_matches("urn:sidged:capability:"),
                e.step.as_str(),
                e.decision.as_str(),
            )
        })
        .collect();
    let read_step = share.steps[0].id.as_str();
    let send_step = share.steps[1].id.as_str();
    let timer_step = summary.steps[0].id.as_str();
    let note_step = noted.steps[0].id.as_str();
    // Each run opens with the Core's acceptance of its task token, and each step's grant
    // reservation precedes its decision (0002 §6a); the denied send reserves nothing.
    assert_eq!(
        kinds,
        [
            ("urn:sidged:grant", "grant", "allow"),
            ("timer.start", timer_step, "spend"),
            ("timer.start", timer_step, "allow"),
            ("timer.start", timer_step, "completed"),
            ("urn:sidged:grant", "grant", "allow"),
            ("notes.append", note_step, "spend"),
            ("notes.append", note_step, "allow"),
            ("notes.append", note_step, "completed"),
            ("urn:sidged:grant", "grant", "allow"),
            ("workspace.read", read_step, "spend"),
            ("workspace.read", read_step, "allow"),
            ("workspace.read", read_step, "completed"),
            ("message.send", send_step, "deny"),
        ]
    );
    // The decision names the capability's effects; the denial carries the 0004 R11 fields.
    assert_eq!(events[2].effects, ["write"]);
    assert_eq!(events[2].actor, "core");
    let denial = events.last().unwrap();
    let approval = denial.approval.as_ref().expect("R11 approval fields");
    assert_eq!(approval.attestation, "none");
    assert_eq!(approval.approval_binding, "none");
    assert!(denial.reason.as_deref().unwrap().contains("Trusted UI"));
    let _ = fs::remove_dir_all(dir);
}
