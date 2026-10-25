// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! No effect without a grant on `vaikor task` and the companion (invariant 2, 0002 §6a,
//! ROADMAP 11f). The node runs a plan only under a task token that a valid owner mandate
//! covers; every refusal is an audited denial and leaves nothing on disk.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use vaikor_cli::engine::Presenter;
use vaikor_cli::init::Terminal;
use vaikor_cli::linguist::{IntentCatalog, LinguistModel, Ordered, VerifiedIntent};
use vaikor_cli::node_grant::{default_mandate_rights, DEFAULT_MANDATE_MESSAGES};
use vaikor_cli::turnkey::{
    bootstrap_workspace, default_catalog, execute_turnkey_task_presented,
    execute_turnkey_task_with, issue_workspace_mandate, renew_mandate, run_verified_intent,
    run_verified_intent_presented, TurnkeyTaskSummary, GRANT_POLICY_FILE, MANDATE_FILE,
};
use vaikor_core::AuditEvent;
use zeroize::Zeroizing;

const TIMER: &str = "tag:vaikor.com,2026:capability:timer.start";
const NOTE: &str = "tag:vaikor.com,2026:capability:notes.append";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vaikor-grant-{name}-{}", std::process::id()));
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

struct OneReply(String);

impl LinguistModel for OneReply {
    fn propose(&self, _system: &str, _user: &str) -> Result<String, String> {
        Ok(self.0.clone())
    }
}

/// Both entry points: the companion's `run_verified_intent` and `vaikor task`.
#[derive(Clone, Copy, Debug)]
enum Entry {
    Companion,
    Task,
}

const ENTRIES: [Entry; 2] = [Entry::Companion, Entry::Task];

fn run_timer(dir: &Path, entry: Entry) -> Result<TurnkeyTaskSummary, String> {
    run_intent(dir, entry, "timer.set", &[("duration", "10 minutes")])
}

fn run_intent(
    dir: &Path,
    entry: Entry,
    intent: &str,
    slots: &[(&str, &str)],
) -> Result<TurnkeyTaskSummary, String> {
    match entry {
        Entry::Companion => run_verified_intent(
            dir,
            &IntentCatalog::builtin().unwrap(),
            &verified(intent, slots),
        ),
        Entry::Task => {
            // The Core keeps only slot values the utterance contains.
            let utterance: Vec<&str> = slots.iter().map(|(_, value)| *value).collect();
            let model = OneReply(envelope(intent, slots));
            execute_turnkey_task_with(dir, &utterance.join(" "), false, &model)
        }
    }
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

fn events(dir: &Path) -> Vec<AuditEvent> {
    let public = vaikor_log::public_key(&log_seed(dir));
    let path = dir.join("logs").join("audit.log");
    vaikor_log::verify_file(&path, &public).unwrap();
    vaikor_log::read_events(&path, &public).unwrap()
}

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

/// The run was refused before its first step: the error names `reason`, nothing happened
/// on disk, and the audit log ends with the Core's denial carrying that reason, with no
/// step decision after the log was last seen at `before` events.
fn assert_refused(
    dir: &Path,
    result: Result<TurnkeyTaskSummary, String>,
    reason: &str,
    before: usize,
) {
    let err = result.unwrap_err();
    assert!(err.contains(reason), "{err}");
    assert_no_effects(dir);
    let events = events(dir);
    let new = &events[before..];
    assert_eq!(new.len(), 1, "{new:?}");
    assert_eq!(new[0].decision, "deny");
    assert_eq!(new[0].actor, "core");
    assert_eq!(new[0].capability, "tag:vaikor.com,2026:grant");
    assert!(
        new[0].reason.as_deref().unwrap().contains(reason),
        "{new:?}"
    );
}

fn now() -> String {
    vaikor_gateway::utc_stamp()
}

fn default_rights() -> Vec<Value> {
    default_mandate_rights(&default_catalog())
}

#[test]
fn init_issues_a_private_owner_mandate_and_a_grant_policy_for_the_node() {
    let dir = scratch("init");
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap();
    let path = dir.join(MANDATE_FILE);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let mandate: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let parsed =
        vaikor_grant::verify_mandate(&mandate, manifest["owner_did"].as_str().unwrap(), &now())
            .unwrap();
    assert_eq!(parsed.executor, manifest["edge1_did"].as_str().unwrap());
    assert_eq!(parsed.aud, manifest["edge1_did"].as_str().unwrap());
    assert_eq!(parsed.budget.messages, Some(DEFAULT_MANDATE_MESSAGES));
    assert_eq!(mandate["rights"], json!(default_rights()));
    let iat = vaikor_grant::parse_rfc3339_z(&parsed.iat).unwrap();
    let exp = vaikor_grant::parse_rfc3339_z(&parsed.exp).unwrap();
    assert_eq!(exp - iat, 30 * 24 * 3600);

    let policy = fs::read_to_string(dir.join(GRANT_POLICY_FILE)).unwrap();
    assert!(policy.contains(manifest["edge1_did"].as_str().unwrap()));
    let cedar = vaikor_grant::CedarEvaluator::parse(&policy).unwrap();
    let context = |audience| vaikor_grant::AuthContext {
        audience,
        data_classes: &[],
        residency: &["CH"],
    };
    let node = manifest["edge1_did"].as_str().unwrap();
    assert!(cedar
        .permit(node, "timer.start", TIMER, context(node))
        .unwrap());
    assert!(!cedar
        .permit(node, "timer.start", TIMER, context("did:example:other"))
        .unwrap());
    // The flow policy stays as it was.
    assert_eq!(
        fs::read_to_string(dir.join("policy.cedar")).unwrap().trim(),
        vaikor_cli::turnkey::DEFAULT_TURNKEY_FLOW_POLICY.trim()
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn bootstrapping_an_existing_workspace_never_signs_a_mandate() {
    // Only the act that creates the owner key signs the first mandate; an existing workspace
    // without one is refused until the owner renews it on a terminal.
    let dir = scratch("rebootstrap");
    fs::remove_file(dir.join(MANDATE_FILE)).unwrap();
    bootstrap_workspace(&dir).unwrap();
    assert!(!dir.join(MANDATE_FILE).exists());
    // `vaikor task` bootstraps again when manifest.json is missing; that signs nothing either.
    fs::remove_file(dir.join("manifest.json")).unwrap();
    assert!(run_timer(&dir, Entry::Task).is_err());
    assert!(!dir.join(MANDATE_FILE).exists());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_node_without_a_mandate_runs_no_step() {
    for entry in ENTRIES {
        let dir = scratch(&format!("none-{entry:?}"));
        fs::remove_file(dir.join(MANDATE_FILE)).unwrap();
        let before = events(&dir).len();
        assert_refused(
            &dir,
            run_timer(&dir, entry),
            "no owner mandate; run `vaikor mandate renew`",
            before,
        );
        // Never an implicit one.
        assert!(!dir.join(MANDATE_FILE).exists());
        let _ = fs::remove_dir_all(dir);
    }
}

#[test]
fn a_node_without_a_grant_policy_runs_no_step() {
    for entry in ENTRIES {
        let dir = scratch(&format!("nopolicy-{entry:?}"));
        fs::remove_file(dir.join(GRANT_POLICY_FILE)).unwrap();
        assert_refused(&dir, run_timer(&dir, entry), GRANT_POLICY_FILE, 0);
        let _ = fs::remove_dir_all(dir);
    }
}

#[test]
fn an_expired_mandate_runs_no_step() {
    for entry in ENTRIES {
        let dir = scratch(&format!("expired-{entry:?}"));
        issue_workspace_mandate(
            &dir,
            default_rights(),
            json!({"messages": 10}),
            "2026-01-01T00:00:00Z",
            3600,
        )
        .unwrap();
        assert_refused(&dir, run_timer(&dir, entry), "mandate is not valid now", 0);
        let _ = fs::remove_dir_all(dir);
    }
}

#[test]
fn a_mandate_that_does_not_cover_a_capability_runs_no_step() {
    for entry in ENTRIES {
        let dir = scratch(&format!("uncovered-{entry:?}"));
        issue_workspace_mandate(
            &dir,
            vec![json!({"action": "timer.start", "resource": TIMER})],
            json!({"messages": 10}),
            &now(),
            3600,
        )
        .unwrap();
        assert_refused(
            &dir,
            run_intent(&dir, entry, "task.note", &[("content", "buy milk")]),
            &format!("the mandate does not allow {NOTE}"),
            0,
        );
        let _ = fs::remove_dir_all(dir);
    }
}

#[test]
fn a_mandate_from_another_owner_runs_no_step() {
    let dir = scratch("stranger");
    let other = scratch("stranger-other");
    fs::copy(other.join(MANDATE_FILE), dir.join(MANDATE_FILE)).unwrap();
    assert_refused(&dir, run_timer(&dir, Entry::Companion), "owner", 0);
    let _ = fs::remove_dir_all(dir);
    let _ = fs::remove_dir_all(other);
}

#[test]
fn the_period_budget_counts_steps_across_task_runs() {
    for entry in ENTRIES {
        // A budget of N = 1 message: the first run's step uses it, the second run's step
        // (the N+1st) is refused before it acts.
        let dir = scratch(&format!("budget-{entry:?}"));
        issue_workspace_mandate(&dir, default_rights(), json!({"messages": 1}), &now(), 3600)
            .unwrap();
        let first = run_timer(&dir, entry).unwrap();
        assert_eq!(first.steps_executed, 1, "{first:?}");
        let timers = fs::read_to_string(dir.join("timers.json")).unwrap();
        fs::remove_file(dir.join("records/latest-record.json")).unwrap();
        let before = events(&dir).len();
        let err = run_intent(&dir, entry, "task.note", &[("content", "buy milk")]).unwrap_err();
        assert!(err.contains("grant budget"), "{err}");
        assert!(!dir.join("files/notes/inbox.md").exists());
        assert!(!dir.join("records/latest-record.json").exists());
        assert_eq!(fs::read_to_string(dir.join("timers.json")).unwrap(), timers);
        let new = &events(&dir)[before..];
        assert_eq!(new.len(), 1, "{new:?}");
        assert_eq!(new[0].decision, "deny");
        assert!(new[0].reason.as_deref().unwrap().contains("grant budget"));

        // A renewed mandate starts a new period: spends before its `iat` no longer count.
        // Spends within the same second as `iat` still do, so the renewal waits a second.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        issue_workspace_mandate(&dir, default_rights(), json!({"messages": 1}), &now(), 3600)
            .unwrap();
        let noted = run_intent(&dir, entry, "task.note", &[("content", "buy milk")]).unwrap();
        assert_eq!(noted.steps_executed, 1, "{noted:?}");
        let _ = fs::remove_dir_all(dir);
    }
}

#[test]
fn a_grant_policy_that_forbids_a_step_stops_it_before_its_effect() {
    for entry in ENTRIES {
        let dir = scratch(&format!("forbid-{entry:?}"));
        let path = dir.join(GRANT_POLICY_FILE);
        let mut policy = fs::read_to_string(&path).unwrap();
        policy.push_str(&format!(
            "forbid(principal, action, resource == Resource::\"{NOTE}\");\n"
        ));
        fs::write(&path, policy).unwrap();
        let summary = run_intent(&dir, entry, "task.note", &[("content", "buy milk")]).unwrap();
        assert_eq!(summary.steps_executed, 0);
        assert_eq!(summary.steps[0].status, "denied");
        let reason = summary.steps[0].reason.as_deref().unwrap();
        assert!(reason.contains("policy denied"), "{reason}");
        assert!(!dir.join("files/notes/inbox.md").exists());
        let events = events(&dir);
        let last = events.last().unwrap();
        assert_eq!(
            (last.capability.as_str(), last.decision.as_str()),
            (NOTE, "deny")
        );
        assert!(events.iter().all(|e| e.usage.is_none()), "{events:?}");
        let _ = fs::remove_dir_all(dir);
    }
}

#[test]
fn a_valid_mandate_runs_the_plan_with_the_token_reserved_before_the_effect() {
    for entry in ENTRIES {
        let dir = scratch(&format!("valid-{entry:?}"));
        let mandate: Value =
            serde_json::from_str(&fs::read_to_string(dir.join(MANDATE_FILE)).unwrap()).unwrap();
        let summary = run_timer(&dir, entry).unwrap();
        assert_eq!(summary.steps_executed, 1);
        assert!(dir.join("timers.json").exists());
        let events = events(&dir);
        let trail: Vec<(&str, &str)> = events
            .iter()
            .map(|e| (e.capability.as_str(), e.decision.as_str()))
            .collect();
        assert_eq!(
            trail,
            [
                ("tag:vaikor.com,2026:grant", "allow"),
                (TIMER, "spend"),
                (TIMER, "allow"),
                (TIMER, "completed"),
            ]
        );
        // The acceptance names the task token and the mandate it ran under.
        use sha2::Digest;
        let digest = format!(
            "{:x}",
            sha2::Sha256::digest(vaikor_grant::canonicalize(&mandate).as_bytes())
        );
        let accepted = events[0].reason.as_deref().unwrap();
        assert!(
            accepted.contains(&format!("mandate_sha256={digest}")),
            "{accepted}"
        );
        let token_id = accepted
            .split(' ')
            .find_map(|part| part.strip_prefix("task_token="))
            .unwrap();
        // The reservation is the token's: executor as issuer, its id, one use.
        let (key, index, uses) = events[1].usage.clone().unwrap();
        let key: Vec<String> = serde_json::from_str(&key).unwrap();
        assert_eq!(key, [mandate["executor"].as_str().unwrap(), token_id]);
        assert_eq!((index, uses), (0, 1));
        let _ = fs::remove_dir_all(dir);
    }
}

#[test]
fn every_task_gets_its_own_token() {
    let dir = scratch("fresh-token");
    run_timer(&dir, Entry::Companion).unwrap();
    run_timer(&dir, Entry::Task).unwrap();
    let ids: Vec<String> = events(&dir)
        .iter()
        .filter(|e| e.capability == "tag:vaikor.com,2026:grant")
        .map(|e| e.reason.clone().unwrap())
        .collect();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
    let _ = fs::remove_dir_all(dir);
}

struct Typed {
    answers: Vec<String>,
    said: Vec<String>,
}

impl Terminal for Typed {
    fn ask(&mut self, prompt: &str) -> Result<String, String> {
        self.said.push(prompt.into());
        if self.answers.is_empty() {
            return Err("end of input".into());
        }
        Ok(self.answers.remove(0))
    }

    fn ask_secret(&mut self, _prompt: &str) -> Result<Zeroizing<String>, String> {
        Err("no secret is asked".into())
    }

    fn say(&mut self, text: &str) {
        self.said.push(text.into());
    }
}

#[test]
fn renewal_needs_the_typed_confirmation_and_restores_an_existing_workspace() {
    let dir = scratch("renew");
    fs::remove_file(dir.join(MANDATE_FILE)).unwrap();
    fs::remove_file(dir.join(GRANT_POLICY_FILE)).unwrap();

    let mut term = Typed {
        answers: vec!["yes".into()],
        said: Vec::new(),
    };
    assert!(renew_mandate(&mut term, &dir).is_err());
    assert!(!dir.join(MANDATE_FILE).exists());
    assert!(term.said.iter().any(|s| s.contains("renew")));

    let mut term = Typed {
        answers: vec!["renew".into()],
        said: Vec::new(),
    };
    let mandate = renew_mandate(&mut term, &dir).unwrap();
    let written: Value =
        serde_json::from_str(&fs::read_to_string(dir.join(MANDATE_FILE)).unwrap()).unwrap();
    assert_eq!(written, mandate);
    assert_eq!(
        fs::metadata(dir.join(MANDATE_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(dir.join(GRANT_POLICY_FILE).exists());
    let summary = run_timer(&dir, Entry::Companion).unwrap();
    assert_eq!(summary.steps_executed, 1);
    let _ = fs::remove_dir_all(dir);
}

fn edge1_seed(dir: &Path) -> [u8; 32] {
    let text = fs::read_to_string(dir.join("keys/edge1.key")).unwrap();
    let text = text.trim();
    let mut seed = [0u8; 32];
    for (i, slot) in seed.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap();
    }
    seed
}

/// Presents with `seed`, over `digest` instead of the run's plan when given.
struct Signs([u8; 32], Option<&'static str>);

impl Presenter for Signs {
    fn prove(&self, token: &Value, aud: &str, digest: &str, nonce: &str) -> [u8; 64] {
        vaikor_grant::sign_pop(&self.0, token, aud, self.1.unwrap_or(digest), nonce)
    }
}

/// Signs with `seed` and keeps the proof; once replaying, hands it out again.
struct Replay([u8; 32], std::sync::Mutex<(Option<[u8; 64]>, bool)>);

impl Presenter for Replay {
    fn prove(&self, token: &Value, aud: &str, digest: &str, nonce: &str) -> [u8; 64] {
        let mut state = self.1.lock().unwrap();
        match (state.0, state.1) {
            (Some(proof), true) => proof,
            _ => {
                let proof = vaikor_grant::sign_pop(&self.0, token, aud, digest, nonce);
                state.0 = Some(proof);
                proof
            }
        }
    }
}

fn run_timer_presented(
    dir: &Path,
    entry: Entry,
    presenter: &dyn Presenter,
) -> Result<TurnkeyTaskSummary, String> {
    let slots = [("duration", "10 minutes")];
    match entry {
        Entry::Companion => run_verified_intent_presented(
            dir,
            &IntentCatalog::builtin().unwrap(),
            &verified("timer.set", &slots),
            Some(presenter),
        ),
        Entry::Task => execute_turnkey_task_presented(
            dir,
            "10 minutes",
            false,
            &OneReply(envelope("timer.set", &slots)),
            Some(presenter),
        ),
    }
}

/// 0002 R25 on `vaikor task` and the companion: a task token presented with a wrong key,
/// over another plan, or with a proof replayed from an earlier run is refused before the
/// first step; the refusal is audited and nothing happens on disk.
#[test]
fn a_task_token_without_a_valid_proof_runs_no_step() {
    for entry in ENTRIES {
        let dir = scratch(&format!("pop-{entry:?}"));
        let executor = edge1_seed(&dir);
        let stranger = Signs([7; 32], None);
        let other_plan = Signs(executor, Some("another-plan-digest"));
        for presenter in [&stranger as &dyn Presenter, &other_plan] {
            let before = events(&dir).len();
            assert_refused(
                &dir,
                run_timer_presented(&dir, entry, presenter),
                "grant holder",
                before,
            );
        }
        let replay = Replay(executor, Default::default());
        let first = run_timer_presented(&dir, entry, &replay).unwrap();
        assert_eq!(first.steps_executed, 1, "{first:?}");
        let timers = fs::read_to_string(dir.join("timers.json")).unwrap();
        fs::remove_file(dir.join("records/latest-record.json")).unwrap();
        replay.1.lock().unwrap().1 = true;
        let before = events(&dir).len();
        let err = run_timer_presented(&dir, entry, &replay).unwrap_err();
        assert!(err.contains("grant holder"), "{err}");
        assert_eq!(fs::read_to_string(dir.join("timers.json")).unwrap(), timers);
        assert!(!dir.join("records/latest-record.json").exists());
        let new = &events(&dir)[before..];
        assert_eq!(new.len(), 1, "{new:?}");
        assert_eq!(new[0].decision, "deny");
        let _ = fs::remove_dir_all(dir);
    }
}
