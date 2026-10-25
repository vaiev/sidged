use serde_json::{json, Value};
use std::cell::{Cell, RefCell};
use vaikor_cli::{ApprovalChannel, ApprovalDecision, ApprovalRequest};
const NOW: &str = "2026-10-18T10:00:00Z";
const EXP: &str = "2026-10-18T10:30:00Z";
struct Owner {
    calls: Cell<u32>,
    bound: bool,
    granted: bool,
    killed: Cell<bool>,
    revoked: RefCell<Vec<String>>,
}
impl ApprovalChannel for Owner {
    fn decide(&self, r: &ApprovalRequest, now: &str) -> ApprovalDecision {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(r.scope.as_ref().unwrap()["task_type"], "planner");
        assert!(r.scope_digest.is_some());
        ApprovalDecision {
            granted: self.granted,
            actor: "test-approver".into(),
            at: now.into(),
        }
    }
    fn standing_scope_approved(&self, _: &ApprovalRequest) -> bool {
        self.bound
    }
    fn killed(&self) -> bool {
        self.killed.get()
    }
    fn take_revocations(&self) -> Vec<String> {
        self.revoked.take()
    }
}
fn owner(bound: bool) -> Owner {
    Owner {
        calls: Cell::new(0),
        bound,
        granted: true,
        killed: Cell::new(false),
        revoked: RefCell::new(vec![]),
    }
}
fn scope() -> Value {
    json!({"standing":true,"provider":"test-provider","task_type":"planner","limit":{"calls":2},"expiry":EXP})
}
fn call(
    c: &mut vaikor_log::Chain,
    a: &Owner,
    s: &Value,
    id: &str,
    now: &str,
) -> Result<(), String> {
    let r = ApprovalRequest::new(
        "plan",
        "planner",
        "tag:vaikor.com,2026:capability:model.complete",
        &json!({}),
    )
    .unwrap();
    vaikor_cli::standing::authorize_planner(c, a, r, s, id, EXP, now).map(|_| ())
}
fn fixture(tag: &str) -> (std::path::PathBuf, vaikor_log::Chain, String) {
    let p = std::env::temp_dir().join(format!("vaikor-standing-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    let c = vaikor_log::Chain::open(&p, &[53; 32]).unwrap();
    let id = vaikor_grant::did_key(&vaikor_log::public_key(&[54; 32]));
    (p, c, id)
}
#[test]
fn bounded_approval_survives_reopen_and_never_renews_over_limit() {
    let (p, mut c, id) = fixture("bounded");
    let a = owner(true);
    call(&mut c, &a, &scope(), &id, NOW).unwrap();
    drop(c);
    let mut c = vaikor_log::Chain::open(&p, &[53; 32]).unwrap();
    call(&mut c, &a, &scope(), &id, NOW).unwrap();
    assert_eq!(a.calls.get(), 1);
    for _ in 0..2 {
        call(&mut c, &a, &scope(), &id, NOW).unwrap();
    }
    assert_eq!(a.calls.get(), 3);
    let events = c.read_events().unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|e| e.capability == "core.standing-approval" && e.decision == "store")
            .count(),
        1
    );
    assert!(events
        .iter()
        .filter(|e| e.decision == "approve")
        .all(|e| e.approval.is_some()));
    drop(c);
    std::fs::remove_file(p).unwrap();
}
#[test]
fn plain_answers_never_become_standing() {
    let (p, mut c, id) = fixture("plain");
    let a = owner(false);
    for _ in 0..2 {
        call(&mut c, &a, &scope(), &id, NOW).unwrap();
    }
    assert_eq!(a.calls.get(), 2);
    assert!(!c
        .read_events()
        .unwrap()
        .iter()
        .any(|e| e.decision == "store"));
    drop(c);
    std::fs::remove_file(p).unwrap();
}
#[test]
fn pair_owner_expiry_revocation_and_kill_constrain_reuse() {
    let (p, mut c, id) = fixture("scope");
    let a = owner(true);
    call(&mut c, &a, &scope(), &id, NOW).unwrap();
    let mut s = scope();
    s["provider"] = "other-provider".into();
    call(&mut c, &a, &s, &id, NOW).unwrap();
    let other = vaikor_grant::did_key(&vaikor_log::public_key(&[55; 32]));
    call(&mut c, &a, &scope(), &other, NOW).unwrap();
    assert_eq!(a.calls.get(), 3);
    let stored = c
        .read_events()
        .unwrap()
        .into_iter()
        .find(|e| e.decision == "store")
        .unwrap();
    let stored: Value = serde_json::from_str(stored.privacy_report.as_deref().unwrap()).unwrap();
    a.revoked
        .borrow_mut()
        .push(stored["approval_digest"].as_str().unwrap().into());
    call(&mut c, &a, &scope(), &id, NOW).unwrap();
    assert_eq!(a.calls.get(), 4);
    call(&mut c, &a, &s, &id, NOW).unwrap();
    assert_eq!(a.calls.get(), 4, "another provider's scope remains valid");
    a.revoked.borrow_mut().push("*".into());
    call(&mut c, &a, &scope(), &other, NOW).unwrap();
    assert_eq!(a.calls.get(), 5);
    assert!(call(&mut c, &a, &scope(), &id, EXP).is_err());
    a.killed.set(true);
    assert!(call(&mut c, &a, &scope(), &id, NOW).is_err());
    assert_eq!(a.calls.get(), 5);
    drop(c);
    std::fs::remove_file(p).unwrap();
}
#[test]
fn denied_scope_has_r11_audit_and_no_standing_state() {
    let (p, mut c, id) = fixture("deny");
    let mut a = owner(true);
    a.granted = false;
    assert!(call(&mut c, &a, &scope(), &id, NOW).is_err());
    let events = c.read_events().unwrap();
    assert!(events
        .iter()
        .any(|e| e.decision == "deny" && e.approval.is_some()));
    assert!(!events.iter().any(|e| e.decision == "store"));
    drop(c);
    std::fs::remove_file(p).unwrap();
}

#[test]
fn revocation_has_the_same_channel_binding_as_approval() {
    let (path, mut chain, id) = fixture("revoke-binding");
    let channel = owner(true);
    call(&mut chain, &channel, &scope(), &id, NOW).unwrap();
    channel.revoked.borrow_mut().push("*".into());
    vaikor_cli::standing::check_revocations(&mut chain, &channel, NOW).unwrap();
    let events = chain.read_events().unwrap();
    let approved = events.iter().find(|e| e.decision == "approve").unwrap();
    let revoked = events.iter().find(|e| e.decision == "revoke").unwrap();
    assert!(revoked.approval.is_some());
    assert_eq!(revoked.approval, approved.approval);
    assert_eq!(revoked.actor, "approval-channel");
    drop(chain);
    std::fs::remove_file(path).unwrap();
}
