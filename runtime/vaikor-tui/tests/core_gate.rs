//! Core gate: report on screen before any request, approval only via
//! the Core approval channel, grant + budget before every call, mandatory
//! signed audit written before the send, one entry per attempt.
use std::cell::{Cell, RefCell};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use ratatui::{backend::TestBackend, Terminal};
use serde_json::{json, Value};
use vaikor_cli::{ApprovalChannel, ApprovalDecision, ApprovalRequest};
use vaikor_tui::*;

const CANARY: &str = "gemini-CANARY-core-gate-0b1d";
const NOW: &str = "2026-10-17T08:10:00Z";
const ISSUER_SEED: [u8; 32] = [7; 32];
const HOLDER_SEED: [u8; 32] = [8; 32];
const LOG_SEED: [u8; 32] = [9; 32];
/// The Core's configured grant audience (from config): in the
/// demo, the did:key of the holder key (demo.env on the host, never a repo
/// constant); here a test did:key.
fn aud() -> String {
    did(&HOLDER_SEED).0
}

fn did(seed: &[u8; 32]) -> (String, String) {
    let public = vaikor_log::public_key(seed);
    (
        vaikor_grant::did_key(&public),
        vaikor_grant::jwk_thumbprint(&public),
    )
}

fn grant(action: &str, resource: &str, messages: u64) -> Value {
    let (iss, _) = did(&ISSUER_SEED);
    let (sub, jkt) = did(&HOLDER_SEED);
    vaikor_grant::attach_signature(
        &json!({
            "v": "0.1", "id": "tok-demo1", "iss": iss, "sub": sub,
            "aud": aud(),
            "iat": "2026-10-17T08:00:00Z", "exp": "2026-10-17T08:30:00Z",
            "cnf": { "kid": sub, "jkt": jkt },
            "rights": [{ "action": action, "resource": resource }],
            "budget": { "messages": messages },
            "chain": []
        }),
        &ISSUER_SEED,
        &iss,
    )
}

fn good_grant() -> Value {
    grant(EGRESS_ACTION, CLOUD_URL, 5)
}

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "vaikor-tui-core-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn key(dir: &Tmp) -> KeySource {
    let p = dir.0.join("key");
    std::fs::write(&p, CANARY).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    KeySource::File(p)
}

struct Mock {
    calls: Cell<u32>,
    /// Audit lines on disk at the moment of the send (written BEFORE).
    lines_at_send: RefCell<Vec<usize>>,
    log: PathBuf,
    status: u16,
    body: &'static str,
}
impl Mock {
    fn new(log: PathBuf) -> Self {
        Self {
            calls: Cell::new(0),
            lines_at_send: RefCell::new(Vec::new()),
            log,
            status: 200,
            body: r#"{"choices":[{"message":{"content":"Hello from Gemini"}}]}"#,
        }
    }
}
impl CloudSender for Mock {
    fn send(&self, body: &[u8], credential: &KeySource) -> Result<SendOutcome, String> {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(*credential.bearer().unwrap(), format!("Bearer {CANARY}"));
        assert!(serde_json::from_slice::<Value>(body).is_ok());
        let n = std::fs::read_to_string(&self.log)
            .map(|s| s.lines().count())
            .unwrap_or(0);
        self.lines_at_send.borrow_mut().push(n);
        Ok(SendOutcome {
            status: self.status,
            body: self.body.into(),
            report: json!({"provider_id": CLOUD_PROVIDER, "profile": "P0"}),
        })
    }
}

/// Records whether the privacy report was on screen when approval was asked.
struct Approver<'a> {
    granted: bool,
    asked: Cell<u32>,
    screen_had_report: RefCell<Vec<bool>>,
    app_screen: &'a RefCell<String>,
}
impl ApprovalChannel for Approver<'_> {
    fn decide(&self, _r: &ApprovalRequest, now: &str) -> ApprovalDecision {
        self.asked.set(self.asked.get() + 1);
        self.screen_had_report
            .borrow_mut()
            .push(self.app_screen.borrow().contains("Privacy report"));
        ApprovalDecision {
            granted: self.granted,
            actor: "uid:2001".into(),
            at: now.into(),
        }
    }
    fn approver_uid(&self) -> Option<u32> {
        Some(2001)
    }
}

fn screen(app: &App) -> String {
    let mut term = Terminal::new(TestBackend::new(110, 30)).unwrap();
    term.draw(|f| render(app, f)).unwrap();
    let buf = term.backend().buffer().clone();
    let mut out = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

struct Fixture {
    dir: Tmp,
    log: PathBuf,
}
fn fixture(tag: &str) -> Fixture {
    let dir = Tmp::new(tag);
    let log = dir.0.join("audit.log");
    Fixture { dir, log }
}

fn core<'a>(
    f: &'a Fixture,
    grant: Option<&'a Value>,
    approval: &'a dyn ApprovalChannel,
    sender: &'a dyn CloudSender,
) -> Result<Core<'a>, String> {
    let (iss, _) = did(&ISSUER_SEED);
    Core::open(
        CoreConfig {
            log_path: Some(&f.log),
            log_seed: Some(LOG_SEED),
            grant,
            trusted_issuers: vec![iss],
            policy: Some(DEMO_POLICY),
            audience: Some(aud()),
            now: Some(NOW.into()),
        },
        approval,
        sender,
    )
}

/// Test-only owner policy without the class/residency constraints, so the
/// §5.3 check A tests reach check A (the demo policy refuses earlier).
const ANY_CLASS_POLICY: &str = r#"permit(principal, action == Action::"egress.send", resource == Resource::"https://generativelanguage.googleapis.com/v1beta/openai/chat/completions");"#;

fn core_with_policy<'a>(
    f: &'a Fixture,
    policy: &'a str,
    grant: Option<&'a Value>,
    approval: &'a dyn ApprovalChannel,
    sender: &'a dyn CloudSender,
) -> Result<Core<'a>, String> {
    let (iss, _) = did(&ISSUER_SEED);
    Core::open(
        CoreConfig {
            log_path: Some(&f.log),
            log_seed: Some(LOG_SEED),
            grant,
            trusted_issuers: vec![iss],
            policy: Some(policy),
            audience: Some(aud()),
            now: Some(NOW.into()),
        },
        approval,
        sender,
    )
}

fn events(f: &Fixture) -> Vec<vaikor_core::AuditEvent> {
    vaikor_log::verify_file(&f.log, &vaikor_log::public_key(&LOG_SEED)).unwrap();
    vaikor_log::read_events(&f.log, &vaikor_log::public_key(&LOG_SEED)).unwrap()
}

/// Request approval, render (as the TUI loop does), then let the Core ask.
fn run_call(
    app: &mut App,
    core: &mut Core,
    key: Option<&KeySource>,
    shown: &RefCell<String>,
) -> Result<(), String> {
    app.request_approval();
    *shown.borrow_mut() = screen(app);
    app.ask_cloud(core, key)
}

// ---------------- audit mandatory
#[test]
fn no_audit_path_refuses_to_start() {
    let f = fixture("m4a");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let (iss, _) = did(&ISSUER_SEED);
    for (path, seed) in [(None, Some(LOG_SEED)), (Some(f.log.as_path()), None)] {
        let r = Core::open(
            CoreConfig {
                log_path: path,
                log_seed: seed,
                grant: Some(&g),
                trusted_issuers: vec![iss.clone()],
                policy: Some(DEMO_POLICY),
                audience: Some(aud()),
                now: Some(NOW.into()),
            },
            &a,
            &m,
        );
        assert!(r.is_err());
    }
}

#[test]
fn audit_written_before_send_and_signed() {
    let f = fixture("m4b");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let mut c = core(&f, Some(&g), &a, &m).unwrap();
    let k = key(&f.dir);
    let mut app = App::new("t", 10);
    run_call(&mut app, &mut c, Some(&k), &shown).unwrap();
    assert_eq!(m.calls.get(), 1);
    // at least the pre-send attempt entry existed when the bytes left
    assert!(m.lines_at_send.borrow()[0] >= 1);
    drop(c);
    let ev = events(&f);
    let pre = ev
        .iter()
        .find(|e| e.decision == "approve")
        .expect("pre-send entry");
    let r11 = pre.approval.as_ref().expect("R11 fields");
    assert_eq!(r11.approver_uid, Some(2001));
    assert!(!r11.attestation.is_empty() && !r11.approval_binding.is_empty());
    assert!(pre.privacy_report.is_some());
    assert!(pre.usage.is_some());
    assert!(ev.iter().any(|e| e.decision == "sent"));
    let raw = std::fs::read_to_string(&f.log).unwrap();
    assert!(!raw.contains(CANARY));
}

#[test]
fn every_refusal_is_audited() {
    let f = fixture("m4c");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: false,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let mut c = core(&f, Some(&g), &a, &m).unwrap();
    let k = key(&f.dir);
    let mut app = App::new("t", 10);
    assert!(run_call(&mut app, &mut c, Some(&k), &shown).is_err()); // denied by approver
    assert!(run_call(&mut app, &mut c, None, &shown).is_err()); // no key
    assert!(app.ask_cloud(&mut c, Some(&k)).is_err()); // no report requested
    drop(c);
    let ev = events(&f);
    assert_eq!(
        ev.iter().filter(|e| e.decision == "deny").count(),
        3,
        "{ev:?}"
    );
    assert_eq!(m.calls.get(), 0);
}

#[test]
fn failed_send_is_audited() {
    let f = fixture("m4d");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let mut m = Mock::new(f.log.clone());
    m.status = 500;
    let g = good_grant();
    let mut c = core(&f, Some(&g), &a, &m).unwrap();
    let k = key(&f.dir);
    let mut app = App::new("t", 10);
    assert!(run_call(&mut app, &mut c, Some(&k), &shown).is_err());
    drop(c);
    assert!(events(&f).iter().any(|e| e.decision == "failed"));
}

// ---------------- report on screen before any request
#[test]
fn no_send_unless_report_was_rendered() {
    let f = fixture("m1");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let mut c = core(&f, Some(&g), &a, &m).unwrap();
    let k = key(&f.dir);
    let mut app = App::new("t", 10);
    app.request_approval(); // requested but never drawn
    assert!(app.ask_cloud(&mut c, Some(&k)).is_err());
    assert_eq!((m.calls.get(), a.asked.get()), (0, 0));
    run_call(&mut app, &mut c, Some(&k), &shown).unwrap();
    assert_eq!(a.screen_had_report.borrow().as_slice(), &[true]);
    assert_eq!(m.calls.get(), 1);
}

// ---------------- approval only via the Core channel
#[test]
fn tty_cannot_approve() {
    // There is no TTY approval API: `App` has no approve(); the only path is
    // the ApprovalChannel. A denial by the channel blocks the call.
    let f = fixture("m2");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: false,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let mut c = core(&f, Some(&g), &a, &m).unwrap();
    let k = key(&f.dir);
    let mut app = App::new("t", 10);
    assert!(run_call(&mut app, &mut c, Some(&k), &shown).is_err());
    assert_eq!(a.asked.get(), 1);
    assert_eq!(m.calls.get(), 0);
    assert_eq!(key_action('y'), KeyAction::None);
    assert_eq!(key_action('a'), KeyAction::RequestApproval);
    assert_eq!(key_action('q'), KeyAction::Quit);
}

// ---------------- grant + budget
#[test]
fn missing_or_wrong_grant_refuses() {
    let f = fixture("m3a");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let k = key(&f.dir);
    let wrong_action = grant("calendar.free_slots", CLOUD_URL, 5);
    let wrong_res = grant(
        EGRESS_ACTION,
        "https://api.example.com/v1/chat/completions",
        5,
    );
    let mut tampered = good_grant();
    tampered["budget"]["messages"] = json!(99);
    for g in [None, Some(&wrong_action), Some(&wrong_res), Some(&tampered)] {
        let mut c = core(&f, g, &a, &m).unwrap();
        let mut app = App::new("t", 10);
        assert!(run_call(&mut app, &mut c, Some(&k), &shown).is_err());
    }
    assert_eq!((m.calls.get(), a.asked.get()), (0, 0));
}

#[test]
fn budget_exhausted_refuses() {
    let f = fixture("m3b");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = grant(EGRESS_ACTION, CLOUD_URL, 1);
    let mut c = core(&f, Some(&g), &a, &m).unwrap();
    let k = key(&f.dir);
    let mut app = App::new("t", 10);
    run_call(&mut app, &mut c, Some(&k), &shown).unwrap();
    assert!(run_call(&mut app, &mut c, Some(&k), &shown).is_err());
    assert_eq!(m.calls.get(), 1);
    drop(c);
    let ev = events(&f);
    assert!(ev
        .iter()
        .any(|e| e.decision == "deny" && e.reason.as_deref().unwrap_or("").contains("budget")));
}

#[test]
fn budget_survives_restart_via_audit() {
    // Spent messages are recovered from the audit log on reopen.
    let f = fixture("m3c");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = grant(EGRESS_ACTION, CLOUD_URL, 1);
    let k = key(&f.dir);
    {
        let mut c = core(&f, Some(&g), &a, &m).unwrap();
        let mut app = App::new("t", 10);
        run_call(&mut app, &mut c, Some(&k), &shown).unwrap();
    }
    let mut c = core(&f, Some(&g), &a, &m).unwrap();
    let mut app = App::new("t", 10);
    assert!(run_call(&mut app, &mut c, Some(&k), &shown).is_err());
    assert_eq!(m.calls.get(), 1);
}

// ---------------- A2 again with the gate: canary never leaks
#[test]
fn canary_not_on_screen_or_in_debug() {
    let f = fixture("a2");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let mut c = core(&f, Some(&g), &a, &m).unwrap();
    let k = key(&f.dir);
    let mut app = App::new("t", 10);
    run_call(&mut app, &mut c, Some(&k), &shown).unwrap();
    assert!(screen(&app).contains("Hello from Gemini"));
    assert!(!screen(&app).contains(CANARY));
    assert!(!format!("{app:?}").contains(CANARY));
}

// ---------------- 0007 §5.3 checks A-D before send, R13 audit
#[test]
fn s53_default_payload_is_query_and_passes_with_r13_record() {
    let f = fixture("s53a");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let mut c = core(&f, Some(&g), &a, &m).unwrap();
    let k = key(&f.dir);
    let mut app = App::new("Call Anna at +41 44 668 18 00", 10); // task text never leaves
    run_call(&mut app, &mut c, Some(&k), &shown).unwrap();
    assert_eq!(m.calls.get(), 1);
    drop(c);
    let ev = events(&f);
    let check = ev
        .iter()
        .find(|e| e.decision == "permit")
        .expect("§5.3 permit entry");
    let r: Value = serde_json::from_str(check.privacy_report.as_deref().unwrap()).unwrap();
    for field in [
        "payload_sha256",
        "detector_version",
        "input_classes",
        "residency_tags",
        "destination_class",
        "provider",
    ] {
        assert!(!r[field].is_null(), "missing {field}: {r}");
    }
    assert_eq!(r["input_classes"], json!(["query"]));
    assert_eq!(r["destination_class"], "GLOBAL");
    let raw = std::fs::read_to_string(&f.log).unwrap();
    // (a bare "668" can occur inside a hex digest; check the full number)
    assert!(!raw.contains("Anna") && !raw.contains("+41 44 668 18 00"));
}

#[test]
fn s53_communications_content_is_refused_and_audited() {
    let f = fixture("s53b");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let mut c = core_with_policy(&f, ANY_CLASS_POLICY, Some(&g), &a, &m).unwrap();
    let k = key(&f.dir);
    let mut app = App::with_payload(
        "t",
        10,
        "communications.content",
        "Summarize my last message",
    );
    assert!(run_call(&mut app, &mut c, Some(&k), &shown).is_err());
    assert_eq!(m.calls.get(), 0);
    drop(c);
    let ev = events(&f);
    let deny = ev
        .iter()
        .find(|e| e.decision == "deny" && e.reason.as_deref() == Some("data-class-forbidden"))
        .expect("refusal entry");
    let r: Value = serde_json::from_str(deny.privacy_report.as_deref().unwrap()).unwrap();
    assert_eq!(r["input_classes"], json!(["communications.content"]));
}

#[test]
fn s53_pii_in_payload_is_refused() {
    let f = fixture("s53c");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let mut c = core(&f, Some(&g), &a, &m).unwrap();
    let k = key(&f.dir);
    let mut app = App::with_payload("t", 10, "query", "mail anna@example.ch");
    assert!(run_call(&mut app, &mut c, Some(&k), &shown).is_err());
    assert_eq!(m.calls.get(), 0);
    drop(c);
    let raw = std::fs::read_to_string(&f.log).unwrap();
    assert!(raw.contains("email") && !raw.contains("anna@"));
}

// ---------------- nits
struct FailingSink {
    ok_appends: Cell<usize>,
}
impl AuditSink for FailingSink {
    fn append(&mut self, _e: &vaikor_core::AuditEvent) -> Result<(), String> {
        if self.ok_appends.get() == 0 {
            return Err("disk full".into());
        }
        self.ok_appends.set(self.ok_appends.get() - 1);
        Ok(())
    }
    fn read_events(&mut self) -> Result<Vec<vaikor_core::AuditEvent>, String> {
        Ok(Vec::new())
    }
}

#[test]
fn failed_pre_send_audit_write_refuses() {
    let f = fixture("sink");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let k = key(&f.dir);
    let (iss, _) = did(&ISSUER_SEED);
    // 0 and 1 successful appends: the approve entry or the §5.3 entry fails.
    for ok in [0usize, 1] {
        let mut c = Core::with_sink(
            Box::new(FailingSink {
                ok_appends: Cell::new(ok),
            }),
            DEMO_POLICY,
            Some(&g),
            vec![iss.clone()],
            Some(NOW.into()),
            &a,
            &m,
        )
        .unwrap()
        .with_audience(&aud())
        .unwrap();
        let mut app = App::new("t", 10);
        let e = run_call(&mut app, &mut c, Some(&k), &shown).unwrap_err();
        assert!(e.contains("audit"), "{e}");
    }
    assert_eq!(m.calls.get(), 0);
}

#[test]
fn build_sha_is_required() {
    assert!(require_build_sha("9feeace").is_ok());
    for bad in ["", "unknown"] {
        assert!(require_build_sha(bad).is_err());
    }
}

#[test]
fn non_tty_is_refused() {
    assert!(require_tty(true, true).is_ok());
    for (i, o) in [(false, true), (true, false), (false, false)] {
        assert!(require_tty(i, o).unwrap_err().contains("terminal"));
    }
}

// ---------------- R9c refusal has its own audit reason (WOUF addendum)
/// A channel that refused to start (0004 R9c), like vaikor_cli's Refused.
struct UntrustedChannel {
    asked: Cell<u32>,
}
impl ApprovalChannel for UntrustedChannel {
    fn decide(&self, _r: &ApprovalRequest, now: &str) -> ApprovalDecision {
        self.asked.set(self.asked.get() + 1);
        ApprovalDecision {
            granted: false,
            actor: "approval-channel".into(),
            at: now.into(),
        }
    }
    fn refusal(&self) -> Option<&str> {
        Some("approval channel refused: agent process 1 (uid 999) holds CAP_SYS_PTRACE (0004 R9c)")
    }
}

#[test]
fn r9c_channel_refusal_is_audited_as_approval_channel_untrusted() {
    let f = fixture("r9c");
    let shown = RefCell::new(String::new());
    let a = UntrustedChannel {
        asked: Cell::new(0),
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let mut c = core(&f, Some(&g), &a, &m).unwrap();
    let k = key(&f.dir);
    let mut app = App::new("t", 10);
    let e = run_call(&mut app, &mut c, Some(&k), &shown).unwrap_err();
    assert!(e.starts_with("approval_channel_untrusted"), "{e}");
    assert!(e.contains("R9c"), "{e}");
    assert_eq!(a.asked.get(), 0, "an untrusted channel is never asked");
    assert_eq!(m.calls.get(), 0);
    drop(c);
    let ev = events(&f);
    let deny: Vec<_> = ev.iter().filter(|e| e.decision == "deny").collect();
    assert_eq!(deny.len(), 1);
    let reason = deny[0].reason.as_deref().unwrap();
    assert!(reason.starts_with("approval_channel_untrusted"), "{reason}");
    assert!(!ev
        .iter()
        .any(|e| e.reason.as_deref() == Some("approver denied or timed out")));
}

#[test]
fn plain_denial_keeps_its_reason() {
    let f = fixture("deny");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: false,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let mut c = core(&f, Some(&g), &a, &m).unwrap();
    let k = key(&f.dir);
    let mut app = App::new("t", 10);
    assert!(run_call(&mut app, &mut c, Some(&k), &shown).is_err());
    drop(c);
    assert!(events(&f)
        .iter()
        .any(|e| e.reason.as_deref() == Some("approver denied or timed out")));
}

// ---------------- leftover provider text (Gemini switch)
#[test]
fn reply_without_content_names_gemini_not_xai() {
    let f = fixture("nocontent");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let mut m = Mock::new(f.log.clone());
    m.body = r#"{"choices":[]}"#;
    let g = good_grant();
    let mut c = core(&f, Some(&g), &a, &m).unwrap();
    let k = key(&f.dir);
    let mut app = App::new("t", 10);
    let e = run_call(&mut app, &mut c, Some(&k), &shown).unwrap_err();
    assert!(e.contains("Gemini") && !e.contains("xAI"), "{e}");
}

// ---------------- no xAI text left in the TUI
#[test]
fn no_xai_text_in_tui_sources() {
    for (name, src) in [
        ("lib.rs", include_str!("../src/lib.rs")),
        ("main.rs", include_str!("../src/main.rs")),
    ] {
        assert!(!src.contains("xAI"), "xAI text left in {name}");
    }
    let e = load_key(Some("k".into()), None).unwrap_err();
    assert!(
        e.contains("VAIKOR_API_KEY_FILE") && !e.contains("xAI"),
        "{e}"
    );
}

#[test]
fn http_error_names_gemini() {
    let f = fixture("m1http");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let mut m = Mock::new(f.log.clone());
    m.status = 503;
    let g = good_grant();
    let mut c = core(&f, Some(&g), &a, &m).unwrap();
    let k = key(&f.dir);
    let mut app = App::new("t", 10);
    let e = run_call(&mut app, &mut c, Some(&k), &shown).unwrap_err();
    assert_eq!(e, "Gemini HTTP 503");
}

// ---------------- Cedar (0002) in production, PermitAll only in tests
#[test]
fn demo_policy_permits_exactly_the_gemini_call() {
    let cedar = vaikor_grant::CedarEvaluator::parse(DEMO_POLICY).unwrap();
    let (holder, _) = did(&HOLDER_SEED);
    let ctx = vaikor_grant::AuthContext {
        audience: "did:example:vaikor-tui",
        data_classes: &["query"],
        residency: &["unrestricted"],
    };
    assert!(cedar
        .permit(&holder, EGRESS_ACTION, CLOUD_URL, ctx)
        .unwrap());
    for (action, resource) in [
        ("calendar.free_slots", CLOUD_URL),
        ("egress.read", CLOUD_URL),
        (
            EGRESS_ACTION,
            "https://generativelanguage.googleapis.com/v1beta/openai/",
        ),
        (
            EGRESS_ACTION,
            "https://generativelanguage.googleapis.com/v1beta/models/m:generateContent",
        ),
        (EGRESS_ACTION, "https://api.x.ai/v1/chat/completions"),
    ] {
        assert!(
            !cedar.permit(&holder, action, resource, ctx).unwrap(),
            "{action} {resource}"
        );
    }
}

#[test]
fn production_core_has_no_permit_all() {
    let src = include_str!("../src/lib.rs");
    assert!(
        !src.contains("PermitAll"),
        "PermitAll is the test double (0002)"
    );
}

#[test]
fn policy_deny_refuses_and_is_audited() {
    // The grant covers the call; the owner policy does not: Cedar denies.
    let f = fixture("m2cedar");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let other = r#"permit(principal, action == Action::"egress.send", resource == Resource::"https://example.invalid/v1");"#;
    let (iss, _) = did(&ISSUER_SEED);
    let mut c = Core::open(
        CoreConfig {
            log_path: Some(&f.log),
            log_seed: Some(LOG_SEED),
            grant: Some(&g),
            trusted_issuers: vec![iss],
            policy: Some(other),
            audience: Some(aud()),
            now: Some(NOW.into()),
        },
        &a,
        &m,
    )
    .unwrap();
    let k = key(&f.dir);
    let mut app = App::new("t", 10);
    let e = run_call(&mut app, &mut c, Some(&k), &shown).unwrap_err();
    assert!(e.contains("Policy"), "{e}");
    assert_eq!((m.calls.get(), a.asked.get()), (0, 0));
    drop(c);
    let ev = events(&f);
    assert!(ev
        .iter()
        .any(|e| e.decision == "deny" && e.reason.as_deref().unwrap_or("").contains("Policy")));
}

#[test]
fn missing_or_invalid_policy_refuses_to_start() {
    let f = fixture("m2nopol");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let (iss, _) = did(&ISSUER_SEED);
    for policy in [None, Some("this is not cedar(")] {
        let r = Core::open(
            CoreConfig {
                log_path: Some(&f.log),
                log_seed: Some(LOG_SEED),
                grant: Some(&g),
                trusted_issuers: vec![iss.clone()],
                policy,
                audience: Some(aud()),
                now: Some(NOW.into()),
            },
            &a,
            &m,
        );
        assert!(r.is_err(), "{policy:?}");
    }
}

// ---------------- channel-start audit with the R9c attestation
struct StartingChannel {
    started: Cell<bool>,
}
impl ApprovalChannel for StartingChannel {
    fn decide(&self, _r: &ApprovalRequest, now: &str) -> ApprovalDecision {
        ApprovalDecision {
            granted: true,
            actor: "uid:2001".into(),
            at: now.into(),
        }
    }
    fn approver_uid(&self) -> Option<u32> {
        Some(2001)
    }
    fn r9c_attestation(&self) -> Option<String> {
        Some("attestation=R9c undetected=kernel-exploits,root-processes".into())
    }
    fn take_channel_start(&self) -> Option<String> {
        (!self.started.replace(true))
            .then(|| "attestation=R9c undetected=kernel-exploits,root-processes".into())
    }
}

#[test]
fn channel_start_is_audited_with_r9c() {
    let f = fixture("m3start");
    let a = StartingChannel {
        started: Cell::new(false),
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let c = core(&f, Some(&g), &a, &m).unwrap();
    drop(c);
    let ev = events(&f);
    assert_eq!(ev.len(), 1, "{ev:?}");
    let start = &ev[0];
    assert_eq!(
        (start.step.as_str(), start.actor.as_str()),
        ("approval", "approval-channel")
    );
    let r = start.approval.as_ref().expect("R9c fields");
    assert_eq!(r.attestation, "R9c");
    assert_eq!(r.undetected, ["kernel-exploits", "root-processes"]);
    assert_eq!(r.approver_uid, Some(2001));
    // audited once: a second Core on the same channel adds nothing
    let c = core(&f, Some(&g), &a, &m).unwrap();
    drop(c);
    assert_eq!(events(&f).len(), 1);
}

#[test]
fn failed_channel_start_audit_refuses_to_start() {
    let a = StartingChannel {
        started: Cell::new(false),
    };
    let f = fixture("m3startfail");
    let m = Mock::new(f.log.clone());
    let r = Core::with_sink(
        Box::new(FailingSink {
            ok_appends: Cell::new(0),
        }),
        DEMO_POLICY,
        None,
        Vec::new(),
        Some(NOW.into()),
        &a,
        &m,
    );
    assert!(r.is_err());
}

// ---------------- preview class and provider id
#[test]
fn preview_shows_the_real_class() {
    let f = fixture("n3");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let mut c = core_with_policy(&f, ANY_CLASS_POLICY, Some(&g), &a, &m).unwrap();
    let k = key(&f.dir);
    let mut app = App::with_payload("t", 10, "documents.text", DEMO_PROMPT);
    run_call(&mut app, &mut c, Some(&k), &shown).unwrap();
    drop(c);
    let ev = events(&f);
    let pre = ev.iter().find(|e| e.decision == "approve").unwrap();
    let r: Value = serde_json::from_str(pre.privacy_report.as_deref().unwrap()).unwrap();
    assert_eq!(r["data_classes"], json!(["documents.text"]));
    assert_eq!(
        privacy_preview("query", "x")["data_classes"],
        json!(["query"])
    );
}

#[test]
fn provider_id_is_the_gateway_registry_id_in_r13() {
    assert_eq!(PROVIDER_ID, CLOUD_PROVIDER);
    let f = fixture("n4");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let mut c = core(&f, Some(&g), &a, &m).unwrap();
    let k = key(&f.dir);
    let mut app = App::new("t", 10);
    run_call(&mut app, &mut c, Some(&k), &shown).unwrap();
    drop(c);
    let ev = events(&f);
    let check = ev.iter().find(|e| e.decision == "permit").unwrap();
    let r13: Value = serde_json::from_str(check.privacy_report.as_deref().unwrap()).unwrap();
    let sent = ev.iter().find(|e| e.decision == "sent").unwrap();
    let report: Value = serde_json::from_str(sent.privacy_report.as_deref().unwrap()).unwrap();
    assert_eq!(r13["provider"], report["provider_id"]);
    assert_eq!(r13["provider"], CLOUD_PROVIDER);
}

// ---------------- no launcher-set export threshold
#[test]
fn m1b_export_threshold_flag_is_refused() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_vaikor-tui"))
        .args(["run", "--export-threshold", "communications.content"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unknown argument --export-threshold"), "{err}");
    assert!(!include_str!("../src/main.rs").contains("--export-threshold"));
    assert!(!include_str!("../src/lib.rs").contains("parse_export_threshold"));
}

// ---------------- operator attestation (V1 :79, 0004 R9c, 0005 R3b)
struct AttestedChannel {
    operator_attest: bool,
    granted: bool,
    started: Cell<bool>,
}
impl ApprovalChannel for AttestedChannel {
    fn decide(&self, _r: &ApprovalRequest, now: &str) -> ApprovalDecision {
        ApprovalDecision {
            granted: self.granted,
            actor: "uid:2001".into(),
            at: now.into(),
        }
    }
    fn approver_uid(&self) -> Option<u32> {
        Some(2001)
    }
    // as SocketApproval: Some only when --operator-attest was given
    fn attestation(&self) -> Option<&str> {
        self.operator_attest
            .then_some(vaikor_cli::OPERATOR_ATTESTED)
    }
    fn r9c_attestation(&self) -> Option<String> {
        Some(vaikor_cli::r9c_attestation_text())
    }
    fn take_channel_start(&self) -> Option<String> {
        (!self.started.replace(true)).then(vaikor_cli::r9c_attestation_text)
    }
}

fn attested_run(tag: &str, operator_attest: bool, granted: bool) -> Vec<vaikor_core::AuditEvent> {
    let f = fixture(tag);
    let shown = RefCell::new(String::new());
    let a = AttestedChannel {
        operator_attest,
        granted,
        started: Cell::new(false),
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let mut c = core(&f, Some(&g), &a, &m).unwrap();
    let k = key(&f.dir);
    let mut app = App::new("t", 10);
    let _ = run_call(&mut app, &mut c, Some(&k), &shown);
    drop(c);
    events(&f)
}

#[test]
fn op_attest_flag_marks_start_and_every_approval_record() {
    for granted in [true, false] {
        let ev = attested_run(&format!("opa-{granted}"), true, granted);
        let with_r11: Vec<_> = ev.iter().filter_map(|e| e.approval.as_ref()).collect();
        // channel start + (approve | deny)
        assert!(with_r11.len() >= 2, "{ev:?}");
        assert_eq!(ev[0].step, "approval");
        for r in with_r11 {
            assert_eq!(r.approval_binding, "operator-attested");
            assert_eq!(r.attestation, "R9c");
            assert_eq!(r.undetected, vaikor_cli::R9C_UNDETECTED);
        }
    }
    for item in [
        "setuid-helpers",
        "sudo-doas-other-paths",
        "su-password",
        "stored-credentials",
        "keys",
        "container-runtimes",
    ] {
        assert!(vaikor_cli::R9C_UNDETECTED.contains(&item), "{item}");
    }
}

#[test]
fn op_attest_absent_without_the_flag() {
    let ev = attested_run("opa-none", false, true);
    let with_r11: Vec<_> = ev.iter().filter_map(|e| e.approval.as_ref()).collect();
    assert!(with_r11.len() >= 2);
    for r in with_r11 {
        assert_eq!(r.approval_binding, vaikor_core::ApprovalAudit::NONE);
        assert_eq!(r.attestation, "R9c");
    }
}

#[test]
fn op_attest_unclear_sudo_without_flag_refuses() {
    let unclear = vec!["/etc/sudoers unreadable".to_string()];
    assert!(vaikor_cli::attestation_verdict(&unclear, false)
        .unwrap_err()
        .contains("--operator-attest"));
    assert_eq!(vaikor_cli::attestation_verdict(&[], false), Ok(None));
    assert_eq!(
        vaikor_cli::attestation_verdict(&unclear, true),
        Ok(Some(vaikor_cli::OPERATOR_ATTESTED))
    );
}

#[test]
fn op_attest_is_visible_in_the_tui() {
    let mut app = App::new("t", 10);
    assert!(!screen(&app).contains("operator-attested"));
    app.set_operator_attested(true);
    assert!(screen(&app).contains("operator-attested (R9c)"));
    app.request_approval();
    assert!(screen(&app).contains("operator-attested (R9c)"));
}

// ---------------- Cedar principal + context tightened
#[test]
fn n2b_demo_policy_constrains_context() {
    let cedar = vaikor_grant::CedarEvaluator::parse(DEMO_POLICY).unwrap();
    let (holder, _) = did(&HOLDER_SEED);
    let ctx = |classes: &'static [&'static str], residency: &'static [&'static str]| {
        vaikor_grant::AuthContext {
            audience: "urn:test",
            data_classes: classes,
            residency,
        }
    };
    let ok = ctx(&["query"], &["unrestricted"]);
    assert!(cedar.permit(&holder, EGRESS_ACTION, CLOUD_URL, ok).unwrap());
    for bad in [
        ctx(&["communications.content"], &["unrestricted"]),
        ctx(&["query", "documents.text"], &["unrestricted"]),
        ctx(&[], &["unrestricted"]),
        ctx(&["query"], &["CH"]),
        ctx(&["query"], &["unrestricted", "CH"]),
        ctx(&["query"], &[]),
    ] {
        assert!(
            !cedar
                .permit(&holder, EGRESS_ACTION, CLOUD_URL, bad)
                .unwrap(),
            "{:?} {:?}",
            bad.data_classes,
            bad.residency
        );
    }
    assert!(DEMO_POLICY.contains("principal is User"));
}

#[test]
fn n2b_class_outside_the_policy_is_denied_and_audited() {
    let f = fixture("n2b");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let mut c = core(&f, Some(&g), &a, &m).unwrap();
    let k = key(&f.dir);
    let mut app = App::with_payload("t", 10, "documents.text", DEMO_PROMPT);
    let e = run_call(&mut app, &mut c, Some(&k), &shown).unwrap_err();
    assert!(e.contains("Policy"), "{e}");
    assert_eq!((m.calls.get(), a.asked.get()), (0, 0));
    drop(c);
    assert!(events(&f)
        .iter()
        .any(|e| e.decision == "deny" && e.reason.as_deref().unwrap_or("").contains("Policy")));
}

// ---------------- policy digest in R13 and channel start
fn sha256_hex(text: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

#[test]
fn n2b_policy_digest_in_r13_and_channel_start() {
    for (tag, policy) in [("builtin", DEMO_POLICY), ("file", ANY_CLASS_POLICY)] {
        let f = fixture(&format!("pdig-{tag}"));
        let shown = RefCell::new(String::new());
        let a = AttestedChannel {
            operator_attest: false,
            granted: true,
            started: Cell::new(false),
        };
        let m = Mock::new(f.log.clone());
        let g = good_grant();
        let mut c = core_with_policy(&f, policy, Some(&g), &a, &m).unwrap();
        let k = key(&f.dir);
        let mut app = App::new("t", 10);
        run_call(&mut app, &mut c, Some(&k), &shown).unwrap();
        drop(c);
        let ev = events(&f);
        let digest = sha256_hex(policy);
        let start = ev.iter().find(|e| e.step == "approval").unwrap();
        assert!(
            start
                .reason
                .as_deref()
                .unwrap()
                .contains(&format!("policy_sha256={digest}")),
            "{start:?}"
        );
        let r13 = ev.iter().find(|e| e.decision == "permit").unwrap();
        let r: Value = serde_json::from_str(r13.privacy_report.as_deref().unwrap()).unwrap();
        assert_eq!(r["policy_sha256"], digest.as_str());
    }
}

// ---------------- the audience comes from config
#[test]
fn grant_audience_must_match_the_configured_audience() {
    let f = fixture("aud");
    let shown = RefCell::new(String::new());
    let a = Approver {
        granted: true,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let (iss, _) = did(&ISSUER_SEED);
    let open = |audience: Option<String>| {
        Core::open(
            CoreConfig {
                log_path: Some(&f.log),
                log_seed: Some(LOG_SEED),
                grant: Some(&g),
                trusted_issuers: vec![iss.clone()],
                policy: Some(DEMO_POLICY),
                audience,
                now: Some(NOW.into()),
            },
            &a,
            &m,
        )
    };
    assert!(
        open(None).is_err(),
        "no audience configured: refuse to start"
    );
    let mut c = open(Some("tag:vaikor.com,2026:core:other".into())).unwrap();
    let k = key(&f.dir);
    let mut app = App::new("t", 10);
    let e = run_call(&mut app, &mut c, Some(&k), &shown).unwrap_err();
    assert!(e.contains("Audience"), "{e}");
    assert_eq!((m.calls.get(), a.asked.get()), (0, 0));
    drop(c);
    assert!(events(&f)
        .iter()
        .any(|e| e.decision == "deny" && e.reason.as_deref().unwrap_or("").contains("Audience")));
}

#[test]
fn require_audience_has_no_placeholder_default() {
    assert!(require_audience(None).is_err());
    assert!(require_audience(Some("  ")).is_err());
    assert!(require_audience(Some("did:example:vaikor-tui")).is_err());
    assert_eq!(require_audience(Some(&aud())).unwrap(), aud());
}

// ---------------- configured audience recorded at channel start
#[test]
fn audience_is_recorded_in_channel_start() {
    let f = fixture("aud-start");
    let a = AttestedChannel {
        operator_attest: false,
        granted: true,
        started: Cell::new(false),
    };
    let m = Mock::new(f.log.clone());
    let g = good_grant();
    let c = core(&f, Some(&g), &a, &m).unwrap();
    drop(c);
    let ev = events(&f);
    let start = ev.iter().find(|e| e.step == "approval").unwrap();
    let reason = start.reason.as_deref().unwrap();
    assert!(reason.contains(&format!("audience={}", aud())), "{reason}");
    assert!(reason.contains("policy_sha256="), "{reason}");
}

#[test]
fn refused_call_with_fifo_credential_never_opens_the_file() {
    use std::ffi::CString;
    let f = fixture("fifo-reference");
    let fifo = f.dir.0.join("credential");
    let path = CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: valid NUL-terminated path, no borrowed pointers retained.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // SAFETY: init creates a new descriptor; OwnedFd closes it once.
    let watch_fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    assert!(watch_fd >= 0);
    let watcher = unsafe { OwnedFd::from_raw_fd(watch_fd) };
    // SAFETY: live descriptor and valid NUL-terminated path.
    assert!(
        unsafe { libc::inotify_add_watch(watcher.as_raw_fd(), path.as_ptr(), libc::IN_OPEN) } >= 0
    );
    let credential = load_key(None, Some(fifo.as_os_str()));
    assert!(
        credential.is_ok(),
        "startup must retain a reference without opening the FIFO"
    );
    let shown = RefCell::new(String::new());
    let approval = Approver {
        granted: false,
        asked: Cell::new(0),
        screen_had_report: Default::default(),
        app_screen: &shown,
    };
    let sender = Mock::new(f.log.clone());
    let grant = good_grant();
    let mut c = core(&f, Some(&grant), &approval, &sender).unwrap();
    let mut app = App::new("test", 10);
    assert!(run_call(&mut app, &mut c, credential.as_ref().ok(), &shown).is_err());
    assert_eq!(sender.calls.get(), 0);
    let mut events = [0u8; 1024];
    // SAFETY: valid output buffer and live nonblocking descriptor.
    assert_eq!(
        unsafe {
            libc::read(
                watcher.as_raw_fd(),
                events.as_mut_ptr().cast(),
                events.len(),
            )
        },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().kind(),
        std::io::ErrorKind::WouldBlock,
        "refusal must never open the FIFO"
    );
}
