//! Demo 1: an unsigned preview TUI. One task with a countdown and exactly one
//! cloud call (Gemini) per human approval, sent only through `vaikor_gateway::send`.
//! The API key comes only from a file (`VAIKOR_API_KEY_FILE`) and is never
//! rendered, logged or formatted.
pub mod issue;
pub mod logkey;

use std::cell::Cell;
use std::ffi::OsStr;

use sha2::{Digest, Sha256};
use std::path::Path;
use vaikor_cli::{ApprovalChannel, ApprovalRequest};
use vaikor_core::{ApprovalAudit, AuditEvent};
use vaikor_grant::Budget;

use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

pub use vaikor_gateway::{ApiKey, KeySource};

pub const BANNER: &str = "UNSIGNED PREVIEW - NO PROVENANCE";
/// The gateway's reviewed Gemini surface (0007 R3 registry, GLOBAL): exactly
/// the stateless OpenAI-compatible chat-completions endpoint.
pub const CLOUD_URL: &str =
    "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions";
pub const CLOUD_PROVIDER: &str = "https://generativelanguage.googleapis.com/";
pub const CLOUD_REGION: &str = "GLOBAL";
pub const PROFILE: &str = "P0";
/// Fixed, public demo content only: the payload is `unrestricted`.
pub const RESIDENCY: &str = "unrestricted";
/// Cheapest stable free-tier Flash text model available to this key, from
/// GET /v1beta/models (2026-10-17, as vaikor-demo; supports generateContent).
/// Pricing (ai.google.dev/gemini-api/docs/pricing, 2026-10-16): Free tier
/// free of charge; paid $0.25 in / $1.50 out per 1M. gemini-2.5-flash-lite is
/// cheaper but 2.5 models are limited to existing users (docs/models,
/// 2026-10-13); 3.5-flash-lite ($0.30/$2.50) and 3.8-flash cost more.
pub const DEFAULT_MODEL: &str = "gemini-3.1-flash-lite";
/// The provider id in the R13 record: the gateway registry id (0007 R3, the
/// origin the gateway validates), identical to what `send()` gets.
pub const PROVIDER_ID: &str = CLOUD_PROVIDER;
pub const CALL_LABEL: &str = "cloud call (Gemini)";
/// The Demo 1 owner policy (Cedar, 0002 R18): permits exactly the one call.
pub const DEMO_POLICY: &str = include_str!("../policy.cedar");

/// The gateway refuses Gemini without a project (`provider_project`).
pub fn require_project(project: Option<&str>) -> Result<String, String> {
    match project.map(str::trim) {
        Some(p) if !p.is_empty() => Ok(p.to_string()),
        _ => Err("Gemini needs its project id (--gemini-project or VAIKOR_GEMINI_PROJECT)".into()),
    }
}
pub const GIT_SHA: &str = env!("VAIKOR_TUI_GIT_SHA");

pub struct SendOutcome {
    pub status: u16,
    pub body: String,
    pub report: serde_json::Value,
}

/// The one egress seam; production uses [`GatewaySender`].
pub trait CloudSender {
    fn send(&self, body: &[u8], credential: &KeySource) -> Result<SendOutcome, String>;
}

pub fn format_remaining(secs: u64) -> String {
    format!("{:02}:{:02}", secs / 60, secs % 60)
}

pub fn remaining_secs(total: u64, elapsed: u64) -> u64 {
    total.saturating_sub(elapsed)
}

/// File only (RONI files audit, 0007): a key in the environment is refused.
/// Errors never contain the key.
pub fn load_key(env_key: Option<String>, file: Option<&OsStr>) -> Result<KeySource, String> {
    if env_key.is_some_and(|k| !k.is_empty()) {
        return Err("the cloud API key comes from a file (VAIKOR_API_KEY_FILE); VAIKOR_API_KEY in the environment is refused".into());
    }
    match file.filter(|p| !p.is_empty()) {
        Some(path) => Ok(KeySource::File(Path::new(path).to_path_buf())),
        None => Err("VAIKOR_API_KEY_FILE is not set".into()),
    }
}

pub fn demo_request_body(prompt: &str) -> Vec<u8> {
    demo_request_body_for(DEFAULT_MODEL, prompt)
}

pub fn demo_request_body_for(model: &str, prompt: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "model": model,
        "temperature": 0,
        "messages": [{ "role": "user", "content": prompt }],
    }))
    .expect("json")
}

/// Production sender: the gateway is the only HTTP path.
pub struct GatewaySender {
    pub step: std::cell::Cell<u32>,
    /// Gemini project id (not a secret; required by the gateway).
    pub project: String,
}

impl CloudSender for GatewaySender {
    fn send(&self, body: &[u8], credential: &KeySource) -> Result<SendOutcome, String> {
        let step = self.step.get() + 1;
        self.step.set(step);
        let stamp = vaikor_gateway::utc_stamp();
        let residency = [RESIDENCY.to_string()];
        let step = format!("tui-{step}");
        vaikor_gateway::send_with_credential(
            &vaikor_gateway::SendRequest {
                url: CLOUD_URL,
                provider_id: PROVIDER_ID,
                provider_project: Some(&self.project),
                profile: PROFILE,
                residency: &residency,
                region: CLOUD_REGION,
                data_classes: &[DEMO_CLASS],
                fields: &["messages"],
                body,
                authorization: None,
                call_at: &stamp,
                step: &step,
                local: false,
            },
            Some(credential),
        )
        .map(|r| SendOutcome {
            status: r.status,
            body: r.body,
            report: r.report,
        })
        .map_err(|e| e.message)
    }
}

pub const EGRESS_ACTION: &str = "egress.send";
pub const CAPABILITY: &str = "tag:vaikor.com,2026:capability:egress.send:gemini";
/// The demo payload class (0007 §5.3 A: allowed by the default threshold).
pub const DEMO_CLASS: &str = "query";
/// Fixed, PII-free demo prompt. The task text is never sent.
pub const DEMO_PROMPT: &str =
    "In one short sentence, give a practical tip for finishing a software demo on time.";

/// TTY keys only display or quit: approval comes from the Core channel.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyAction {
    None,
    RequestApproval,
    Quit,
}

pub fn key_action(c: char) -> KeyAction {
    match c {
        'a' => KeyAction::RequestApproval,
        'q' => KeyAction::Quit,
        _ => KeyAction::None,
    }
}

pub trait AuditSink {
    fn append(&mut self, event: &AuditEvent) -> Result<(), String>;
    fn read_events(&mut self) -> Result<Vec<AuditEvent>, String>;
}
impl AuditSink for vaikor_log::Chain {
    fn append(&mut self, event: &AuditEvent) -> Result<(), String> {
        vaikor_log::Chain::append(self, event)
    }
    fn read_events(&mut self) -> Result<Vec<AuditEvent>, String> {
        vaikor_log::Chain::read_events(self)
    }
}

/// `run` flags (no launcher-set export threshold; check A uses the
/// owner policy default, 0007 R11 A). Any other flag is refused before the
/// terminal check, so a misconfigured launcher fails loudly.
pub const RUN_VALUE_FLAGS: &[&str] = &[
    "--log",
    "--log-key",
    "--grant",
    "--trusted-issuer",
    "--approve",
    "--approve-uid",
    "--non-approver-uid",
    "--agent-uid",
    "--approve-timeout",
    "--gemini-project",
    "--policy",
    "--audience",
    "--task",
    "--seconds",
];

pub fn check_run_flags(args: &[String]) -> Result<(), String> {
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--operator-attest" => {}
            f if RUN_VALUE_FLAGS.contains(&f) => i += 1,
            other => return Err(format!("unknown argument {other}")),
        }
        i += 1;
    }
    Ok(())
}

/// The configured grant audience (`--audience` / `VAIKOR_AUDIENCE`). No
/// default: `did:example:` is a non-resolvable placeholder (0002), refused.
pub fn require_audience(configured: Option<&str>) -> Result<String, String> {
    match configured.map(str::trim) {
        Some(a) if a.starts_with("did:example:") => {
            Err("grant audience did:example:* is a placeholder; configure the real one".into())
        }
        Some(a) if !a.is_empty() => Ok(a.to_string()),
        _ => Err("grant audience is required (--audience or VAIKOR_AUDIENCE)".into()),
    }
}

/// The build must carry its commit (`VAIKOR_GIT_SHA` at build time).
pub fn require_build_sha(sha: &str) -> Result<(), String> {
    if sha.is_empty() || sha == "unknown" {
        return Err("built without VAIKOR_GIT_SHA; refusing to start".into());
    }
    Ok(())
}

/// The TUI needs a real terminal on stdin and stdout.
pub fn require_tty(stdin_tty: bool, stdout_tty: bool) -> Result<(), String> {
    if !(stdin_tty && stdout_tty) {
        return Err(
            "vaikor-tui run needs a terminal on stdin and stdout; refusing (no non-tty mode)"
                .into(),
        );
    }
    Ok(())
}

pub struct CoreConfig<'a> {
    /// Mandatory: no path or no key = refuse to start.
    pub log_path: Option<&'a Path>,
    pub log_seed: Option<[u8; 32]>,
    /// The presented grant; `None` refuses every call (audited).
    pub grant: Option<&'a serde_json::Value>,
    pub trusted_issuers: Vec<String>,
    /// Owner policy (Cedar text); `None` refuses to start.
    pub policy: Option<&'a str>,
    /// The Core's grant audience (0002 `aud`), from config; `None` refuses
    /// to start. A grant whose `aud` differs is denied.
    pub audience: Option<String>,
    /// Fixed clock for tests; `None` = gateway UTC stamp.
    pub now: Option<String>,
}

/// The Core gate in front of the one egress: grant, budget, approval channel,
/// signed audit before the send.
pub struct Core<'a> {
    approval: &'a dyn ApprovalChannel,
    sender: &'a dyn CloudSender,
    chain: Box<dyn AuditSink>,
    grant: Option<&'a serde_json::Value>,
    trusted: Vec<String>,
    /// Owner policy (0002 R18): always the Cedar evaluator (the permit-all double is test-only).
    policy: vaikor_grant::CedarEvaluator,
    now: Option<String>,
    /// SHA-256 (hex) of the loaded policy text (built-in or --policy),
    /// recorded at channel start and in every R13 record.
    policy_sha256: String,
    /// Configured grant audience; `None` denies every call.
    audience: Option<String>,
    attempt: u32,
    /// Input class of the current call, from the Core's record (the App).
    class: String,
}

impl<'a> Core<'a> {
    /// A Core on `sink` with the channel start audited at once (no
    /// configured audience: use [`Core::open`] in production).
    pub fn with_sink(
        sink: Box<dyn AuditSink>,
        policy: &str,
        grant: Option<&'a serde_json::Value>,
        trusted: Vec<String>,
        now: Option<String>,
        approval: &'a dyn ApprovalChannel,
        sender: &'a dyn CloudSender,
    ) -> Result<Self, String> {
        let mut core = Self::assemble(sink, policy, grant, trusted, now, approval, sender)?;
        core.start_channel()?;
        Ok(core)
    }

    fn assemble(
        sink: Box<dyn AuditSink>,
        policy: &str,
        grant: Option<&'a serde_json::Value>,
        trusted: Vec<String>,
        now: Option<String>,
        approval: &'a dyn ApprovalChannel,
        sender: &'a dyn CloudSender,
    ) -> Result<Self, String> {
        // 0002: a parse error is a denial; here it refuses to start.
        let policy_sha256 = format!("{:x}", Sha256::digest(policy.as_bytes()));
        let policy = vaikor_grant::CedarEvaluator::parse(policy)
            .map_err(|e| format!("owner policy (Cedar) invalid: {e}"))?;
        Ok(Self {
            approval,
            sender,
            chain: sink,
            grant,
            trusted,
            policy,
            now,
            policy_sha256,
            audience: None,
            attempt: 0,
            class: DEMO_CLASS.into(),
        })
    }

    /// 0004 R9c: the channel start is audited (attestation=R9c + undetected,
    /// policy digest, configured audience) before any request; a failed write
    /// refuses to start.
    fn start_channel(&mut self) -> Result<(), String> {
        let now = self.now();
        if let Some(mut event) = vaikor_cli::channel_start_event(self.approval, &now) {
            let reason = event.reason.take().unwrap_or_default();
            event.reason = Some(format!(
                "{reason} policy_sha256={} audience={}",
                self.policy_sha256,
                self.audience.as_deref().unwrap_or("unset")
            ));
            self.chain
                .append(&event)
                .map_err(|e| format!("channel-start audit failed, refusing to start: {e}"))?;
        }
        Ok(())
    }
    pub fn open(
        config: CoreConfig<'a>,
        approval: &'a dyn ApprovalChannel,
        sender: &'a dyn CloudSender,
    ) -> Result<Self, String> {
        let path = config
            .log_path
            .ok_or("vaikor-tui requires a signed audit log (--log)")?;
        let seed = config
            .log_seed
            .ok_or("vaikor-tui requires the audit log key (--log-key)")?;
        let chain = vaikor_log::Chain::open(path, &seed)?;
        let audience = require_audience(config.audience.as_deref())?;
        let mut core = Self::assemble(
            Box::new(chain),
            config
                .policy
                .ok_or("vaikor-tui requires an owner policy (Cedar)")?,
            config.grant,
            config.trusted_issuers,
            config.now,
            approval,
            sender,
        )?;
        core.audience = Some(audience);
        core.start_channel()?;
        Ok(core)
    }

    /// Set the configured grant audience (for sinks built with `with_sink`).
    pub fn with_audience(mut self, audience: &str) -> Result<Self, String> {
        self.audience = Some(require_audience(Some(audience))?);
        Ok(self)
    }

    fn now(&self) -> String {
        self.now.clone().unwrap_or_else(vaikor_gateway::utc_stamp)
    }

    fn event(&self, step: &str, decision: &str, actor: &str, reason: Option<String>) -> AuditEvent {
        AuditEvent {
            privacy_report: None,
            usage: None,
            reason,
            step: step.into(),
            capability: CAPABILITY.into(),
            effects: vec!["egress".into()],
            data_classes: vec![self.class.clone()],
            decision: decision.into(),
            actor: actor.into(),
            at: self.now(),
            approval: None,
        }
    }

    fn deny(
        &mut self,
        step: &str,
        actor: &str,
        reason: String,
        approval: Option<ApprovalAudit>,
    ) -> String {
        let mut event = self.event(step, "deny", actor, Some(reason.clone()));
        event.approval = approval;
        match self.chain.append(&event) {
            Ok(()) => reason,
            Err(e) => format!("{reason}; audit write failed: {e}"),
        }
    }

    fn approval_audit(&self) -> ApprovalAudit {
        let mut audit = ApprovalAudit {
            approver_uid: self.approval.approver_uid(),
            ..ApprovalAudit::not_attested()
        };
        if let Some(text) = self.approval.r9c_attestation() {
            let (attestation, undetected) = vaikor_cli::r9c_fields(&text);
            if let Some(attestation) = attestation {
                audit.attestation = attestation;
            }
            audit.undetected = undetected;
        }
        if let Some(binding) = self.approval.attestation() {
            audit.approval_binding = binding.to_string();
        }
        audit
    }

    /// Grant (0007 R7/R8, INV 2) and remaining budget, recovered from the audit.
    fn check_grant(&mut self, now: &str) -> Result<(String, Budget), String> {
        let document = self.grant.ok_or("no grant presented")?;
        let roots: Vec<&str> = self.trusted.iter().map(String::as_str).collect();
        let token = vaikor_grant::accept_presented(document, now, &roots)
            .map_err(|e| format!("grant denied: {e:?}"))?;
        let residency = [RESIDENCY];
        let audience = self
            .audience
            .as_deref()
            .ok_or("grant denied: no audience configured")?;
        vaikor_grant::authorise(
            &token,
            &vaikor_grant::Request {
                holder: &token.link.sub,
                audience,
                action: EGRESS_ACTION,
                resource: Some(CLOUD_URL),
                data_classes: &[self.class.as_str()],
                residency: &residency,
            },
            Some(now),
            &self.policy,
        )
        .map_err(|e| format!("grant denied: {e:?}"))?;
        let id = document["id"]
            .as_str()
            .filter(|i| !i.is_empty())
            .ok_or("grant denied: missing token id")?;
        let account = serde_json::json!([token.link.iss, id]).to_string();
        let mut budget = token.link.budget.clone();
        for event in self.chain.read_events()? {
            if let Some((key, _, uses)) = &event.usage {
                if key == &account {
                    let bound = u32::try_from(*uses).map_err(|_| "audit bound")?;
                    vaikor_grant::spend_step(&mut budget, None, bound)
                        .map_err(|_| "budget exhausted (audit)".to_string())?;
                }
            }
        }
        Ok((account, budget))
    }
}

#[derive(Debug, PartialEq)]
enum Mode {
    Idle,
    AwaitingApproval,
}

#[derive(Debug)]
pub struct App {
    task: String,
    total: u64,
    elapsed: u64,
    mode: Mode,
    /// Set by `render` when the privacy report was actually drawn.
    report_rendered: Cell<bool>,
    class: String,
    prompt: String,
    reply: String,
    status: String,
    /// Shown in the banner as `operator-attested (R9c)`.
    operator_attested: bool,
}

impl App {
    pub fn new(task: &str, total_secs: u64) -> Self {
        Self {
            task: task.into(),
            total: total_secs,
            elapsed: 0,
            mode: Mode::Idle,
            report_rendered: Cell::new(false),
            class: DEMO_CLASS.into(),
            prompt: DEMO_PROMPT.into(),
            reply: String::new(),
            status: "press [a] to show the privacy report and request approval, [q] to quit".into(),
            operator_attested: false,
        }
    }

    pub fn with_payload(task: &str, total_secs: u64, class: &str, prompt: &str) -> Self {
        let mut app = Self::new(task, total_secs);
        app.class = class.into();
        app.prompt = prompt.into();
        app
    }

    /// Set from the channel's attestation, which is `operator-attested` only
    /// with `--operator-attest` (never automatic; 0005 R3b).
    pub fn set_operator_attested(&mut self, on: bool) {
        self.operator_attested = on;
    }

    pub fn tick(&mut self, elapsed: u64) {
        self.elapsed = elapsed;
    }

    /// Show the privacy report; the request goes to the approver only after
    /// the report has been rendered.
    pub fn request_approval(&mut self) {
        self.mode = Mode::AwaitingApproval;
        self.report_rendered.set(false);
        self.status = "waiting for the approver (second terminal, Core socket)...".into();
    }

    pub fn awaiting_approval(&self) -> bool {
        self.mode == Mode::AwaitingApproval
    }

    pub fn ask_cloud(&mut self, core: &mut Core, key: Option<&KeySource>) -> Result<(), String> {
        let result = self.ask_inner(core, key);
        self.mode = Mode::Idle;
        self.report_rendered.set(false);
        if let Err(e) = &result {
            self.status = format!("refused: {e}");
        }
        result
    }

    fn ask_inner(&mut self, core: &mut Core, key: Option<&KeySource>) -> Result<(), String> {
        core.attempt += 1;
        core.class = self.class.clone();
        let step = format!("tui-{}", core.attempt);
        let now = core.now();
        if self.mode != Mode::AwaitingApproval || !self.report_rendered.get() {
            return Err(core.deny(
                &step,
                "core",
                "privacy report was not on screen".into(),
                None,
            ));
        }
        let (account, mut budget) = match core.check_grant(&now) {
            Ok(v) => v,
            Err(e) => return Err(core.deny(&step, "core", e, None)),
        };
        if vaikor_grant::spend_step(&mut budget, None, 1).is_err() {
            return Err(core.deny(&step, "core", "grant budget exhausted".into(), None));
        }
        let Some(key) = key else {
            return Err(core.deny(
                &step,
                "core",
                "no API key (VAIKOR_API_KEY_FILE)".into(),
                None,
            ));
        };
        let body = demo_request_body(&self.prompt);
        let digest = format!("{:x}", Sha256::digest(&body));
        let request = ApprovalRequest::new(
            &digest,
            &step,
            CAPABILITY,
            &serde_json::json!({"url": CLOUD_URL, "body_sha256": digest}),
        )?;
        // 0004 R9c: a channel that refused to start is untrusted; its own
        // reason, distinct from an approver's denial or a timeout.
        if let Some(why) = core.approval.refusal() {
            let r11 = core.approval_audit();
            return Err(core.deny(
                &step,
                "core",
                format!("approval_channel_untrusted ({why})"),
                Some(r11),
            ));
        }
        let decision = core.approval.decide(&request, &now);
        let r11 = core.approval_audit();
        if !decision.granted {
            return Err(core.deny(
                &step,
                &decision.actor,
                "approver denied or timed out".into(),
                Some(r11),
            ));
        }
        // The attempt is on the signed chain before any byte leaves.
        let mut pre = core.event(&step, "approve", &decision.actor, None);
        pre.privacy_report = Some(privacy_preview(&self.class, &self.prompt).to_string());
        pre.usage = Some((account, 0, 1));
        pre.approval = Some(r11);
        core.chain
            .append(&pre)
            .map_err(|e| format!("audit write failed, not sent: {e}"))?;
        // 0007 §5.3 (R8d: every call, approved or not): checks A-D on the exact
        // bytes; the R13 entry is appended before send() or the refusal.
        let tags = [RESIDENCY.to_string()];
        // Input class: the Core's record of this payload (fixed demo prompt;
        // a dynamic input would take it from the step read log, 0012 R10).
        let classes = [self.class.as_str()];
        let checked =
            // owner-policy defaults (0007 R11 A/C, R12): size, detector
            // version and export threshold; no launcher override
            vaikor_gateway::egress_check::egress_check(&vaikor_gateway::egress_check::Check::new(
                PROVIDER_ID,
                CLOUD_REGION,
                &classes,
                &tags,
                &body,
            ));
        let verdict = if checked.refusal.is_some() {
            "deny"
        } else {
            "permit"
        };
        let mut entry = core.event(&step, verdict, "core", checked.refusal.clone());
        let mut record = checked.record;
        record["policy_sha256"] = core.policy_sha256.clone().into();
        entry.privacy_report = Some(record.to_string());
        core.chain
            .append(&entry)
            .map_err(|e| format!("audit write failed, not sent: {e}"))?;
        if let Some(reason) = checked.refusal {
            return Err(reason);
        }
        let sent = core.sender.send(&body, key);
        let (decision, report, outcome) = match sent {
            Ok(out) if (200..300).contains(&out.status) => {
                let reply = serde_json::from_str::<serde_json::Value>(&out.body)
                    .ok()
                    .and_then(|v| {
                        v["choices"][0]["message"]["content"]
                            .as_str()
                            .map(str::to_string)
                    });
                match reply {
                    Some(text) => ("sent", Some(out.report), Ok((text, out.status))),
                    None => (
                        "failed",
                        Some(out.report),
                        Err("Gemini response has no message content".to_string()),
                    ),
                }
            }
            Ok(out) => (
                "failed",
                Some(out.report),
                Err(format!("Gemini HTTP {}", out.status)),
            ),
            Err(e) => ("failed", None, Err(e)),
        };
        let mut post = core.event(&step, decision, "core", outcome.as_ref().err().cloned());
        post.privacy_report = report.map(|r| r.to_string());
        core.chain.append(&post)?;
        let (text, status) = outcome?;
        self.reply = text;
        self.status = format!("Gemini replied (HTTP {status})");
        Ok(())
    }
}

/// What the TUI shows and the audit stores before the send.
pub fn privacy_preview(class: &str, prompt: &str) -> serde_json::Value {
    serde_json::json!({
        "destination": CLOUD_URL, "profile": PROFILE, "region": CLOUD_REGION,
        "residency": [RESIDENCY], "data_classes": [class], "fields": ["messages"],
        "prompt_chars": prompt.chars().count(),
    })
}

pub fn render(app: &App, f: &mut Frame) {
    let [banner, task, cloud, status] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(4),
        Constraint::Min(8),
        Constraint::Length(3),
    ])
    .areas(f.area());
    f.render_widget(
        Paragraph::new(format!("{BANNER}  (build {GIT_SHA})"))
            .style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::ALL)),
        banner,
    );
    let left = remaining_secs(app.total, app.elapsed);
    f.render_widget(
        Paragraph::new(format!(
            "Task: {}\nCountdown: {}",
            app.task,
            format_remaining(left)
        ))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Task & Countdown "),
        ),
        task,
    );
    let cloud_text = match app.mode {
        Mode::AwaitingApproval => {
            app.report_rendered.set(true);
            format!(
                "Privacy report (before send):\n  destination: {CLOUD_URL}\n  profile: {PROFILE}  region: {CLOUD_REGION}  residency: {RESIDENCY}\n  data: {} (field: messages)\n  prompt: {}\n\nApproval: the approver decides in the second terminal (Core socket).",
                app.class,
                app.prompt
            )
        }
        _ if app.reply.is_empty() => "(no call yet)".into(),
        _ => format!("Gemini: {}", app.reply),
    };
    f.render_widget(
        Paragraph::new(cloud_text).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" cloud call (Gemini) via vaikor-gateway "),
        ),
        cloud,
    );
    f.render_widget(
        Paragraph::new(app.status.as_str()).block({
            let block = Block::default().borders(Borders::ALL);
            // Never automatic: only with --operator-attest (0005 R3b).
            if app.operator_attested {
                block.title(" approval: operator-attested (R9c) ")
            } else {
                block
            }
        }),
        status,
    );
}
