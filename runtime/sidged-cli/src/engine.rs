// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! The one execution engine (ROADMAP 11f; 0002 R25, R26; 0004 R9; 0005 R5a).
//!
//! Every entry point runs a plan through [`run`]: `sidged run` and `sidged guard` with a
//! presented token and its holder's proof, `sidged task` and the companion under the node's
//! owner mandate. The engine, in order:
//!
//! 1. refuses an effectful run whose audit sink is not durable (0005 R5a);
//! 2. reads the plan with the one parser and runs the verifier (and the Cedar flow check,
//!    when given) on exactly that representation (0003, 0013 §4);
//! 3. lets the backend check what it would send before anyone is asked (destinations);
//! 4. accepts the grant: the token, its chain and the presenter's proof over the plan
//!    digest and a nonce the Core draws now (R25), or the node mandate path;
//! 5. per step: kill switch, arguments, authorisation and reservation at the step's own time
//!    (R17-R22), approval (0004 R9), the reservation and the decision on the audit sink before
//!    the effect (0005 R5a, invariant 9), dispatch to the backend, the outcome after it.
//!
//! A step that is not completed stops the plan; every later step is `skipped`.

use serde_json::{json, Value};
use sidged_capability::Registry;
use sidged_core::{AuditEvent, CapabilityRecord};
use sidged_grant::{accept_presented, authorise, verify_pop, CedarEvaluator, Request, Token};
use sidged_verify::flow::{check_plan_flows, CedarFlowPolicy};
use sidged_verify::{verify, Arg, Plan, Step, Summary};
use zeroize::Zeroizing;

use crate::approval::{ApprovalChannel, ApprovalRequest};
use crate::node_grant::{grant_denial, PlanGrant, PlanGrantInputs};
use crate::{approval_audit, rejected_peer_event, reserve_step, spend_event, LedgerAccount};

/// Whoever presents a grant proves possession of its holder key (0002 R25): it signs the
/// presentation over the plan digest and the nonce the Core drew for this run.
pub trait Presenter {
    fn prove(&self, token: &Value, audience: &str, plan_digest: &str, nonce: &str) -> [u8; 64];
}

/// A holder key read from a file (`sidged run --holder-key`) or the node's executor key.
pub struct HolderKey(Zeroizing<[u8; 32]>);

impl HolderKey {
    pub fn new(seed: [u8; 32]) -> Self {
        Self(Zeroizing::new(seed))
    }

    /// The holder's seed from a regular 0600 file of 64 hex characters owned by the reading
    /// uid (`sidged run --holder-key`). The file is opened without following a symlink and
    /// checked on the open descriptor, so no swap between check and read is possible.
    pub fn from_file(path: &std::path::Path) -> Result<Self, String> {
        use std::io::Read as _;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let shown = path.display();
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|err| {
                if err.raw_os_error() == Some(libc::ELOOP) {
                    format!("holder key {shown} is a symlink; refused")
                } else {
                    format!("holder key {shown}: {}", err.kind())
                }
            })?;
        let meta = file
            .metadata()
            .map_err(|err| format!("holder key {shown}: {}", err.kind()))?;
        if !meta.is_file() {
            return Err(format!("holder key {shown} is not a regular file; refused"));
        }
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        sidged_gateway::check_key_file_meta(meta.mode(), meta.uid(), euid)
            .map_err(|why| format!("holder key {shown}: {why}"))?;
        let mut text = Zeroizing::new(String::new());
        file.by_ref()
            .take(256)
            .read_to_string(&mut text)
            .map_err(|err| format!("holder key {shown}: {}", err.kind()))?;
        let hex = text.trim();
        let mut seed = Zeroizing::new([0u8; 32]);
        if hex.len() != 64 || !hex.is_ascii() {
            return Err(format!("holder key {shown}: expected 64 hex characters"));
        }
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| format!("holder key {shown}: expected 64 hex characters"))?;
        }
        Ok(Self(seed))
    }
}

impl Presenter for HolderKey {
    fn prove(&self, token: &Value, audience: &str, plan_digest: &str, nonce: &str) -> [u8; 64] {
        sidged_grant::sign_pop(&self.0, token, audience, plan_digest, nonce)
    }
}

/// A fresh nonce from the Core's randomness (0002 R25): 32 bytes, hex.
pub(crate) fn fresh_hex(bytes: usize) -> Result<String, String> {
    let mut buf = vec![0u8; bytes];
    getrandom::getrandom(&mut buf).map_err(|e| format!("randomness: {e}"))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Where the engine records each step (invariant 9; 0005 R5, R5a, R6; 0004 R11): the
/// reservation and the decision before the effect, the outcome after it. An error from
/// either method stops the plan; after a failed decision the step does not run.
pub trait AuditSink {
    /// `allow`, `approve`, `reserve` or `deny`, and the `spend` reservations before them.
    fn decision(&mut self, event: &AuditEvent) -> Result<(), String>;
    /// What the backend did after an `allow` or `approve`.
    fn outcome(&mut self, event: &AuditEvent) -> Result<(), String>;
    /// Whether what is appended survives the process: only a signed chain is (0005 R5a).
    fn durable(&self) -> bool;
    /// Everything recorded so far: the ledger the grant replays (0002 R20, R21).
    fn history(&mut self) -> Result<Vec<AuditEvent>, String>;
}

/// The signed audit chain: both kinds are appended and synced in order.
impl AuditSink for sidged_log::Chain {
    fn decision(&mut self, event: &AuditEvent) -> Result<(), String> {
        self.append(event)
    }

    fn outcome(&mut self, event: &AuditEvent) -> Result<(), String> {
        self.append(event)
    }

    fn durable(&self) -> bool {
        true
    }

    fn history(&mut self) -> Result<Vec<AuditEvent>, String> {
        self.read_events()
    }
}

/// A chain when there is one; without one nothing is recorded, so only a dry run may run.
impl AuditSink for Option<sidged_log::Chain> {
    fn decision(&mut self, event: &AuditEvent) -> Result<(), String> {
        self.as_mut().map_or(Ok(()), |chain| chain.append(event))
    }

    fn outcome(&mut self, event: &AuditEvent) -> Result<(), String> {
        self.as_mut().map_or(Ok(()), |chain| chain.append(event))
    }

    fn durable(&self) -> bool {
        self.is_some()
    }

    fn history(&mut self) -> Result<Vec<AuditEvent>, String> {
        self.as_mut()
            .map_or(Ok(Vec::new()), |chain| chain.read_events())
    }
}

/// What happened to one plan step.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StepOutcome {
    pub id: String,
    pub capability: String,
    /// `completed`, `refused` (no backend or bad input), `denied` (no grant, no approval),
    /// `failed` (the backend reported an error) or `skipped` (an earlier step stopped the run).
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The verifier's flow stage for this run (0003 R11, 0013 §4).
pub enum Flow<'a> {
    /// The hosted verifier: no sensitive class reaches egress.
    DenySensitive,
    /// The owner's Cedar flow policy, evaluated on the parsed plan.
    Cedar {
        policy: &'a CedarFlowPolicy,
        owner: &'a str,
    },
    /// Tests of the step loop only.
    #[cfg(test)]
    Structural,
}

/// Where the grant of a run comes from (0002 R26: one per-step grant interface).
pub enum GrantSource<'a> {
    /// A presented token and its holder's proof (`sidged run`, `sidged guard`).
    Presented {
        token: Option<&'a Value>,
        trusted_issuers: &'a [&'a str],
        /// The grant policy (Cedar, R18).
        policy: &'a str,
        /// The run's audience; the token must name it.
        audience: &'a str,
        /// Without one only a dry run may proceed.
        presenter: Option<&'a dyn Presenter>,
        /// The time every step is authorised at; `None` is the clock at each step (R17).
        at: Option<&'a str>,
    },
    /// The node's owner mandate (`sidged task`, the companion): the executor mints a task
    /// token for the plan and `presenter` proves possession of the executor key.
    Mandate {
        mandate: Option<&'a Value>,
        policy: Option<&'a str>,
        owner: &'a str,
        audience: &'a str,
        executor_seed: &'a [u8; 32],
        presenter: &'a dyn Presenter,
    },
    /// Tests of the step loop only: every step is covered and nothing is reserved.
    #[cfg(test)]
    Unchecked,
}

/// The per-step grant interface: authorise one call at its own time and reserve its use and
/// budget. Returns the reservations to record before the effect; the error is the denial.
pub trait StepGrant {
    fn reserve(
        &mut self,
        step: &str,
        capability: &str,
        record: &CapabilityRecord,
        bound: u32,
    ) -> Result<Vec<AuditEvent>, String>;
}

/// A presented token after acceptance: its proven holder and its ledger accounts.
struct PresentedGrant {
    token: Token,
    /// The presenter whose proof verified (`sub`, `cnf`), never taken unproven for an effect.
    holder: String,
    audience: String,
    policy: CedarEvaluator,
    accounts: Vec<LedgerAccount>,
    at: Option<String>,
}

impl StepGrant for PresentedGrant {
    fn reserve(
        &mut self,
        step: &str,
        capability: &str,
        record: &CapabilityRecord,
        bound: u32,
    ) -> Result<Vec<AuditEvent>, String> {
        let now = self.at.clone().unwrap_or_else(sidged_gateway::utc_stamp);
        let action = capability.rsplit(':').next().unwrap_or(capability);
        let classes: Vec<&str> = record.data_classes.iter().map(String::as_str).collect();
        let tags: Vec<&str> = record.residency.iter().map(String::as_str).collect();
        let request = Request {
            holder: &self.holder,
            audience: &self.audience,
            action,
            resource: Some(capability),
            data_classes: &classes,
            residency: &tags,
        };
        authorise(&self.token, &request, Some(&now), &self.policy)
            .map_err(|err| format!("grant denied {step}: {err}"))?;
        let cost = record
            .cost_amount
            .as_deref()
            .zip(record.cost_currency.as_deref());
        let selections = reserve_step(
            &mut self.accounts,
            action,
            capability,
            &classes,
            cost,
            bound,
        )
        .map_err(|err| format!("grant denied {step}: {err}"))?;
        Ok(selections
            .into_iter()
            .map(|(key, index)| spend_event(key, index, bound, cost, step, capability, &now))
            .collect())
    }
}

impl StepGrant for PlanGrant {
    fn reserve(
        &mut self,
        step: &str,
        capability: &str,
        _record: &CapabilityRecord,
        bound: u32,
    ) -> Result<Vec<AuditEvent>, String> {
        self.reserve_bound(step, capability, bound)
    }
}

#[cfg(test)]
struct Unchecked;

#[cfg(test)]
impl StepGrant for Unchecked {
    fn reserve(
        &mut self,
        _: &str,
        _: &str,
        _: &CapabilityRecord,
        _: u32,
    ) -> Result<Vec<AuditEvent>, String> {
        Ok(Vec::new())
    }
}

/// One call step as the engine hands it to the backend.
pub struct StepCall<'a> {
    pub id: &'a str,
    pub capability: &'a str,
    pub record: &'a CapabilityRecord,
    pub args: &'a [(String, Arg)],
    pub now: &'a str,
    pub dry_run: bool,
    /// The approval binding text, when a person approved the step.
    pub binding: Option<&'a str>,
    /// Who decided the step (`core` or the approver) and the R11 approval fields.
    pub actor: &'a str,
    pub approval: Option<&'a sidged_core::ApprovalAudit>,
}

/// Whether the backend runs a step.
pub enum Admit {
    Run,
    /// Not a call this backend executes, and nothing to decide (an `expr` the gateway does
    /// not evaluate).
    Skip,
    /// Refused before any grant or approval, with the reason.
    Refuse(String),
}

/// A refusal before the grant is looked at, for one step or for the whole plan.
pub struct Preflight {
    pub step: Option<(String, String)>,
    pub message: String,
}

/// What the backend did with a call.
pub struct Dispatched {
    /// `completed`, `failed` or `refused`.
    pub status: &'static str,
    pub output: Option<Value>,
    pub reason: Option<String>,
    /// The outcome to record after the effect; `None` when nothing ran (a report-only
    /// proposal, whose decision is the record).
    pub outcome: Option<AuditEvent>,
    /// A privacy report for what was sent.
    pub report: Option<String>,
}

/// Where steps go: the node's local executors or the gateway (weather, report-only egress).
pub trait Backend {
    /// Check every step this backend would run before the grant or a person is asked.
    fn preflight(&mut self, plan: &Plan, registry: &Registry, now: &str) -> Result<(), Preflight>;
    fn admit(&self, step: &Step) -> Admit;
    /// The arguments the approval binds and the dispatch receives; an error refuses the step.
    fn arguments(&self, call: &StepCall, outputs: &[(String, Value)]) -> Result<Value, String>;
    /// The SHA-256 of the exact bytes the step will send, when the backend knows them.
    fn sent_url_sha256(&self, _id: &str) -> Option<String> {
        None
    }
    /// The privacy report the decision carries, and whether it is the step's report of what
    /// leaves (`true`) or of what is about to (`false`); an error denies the step.
    fn intent_report(
        &self,
        call: &StepCall,
        args: &Value,
    ) -> Result<Option<(String, bool)>, String>;
    fn dispatch(&self, call: &StepCall, args: &Value) -> Dispatched;
}

/// One run of the engine.
pub struct EngineInput<'a> {
    pub plan: &'a Value,
    /// SDG-L1 descriptors, or an MCP tools document.
    pub catalog: &'a Value,
    pub flow: Flow<'a>,
    pub grant: GrantSource<'a>,
    pub approval: &'a dyn ApprovalChannel,
    /// Verification and simulation only: the backend sends nothing.
    pub dry_run: bool,
    /// Reserve the grant for each step and record it, but dispatch nothing and ask no one
    /// (the planner reservation of `sidged guard`).
    pub reserve_only: bool,
    pub now: &'a str,
}

/// Why a run stopped before its first step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// No durable audit sink for an effectful run, or the sink failed.
    Audit,
    /// The plan does not parse or does not verify.
    Plan,
    /// A backend refused a step before anyone was asked.
    Preflight,
    /// The grant was not accepted.
    Grant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub stage: Stage,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct EngineReport {
    pub plan_digest: Option<String>,
    pub summary: Option<Summary>,
    pub steps: Vec<StepOutcome>,
    /// Every decision and outcome recorded, in order, without the reservations.
    pub events: Vec<AuditEvent>,
    /// Privacy reports of what was sent or proposed for sending.
    pub reports: Vec<String>,
    pub refusal: Option<Refusal>,
    /// Why the audit sink stopped the run: a step's decision or outcome was not recorded.
    pub audit_failure: Option<String>,
}

impl EngineReport {
    /// The reason the run did not complete, if it did not.
    pub fn failure(&self) -> Option<String> {
        if let Some(refusal) = &self.refusal {
            return Some(refusal.message.clone());
        }
        if let Some(failure) = &self.audit_failure {
            return Some(failure.clone());
        }
        self.steps
            .iter()
            .find(|s| s.status != "completed")
            .map(|s| s.reason.clone().unwrap_or_else(|| s.status.clone()))
    }
}

fn deny_event(
    step: &str,
    capability: &str,
    record: Option<&CapabilityRecord>,
    actor: &str,
    at: &str,
    reason: String,
) -> AuditEvent {
    AuditEvent {
        privacy_report: None,
        usage: None,
        reason: Some(reason),
        step: step.to_string(),
        capability: capability.to_string(),
        effects: record.map(|r| r.effects.clone()).unwrap_or_default(),
        data_classes: record.map(|r| r.data_classes.clone()).unwrap_or_default(),
        decision: "deny".into(),
        actor: actor.to_string(),
        at: at.to_string(),
        approval: None,
    }
}

/// The arguments as the plan states them (`lit`, `ref`, `item`), rebuilt from the parsed plan.
pub fn proposed_arguments(args: &[(String, Arg)]) -> Value {
    Value::Object(
        args.iter()
            .map(|(name, arg)| {
                let form = match arg {
                    Arg::Lit(value) => json!({"lit": value}),
                    Arg::Ref { step, field: None } => json!({"ref": step}),
                    Arg::Ref {
                        step,
                        field: Some(field),
                    } => json!({"ref": step, "field": field}),
                    Arg::Item => json!({"item": true}),
                };
                (name.clone(), form)
            })
            .collect(),
    )
}

/// The capability registry of a catalog in either form.
pub(crate) fn registry_of(catalog: &Value) -> Result<Registry, String> {
    if catalog.get("tools").is_some() {
        sidged_mcp::registry_from_tools(catalog)
    } else {
        Registry::from_descriptors(catalog)
    }
}

struct Run<'s> {
    sink: &'s mut dyn AuditSink,
    report: EngineReport,
}

impl Run<'_> {
    fn decision(&mut self, event: AuditEvent) -> Result<(), String> {
        let recorded = self.sink.decision(&event);
        self.report.events.push(event);
        recorded
    }

    /// A refusal before the first step, recorded where there is a durable record.
    fn refuse(&mut self, stage: Stage, event: Option<AuditEvent>, mut message: String) {
        if let Some(event) = event {
            if let Err(e) = self.decision(event) {
                let why = format!("audit: the refusal was not recorded ({e})");
                message = format!("{message}; {why}");
                self.report.audit_failure = Some(why);
            }
        }
        self.report.refusal = Some(Refusal { stage, message });
    }
}

/// Run `input` through the one step loop, recording on `sink` and dispatching to `backend`.
pub fn run(
    input: &EngineInput,
    backend: &mut dyn Backend,
    sink: &mut dyn AuditSink,
) -> EngineReport {
    let mut run = Run {
        sink,
        report: EngineReport::default(),
    };
    // 0005 R5a: an effect needs a durable record; refuse before anything else.
    if !input.dry_run && !run.sink.durable() {
        run.refuse(
            Stage::Audit,
            None,
            "effectful execution requires a signed audit log target and key".into(),
        );
        return run.report;
    }
    if run.sink.durable() {
        // 0004 R9c: the channel start, once.
        if let Some(event) = crate::channel_start_event(input.approval, input.now) {
            if let Err(e) = run.sink.decision(&event) {
                run.refuse(Stage::Audit, None, format!("audit: {e}"));
                return run.report;
            }
        }
    }
    steps(input, backend, &mut run);
    // 0004 R9: every SO_PEERCRED rejection, even when no approval was decided.
    if run.sink.durable() {
        for uid in input.approval.take_rejected_peers() {
            let event = rejected_peer_event(
                input.approval,
                uid,
                "approval",
                "urn:sidged:approval",
                input.now,
            );
            if let Err(e) = run.sink.decision(&event) {
                run.report
                    .audit_failure
                    .get_or_insert(format!("audit: {e}"));
            }
        }
    }
    run.report
}

fn steps(input: &EngineInput, backend: &mut dyn Backend, run: &mut Run) {
    let now = input.now;
    let plan_denial = |message: &str| {
        deny_event(
            "plan",
            "urn:sidged:plan",
            None,
            "core",
            now,
            message.to_string(),
        )
    };
    // The plan as the one parser reads it, verified as read (0003 R1, R4a; ROADMAP 11f).
    let checked = (|| {
        let plan = sidged_verify::stored::read_plan(input.plan)
            .map_err(|e| format!("plan: {}", e.detail))?;
        let registry = registry_of(input.catalog)?;
        let caps = crate::caps_from(&registry, input.catalog, &plan)?;
        let summary = match &input.flow {
            Flow::DenySensitive => verify(&plan, &caps, &sidged_verify::DenySensitive),
            Flow::Cedar { .. } => verify(&plan, &caps, &sidged_verify::DeferToCedar),
            #[cfg(test)]
            Flow::Structural => verify(&plan, &caps, &sidged_verify::DeferToCedar),
        }
        .map_err(|problems| problems.join("; "))?;
        let digest = crate::plan_digest(input.plan)?;
        if let Flow::Cedar { policy, owner } = &input.flow {
            check_plan_flows(&plan, &digest, input.catalog, owner, policy).map_err(|flow| {
                format!(
                    "{}: {} -> {} (step {})",
                    flow.reason, flow.class, flow.capability, flow.step
                )
            })?;
        }
        Ok::<_, String>((plan, registry, summary, digest))
    })();
    let (plan, registry, summary, digest) = match checked {
        Ok(checked) => checked,
        Err(message) => {
            let event = run.sink.durable().then(|| plan_denial(&message));
            run.refuse(Stage::Plan, event, message);
            return;
        }
    };
    run.report.plan_digest = Some(digest.clone());
    run.report.summary = Some(summary);

    if let Err(refused) = backend.preflight(&plan, &registry, now) {
        let event = match &refused.step {
            Some((id, capability)) => Some(deny_event(
                id,
                capability,
                registry.get(capability),
                "core",
                now,
                refused.message.clone(),
            )),
            None => run.sink.durable().then(|| plan_denial(&refused.message)),
        };
        run.refuse(Stage::Preflight, event, refused.message);
        return;
    }

    let mut grant = match accept(input, &digest, run) {
        Ok(grant) => grant,
        Err(message) => {
            let event = grant_denial(&message, now);
            run.refuse(Stage::Grant, Some(event), message);
            return;
        }
    };
    if let Some(failure) = run.report.audit_failure.clone() {
        run.report.refusal = Some(Refusal {
            stage: Stage::Audit,
            message: failure,
        });
        return;
    }

    let mut outputs: Vec<(String, Value)> = Vec::new();
    for step in &plan.steps {
        let (id, capability, approval_flag, args, bound) = match step {
            Step::Call {
                id,
                capability,
                approval,
                args,
            } => (id, capability.as_str(), *approval, &args[..], 1),
            Step::Map {
                id,
                capability,
                approval,
                args,
                bound,
                ..
            } => (id, capability.as_str(), *approval, &args[..], *bound),
            Step::Expr { id, .. } => (id, "", false, &[][..], 0),
        };
        let stopped = run.report.audit_failure.is_some()
            || run.report.steps.iter().any(|s| s.status != "completed");
        let outcome = |status: &str, output: Option<Value>, reason: Option<String>| StepOutcome {
            id: id.clone(),
            capability: capability.to_string(),
            status: status.into(),
            output,
            reason,
        };
        if stopped {
            run.report.steps.push(outcome("skipped", None, None));
            continue;
        }
        let record = registry.get(capability);
        // A denial: recorded before anything else happens, and the plan stops here.
        let deny = |run: &mut Run, status: &str, event: AuditEvent| {
            let reason = event.reason.clone().unwrap_or_default();
            let mut step_outcome = outcome(status, None, Some(reason.clone()));
            if let Err(e) = run.decision(event) {
                let why =
                    format!("audit: the decision was not recorded ({e}); the step did not run");
                run.report.audit_failure = Some(format!("step {id}: {why}"));
                step_outcome.reason = Some(format!("{reason}; {why}"));
            }
            run.report.steps.push(step_outcome);
        };
        match backend.admit(step) {
            Admit::Skip => continue,
            Admit::Refuse(why) => {
                deny(
                    run,
                    "refused",
                    deny_event(id, capability, record, "core", now, why),
                );
                continue;
            }
            Admit::Run => {}
        }
        let Some(record) = record else {
            deny(
                run,
                "refused",
                deny_event(id, capability, None, "core", now, "no descriptor".into()),
            );
            continue;
        };
        let mut binding: Option<String> = None;
        let mut fields: Option<sidged_core::ApprovalAudit> = None;
        let mut actor = "core".to_string();
        let mut call = StepCall {
            id,
            capability,
            record,
            args,
            now,
            dry_run: input.dry_run,
            binding: None,
            actor: "core",
            approval: None,
        };
        if input.approval.killed() {
            let event = deny_event(
                id,
                capability,
                Some(record),
                "kill-switch",
                now,
                format!("killed before {id}"),
            );
            deny(run, "denied", event);
            continue;
        }
        let arguments = match backend.arguments(&call, &outputs) {
            Ok(arguments) => arguments,
            Err(why) => {
                deny(
                    run,
                    "refused",
                    deny_event(id, capability, Some(record), "core", now, why),
                );
                continue;
            }
        };
        let spends = match grant.reserve(id, capability, record, bound) {
            Ok(spends) => spends,
            Err(why) => {
                deny(
                    run,
                    "denied",
                    deny_event(id, capability, Some(record), "core", now, why),
                );
                continue;
            }
        };
        let verdict = if input.reserve_only {
            // 0004 R9: a refused channel is not "no channel"; planner egress fails closed
            // before anything is reserved or sent. The reservation is not an approval.
            if let Some(reason) = input.approval.refusal() {
                let event = deny_event(
                    id,
                    capability,
                    Some(record),
                    "core",
                    now,
                    format!("planner egress denied: {reason}"),
                );
                deny(run, "denied", event);
                continue;
            }
            "reserve"
        } else if approval_flag || record.is_consequential() {
            let mut request = match ApprovalRequest::new(&digest, id, capability, &arguments) {
                Ok(request) => request,
                Err(err) => {
                    let event = deny_event(
                        id,
                        capability,
                        Some(record),
                        "core",
                        now,
                        format!("approval nonce generation failed: {err}"),
                    );
                    deny(run, "denied", event);
                    continue;
                }
            };
            request.sent_url_sha256 = backend.sent_url_sha256(id);
            let mut text = format!(
                "approval args_sha256={} plan_digest={}{}",
                request.args_digest,
                request.plan_digest,
                request
                    .sent_url_sha256
                    .as_ref()
                    .map(|digest| format!(" sent_url_sha256={digest}"))
                    .unwrap_or_default()
            );
            if let Some(uid) = input.approval.approver_uid() {
                text.push_str(&format!(" approver_uid={uid}"));
            }
            if let Some(r9c) = input.approval.r9c_attestation() {
                text.push_str(&format!(" {r9c}"));
            }
            if let Some(attested) = input.approval.attestation() {
                text.push_str(&format!(" approval_binding={attested}"));
            }
            let audit = approval_audit(input.approval);
            let decided = input.approval.decide(&request, now);
            for uid in input.approval.take_rejected_peers() {
                let mut event = rejected_peer_event(input.approval, uid, id, capability, now);
                event.effects = record.effects.clone();
                event.data_classes = record.data_classes.clone();
                if let Err(e) = run.decision(event) {
                    run.report.audit_failure = Some(format!("step {id}: audit: {e}"));
                }
            }
            for _ in 0..input.approval.take_stale_responses() {
                let mut event = deny_event(
                    id,
                    capability,
                    Some(record),
                    "approval-channel",
                    now,
                    "stale approval response".into(),
                );
                event.approval = None;
                if let Err(e) = run.decision(event) {
                    run.report.audit_failure = Some(format!("step {id}: audit: {e}"));
                }
            }
            if run.report.audit_failure.is_some() {
                run.report
                    .steps
                    .push(outcome("refused", None, run.report.audit_failure.clone()));
                continue;
            }
            if !decided.granted {
                let mut event = deny_event(
                    id,
                    capability,
                    Some(record),
                    &decided.actor,
                    &decided.at,
                    format!("approval denied {id}: {}; {text}", decided.actor),
                );
                event.approval = Some(audit);
                deny(run, "denied", event);
                continue;
            }
            actor = decided.actor;
            binding = Some(text);
            fields = Some(audit);
            "approve"
        } else {
            "allow"
        };
        if record.is_egress() && sidged_gateway::is_local() {
            let event = deny_event(
                id,
                capability,
                Some(record),
                "core",
                now,
                "local mode refuses egress".into(),
            );
            deny(run, "denied", event);
            continue;
        }
        call.binding = binding.as_deref();
        call.actor = &actor;
        call.approval = fields.as_ref();
        let mut privacy_report = None;
        if !input.reserve_only {
            match backend.intent_report(&call, &arguments) {
                Ok(Some((document, last))) => {
                    if last {
                        run.report.reports.push(document.clone());
                    }
                    privacy_report = Some(document);
                }
                Ok(None) => {}
                Err(why) => {
                    deny(
                        run,
                        "denied",
                        deny_event(id, capability, Some(record), "core", now, why),
                    );
                    continue;
                }
            }
        }
        // 0002 R20, R21: the reservation is on the chain before the step may act.
        if let Err(e) = spends.iter().try_for_each(|spend| run.sink.decision(spend)) {
            let why = format!(
                "audit: the grant reservation was not recorded ({e}); the step did not run"
            );
            run.report.audit_failure = Some(format!("step {id}: {why}"));
            run.report.steps.push(outcome("refused", None, Some(why)));
            continue;
        }
        let decision = AuditEvent {
            privacy_report,
            usage: None,
            reason: binding.clone(),
            step: id.clone(),
            capability: capability.to_string(),
            effects: record.effects.clone(),
            data_classes: record.data_classes.clone(),
            decision: verdict.into(),
            actor: actor.clone(),
            at: now.into(),
            approval: fields.clone(),
        };
        if let Err(e) = run.decision(decision) {
            let why = format!("audit: the decision was not recorded ({e}); the step did not run");
            run.report.audit_failure = Some(format!("step {id}: {why}"));
            run.report.steps.push(outcome("refused", None, Some(why)));
            continue;
        }
        if input.reserve_only {
            run.report.steps.push(outcome(
                "completed",
                Some(json!({"mode": "reserved"})),
                None,
            ));
            continue;
        }
        let done = backend.dispatch(&call, &arguments);
        if let Some(document) = done.report {
            run.report.reports.push(document);
        }
        let mut reason = done.reason;
        if let Some(event) = done.outcome {
            let recorded = run.sink.outcome(&event);
            run.report.events.push(event);
            if let Err(e) = recorded {
                let why = format!(
                    "audit: the outcome was not recorded ({e}); the step ran, its outcome is unaudited"
                );
                run.report.audit_failure = Some(format!("step {id}: {why}"));
                reason = Some(match reason {
                    Some(reason) => format!("{reason}; {why}"),
                    None => why,
                });
            }
        }
        if let Some(output) = &done.output {
            outputs.push((id.clone(), output.clone()));
        }
        run.report
            .steps
            .push(outcome(done.status, done.output, reason));
    }
}

/// Accept the run's grant before its first step (0002 R17-R26); the error is the refusal.
fn accept(input: &EngineInput, digest: &str, run: &mut Run) -> Result<Box<dyn StepGrant>, String> {
    match &input.grant {
        GrantSource::Presented {
            token,
            trusted_issuers,
            policy,
            audience,
            presenter,
            at,
        } => {
            let document = token.ok_or("missing grant")?;
            let policy = CedarEvaluator::parse(policy).map_err(|e| format!("grant policy: {e}"))?;
            let now = at
                .map(str::to_string)
                .unwrap_or_else(sidged_gateway::utc_stamp);
            let token = accept_presented(document, &now, trusted_issuers)
                .map_err(|err| format!("grant denied: {err}"))?;
            // R25: the presenter proves possession over this plan and a nonce drawn now.
            let holder = match presenter {
                Some(presenter) => {
                    let nonce = fresh_hex(32)?;
                    let proof = presenter.prove(document, audience, digest, &nonce);
                    verify_pop(document, audience, digest, &nonce, &proof)
                        .map_err(|err| format!("grant denied: {err} (proof of possession)"))?;
                    token.link.sub.clone()
                }
                None if input.dry_run => token.link.sub.clone(),
                None => {
                    return Err(
                        "grant denied: no proof of possession; the grant holder presents \
                                it with its key (sidged run --holder-key)"
                            .into(),
                    )
                }
            };
            let history = run.sink.history()?;
            // Charge every link so fresh delegated children share their ancestor's caps.
            let documents = document["chain"]
                .as_array()
                .into_iter()
                .flatten()
                .chain(std::iter::once(document));
            let mut accounts = Vec::new();
            for (link, doc) in token
                .chain
                .iter()
                .chain(std::iter::once(&token.link))
                .zip(documents)
            {
                let id = doc["id"]
                    .as_str()
                    .filter(|id| !id.is_empty())
                    .ok_or("grant denied: missing token id for audit ledger")?;
                accounts.push(LedgerAccount::replayed(link, id, &history)?);
            }
            Ok(Box::new(PresentedGrant {
                token,
                holder,
                audience: audience.to_string(),
                policy,
                accounts,
                at: at.map(str::to_string),
            }))
        }
        GrantSource::Mandate {
            mandate,
            policy,
            owner,
            audience,
            executor_seed,
            presenter,
        } => {
            let history = run.sink.history()?;
            let grant = PlanGrant::open(&PlanGrantInputs {
                mandate: *mandate,
                policy: *policy,
                owner,
                audience,
                executor_seed,
                presenter: *presenter,
                plan: input.plan,
                plan_digest: digest,
                capabilities: input.catalog,
                history: &history,
                now: input.now,
            })?;
            if let Err(e) = run.decision(grant.acceptance(digest, input.now)) {
                run.report.audit_failure = Some(format!(
                    "audit: the grant acceptance was not recorded ({e})"
                ));
            }
            Ok(Box::new(grant))
        }
        #[cfg(test)]
        GrantSource::Unchecked => Ok(Box::new(Unchecked)),
    }
}
