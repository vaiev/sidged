//! End-to-end hosted check: registry, plan verifier, Cedar grant, privacy report, audit log.

pub mod standing;

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use sidged_capability::Registry;
use sidged_core::{AuditEvent, ExecutionReport};
use sidged_gateway::{call_id, known_profile, provider_allows, report, Egress};
use sidged_grant::{format_rfc3339_z, spend_step, spend_uses};
use sidged_verify::{verify, Arg, Cap, Plan, Step};

/// Experimental (ROADMAP v0.5): the v0.1 signed-adapter prototype.
#[cfg(feature = "experimental")]
pub mod adapter;
mod approval;
mod contained;
pub mod engine;
pub mod gguf;
pub mod init;
pub mod intent_plan;
pub mod linguist;
pub mod linguist_eval;
pub mod node_exec;
pub mod node_grant;
/// Experimental (ROADMAP v0.5): the v0.1 swarm prototype.
#[cfg(feature = "experimental")]
pub mod swarm;
pub mod system_config;
pub mod turnkey;
pub mod webauthn;
pub mod webauthn_enroll;
pub mod when;
pub use approval::{
    attestation_verdict, harden_process, open_channel, post_approval, r9c_attestation_text,
    r9c_fields, require_single_threaded, ApprovalChannel, ApprovalDecision, ApprovalRequest,
    ChannelConfig, FixedApproval, NonInteractive, SocketApproval, OPERATOR_ATTESTED,
    R9C_UNDETECTED,
};

/// `--agent-uid 1000,1002`: explicit agent/launcher/worker uids (0004 R9c).
pub fn parse_uid_list(text: &str) -> Result<Vec<u32>, String> {
    text.split(',')
        .map(|uid| {
            uid.trim()
                .parse::<u32>()
                .map_err(|_| format!("--agent-uid: invalid uid {uid:?}"))
        })
        .collect()
}

/// `config.json` `approval.non_approver_uids`: a list of uids (0004 R9c).
/// Missing means none; anything malformed refuses.
pub fn config_non_approver_uids(config: &serde_json::Value) -> Result<Vec<u32>, String> {
    let list = &config["approval"]["non_approver_uids"];
    if list.is_null() {
        return Ok(Vec::new());
    }
    list.as_array()
        .ok_or("config approval.non_approver_uids must be a list of uids")?
        .iter()
        .map(|v| {
            v.as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| format!("config approval.non_approver_uids: invalid uid {v}"))
        })
        .collect()
}

/// 0004 R9c: audit the approval channel start once, with
/// `attestation=R9c` and what the start checks do not detect.
pub fn audit_channel_start(
    approval: &dyn ApprovalChannel,
    chain: &mut sidged_log::Chain,
    now: &str,
) -> Result<Option<AuditEvent>, String> {
    let Some(event) = channel_start_event(approval, now) else {
        return Ok(None);
    };
    chain.append(&event)?;
    Ok(Some(event))
}

/// The 0004 R9c channel-start event, taken once from the channel; the caller
/// appends it to its signed chain (sidged-tui writes through its own sink).
pub fn channel_start_event(approval: &dyn ApprovalChannel, now: &str) -> Option<AuditEvent> {
    let text = approval.take_channel_start()?;
    Some(AuditEvent {
        privacy_report: None,
        usage: None,
        reason: Some(format!("approval channel started {text}")),
        step: "approval".into(),
        capability: "urn:sidged:approval".into(),
        effects: Vec::new(),
        data_classes: Vec::new(),
        decision: "allow".into(),
        actor: "approval-channel".into(),
        at: now.into(),
        approval: Some(approval_audit(approval)),
    })
}

/// 0004 R9: audit every SO_PEERCRED rejection with the observed uid.
/// Called on every exit path, after the listener is shut down.
pub fn audit_rejected_peers(
    approval: &dyn ApprovalChannel,
    chain: &mut sidged_log::Chain,
    step: &str,
    now: &str,
) -> Result<Vec<AuditEvent>, String> {
    let mut events = Vec::new();
    for uid in approval.take_rejected_peers() {
        let event = rejected_peer_event(approval, uid, step, "urn:sidged:approval", now);
        chain.append(&event)?;
        events.push(event);
    }
    Ok(events)
}

/// 0004 R11: the three R11 fields for every approval event,
/// with explicit `none`/`[]` values when nothing was attested.
pub fn approval_audit(approval: &dyn ApprovalChannel) -> sidged_core::ApprovalAudit {
    let mut audit = sidged_core::ApprovalAudit {
        approver_uid: approval.approver_uid(),
        ..sidged_core::ApprovalAudit::not_attested()
    };
    if let Some(text) = approval.r9c_attestation() {
        let (attestation, undetected) = approval::r9c_fields(&text);
        if let Some(attestation) = attestation {
            audit.attestation = attestation;
        }
        audit.undetected = undetected;
    }
    if let Some(binding) = approval.attestation() {
        audit.approval_binding = binding.to_string();
    }
    audit
}

pub(crate) fn rejected_peer_event(
    approval: &dyn ApprovalChannel,
    uid: u32,
    step: &str,
    capability: &str,
    now: &str,
) -> AuditEvent {
    let expected = approval
        .approver_uid()
        .map(|u| u.to_string())
        .unwrap_or_else(|| "none".into());
    let observed = if uid == u32::MAX {
        "unknown".to_string()
    } else {
        uid.to_string()
    };
    AuditEvent {
        privacy_report: None,
        usage: None,
        reason: Some(format!(
            "approval peer uid rejected: observed uid {observed}, approver uid {expected}"
        )),
        step: step.into(),
        capability: capability.into(),
        effects: Vec::new(),
        data_classes: Vec::new(),
        decision: "deny".into(),
        actor: "approval-channel".into(),
        at: now.into(),
        approval: Some(sidged_core::ApprovalAudit {
            observed_uid: (uid != u32::MAX).then_some(uid),
            ..approval_audit(approval)
        }),
    }
}

#[derive(Debug)]
pub struct RunArgs {
    pub dry_run: bool,
    pub plan: String,
    pub catalog: String,
    pub policy: String,
    pub grant: String,
    pub now: Option<String>,
    pub audience: String,
    pub trusted_issuers: Vec<String>,
    pub approve: Option<String>,
    pub approve_timeout: u64,
    pub approve_uid: Option<u32>,
    /// Every non-approver uid (agent, launcher, worker, model/llama; 0004 R9c),
    /// from `--non-approver-uid` (alias `--agent-uid`).
    pub agent_uids: Vec<u32>,
    /// `--operator-attest` (0004 R9c): allow unclear sudo/doas rules; every
    /// approval is then audited as operator-attested.
    pub operator_attest: bool,
    pub log: Option<String>,
    pub log_key: Option<String>,
    /// `--holder-key`: the seed of the grant holder, who proves possession (0002 R25).
    pub holder_key: Option<String>,
    pub provider: String,
    pub profile: String,
    pub local: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunFailure {
    pub message: String,
    pub events: Vec<AuditEvent>,
}

impl std::fmt::Display for RunFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for RunFailure {}

/// `sidged run <plan.json> <catalog.json> --policy <file> --grant <token.json> --trusted-issuer <did> [--audience <id>] [--now <utc>]`
pub fn parse_run_args<I>(args: I) -> Result<RunArgs, String>
where
    I: IntoIterator<Item = String>,
{
    let usage = "usage: sidged run <plan.json> <catalog.json> --policy <file> --grant <token.json> --trusted-issuer <did> (--holder-key <seed-file> | --dry-run) [--audience <id>] [--now <utc>] [--log-key <seed-file>] [--log <file>]\n  --holder-key: the grant holder's seed; the Core draws a nonce and the run proves possession of the grant over the plan digest before any step (0002 R25). An effectful run without it refuses, and so does one without a signed audit log (--log-key).";
    let mut args = args.into_iter();
    if args.next().as_deref() != Some("run") {
        return Err(usage.into());
    }
    let plan = args.next().ok_or(usage)?;
    let catalog = args.next().ok_or(usage)?;
    let mut policy = None;
    let mut grant = None;
    let mut now = None;
    let mut trusted_issuers = Vec::new();
    let mut approve = None;
    let mut approve_timeout = 30u64;
    let mut approve_uid = None;
    let mut agent_uids = Vec::new();
    let mut operator_attest = false;
    let mut log = None;
    let mut log_key = None;
    let mut holder_key = None;
    let mut provider = "https://hosted.sidged.example".to_string();
    let mut profile = "P0".to_string();
    let mut local = false;
    let mut dry_run = false;
    let mut audience = "urn:sidged:runtime:hosted".to_string();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--policy" => {
                policy = Some(args.next().ok_or("--policy needs a file")?);
            }
            "--grant" => {
                grant = Some(args.next().ok_or("--grant needs a file")?);
            }
            "--trusted-issuer" => {
                trusted_issuers.push(args.next().ok_or("--trusted-issuer needs a did:key")?);
            }
            "--audience" => {
                audience = args.next().ok_or("--audience needs an identifier")?;
            }
            "--now" => {
                now = Some(args.next().ok_or("--now needs a UTC timestamp")?);
            }
            "--approve" => {
                approve = Some(args.next().ok_or("--approve needs tty or unix:<path>")?);
            }
            "--operator-attest" => operator_attest = true,
            "--agent-uid" | "--non-approver-uid" => {
                agent_uids.extend(parse_uid_list(
                    &args.next().ok_or("--non-approver-uid needs uid[,uid...]")?,
                )?);
            }
            "--approve-uid" => {
                approve_uid = Some(
                    args.next()
                        .ok_or("--approve-uid needs uid")?
                        .parse()
                        .map_err(|_| "--approve-uid needs uid")?,
                );
            }
            "--approve-timeout" => {
                let text = args.next().ok_or("--approve-timeout needs seconds")?;
                approve_timeout = text
                    .parse()
                    .map_err(|_| "--approve-timeout needs seconds")?;
            }
            "--log" => {
                log = Some(args.next().ok_or("--log needs a file")?);
            }
            "--log-key" => {
                log_key = Some(args.next().ok_or("--log-key needs a seed file")?);
            }
            "--holder-key" => {
                holder_key = Some(args.next().ok_or("--holder-key needs a seed file")?);
            }
            "--provider" => {
                provider = args.next().ok_or("--provider needs an identifier")?;
            }
            "--profile" => {
                profile = args.next().ok_or("--profile needs P0, P1, P2, or P3")?;
            }
            "--dry-run" => dry_run = true,
            "--local" => {
                local = true;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let policy = policy.ok_or("--policy is required")?;
    let grant = grant.ok_or("--grant is required")?;
    if trusted_issuers.is_empty() {
        return Err("--trusted-issuer is required".into());
    }
    if !known_profile(&profile) {
        return Err("--profile must be P0, P1, P2, or P3".into());
    }
    Ok(RunArgs {
        dry_run,
        plan,
        catalog,
        policy,
        grant,
        now,
        audience,
        trusted_issuers,
        approve,
        approve_timeout,
        approve_uid,
        agent_uids,
        operator_attest,
        log,
        log_key,
        holder_key,
        provider,
        profile,
        local: sidged_gateway::resolve_local(local)?,
    })
}

#[derive(Clone, Copy)]
pub struct AuditTarget<'a> {
    pub path: &'a std::path::Path,
    pub seed: &'a [u8; 32],
}

pub struct RunInput<'a> {
    pub audit: Option<AuditTarget<'a>>,
    /// Verification/simulation only; no effects and no durable reservations.
    pub dry_run: bool,
    pub plan: &'a serde_json::Value,
    pub catalog: &'a serde_json::Value,
    pub policy: &'a str,
    pub audience: &'a str,
    pub grant: Option<&'a serde_json::Value>,
    /// The grant holder, who proves possession over the plan digest and the Core's nonce
    /// (0002 R25). Without one an effectful run refuses.
    pub holder: Option<&'a dyn engine::Presenter>,
    pub now: Option<&'a str>,
    pub region: Option<&'a str>,
    pub trusted_issuers: &'a [&'a str],
    pub approval: &'a dyn ApprovalChannel,
    pub provider: &'a str,
    pub profile: &'a str,
    pub local: bool,
}

/// 0013 R2: hash the complete plan tree encoded with the 0012 dCBOR codec.
pub fn plan_digest(plan: &serde_json::Value) -> Result<String, String> {
    use base64::Engine;
    use sha2::Digest;
    let bytes = sidged_record::encode(plan).map_err(|e| e.to_string())?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(bytes)))
}

/// Parse the plan and run the verifier. Callers that read plan fields for
/// another check, including residency, do that only after this returns.
pub fn check_plan(plan: &serde_json::Value, catalog: &serde_json::Value) -> Result<(), String> {
    let (registry, plan) = prepare(plan, catalog)?;
    let caps = caps_from(&registry, catalog, &plan)?;
    verify(&plan, &caps, &sidged_verify::DenySensitive).map_err(|problems| problems.join("; "))?;
    Ok(())
}

pub fn execute(input: &RunInput) -> Result<ExecutionReport, RunFailure> {
    let mut chain = match input.audit {
        Some(target) if !input.dry_run => {
            eprintln!("audit log: {}", target.path.display());
            Some(sidged_log::Chain::open(target.path, target.seed).map_err(fail)?)
        }
        _ => None,
    };
    execute_with_chain(input, &mut chain)
}

/// Execute while retaining a caller's already opened audit lock.
pub fn execute_with_chain(
    input: &RunInput,
    chain: &mut Option<sidged_log::Chain>,
) -> Result<ExecutionReport, RunFailure> {
    execute_mode(input, chain, None)
}

/// Authorize and durably reserve a single planner invocation. The caller sends
/// the request only after this returns; no proposed-payload report is emitted.
#[doc(hidden)]
pub fn reserve_planner(
    input: &RunInput,
    destination: &str,
    chain: &mut Option<sidged_log::Chain>,
) -> Result<ExecutionReport, RunFailure> {
    if input.dry_run
        || input.plan["steps"].as_array().map(Vec::len) != Some(1)
        || input.plan["steps"][0]["capability"] != "urn:sidged:capability:model.complete"
    {
        return Err(fail(
            "planner reservation requires one model.complete call".into(),
        ));
    }
    execute_mode(input, chain, Some(destination))
}

/// `sidged run` and `sidged guard` on the one engine: a presented token and its holder's
/// proof, the gateway backend, the signed chain when there is one.
fn execute_mode(
    input: &RunInput,
    chain: &mut Option<sidged_log::Chain>,
    planner_destination: Option<&str>,
) -> Result<ExecutionReport, RunFailure> {
    let now_owned;
    let now = match input.now {
        Some(now) => now,
        None => {
            now_owned = utc_now();
            now_owned.as_str()
        }
    };
    let mut backend = GatewayBackend {
        provider: input.provider,
        profile: input.profile,
        region: input.region,
        local: input.local,
        destination: planner_destination,
        weather_base: weather_base(),
        weather: HashMap::new(),
    };
    let report = engine::run(
        &engine::EngineInput {
            plan: input.plan,
            catalog: input.catalog,
            flow: engine::Flow::DenySensitive,
            grant: engine::GrantSource::Presented {
                token: input.grant,
                trusted_issuers: input.trusted_issuers,
                policy: input.policy,
                audience: input.audience,
                presenter: input.holder,
                at: input.now,
            },
            approval: input.approval,
            dry_run: input.dry_run,
            reserve_only: planner_destination.is_some(),
            now,
        },
        &mut backend,
        chain,
    );
    if let Some(message) = report.failure() {
        return Err(RunFailure {
            message,
            events: report.events,
        });
    }
    let summary = report.summary.unwrap_or(sidged_verify::Summary {
        capabilities: Vec::new(),
        approvals: Vec::new(),
        egress: Vec::new(),
    });
    Ok(ExecutionReport {
        capabilities: summary.capabilities,
        approvals: summary.approvals,
        egress: summary.egress,
        events: report.events,
        reports: report.reports,
        results: report
            .steps
            .into_iter()
            .filter_map(|step| Some((step.id, step.output?.to_string())))
            .collect(),
    })
}

const WEATHER: &str = "urn:sidged:capability:weather.lookup";
const WEATHER_BASE: &str = "https://api.open-meteo.com";

#[cfg(test)]
thread_local! { static TEST_WEATHER_BASE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) }; }
fn weather_base() -> String {
    #[cfg(test)]
    if let Some(base) = TEST_WEATHER_BASE.with(|b| b.borrow().clone()) {
        return base;
    }
    WEATHER_BASE.into()
}

// Only literal, explicitly verified public-weather arguments are supported.
fn weather_url(args: &[(String, Arg)], base: &str) -> Result<String, String> {
    if args.len() != 3 {
        return Err("weather requires latitude, longitude and current only".into());
    }
    let lit = |name: &str| {
        args.iter()
            .find(|(n, _)| n == name)
            .and_then(|(_, arg)| match arg {
                Arg::Lit(value) => Some(value),
                _ => None,
            })
    };
    let mut query = Vec::new();
    for (name, limit) in [("latitude", "90"), ("longitude", "180")] {
        let text = lit(name)
            .ok_or("weather literal required")?
            .as_str()
            .ok_or("weather decimal string required")?;
        let digits = text.strip_prefix('-').unwrap_or(text);
        if text.len() > 24
            || digits.is_empty()
            || !digits.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            || digits.split('.').any(str::is_empty)
            || digits.matches('.').count() > 1
        {
            return Err("weather decimal string required".into());
        }
        let (whole, fraction) = digits.split_once('.').unwrap_or((digits, ""));
        let whole = whole.trim_start_matches('0');
        if whole.len() > limit.len()
            || (whole.len() == limit.len() && whole > limit)
            || (whole == limit && fraction.bytes().any(|b| b != b'0'))
        {
            return Err("weather coordinate out of range".into());
        }
        query.push(format!("{name}={text}"));
    }
    if lit("current") != Some(&serde_json::json!("temperature_2m")) {
        return Err("unsupported weather current field".into());
    }
    query.push("current=temperature_2m".into());
    Ok(format!("{base}/v1/forecast?{}", query.join("&")))
}

/// The gateway backend of `sidged run` and `sidged guard`: the public-weather lookup is sent
/// (one GET of a URL built from literal arguments); every other egress is checked and
/// reported as a proposal, not sent.
struct GatewayBackend<'a> {
    provider: &'a str,
    profile: &'a str,
    region: Option<&'a str>,
    local: bool,
    /// The planner's destination, for the planner reservation of `sidged guard`.
    destination: Option<&'a str>,
    weather_base: String,
    /// The resolved request URL of each weather step.
    weather: HashMap<String, String>,
}

impl engine::Backend for GatewayBackend<'_> {
    fn preflight(
        &mut self,
        plan: &Plan,
        registry: &Registry,
        _now: &str,
    ) -> Result<(), engine::Preflight> {
        let refuse = |id: &str, capability: &str, message: String| engine::Preflight {
            step: Some((id.to_string(), capability.to_string())),
            message,
        };
        sidged_gateway::resolve_local(self.local).map_err(|message| engine::Preflight {
            step: None,
            message,
        })?;
        // Every destination is checked before any human approval is requested.
        for step in &plan.steps {
            let (id, capability, args) = match step {
                Step::Call {
                    id,
                    capability,
                    args,
                    ..
                }
                | Step::Map {
                    id,
                    capability,
                    args,
                    ..
                } => (id, capability.as_str(), args),
                Step::Expr { .. } => continue,
            };
            let record = registry.get(capability).ok_or_else(|| engine::Preflight {
                step: None,
                message: format!("missing {capability}"),
            })?;
            if capability == WEATHER {
                if !record.is_egress() || record.residency != ["unrestricted"] {
                    return Err(refuse(
                        id,
                        capability,
                        "weather requires egress and unrestricted residency".into(),
                    ));
                }
                if !matches!(step, Step::Call { .. }) {
                    return Err(refuse(
                        id,
                        capability,
                        "weather dispatch requires a single call".into(),
                    ));
                }
                let url = weather_url(args, &self.weather_base)
                    .map_err(|message| refuse(id, capability, message))?;
                self.weather.insert(id.clone(), url);
            }
            if record.is_egress() {
                if sidged_gateway::is_local() {
                    return Err(refuse(id, capability, "local mode refuses egress".into()));
                }
                if !known_profile(self.profile) {
                    return Err(refuse(
                        id,
                        capability,
                        "provider profile is not P0-P3".into(),
                    ));
                }
                let checked = if capability == WEATHER {
                    sidged_gateway::validate_destination(
                        &self.weather[id.as_str()],
                        &self.weather_base,
                        "GLOBAL",
                        &record.residency,
                    )
                } else {
                    sidged_gateway::validate_destination(
                        self.destination.unwrap_or(self.provider),
                        self.provider,
                        self.region.unwrap_or(""),
                        &record.residency,
                    )
                };
                checked.map_err(|message| refuse(id, capability, message))?;
                continue;
            }
            let Some(region) = self.region else {
                continue;
            };
            match provider_allows(&record.residency, region, &HashMap::new()) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(refuse(
                        id,
                        capability,
                        format!("{capability} is not allowed in {region}"),
                    ))
                }
                Err(message) => {
                    return Err(refuse(id, capability, format!("{capability}: {message}")))
                }
            }
        }
        Ok(())
    }

    fn admit(&self, step: &Step) -> engine::Admit {
        match step {
            // This executor evaluates no expressions; their values are never sent.
            Step::Expr { .. } => engine::Admit::Skip,
            _ => engine::Admit::Run,
        }
    }

    /// The proposal as the plan states it: this backend resolves no references.
    fn arguments(
        &self,
        call: &engine::StepCall,
        _outputs: &[(String, serde_json::Value)],
    ) -> Result<serde_json::Value, String> {
        Ok(engine::proposed_arguments(call.args))
    }

    fn sent_url_sha256(&self, id: &str) -> Option<String> {
        use sha2::Digest;
        // The resolved URL is the GET payload. Approve exactly the bytes the gateway will
        // bind in its privacy report.
        self.weather
            .get(id)
            .map(|url| format!("{:x}", sha2::Sha256::digest(url.as_bytes())))
    }

    fn intent_report(
        &self,
        call: &engine::StepCall,
        args: &serde_json::Value,
    ) -> Result<Option<(String, bool)>, String> {
        if !call.record.is_egress() {
            return Ok(None);
        }
        let classes: Vec<&str> = call
            .record
            .data_classes
            .iter()
            .map(String::as_str)
            .collect();
        let tags: Vec<&str> = call.record.residency.iter().map(String::as_str).collect();
        if call.capability == WEATHER && !call.dry_run {
            let url = &self.weather[call.id];
            let report_id = call_id(&self.weather_base, call.now, call.id, url.as_bytes());
            let mut document = report(&Egress {
                id: &report_id,
                call_at: call.now,
                provider_id: &self.weather_base,
                profile: "P0",
                data_classes: &classes,
                fields: &["latitude", "longitude", "current"],
                payload: url.as_bytes(),
                residency: &tags,
            });
            document["payload_binding"] = "request-url".into();
            return Ok(Some((document.to_string(), false)));
        }
        if !known_profile(self.profile) {
            return Err("provider profile is not P0-P3".into());
        }
        // This backend checks proposed calls; it does not serialize or send a provider
        // request. Bind the proposal and label it honestly.
        let payload = serde_json::to_vec(args).map_err(|err| err.to_string())?;
        let report_id = call_id(self.provider, call.now, call.id, &payload);
        let mut document = report(&Egress {
            id: &report_id,
            call_at: call.now,
            provider_id: self.provider,
            profile: self.profile,
            data_classes: &classes,
            fields: &["body"],
            payload: &payload,
            residency: &tags,
        });
        document["payload_binding"] = "proposed-arguments".into();
        Ok(Some((document.to_string(), true)))
    }

    fn dispatch(&self, call: &engine::StepCall, _args: &serde_json::Value) -> engine::Dispatched {
        let report_only = engine::Dispatched {
            status: "completed",
            output: Some(serde_json::json!({"mode":"report-only"})),
            reason: None,
            outcome: None,
            report: None,
        };
        if call.capability != WEATHER || call.dry_run {
            return report_only;
        }
        let url = &self.weather[call.id];
        let classes: Vec<&str> = call
            .record
            .data_classes
            .iter()
            .map(String::as_str)
            .collect();
        let response = sidged_gateway::send_get(&sidged_gateway::SendRequest {
            url,
            provider_id: &self.weather_base,
            provider_project: None,
            profile: "P0",
            residency: &call.record.residency,
            region: "GLOBAL",
            data_classes: &classes,
            fields: &["latitude", "longitude", "current"],
            body: &[],
            authorization: None,
            call_at: call.now,
            step: call.id,
            local: self.local,
        });
        let event = |decision: &str, reason: String, document: Option<String>| AuditEvent {
            privacy_report: document,
            usage: None,
            reason: Some(reason),
            step: call.id.into(),
            capability: call.capability.into(),
            effects: call.record.effects.clone(),
            data_classes: call.record.data_classes.clone(),
            decision: decision.into(),
            actor: if decision == "result" {
                call.actor
            } else {
                "core"
            }
            .into(),
            at: call.now.into(),
            approval: if decision == "result" {
                call.approval.cloned()
            } else {
                None
            },
        };
        match response {
            Ok(response) => {
                use sha2::Digest;
                let reason = format!(
                    "executed status={} sent_url_sha256={:x}{}",
                    response.status,
                    sha2::Sha256::digest(url.as_bytes()),
                    call.binding
                        .map(|binding| format!("; {binding}"))
                        .unwrap_or_default()
                );
                let document = response.report.to_string();
                engine::Dispatched {
                    status: "completed",
                    output: Some(
                        serde_json::json!({"mode":"executed", "status":response.status, "body":response.body}),
                    ),
                    reason: None,
                    outcome: Some(event("result", reason, Some(document.clone()))),
                    report: Some(document),
                }
            }
            Err(error) => {
                let document = error.report.map(|d| d.to_string());
                engine::Dispatched {
                    status: "failed",
                    output: None,
                    reason: Some(error.message.clone()),
                    outcome: Some(event("error", error.message, document.clone())),
                    report: document,
                }
            }
        }
    }
}

/// One grant account on the signed audit ledger (0002 R20, R21): a token link's rights and
/// budget, less every reservation the chain holds under its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerAccount {
    /// `["<issuer>", "<token id>"]` as JSON: the `usage` key of its reservations.
    pub key: String,
    pub rights: Vec<sidged_grant::Right>,
    pub budget: sidged_grant::Budget,
}

/// The ledger key of the token `id` from `issuer`.
pub fn ledger_key(issuer: &str, id: &str) -> String {
    serde_json::json!([issuer, id]).to_string()
}

impl LedgerAccount {
    /// The account of `link` (token `id`) after replaying `history`.
    pub fn replayed(
        link: &sidged_grant::TokenLink,
        id: &str,
        history: &[AuditEvent],
    ) -> Result<Self, String> {
        let key = ledger_key(&link.iss, id);
        let mut rights = link.rights.clone();
        let mut budget = link.budget.clone();
        replay_reservations(
            history,
            |_, spent_key| spent_key == key,
            Some(&mut rights),
            &mut budget,
        )?;
        Ok(Self {
            key,
            rights,
            budget,
        })
    }
}

/// Take every reservation in `history` that `counts` selects (by event and ledger key) off
/// `budget`, and its uses off `rights` when given. New reservations carry their original
/// price; history is never repriced with the current capability catalog.
pub fn replay_reservations(
    history: &[AuditEvent],
    counts: impl Fn(&AuditEvent, &str) -> bool,
    mut rights: Option<&mut [sidged_grant::Right]>,
    budget: &mut sidged_grant::Budget,
) -> Result<(), String> {
    for event in history {
        let Some((spent_key, index, uses)) = &event.usage else {
            continue;
        };
        if !counts(event, spent_key) {
            continue;
        }
        if let Some(rights) = rights.as_deref_mut() {
            let right = rights.get_mut(*index).ok_or("audit right index")?;
            if let Some(left) = right.constraints.max_uses.as_mut() {
                *left = left.checked_sub(*uses).ok_or("audit uses exceed grant")?;
            }
        }
        let price: Option<(String, String)> = match &event.reason {
            Some(reason) => serde_json::from_str(reason).map_err(|_| "audit budget price")?,
            None if budget.money.is_some() => {
                return Err("legacy audit spend lacks budget price".into())
            }
            None => None,
        };
        let bound = u32::try_from(*uses).map_err(|_| "audit bound")?;
        spend_step(
            budget,
            price
                .as_ref()
                .map(|(amount, currency)| (amount.as_str(), currency.as_str())),
            bound,
        )
        .map_err(|_| "audit budget exceeds grant")?;
    }
    Ok(())
}

/// Reserve one step on every account (0002 R20-R22): its budget, then the first right whose
/// caveats hold. Returns each account's key and the selected right index.
pub fn reserve_step(
    accounts: &mut [LedgerAccount],
    action: &str,
    capability: &str,
    classes: &[&str],
    cost: Option<(&str, &str)>,
    bound: u32,
) -> Result<Vec<(String, usize)>, sidged_grant::GrantError> {
    let mut selections = Vec::new();
    for account in accounts {
        spend_step(&mut account.budget, cost, bound)?;
        let index = spend_uses(
            &mut account.rights,
            action,
            capability,
            classes,
            cost,
            bound,
        )?;
        selections.push((account.key.clone(), index));
    }
    Ok(selections)
}

/// The signed reservation of one step on one account, appended before the effect; its
/// reason is the unit price the replay charges.
pub fn spend_event(
    key: String,
    index: usize,
    bound: u32,
    cost: Option<(&str, &str)>,
    step: &str,
    capability: &str,
    now: &str,
) -> AuditEvent {
    AuditEvent {
        privacy_report: None,
        usage: Some((key, index, u64::from(bound))),
        reason: Some(serde_json::json!(cost).to_string()),
        step: step.to_string(),
        capability: capability.to_string(),
        effects: Vec::new(),
        data_classes: Vec::new(),
        decision: "spend".into(),
        actor: "core".into(),
        at: now.to_string(),
        approval: None,
    }
}

fn fail(message: String) -> RunFailure {
    RunFailure {
        message,
        events: Vec::new(),
    }
}

fn utc_now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    format_rfc3339_z(seconds)
}

fn call_of(step: &Step) -> Option<(&str, &str)> {
    match step {
        Step::Call { id, capability, .. } | Step::Map { id, capability, .. } => {
            Some((id, capability))
        }
        Step::Expr { .. } => None,
    }
}

fn prepare(
    plan: &serde_json::Value,
    catalog: &serde_json::Value,
) -> Result<(Registry, Plan), String> {
    let registry = engine::registry_of(catalog)?;
    // ROADMAP 11f: the verifier's parser is the only one, so the plan that runs is the
    // plan the verifier read (0003 R1, R4a).
    let plan = sidged_verify::stored::read_plan(plan).map_err(|e| format!("plan: {}", e.detail))?;
    Ok((registry, plan))
}

/// The property names a capability's `output_schema` declares (0003 R4a), from either
/// catalog form `prepare` accepts.
fn declared_outputs(catalog: &serde_json::Value, id: &str) -> Vec<String> {
    let descriptors: Vec<&serde_json::Value> = match catalog.get("tools") {
        Some(tools) => tools
            .as_array()
            .into_iter()
            .flatten()
            .map(|tool| &tool["_meta"]["io.sidged/capability"])
            .collect(),
        None => catalog.as_array().into_iter().flatten().collect(),
    };
    descriptors
        .into_iter()
        .find(|descriptor| descriptor["id"] == id)
        .and_then(|descriptor| descriptor["output_schema"]["properties"].as_object())
        .map(|properties| properties.keys().cloned().collect())
        .unwrap_or_default()
}

pub(crate) fn caps_from(
    registry: &Registry,
    catalog: &serde_json::Value,
    plan: &Plan,
) -> Result<HashMap<String, Cap>, String> {
    let mut caps = HashMap::new();
    for step in &plan.steps {
        let Some((_, id)) = call_of(step) else {
            continue;
        };
        if caps.contains_key(id) {
            continue;
        }
        let record = registry
            .get(id)
            .ok_or_else(|| format!("unknown capability {id}"))?;
        caps.insert(
            id.to_string(),
            Cap {
                effects: record.effects.clone(),
                data_classes: record.data_classes.clone(),
                consequential: record.consequential,
                cost: match (&record.cost_amount, &record.cost_currency) {
                    (Some(amount), Some(currency)) => Some((amount.clone(), currency.clone())),
                    _ => None,
                },
                outputs: declared_outputs(catalog, id),
            },
        );
    }
    Ok(caps)
}

#[cfg(test)]
mod tests {
    #[test]
    fn operator_attest_flag_is_parsed() {
        let base = [
            "run",
            "plan",
            "catalog",
            "--policy",
            "p",
            "--grant",
            "g",
            "--trusted-issuer",
            "did:key:z",
        ];
        let parse = |extra: &[&str]| {
            let v: Vec<String> = base.iter().chain(extra).map(|s| s.to_string()).collect();
            super::parse_run_args(v).unwrap().operator_attest
        };
        assert!(!parse(&[]));
        assert!(parse(&["--operator-attest"]));
    }
    #[test]
    fn config_approval_non_approver_uids() {
        let uids = |v: serde_json::Value| super::config_non_approver_uids(&v);
        assert_eq!(
            uids(serde_json::json!({"approval":{"non_approver_uids":[1000,4000]}})).unwrap(),
            [1000, 4000]
        );
        assert_eq!(uids(serde_json::json!({})).unwrap(), Vec::<u32>::new());
        assert!(uids(serde_json::json!({"approval":{"non_approver_uids":["1000"]}})).is_err());
        assert!(uids(serde_json::json!({"approval":{"non_approver_uids":[-1]}})).is_err());
        assert!(uids(serde_json::json!({"approval":{"non_approver_uids":1000}})).is_err());
    }
    #[test]
    fn non_approver_uid_covers_worker_and_model_uids() {
        let args = |extra: &[&str]| {
            let mut v: Vec<String> = [
                "run",
                "plan",
                "catalog",
                "--policy",
                "p",
                "--grant",
                "g",
                "--trusted-issuer",
                "did:key:z",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            v.extend(extra.iter().map(|s| s.to_string()));
            super::parse_run_args(v).map(|a| a.agent_uids)
        };
        assert_eq!(
            args(&["--non-approver-uid", "1000,4000"]).unwrap(),
            [1000, 4000]
        );
        assert_eq!(
            args(&["--agent-uid", "1000", "--non-approver-uid", "4000"]).unwrap(),
            [1000, 4000]
        );
    }

    use super::{execute, parse_run_args, AuditTarget, FixedApproval, NonInteractive, RunInput};

    const NOW: &str = "2026-10-14T12:10:00Z";

    /// Unique temp log path per call: name + pid + process-wide counter, so
    /// tests running in parallel (or repeated in one test) never share a file.
    fn unique_log(name: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!("{name}-{}-{n}.log", std::process::id()))
    }

    fn hosted<'a>(
        plan: &'a serde_json::Value,
        catalog: &'a serde_json::Value,
        policy: &'a str,
        grant: Option<&'a serde_json::Value>,
    ) -> RunInput<'a> {
        RunInput {
            audit: None,
            dry_run: true,
            plan,
            catalog,
            policy,
            audience: "did:example:hosted",
            grant,
            holder: Some(&*HOLDER),
            now: Some(NOW),
            region: Some("CH"),
            trusted_issuers: TRUSTED,
            approval: &NONINTERACTIVE,
            provider: "https://api.infomaniak.com/",
            profile: "P0",
            local: false,
        }
    }

    const NONINTERACTIVE: NonInteractive = NonInteractive;

    /// The holder of `signed_grant` tokens (`rfc8032-test-2`), presenting them (0002 R25).
    static HOLDER: std::sync::LazyLock<crate::engine::HolderKey> =
        std::sync::LazyLock::new(|| crate::engine::HolderKey::new(party("rfc8032-test-2").seed));

    const TRUSTED: &[&str] = &["did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw"];

    struct Party {
        seed: [u8; 32],
        did: String,
        jkt: String,
    }

    fn party(name: &str) -> Party {
        let file: serde_json::Value = serde_json::from_str(include_str!(
            "../../../spec/test-vectors/keys/rfc8032-test-keys.json"
        ))
        .unwrap();
        let key = file["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == name)
            .unwrap();
        let seed = hex32(key["secret_key_hex"].as_str().unwrap());
        let public = hex32(key["public_key_hex"].as_str().unwrap());
        Party {
            seed,
            did: sidged_grant::did_key(&public),
            jkt: sidged_grant::jwk_thumbprint(&public),
        }
    }

    fn hex32(text: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    fn signed_grant(rights: &[(&str, &str)]) -> serde_json::Value {
        let owner = party("rfc8032-test-1");
        let holder = party("rfc8032-test-2");
        let rights: Vec<_> = rights
            .iter()
            .map(|(action, resource)| serde_json::json!({ "action": action, "resource": resource }))
            .collect();
        let unsigned = serde_json::json!({
            "v": "0.1",
            "id": "tok-run-test01",
            "iss": owner.did,
            "sub": holder.did,
            "aud": "did:example:hosted",
            "iat": "2026-10-14T12:00:00Z",
            "exp": "2026-10-14T12:30:00Z",
            "cnf": { "kid": holder.did, "jkt": holder.jkt },
            "rights": rights,
            "chain": []
        });
        sidged_grant::attach_signature(&unsigned, &owner.seed, &owner.did)
    }

    #[test]
    fn weather_dispatch_checks_before_connect_and_returns_bound_result() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        use std::{
            io::{Read, Write},
            net::TcpListener,
        };
        let connections = Arc::new(AtomicUsize::new(0));
        let cap = super::WEATHER;
        let plan = serde_json::json!({"v":"0.1","steps":[{"id":"weather","kind":"call","capability":cap,"approval":true,"args":{"latitude":{"lit":"-12.3456"},"longitude":{"lit":"98.7654"},"current":{"lit":"temperature_2m"}}}]});
        let catalog = serde_json::json!([{"id":cap,"effects":["read","egress"],"data_classes":["x-public.weather"],"residency":{"tags":["unrestricted"]},"cost":{"class":"free"},"consequential":true}]);
        let grant = signed_grant(&[("weather.lookup", cap)]);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        super::TEST_WEATHER_BASE.with(|b| *b.borrow_mut() = Some(base.clone()));
        let path = unique_log("weather-dispatch");
        let _ = std::fs::remove_file(&path);
        let seed = [73; 32];
        if std::env::var_os("WEATHER_APPEND_FAILURE").is_some() {
            struct FailAppend(u64);
            impl super::ApprovalChannel for FailAppend {
                fn decide(
                    &self,
                    _: &super::ApprovalRequest,
                    now: &str,
                ) -> super::approval::ApprovalDecision {
                    unsafe {
                        libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
                        let limit = libc::rlimit {
                            rlim_cur: self.0,
                            rlim_max: self.0,
                        };
                        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
                    }
                    super::approval::ApprovalDecision {
                        granted: true,
                        actor: "tester".into(),
                        at: now.into(),
                    }
                }
            }
            let mut input = hosted(
                &plan,
                &catalog,
                "permit(principal, action, resource);",
                Some(&grant),
            );
            let yes = FixedApproval {
                granted: true,
                actor: "tester".into(),
            };
            input.approval = &yes;
            input.dry_run = true;
            input.audit = Some(AuditTarget {
                path: &path,
                seed: &seed,
            });
            let mut probe_chain = Some(sidged_log::Chain::open(&path, &seed).unwrap());
            super::execute_with_chain(&input, &mut probe_chain).unwrap();
            drop(probe_chain);
            let spend_size = std::fs::read_to_string(&path)
                .unwrap()
                .lines()
                .next()
                .unwrap()
                .len() as u64
                + 1;
            std::fs::remove_file(&path).unwrap();
            let fail_append = FailAppend(spend_size);
            input.dry_run = false;
            input.approval = &fail_append;
            let error = execute(&input).unwrap_err();
            assert!(
                error.message.contains("File too large"),
                "{}",
                error.message
            );
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert_eq!(std::fs::metadata(&path).unwrap().len(), spend_size);
            let events = sidged_log::read_events(&path, &sidged_log::public_key(&seed)).unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].decision, "spend");
            std::fs::remove_file(path).unwrap();
            return;
        }
        if std::env::var_os("WEATHER_LOCAL_TEST").is_some() {
            let mut input = hosted(
                &plan,
                &catalog,
                "permit(principal, action, resource);",
                Some(&grant),
            );
            input.local = true;
            input.dry_run = false;
            input.audit = Some(AuditTarget {
                path: &path,
                seed: &seed,
            });
            assert!(execute(&input).unwrap_err().message.contains("local mode"));
            match listener.accept() {
                Ok(_) => {
                    connections.fetch_add(1, Ordering::SeqCst);
                }
                Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock),
            }
            assert_eq!(connections.load(Ordering::SeqCst), 0);
            let _ = std::fs::remove_file(path);
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::weather_dispatch_checks_before_connect_and_returns_bound_result",
            ])
            .env("WEATHER_LOCAL_TEST", "1")
            .env_remove("SIDGED_LOCAL")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        // Every denied execution must leave the listener's accept queue empty.
        for mode in [
            "missing-grant",
            "cedar",
            "residency",
            "approval",
            "uses",
            "budget",
            "invalid-args",
            "non-literal",
            "out-of-range",
            "fraction-out-of-range",
            "dry-run",
        ] {
            let mut cat = catalog.clone();
            let mut proposal = plan.clone();
            let mut token = grant.clone();
            if mode == "residency" {
                cat[0]["residency"]["tags"] = serde_json::json!(["CH"]);
            }
            if mode == "approval" {
                cat[0]["consequential"] = true.into();
            }
            if mode == "invalid-args" {
                proposal["steps"][0]["args"]["extra"] = serde_json::json!({"lit":"secret"});
            }
            if mode == "non-literal" {
                proposal["steps"][0]["args"]["latitude"] = serde_json::json!({"ref":"weather"});
            }
            if mode == "out-of-range" {
                proposal["steps"][0]["args"]["latitude"] = serde_json::json!({"lit":"91"});
            }
            if mode == "fraction-out-of-range" {
                proposal["steps"][0]["args"]["longitude"] =
                    serde_json::json!({"lit":"180.00000000000000001"});
            }
            if mode == "uses" {
                token["rights"][0]["constraints"] = serde_json::json!({"max_uses":0});
            }
            if mode == "budget" {
                token["budget"] = serde_json::json!({"messages":0});
            }
            if mode == "uses" || mode == "budget" {
                let owner = party("rfc8032-test-1");
                token = sidged_grant::attach_signature(&token, &owner.seed, &owner.did);
            }
            let mut input = hosted(
                &proposal,
                &cat,
                if mode == "cedar" {
                    "forbid(principal, action, resource);"
                } else {
                    "permit(principal, action, resource);"
                },
                if mode == "missing-grant" {
                    None
                } else {
                    Some(&token)
                },
            );
            input.dry_run = mode == "dry-run";
            let yes = FixedApproval {
                granted: true,
                actor: "tester".into(),
            };
            if mode == "dry-run" {
                input.approval = &yes;
            }
            input.audit = Some(AuditTarget {
                path: &path,
                seed: &seed,
            });
            let result = execute(&input);
            assert_eq!(result.is_ok(), mode == "dry-run", "{mode}: {result:?}");
            match listener.accept() {
                Ok(_) => {
                    connections.fetch_add(1, Ordering::SeqCst);
                }
                Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock),
            }
            assert_eq!(connections.load(Ordering::SeqCst), 0);
        }
        listener.set_nonblocking(false).unwrap();
        let seen = Arc::clone(&connections);
        let audit_path = path.clone();
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                seen.fetch_add(1, Ordering::SeqCst);
                let events =
                    sidged_log::read_events(&audit_path, &sidged_log::public_key(&seed)).unwrap();
                let intent = events.last().unwrap();
                assert_eq!(intent.decision, "approve");
                assert!(intent
                    .reason
                    .as_deref()
                    .unwrap()
                    .contains("sent_url_sha256="));
                let report: serde_json::Value =
                    serde_json::from_str(intent.privacy_report.as_deref().unwrap()).unwrap();
                assert_eq!(report["payload_binding"], "request-url");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut received = Vec::new();
                while !received.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    received.push(byte[0]);
                }
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\nConnection: close\r\n\r\n{\"temperature\":12}").unwrap();
                requests.push(String::from_utf8(received).unwrap());
            }
            requests
        });
        let mut input = hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            Some(&grant),
        );
        input.dry_run = false;
        input.audit = Some(AuditTarget {
            path: &path,
            seed: &seed,
        });
        let yes = FixedApproval {
            granted: true,
            actor: "tester".into(),
        };
        input.approval = &yes;
        let result = execute(&input).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::weather_dispatch_checks_before_connect_and_returns_bound_result",
            ])
            .env("WEATHER_APPEND_FAILURE", "1")
            .env_remove("SIDGED_LOCAL")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let mut consequential = catalog.clone();
        consequential[0]["consequential"] = true.into();
        let mut approved_plan = plan.clone();
        approved_plan["steps"][0]["approval"] = true.into();
        struct BoundApproval(String, String, String);
        impl super::ApprovalChannel for BoundApproval {
            fn decide(
                &self,
                request: &super::ApprovalRequest,
                now: &str,
            ) -> super::approval::ApprovalDecision {
                use sha2::Digest;
                assert_eq!(request.args_digest, self.2);
                assert_eq!(
                    request.sent_url_sha256.as_deref(),
                    Some(format!("{:x}", sha2::Sha256::digest(self.0.as_bytes())).as_str())
                );
                assert_eq!(request.plan_digest, self.1);
                assert!(!request.nonce.is_empty());
                super::approval::ApprovalDecision {
                    granted: true,
                    actor: "tester".into(),
                    at: now.into(),
                }
            }
        }
        let approval = BoundApproval(
            match &sidged_verify::stored::read_plan(&approved_plan)
                .unwrap()
                .steps[0]
            {
                super::Step::Call { args, .. } => super::weather_url(args, &base).unwrap(),
                _ => unreachable!(),
            },
            super::plan_digest(&approved_plan).unwrap(),
            {
                use sha2::Digest;
                format!(
                    "{:x}",
                    sha2::Sha256::digest(
                        sidged_grant::canonicalize(&approved_plan["steps"][0]["args"]).as_bytes()
                    )
                )
            },
        );
        input.plan = &approved_plan;
        input.catalog = &consequential;
        input.approval = &approval;
        let approved = execute(&input).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&approved.results["weather"]).unwrap()
                ["body"],
            r#"{"temperature":12}"#
        );
        let received = server.join().unwrap();
        assert_eq!(connections.load(Ordering::SeqCst), 2);
        assert_eq!(received[0], received[1]);
        let received = &received[0];
        assert!(!received.to_ascii_lowercase().contains("content-type:"));
        let target = "/v1/forecast?latitude=-12.3456&longitude=98.7654&current=temperature_2m";
        assert!(
            received.starts_with(&format!("GET {target} HTTP/1.1\r\n")),
            "{received}"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&result.results["weather"]).unwrap()["body"],
            r#"{"temperature":12}"#
        );
        assert_eq!(result.reports.len(), 1);
        let document: serde_json::Value = serde_json::from_str(&result.reports[0]).unwrap();
        let expected = sidged_gateway::report(&sidged_gateway::Egress {
            id: "test",
            call_at: NOW,
            provider_id: &base,
            profile: "P0",
            data_classes: &[],
            fields: &[],
            payload: format!("{base}{target}").as_bytes(),
            residency: &[],
        });
        assert_eq!(
            document["minimisation"]["payload_digest"],
            expected["minimisation"]["payload_digest"]
        );
        assert_eq!(document["payload_binding"], "request-url");
        use sha2::Digest;
        let digest = format!(
            "{:x}",
            sha2::Sha256::digest(format!("{base}{target}").as_bytes())
        );
        let allows: Vec<_> = result
            .events
            .iter()
            .filter(|e| e.decision == "approve")
            .collect();
        assert_eq!(allows.len(), 1);
        assert!(allows[0]
            .reason
            .as_deref()
            .unwrap()
            .contains(&format!("sent_url_sha256={digest}")));
        let approved_event = approved
            .events
            .iter()
            .find(|e| e.decision == "approve")
            .unwrap();
        let reason = approved_event.reason.as_deref().unwrap();
        assert!(reason.contains(&format!("sent_url_sha256={digest}")));
        assert!(reason.contains(&format!("approval args_sha256={}", approval.2)));
        assert!(reason.contains(&format!(
            "plan_digest={}",
            super::plan_digest(&approved_plan).unwrap()
        )));
        let events = sidged_log::read_events(&path, &sidged_log::public_key(&seed)).unwrap();
        let durable_allows: Vec<_> = events.iter().filter(|e| e.decision == "approve").collect();
        assert_eq!(durable_allows.len(), 2);
        assert_eq!(durable_allows[0], allows[0]);
        assert!(events.iter().any(|e| e.decision == "spend"));
        assert!(events
            .last()
            .unwrap()
            .reason
            .as_ref()
            .unwrap()
            .contains("executed"));
        super::TEST_WEATHER_BASE.with(|b| *b.borrow_mut() = None);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn durable_ancestor_caps_and_budgets_cover_fresh_children_and_pure_calls() {
        let cap = "urn:sidged:capability:calendar.free_slots";
        let owner = party("rfc8032-test-1");
        let holder = party("rfc8032-test-2");
        let child_holder = party("rfc8032-test-3");
        // The delegated child's holder presents it (0002 R25).
        let child_key = crate::engine::HolderKey::new(child_holder.seed);
        let plan = serde_json::json!({"v":"0.1","budget":{"max":{"amount":"1","currency":"CHF"}},"steps":[{"id":"one","kind":"call","capability":cap,"args":{}}]});
        let catalog = serde_json::json!([{"id":cap,"effects":["read"],"data_classes":[],"consequential":false, "residency": {"tags": ["unrestricted"]},"cost":{"class":"free"}}]);
        for mode in ["uses", "messages", "compute_units", "money"] {
            let mut parent = signed_grant(&[("calendar.free_slots", cap)]);
            if mode == "uses" {
                parent["rights"][0]["constraints"] = serde_json::json!({"max_uses":1});
            } else if mode == "money" {
                parent["budget"] = serde_json::json!({"money":{"amount":"1","currency":"CHF"}});
            } else {
                parent["budget"] = serde_json::json!({mode:1});
            }
            parent = sidged_grant::attach_signature(&parent, &owner.seed, &owner.did);
            let mut child = parent.clone();
            child["id"] = serde_json::json!("child-one");
            child["iss"] = serde_json::json!(holder.did);
            child["sub"] = serde_json::json!(child_holder.did);
            child["cnf"] = serde_json::json!({"kid":child_holder.did,"jkt":child_holder.jkt});
            child["chain"] = serde_json::json!([parent]);
            child = sidged_grant::attach_signature(&child, &holder.seed, &holder.did);
            let mut priced_catalog = catalog.clone();
            if mode == "money" {
                priced_catalog[0]["cost"] =
                    serde_json::json!({"class":"metered","max":{"amount":"1","currency":"CHF"}});
            }
            let path = unique_log(&format!("sidged-ancestor-{mode}"));
            let _ = std::fs::remove_file(&path);
            let run = |grant: &serde_json::Value| {
                let mut input = hosted(
                    &plan,
                    &priced_catalog,
                    "permit(principal, action, resource);",
                    Some(grant),
                );
                input.dry_run = false;
                input.holder = Some(&child_key);
                input.audit = Some(AuditTarget {
                    path: &path,
                    seed: &owner.seed,
                });
                execute(&input)
            };
            // Pure calls still require durable accounting.
            let mut missing = hosted(
                &plan,
                &priced_catalog,
                "permit(principal, action, resource);",
                Some(&child),
            );
            missing.dry_run = false;
            assert!(execute(&missing).is_err());
            run(&child).unwrap();
            child["id"] = serde_json::json!("child-two");
            child = sidged_grant::attach_signature(&child, &holder.seed, &holder.did);
            assert!(
                run(&child).unwrap_err().message.contains("grant denied"),
                "{mode}"
            );
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn missing_id_and_invalid_plan_are_durable_denials() {
        let cap = "urn:sidged:capability:calendar.free_slots";
        let owner = party("rfc8032-test-1");
        let mut grant = signed_grant(&[("calendar.free_slots", cap)]);
        grant.as_object_mut().unwrap().remove("id");
        grant = sidged_grant::attach_signature(&grant, &owner.seed, &owner.did);
        let catalog = serde_json::json!([{"id":cap,"effects":["read"],"data_classes":[],"consequential":false, "residency": {"tags": ["unrestricted"]},"cost":{"class":"free"}}]);
        let good = serde_json::json!({"v":"0.1","steps":[{"id":"one","kind":"call","capability":cap,"args":{}}]});
        let bad = serde_json::json!({"steps":[{"kind":"unknown"}]});
        let path = unique_log("sidged-denials");
        let _ = std::fs::remove_file(&path);
        for plan in [&good, &bad] {
            let mut input = hosted(
                plan,
                &catalog,
                "permit(principal, action, resource);",
                Some(&grant),
            );
            input.dry_run = false;
            input.audit = Some(AuditTarget {
                path: &path,
                seed: &owner.seed,
            });
            let failure = execute(&input).unwrap_err();
            assert_eq!(failure.events[0].decision, "deny");
        }
        let events = sidged_log::read_events(&path, &sidged_log::public_key(&owner.seed)).unwrap();
        assert_eq!(events.len(), 2);
        assert!(events
            .iter()
            .all(|event| event.decision == "deny" && event.reason.is_some()));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn effectful_execution_requires_a_log_and_uses_survive_reopen() {
        let cap = "urn:sidged:capability:calendar.free_slots";
        let mut grant = signed_grant(&[("calendar.free_slots", cap)]);
        grant["rights"][0]["constraints"] = serde_json::json!({"max_uses":1});
        let owner = party("rfc8032-test-1");
        grant = sidged_grant::attach_signature(&grant, &owner.seed, &owner.did);
        let catalog = serde_json::json!([{"id":cap,"effects":["read"],"data_classes":[],"consequential":false, "residency": {"tags": ["unrestricted"]},"cost":{"class":"free"}}]);
        let plan = serde_json::json!({"v":"0.1","steps":[{"id":"one","kind":"call","capability":cap,"args":{}}]});
        let mut input = hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            Some(&grant),
        );
        input.dry_run = false;
        assert!(execute(&input).unwrap_err().message.contains("audit"));
        let path = unique_log("sidged-uses");
        let _ = std::fs::remove_file(&path);
        input.audit = Some(AuditTarget {
            path: &path,
            seed: &owner.seed,
        });
        input.dry_run = true;
        execute(&input).unwrap();
        assert!(!path.exists(), "dry run must not create or spend a ledger");
        input.dry_run = false;
        execute(&input).unwrap();
        // A crash after the durable reservation but before the allow record
        // must still consume the use when the next execution replays the chain.
        let text = std::fs::read_to_string(&path).unwrap();
        let reservation = text.lines().next().unwrap();
        std::fs::write(&path, format!("{reservation}\n")).unwrap();
        let err = execute(&input).unwrap_err();
        assert!(err.message.contains("grant denied"), "{}", err.message);
        assert!(err.events.iter().all(|e| e.decision == "deny"));
        let events = sidged_log::read_events(&path, &sidged_log::public_key(&owner.seed)).unwrap();
        assert!(events.iter().any(|e| e.decision == "deny"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn capped_calls_and_maps_are_checked_through_execute() {
        let cap = "urn:sidged:capability:calendar.free_slots";
        let mut grant = signed_grant(&[("calendar.free_slots", cap)]);
        grant["rights"][0]["constraints"] = serde_json::json!({"max_uses": 1});
        let owner = party("rfc8032-test-1");
        grant = sidged_grant::attach_signature(&grant, &owner.seed, &owner.did);
        let catalog = serde_json::json!([{"id": cap, "effects": ["read"],
            "data_classes": [], "consequential": false, "residency": {"tags": ["unrestricted"]}, "cost": {"class": "free"}}]);
        let plan = serde_json::json!({"v":"0.1","steps": [
            {"id":"one", "kind":"call", "capability":cap, "args":{}},
            {"id":"two", "kind":"call", "capability":cap, "args":{}}]});
        let path = unique_log("sidged-capped-calls");
        let _ = std::fs::remove_file(&path);
        let mut input = hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            Some(&grant),
        );
        input.dry_run = false;
        input.audit = Some(AuditTarget {
            path: &path,
            seed: &owner.seed,
        });
        let err = execute(&input).unwrap_err();
        assert!(err.message.contains("grant denied"));
        assert_eq!(
            err.events
                .iter()
                .map(|e| e.decision.as_str())
                .collect::<Vec<_>>(),
            ["allow", "deny"]
        );
        let events = sidged_log::read_events(&path, &sidged_log::public_key(&owner.seed)).unwrap();
        assert_eq!(events.iter().filter(|e| e.decision == "allow").count(), 1);
        assert!(events.iter().any(|e| e
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("grant denied"))));
        std::fs::remove_file(&path).unwrap();
        let mut consequential = catalog.clone();
        consequential[0]["consequential"] = serde_json::json!(true);
        input.catalog = &consequential;
        let map = serde_json::json!({"v":"0.1","steps": [
            {"id":"rows", "kind":"expr", "expr":"true"},
            {"id":"scan", "kind":"map", "approval":true, "over":{"ref":"rows"}, "bound":2, "capability":cap, "args":{}}]});
        input.plan = &map;
        let err = execute(&input).unwrap_err();
        assert!(err.message.contains("grant denied"), "{}", err.message);
        assert!(err.events.iter().all(|e| e.decision == "deny"));
        let events = sidged_log::read_events(&path, &sidged_log::public_key(&owner.seed)).unwrap();
        assert!(events.iter().all(|e| e.decision == "deny"));
        std::fs::remove_file(&path).unwrap();
        let mut zero = map.clone();
        zero["steps"][1]["bound"] = serde_json::json!(0);
        input.plan = &zero;
        let err = execute(&input).unwrap_err();
        assert!(err.message.contains("map bound"));
        let events = sidged_log::read_events(&path, &sidged_log::public_key(&owner.seed)).unwrap();
        assert!(
            events
                .iter()
                .all(|event| event.decision == "deny" && event.usage.is_none()),
            "the verifier logs a refusal without spending uses"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn replay_spends_the_covering_right_with_uses_left() {
        let cap = "urn:sidged:capability:calendar.free_slots";
        let owner = party("rfc8032-test-1");
        let mut grant = signed_grant(&[("calendar.free_slots", cap), ("calendar.free_slots", cap)]);
        for right in grant["rights"].as_array_mut().unwrap() {
            right["constraints"] = serde_json::json!({"max_uses":1});
        }
        grant = sidged_grant::attach_signature(&grant, &owner.seed, &owner.did);
        let catalog = serde_json::json!([{"id":cap,"effects":["read"],"data_classes":[],"consequential":false, "residency": {"tags": ["unrestricted"]},"cost":{"class":"free"}}]);
        let plan = serde_json::json!({"v":"0.1","steps":[{"id":"one","kind":"call","capability":cap,"args":{}}]});
        let path = unique_log("sidged-covering");
        let _ = std::fs::remove_file(&path);
        let mut input = hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            Some(&grant),
        );
        input.dry_run = false;
        input.audit = Some(AuditTarget {
            path: &path,
            seed: &owner.seed,
        });
        execute(&input).unwrap();
        execute(&input).unwrap();
        assert!(execute(&input)
            .unwrap_err()
            .message
            .contains("grant denied"));
        let events = sidged_log::read_events(&path, &sidged_log::public_key(&owner.seed)).unwrap();
        let indices: Vec<_> = events
            .iter()
            .filter_map(|e| e.usage.as_ref().map(|(_, index, _)| *index))
            .collect();
        assert_eq!(indices, [0, 1]);
        let mut other = grant.clone();
        other["id"] = serde_json::json!("tok-other-0001");
        other = sidged_grant::attach_signature(&other, &owner.seed, &owner.did);
        input.grant = Some(&other);
        execute(&input).unwrap();
        std::fs::remove_file(path).unwrap();
    }

    /// Presents with `seed`, over `digest` instead of the run's plan when given.
    struct Signs([u8; 32], Option<&'static str>);
    impl crate::engine::Presenter for Signs {
        fn prove(
            &self,
            token: &serde_json::Value,
            aud: &str,
            digest: &str,
            nonce: &str,
        ) -> [u8; 64] {
            sidged_grant::sign_pop(&self.0, token, aud, self.1.unwrap_or(digest), nonce)
        }
    }

    /// Signs and keeps every proof; once replaying, hands the first one out again.
    #[derive(Default)]
    struct Replay(std::sync::Mutex<(Option<[u8; 64]>, bool)>);
    impl crate::engine::Presenter for Replay {
        fn prove(
            &self,
            token: &serde_json::Value,
            aud: &str,
            digest: &str,
            nonce: &str,
        ) -> [u8; 64] {
            let mut state = self.0.lock().unwrap();
            match (state.0, state.1) {
                (Some(proof), true) => proof,
                _ => {
                    let proof = HOLDER.prove(token, aud, digest, nonce);
                    state.0 = Some(proof);
                    proof
                }
            }
        }
    }

    use crate::engine::Presenter;

    /// 0002 R25 on `sidged run`: a grant presented without a valid proof of possession (a
    /// wrong key, a proof over another plan, a proof replayed from an earlier run, or no
    /// holder key at all) reserves nothing and runs no step.
    #[test]
    fn a_grant_without_a_valid_proof_has_no_effect_on_sidged_run() {
        let cap = "urn:sidged:capability:calendar.free_slots";
        let grant = signed_grant(&[("calendar.free_slots", cap)]);
        let catalog = serde_json::json!([{"id":cap,"effects":["read"],"data_classes":[],"consequential":false, "residency": {"tags": ["unrestricted"]},"cost":{"class":"free"}}]);
        let plan = serde_json::json!({"v":"0.1","steps":[{"id":"one","kind":"call","capability":cap,"args":{}}]});
        let owner = party("rfc8032-test-1");
        let wrong = Signs(party("rfc8032-test-3").seed, None);
        let other_plan = Signs(party("rfc8032-test-2").seed, Some("another-plan-digest"));
        let effects = |path: &std::path::Path| {
            sidged_log::read_events(path, &sidged_log::public_key(&owner.seed))
                .unwrap()
                .into_iter()
                .filter(|e| e.decision == "spend" || e.decision == "allow")
                .count()
        };
        for (case, presenter) in [
            ("wrong key", Some(&wrong as &dyn Presenter)),
            ("other plan", Some(&other_plan as &dyn Presenter)),
            ("no holder key", None),
        ] {
            let path = unique_log("sidged-pop");
            let _ = std::fs::remove_file(&path);
            let mut input = hosted(
                &plan,
                &catalog,
                "permit(principal, action, resource);",
                Some(&grant),
            );
            input.dry_run = false;
            input.holder = presenter;
            input.audit = Some(AuditTarget {
                path: &path,
                seed: &owner.seed,
            });
            let error = execute(&input).unwrap_err();
            assert!(error.message.contains("grant"), "{case}: {}", error.message);
            assert!(error.events.iter().all(|e| e.decision == "deny"), "{case}");
            assert_eq!(effects(&path), 0, "{case}");
            std::fs::remove_file(path).unwrap();
        }
        let replay = Replay::default();
        let path = unique_log("sidged-pop-replay");
        let _ = std::fs::remove_file(&path);
        let mut input = hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            Some(&grant),
        );
        input.dry_run = false;
        input.holder = Some(&replay);
        input.audit = Some(AuditTarget {
            path: &path,
            seed: &owner.seed,
        });
        execute(&input).unwrap();
        assert_eq!(effects(&path), 2);
        replay.0.lock().unwrap().1 = true;
        let error = execute(&input).unwrap_err();
        assert!(error.message.contains("grant"), "{}", error.message);
        assert_eq!(effects(&path), 2, "a replayed proof reserved or ran a step");
        std::fs::remove_file(path).unwrap();
    }

    /// 0005 R5a: an effectful `sidged run` without an audit target refuses before its first
    /// step: no step decision, no approval request, not even a look at the grant.
    #[test]
    fn an_effectful_run_without_an_audit_target_refuses_before_the_first_step() {
        struct Never;
        impl crate::ApprovalChannel for Never {
            fn decide(
                &self,
                _: &super::ApprovalRequest,
                _: &str,
            ) -> crate::approval::ApprovalDecision {
                panic!("approval asked without an audit target");
            }
        }
        let cap = "urn:sidged:capability:message.send";
        let plan = serde_json::json!({"v":"0.1","steps":[{"id":"send","kind":"call","capability":cap,"approval":true,"args":{"body":{"lit":"hi"}}}]});
        let catalog = serde_json::json!([{"id":cap,"effects":["egress"],"data_classes":["communications.content"],"consequential":true,"residency":{"tags":["unrestricted"]},"cost":{"class":"free"}}]);
        let grant = signed_grant(&[("message.send", cap)]);
        for grant in [Some(&grant), None] {
            let mut input = hosted(
                &plan,
                &catalog,
                "permit(principal, action, resource);",
                grant,
            );
            input.dry_run = false;
            input.approval = &Never;
            let error = execute(&input).unwrap_err();
            assert!(error.message.contains("audit"), "{}", error.message);
            assert!(
                error.events.iter().all(|e| e.step != "send"),
                "{:?}",
                error.events
            );
        }
        // A dry run may still omit it.
        let yes = FixedApproval {
            granted: true,
            actor: "tester".into(),
        };
        let mut input = hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            Some(&grant),
        );
        input.approval = &yes;
        execute(&input).unwrap();
    }

    #[test]
    fn dcbor_plan_digest_matches_0013_vectors() {
        let file: serde_json::Value = serde_json::from_str(include_str!(
            "../../../spec/test-vectors/plan/dcbor-signed.json"
        ))
        .unwrap();
        for vector in file["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["operation"] == "plan-digest")
        {
            let actual = super::plan_digest(&vector["input"]["plan"]);
            if let Some(expected) = vector["expected"]["value"]["digest"].as_str() {
                assert_eq!(actual.unwrap(), expected);
            } else {
                assert_eq!(actual.unwrap_err(), "malformed");
            }
        }
    }

    #[test]
    fn stale_refusals_are_signed_once_on_approval_and_denial_without_nonces() {
        use super::ApprovalChannel;
        struct Channel {
            granted: bool,
            stale: std::sync::Mutex<usize>,
            nonce: std::sync::Mutex<String>,
        }
        impl ApprovalChannel for Channel {
            fn decide(
                &self,
                request: &super::ApprovalRequest,
                now: &str,
            ) -> super::approval::ApprovalDecision {
                *self.nonce.lock().unwrap() = request.nonce.clone();
                let line = |nonce: &str| {
                    format!(
                        "{} operator {} {} {} {} {}\n",
                        if self.granted { "approve" } else { "deny" },
                        request.step,
                        request.capability,
                        request.args_digest,
                        nonce,
                        request.plan_digest
                    )
                };
                let (decision, stale) = super::approval::decide_from_lines(
                    &(line("old-nonce") + &line(&request.nonce)),
                    request,
                    now,
                );
                *self.stale.lock().unwrap() = stale;
                decision
            }
            fn take_stale_responses(&self) -> usize {
                std::mem::take(&mut *self.stale.lock().unwrap())
            }
        }
        let cap = "urn:sidged:capability:calendar.free_slots";
        let plan = serde_json::json!({"v":"0.1","steps":[{"id":"one","kind":"call",
            "capability":cap,"approval":true,"args":{}}]});
        let catalog = serde_json::json!([{"id":cap,"effects":["read"],"data_classes":[],
            "consequential":true,"residency":{"tags":["unrestricted"]},"cost":{"class":"free"}}]);
        let grant = signed_grant(&[("calendar.free_slots", cap)]);
        let owner = party("rfc8032-test-1");
        for granted in [true, false] {
            let channel = Channel {
                granted,
                stale: Default::default(),
                nonce: Default::default(),
            };
            let path = unique_log(&format!("sidged-stale-{granted}"));
            let _ = std::fs::remove_file(&path);
            let mut input = hosted(
                &plan,
                &catalog,
                "permit(principal, action, resource);",
                Some(&grant),
            );
            input.dry_run = false;
            input.approval = &channel;
            input.audit = Some(AuditTarget {
                path: &path,
                seed: &owner.seed,
            });
            let result = execute(&input);
            assert_eq!(result.is_ok(), granted);
            let events =
                sidged_log::read_events(&path, &sidged_log::public_key(&owner.seed)).unwrap();
            let stale: Vec<_> = events
                .iter()
                .filter(|e| e.reason.as_deref() == Some("stale approval response"))
                .collect();
            assert_eq!(stale.len(), 1);
            assert_eq!(stale[0].decision, "deny");
            assert!(!format!("{events:?}").contains(channel.nonce.lock().unwrap().as_str()));
            assert_eq!(
                events.last().unwrap().decision,
                if granted { "approve" } else { "deny" }
            );
            std::fs::remove_file(path).unwrap();
        }
    }

    // 0004 R9 amendment (leads decision): refused channels and rejected peers
    // land in the signed audit log; peer rejections are audited even when no
    // approval is ever decided. No approval_binding flag exists any more.
    #[test]
    fn r9_refusal_and_rejected_peers_are_audited() {
        struct Channel {
            granted: bool,
            refusal: Option<&'static str>,
            rejected: std::sync::Mutex<Vec<u32>>,
            attested: Option<&'static str>,
            started: std::sync::atomic::AtomicBool,
        }
        impl super::ApprovalChannel for Channel {
            fn decide(
                &self,
                _: &super::ApprovalRequest,
                now: &str,
            ) -> super::approval::ApprovalDecision {
                super::approval::ApprovalDecision {
                    granted: self.granted,
                    actor: self.refusal.unwrap_or("approver").into(),
                    at: now.into(),
                }
            }
            fn refusal(&self) -> Option<&str> {
                self.refusal
            }
            fn take_rejected_peers(&self) -> Vec<u32> {
                std::mem::take(&mut *self.rejected.lock().unwrap())
            }
            fn attestation(&self) -> Option<&str> {
                self.attested
            }
            fn approver_uid(&self) -> Option<u32> {
                Some(4242)
            }
            fn r9c_attestation(&self) -> Option<String> {
                Some("attestation=R9c undetected=su-password,keys".into())
            }
            fn take_channel_start(&self) -> Option<String> {
                (!self.started.swap(true, std::sync::atomic::Ordering::SeqCst))
                    .then(|| "attestation=R9c undetected=su-password,keys".into())
            }
        }
        let cap = "urn:sidged:capability:calendar.free_slots";
        let owner = party("rfc8032-test-1");
        let grant = signed_grant(&[("calendar.free_slots", cap)]);
        // (consequential, granted, refusal, rejected peers, expected ok, last decision)
        let cases = [
            (true, true, None, 0, true, "approve"),
            (
                true,
                false,
                Some("approval channel refused: x"),
                0,
                false,
                "deny",
            ),
            (true, false, None, 2, false, "deny"),
            // No approval is decided at all, the rejection is still audited.
            (false, false, None, 1, true, "allow"),
        ];
        for (n, (consequential, granted, refusal, rejected, ok, last)) in
            cases.into_iter().enumerate()
        {
            let plan = serde_json::json!({"v":"0.1","steps":[{"id":"one","kind":"call",
                "capability":cap,"approval":consequential,"args":{}}]});
            let catalog = serde_json::json!([{"id":cap,"effects":["read"],"data_classes":[],
                "consequential":consequential,"residency":{"tags":["unrestricted"]},"cost":{"class":"free"}}]);
            let channel = Channel {
                granted,
                refusal,
                rejected: std::sync::Mutex::new(vec![31337; rejected]),
                attested: (n == 0).then_some(super::OPERATOR_ATTESTED),
                started: Default::default(),
            };
            let path =
                std::env::temp_dir().join(format!("sidged-r9-{}-{n}.log", std::process::id()));
            let _ = std::fs::remove_file(&path);
            let mut input = hosted(
                &plan,
                &catalog,
                "permit(principal, action, resource);",
                Some(&grant),
            );
            input.dry_run = false;
            input.approval = &channel;
            input.audit = Some(AuditTarget {
                path: &path,
                seed: &owner.seed,
            });
            assert_eq!(execute(&input).is_ok(), ok, "case {n}");
            let events =
                sidged_log::read_events(&path, &sidged_log::public_key(&owner.seed)).unwrap();
            let text = format!("{events:?}");
            // binding (4): unclear host checks mark approvals operator-attested
            assert_eq!(
                text.contains("approval_binding=operator-attested"),
                n == 0,
                "case {n}: {text}"
            );
            if n == 0 {
                assert!(text.contains("approver_uid=4242"), "{text}");
            }
            // Every approval binding carries attestation=R9c and the
            // undetected list, separately from operator-attested.
            if consequential && refusal.is_none() {
                assert!(
                    text.contains("approver_uid=4242 attestation=R9c undetected=su-password,keys"),
                    "case {n}: {text}"
                );
            }
            // The channel start is audited once with the same field.
            let starts = events
                .iter()
                .filter(|e| {
                    e.reason.as_deref()
                        == Some(
                            "approval channel started attestation=R9c undetected=su-password,keys",
                        )
                })
                .count();
            assert_eq!(starts, 1, "case {n}: {text}");
            assert!(
                events.iter().any(|e| e.decision == last),
                "case {n}: {text}"
            );
            if let Some(refusal) = refusal {
                assert!(text.contains(refusal), "{text}");
            }
            let peers = events
                .iter()
                .filter(|e| {
                    e.reason.as_deref().is_some_and(|r| {
                        r.starts_with("approval peer uid rejected")
                            && r.contains("observed uid 31337")
                    })
                })
                .count();
            assert_eq!(peers, rejected, "case {n}: {text}");
            // 0004 R11: the same facts as schema fields.
            // All three R11 fields on every approval event.
            let binding = if n == 0 { "operator-attested" } else { "none" };
            let r9c = |binding: &str| sidged_core::ApprovalAudit {
                approver_uid: Some(4242),
                observed_uid: None,
                attestation: "R9c".into(),
                undetected: vec!["su-password".into(), "keys".into()],
                approval_binding: binding.to_string(),
            };
            let start = events
                .iter()
                .find(|e| {
                    e.reason
                        .as_deref()
                        .is_some_and(|r| r.starts_with("approval channel started"))
                })
                .unwrap();
            assert_eq!(start.approval, Some(r9c(binding)), "case {n}");
            if consequential && refusal.is_none() {
                let bound: Vec<_> = events
                    .iter()
                    .filter(|e| {
                        e.reason
                            .as_deref()
                            .is_some_and(|r| r.contains("approval args_sha256="))
                    })
                    .collect();
                assert!(!bound.is_empty(), "case {n}: {text}");
                for e in bound {
                    assert_eq!(e.approval, Some(r9c(binding)), "case {n}");
                }
            }
            for e in events.iter().filter(|e| {
                e.reason
                    .as_deref()
                    .is_some_and(|r| r.starts_with("approval peer uid rejected"))
            }) {
                assert_eq!(
                    e.approval,
                    Some(sidged_core::ApprovalAudit {
                        observed_uid: Some(31337),
                        ..r9c(binding)
                    }),
                    "case {n}"
                );
            }
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn a_plan_is_checked_and_an_egress_is_logged() {
        let plan = serde_json::json!({
            "v": "0.1",
            "steps": [
                {
                    "id": "free",
                    "kind": "call",
                    "capability": "urn:sidged:capability:calendar.free_slots",
                    "args": { "range": { "lit": "next_week" } }
                },
                {
                    "id": "send",
                    "kind": "call",
                    "capability": "urn:sidged:capability:message.send",
                    "approval": true,
                    "args": { "body": { "ref": "free" } }
                }
            ]
        });
        let catalog = serde_json::json!([
            {
                "id": "urn:sidged:capability:calendar.free_slots",
                "effects": ["read"],
                "data_classes": ["calendar.availability"],
                "consequential": false,
                "residency": {"tags": ["unrestricted"]},
                "cost": { "class": "free" }
            },
            {
                "id": "urn:sidged:capability:message.send",
                "effects": ["egress"],
                "data_classes": ["communications.content"],
                "consequential": true,
                "residency": {"tags": ["unrestricted"]},
                "cost": { "class": "free" }
            }
        ]);
        let grant = signed_grant(&[
            (
                "calendar.free_slots",
                "urn:sidged:capability:calendar.free_slots",
            ),
            ("message.send", "urn:sidged:capability:message.send"),
        ]);
        let approval = FixedApproval {
            granted: true,
            actor: "ada".into(),
        };
        let mut input = hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            Some(&grant),
        );
        input.approval = &approval;
        let report = execute(&input).unwrap();
        assert_eq!(report.reports.len(), 1);
        let privacy: serde_json::Value = serde_json::from_str(&report.reports[0]).unwrap();
        assert_eq!(privacy["sent"]["data_classes"][0], "communications.content");
        assert!(privacy["sent"].get("body").is_none());
        assert_eq!(privacy["provider"]["id"], "https://api.infomaniak.com/");
        assert_eq!(privacy["call_at"], NOW);
        assert_eq!(privacy["provider_profile"]["claimed"], "P0");
        assert!(privacy["id"].as_str().unwrap().starts_with("pr-"));
        assert_eq!(report.events.len(), 2);
        assert_eq!(
            report.events[1].privacy_report.as_ref(),
            Some(&report.reports[0])
        );
        assert!(report.events[0].privacy_report.is_none());
        assert_eq!(report.events[1].decision, "approve");
        assert_eq!(report.events[1].actor, "ada");
        assert!(report.events[1]
            .reason
            .as_deref()
            .unwrap()
            .contains("approval args_sha256="));
        assert_eq!(report.events[1].at, NOW);
        assert!(report
            .events
            .iter()
            .all(|event| event.decision != "allow" || event.step != "send"));
        assert!(report
            .egress
            .iter()
            .any(|item| item.contains("message.send")));
    }

    #[test]
    fn an_mcp_tools_document_is_the_catalog() {
        let raw = include_str!("../../../docs/demo/mcp-server-time/annotated-tools.json");
        let catalog: serde_json::Value = serde_json::from_str(raw).unwrap();
        let plan = serde_json::json!({
            "v": "0.1",
            "steps": [{
                "id": "now",
                "kind": "call",
                "capability": "urn:sidged:capability:get_current_time",
                "args": { "timezone": { "lit": "UTC" } }
            }]
        });
        let grant = signed_grant(&[("get_current_time", "urn:sidged:capability:get_current_time")]);
        let report = execute(&hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            Some(&grant),
        ))
        .unwrap();
        assert_eq!(report.events.len(), 1);
        assert!(report.reports.is_empty());
    }

    #[test]
    fn a_forbid_policy_stops_the_plan() {
        let plan = serde_json::json!({
            "v": "0.1",
            "steps": [{
                "id": "now",
                "kind": "call",
                "capability": "urn:sidged:capability:get_current_time",
                "args": {}
            }]
        });
        let catalog = serde_json::json!([{
            "id": "urn:sidged:capability:get_current_time",
            "effects": ["read"],
            "data_classes": [],
            "consequential": false,
            "residency": {"tags": ["unrestricted"]},
            "cost": { "class": "free" }
        }]);
        let grant = signed_grant(&[("get_current_time", "urn:sidged:capability:get_current_time")]);
        let error = execute(&hosted(
            &plan,
            &catalog,
            "forbid(principal, action, resource);",
            Some(&grant),
        ))
        .unwrap_err();
        assert!(error.message.contains("policy denied"), "{}", error.message);
        assert_eq!(error.events.len(), 1);
        assert_eq!(error.events[0].decision, "deny");
        assert!(error.events.iter().all(|event| event.decision != "allow"));
    }

    #[test]
    fn an_argument_that_is_not_lit_ref_or_item_is_rejected() {
        let plan = serde_json::json!({
            "v": "0.1",
            "steps": [{
                "id": "free",
                "kind": "call",
                "capability": "urn:sidged:capability:calendar.free_slots",
                "args": { "range": { "lit": "next_week", "extra": true } }
            }]
        });
        let catalog = serde_json::json!([{
            "id": "urn:sidged:capability:calendar.free_slots",
            "effects": ["read"],
            "data_classes": ["calendar.availability"],
            "consequential": false,
            "residency": {"tags": ["unrestricted"]},
            "cost": { "class": "free" }
        }]);
        let error = execute(&hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            None,
        ))
        .unwrap_err();
        assert!(
            error.message.contains("lit, ref, or item"),
            "{}",
            error.message
        );
        assert!(error.events.is_empty());
    }

    #[test]
    fn a_nested_literal_is_not_a_literal() {
        let plan = serde_json::json!({
            "v": "0.1",
            "steps": [{
                "id": "free",
                "kind": "call",
                "capability": "urn:sidged:capability:calendar.free_slots",
                "args": { "range": { "lit": { "nested": true } } }
            }]
        });
        let catalog = serde_json::json!([{
            "id": "urn:sidged:capability:calendar.free_slots",
            "effects": ["read"],
            "data_classes": ["calendar.availability"],
            "consequential": false,
            "residency": {"tags": ["unrestricted"]},
            "cost": { "class": "free" }
        }]);
        let error = execute(&hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            None,
        ))
        .unwrap_err();
        assert!(
            error.message.contains("lit, ref, or item"),
            "{}",
            error.message
        );
    }

    #[test]
    fn an_unknown_form_inside_a_map_is_not_an_item() {
        let plan = serde_json::json!({
            "v": "0.1",
            "steps": [
                {
                    "id": "rows",
                    "kind": "call",
                    "capability": "urn:sidged:capability:calendar.free_slots",
                    "args": { "range": { "lit": "next_week" } }
                },
                {
                    "id": "scan",
                    "kind": "map",
                    "over": { "ref": "rows" },
                    "bound": 2,
                    "capability": "urn:sidged:capability:calendar.free_slots",
                    "args": { "row": { "secret": "leak" } }
                }
            ]
        });
        let catalog = serde_json::json!([{
            "id": "urn:sidged:capability:calendar.free_slots",
            "effects": ["read"],
            "data_classes": ["calendar.availability"],
            "consequential": false,
            "residency": {"tags": ["unrestricted"]},
            "cost": { "class": "free" }
        }]);
        let error = execute(&hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            None,
        ))
        .unwrap_err();
        assert!(
            error.message.contains("lit, ref, or item"),
            "{}",
            error.message
        );
    }

    #[test]
    fn a_missing_grant_is_denied_before_any_step() {
        let plan = serde_json::json!({
            "v": "0.1",
            "steps": [{
                "id": "now",
                "kind": "call",
                "capability": "urn:sidged:capability:get_current_time",
                "args": {}
            }]
        });
        let catalog = serde_json::json!([{
            "id": "urn:sidged:capability:get_current_time",
            "effects": ["read"],
            "data_classes": [],
            "consequential": false,
            "residency": {"tags": ["unrestricted"]},
            "cost": { "class": "free" }
        }]);
        let error = execute(&hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            None,
        ))
        .unwrap_err();
        assert!(error.message.contains("missing grant"), "{}", error.message);
        assert_eq!(error.events[0].decision, "deny");
    }

    #[test]
    fn an_expired_or_widened_or_unsigned_grant_is_denied() {
        let plan = serde_json::json!({
            "v": "0.1",
            "steps": [{
                "id": "free",
                "kind": "call",
                "capability": "urn:sidged:capability:calendar.free_slots",
                "args": { "range": { "lit": "next_week" } }
            }]
        });
        let catalog = serde_json::json!([{
            "id": "urn:sidged:capability:calendar.free_slots",
            "effects": ["read"],
            "data_classes": ["calendar.availability"],
            "consequential": false,
            "residency": {"tags": ["unrestricted"]},
            "cost": { "class": "free" }
        }]);
        let grant = signed_grant(&[(
            "calendar.free_slots",
            "urn:sidged:capability:calendar.free_slots",
        )]);
        let expired = RunInput {
            audit: None,
            dry_run: true,
            plan: &plan,
            catalog: &catalog,
            policy: "permit(principal, action, resource);",
            audience: "did:example:hosted",
            grant: Some(&grant),
            holder: Some(&*HOLDER),
            now: Some("2026-10-14T13:00:00Z"),
            region: Some("CH"),
            trusted_issuers: TRUSTED,
            approval: &NONINTERACTIVE,
            provider: "https://api.infomaniak.com/",
            profile: "P0",
            local: false,
        };
        let error = execute(&expired).unwrap_err();
        assert!(error.message.contains("expired"), "{}", error.message);
        assert_eq!(error.events[0].decision, "deny");

        let mut tampered = grant.clone();
        let value = tampered["sig"]["value"].as_str().unwrap().to_string();
        let rest = &value[1..];
        let flipped = if value.starts_with('A') {
            format!("B{rest}")
        } else {
            format!("A{rest}")
        };
        tampered["sig"]["value"] = serde_json::json!(flipped);
        let error = execute(&hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            Some(&tampered),
        ))
        .unwrap_err();
        assert!(error.message.contains("signature"), "{}", error.message);

        let owner = party("rfc8032-test-1");
        let holder = party("rfc8032-test-2");
        let child = party("rfc8032-test-3");
        let parent = sidged_grant::attach_signature(
            &serde_json::json!({
                "v": "0.1",
                "id": "tok-run-parent1",
                "iss": owner.did,
                "sub": holder.did,
                "aud": "did:example:hosted",
                "iat": "2026-10-14T12:00:00Z",
                "exp": "2026-10-14T13:00:00Z",
                "cnf": { "kid": holder.did, "jkt": holder.jkt },
                "rights": [{ "action": "calendar.free_slots", "resource": "urn:sidged:capability:calendar.free_slots" }],
                "budget": { "messages": 2 },
                "chain": []
            }),
            &owner.seed,
            &owner.did,
        );
        let widened = sidged_grant::attach_signature(
            &serde_json::json!({
                "v": "0.1",
                "id": "tok-run-child01",
                "iss": holder.did,
                "sub": child.did,
                "aud": "did:example:hosted",
                "iat": "2026-10-14T12:05:00Z",
                "exp": "2026-10-14T12:20:00Z",
                "cnf": { "kid": child.did, "jkt": child.jkt },
                "rights": [{ "action": "calendar.free_slots", "resource": "urn:sidged:capability/*" }],
                "budget": { "messages": 2 },
                "chain": [parent]
            }),
            &holder.seed,
            &holder.did,
        );
        let error = execute(&hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            Some(&widened),
        ))
        .unwrap_err();
        assert!(error.message.contains("widened"), "{}", error.message);
        assert!(error.events.iter().all(|event| event.decision == "deny"));
    }

    #[test]
    fn the_cedar_principal_is_the_grant_holder() {
        let plan = serde_json::json!({
            "v": "0.1",
            "steps": [{
                "id": "free",
                "kind": "call",
                "capability": "urn:sidged:capability:calendar.free_slots",
                "args": { "range": { "lit": "next_week" } }
            }]
        });
        let catalog = serde_json::json!([{
            "id": "urn:sidged:capability:calendar.free_slots",
            "effects": ["read"],
            "data_classes": ["calendar.availability"],
            "consequential": false,
            "residency": {"tags": ["unrestricted"]},
            "cost": { "class": "free" }
        }]);
        let grant = signed_grant(&[(
            "calendar.free_slots",
            "urn:sidged:capability:calendar.free_slots",
        )]);
        let holder = grant["sub"].as_str().unwrap();
        let allow = format!(
            "permit(principal, action, resource) when {{ principal == User::\"{holder}\" }};"
        );
        execute(&hosted(&plan, &catalog, &allow, Some(&grant))).unwrap();
        let deny = "permit(principal, action, resource) when { principal == User::\"holder\" };";
        let error = execute(&hosted(&plan, &catalog, deny, Some(&grant))).unwrap_err();
        assert!(error.message.contains("policy denied"), "{}", error.message);
        assert_eq!(error.events[0].decision, "deny");
    }

    #[test]
    fn a_residency_denial_is_logged_after_the_grant_check() {
        let plan = serde_json::json!({
            "v": "0.1",
            "steps": [{
                "id": "model",
                "kind": "call",
                "capability": "urn:sidged:capability:model.complete",
                "approval": true,
                "args": { "prompt": { "lit": "c1" } }
            }]
        });
        let catalog = serde_json::json!([{
            "id": "urn:sidged:capability:model.complete",
            "effects": ["egress"],
            "data_classes": ["communications.content"],
            "consequential": true,
            "cost": { "class": "free" },
            "residency": { "tags": ["CH"] }
        }]);
        let grant = signed_grant(&[("model.complete", "urn:sidged:capability:model.complete")]);
        let input = RunInput {
            audit: None,
            dry_run: true,
            plan: &plan,
            catalog: &catalog,
            policy: "permit(principal, action, resource);",
            audience: "did:example:hosted",
            grant: Some(&grant),
            holder: Some(&*HOLDER),
            now: Some(NOW),
            region: Some("EU"),
            trusted_issuers: TRUSTED,
            approval: &NONINTERACTIVE,
            provider: "https://api.infomaniak.com/",
            profile: "P0",
            local: false,
        };
        let error = execute(&input).unwrap_err();
        assert!(
            error.message.contains("not allowed in EU"),
            "{}",
            error.message
        );
        assert_eq!(error.events[0].decision, "deny");
        assert!(error.events.iter().all(|event| event.decision != "allow"));

        struct NeverApprove;
        impl super::ApprovalChannel for NeverApprove {
            fn decide(
                &self,
                _: &super::ApprovalRequest,
                _: &str,
            ) -> super::approval::ApprovalDecision {
                panic!("approval called before destination preflight")
            }
        }
        let approval = NeverApprove;
        for region in [Some("CH"), None] {
            let mismatched = RunInput {
                provider: "https://api.openai.com",
                region,
                approval: &approval,
                ..input
            };
            let error = execute(&mismatched).unwrap_err();
            assert!(
                error.message.contains("destination residency is unknown"),
                "{}",
                error.message
            );
            assert_eq!(error.events.last().unwrap().decision, "deny");
        }
    }

    #[test]
    fn two_egress_steps_that_share_a_capability_get_distinct_report_ids() {
        let plan = serde_json::json!({
            "v": "0.1",
            "steps": [
                {
                    "id": "first",
                    "kind": "call",
                "approval": true,
                    "capability": "urn:sidged:capability:message.send",
                    "args": { "body": { "lit": "a" } }
                },
                {
                    "id": "second",
                    "kind": "call",
                "approval": true,
                    "capability": "urn:sidged:capability:message.send",
                    "args": { "body": { "lit": "b" } }
                }
            ]
        });
        let catalog = serde_json::json!([{
            "id": "urn:sidged:capability:message.send",
            "effects": ["egress"],
            "data_classes": ["communications.content"],
            "consequential": true,
            "residency": {"tags": ["unrestricted"]},
            "cost": { "class": "free" }
        }]);
        let grant = signed_grant(&[("message.send", "urn:sidged:capability:message.send")]);
        let mut input = hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            Some(&grant),
        );
        let yes = FixedApproval {
            granted: true,
            actor: "tester".into(),
        };
        input.approval = &yes;
        let report = execute(&input).unwrap();
        assert_eq!(report.reports.len(), 2);
        let first: serde_json::Value = serde_json::from_str(&report.reports[0]).unwrap();
        let second: serde_json::Value = serde_json::from_str(&report.reports[1]).unwrap();
        assert_ne!(first["id"], second["id"]);
        assert_ne!(
            first["minimisation"]["payload_digest"],
            second["minimisation"]["payload_digest"]
        );
        assert_eq!(
            first["sent"]["bytes"],
            serde_json::to_vec(&plan["steps"][0]["args"]).unwrap().len()
        );
        assert_eq!(first["payload_binding"], "proposed-arguments");
        assert!(first["provider_profile"]["effective"].is_null());
    }

    #[test]
    fn an_unknown_provider_profile_is_refused() {
        let plan = serde_json::json!({
            "v": "0.1",
            "steps": [{
                "id": "send",
                "kind": "call",
                "approval": true,
                "capability": "urn:sidged:capability:message.send",
                "args": { "body": { "lit": "a" } }
            }]
        });
        let catalog = serde_json::json!([{
            "id": "urn:sidged:capability:message.send",
            "effects": ["egress"],
            "data_classes": ["communications.content"],
            "consequential": true,
            "residency": {"tags": ["unrestricted"]},
            "cost": { "class": "free" }
        }]);
        let grant = signed_grant(&[("message.send", "urn:sidged:capability:message.send")]);
        let mut input = hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            Some(&grant),
        );
        input.profile = "P9";
        let error = execute(&input).unwrap_err();
        assert!(error.message.contains("P0-P3"), "{}", error.message);
        assert!(error.events.iter().all(|event| event.decision == "deny"));
    }

    #[test]
    fn destination_preflight_precedes_approval() {
        struct Never;
        impl crate::ApprovalChannel for Never {
            fn decide(
                &self,
                _: &super::ApprovalRequest,
                _: &str,
            ) -> crate::approval::ApprovalDecision {
                panic!("approval before preflight");
            }
        }
        let plan = serde_json::json!({ "v": "0.1", "steps": [
            { "id": "first", "kind": "call", "capability": "urn:sidged:capability:message.send", "approval": true, "args": {} }
        ] });
        let catalog = serde_json::json!([{ "id": "urn:sidged:capability:message.send", "effects": ["egress"],
            "data_classes": ["communications.content"], "consequential": true, "residency": {"tags": ["unrestricted"]}, "cost": {"class": "free"} }]);
        let grant = signed_grant(&[("message.send", "urn:sidged:capability:message.send")]);
        let mut input = hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            Some(&grant),
        );
        input.approval = &Never;
        input.profile = "unknown";
        let error = execute(&input).unwrap_err();
        assert!(error.message.contains("P0-P3"), "{}", error.message);
    }

    #[test]
    fn local_egress_is_refused_and_audited() {
        let plan = serde_json::json!({
            "v": "0.1",
            "steps": [{
                "id": "send",
                "kind": "call",
                "approval": true,
                "capability": "urn:sidged:capability:message.send",
                "args": { "body": { "lit": "a" } }
            }]
        });
        let catalog = serde_json::json!([{
            "id": "urn:sidged:capability:message.send",
            "effects": ["egress"],
            "data_classes": ["communications.content"],
            "consequential": true,
            "residency": {"tags": ["unrestricted"]},
            "cost": { "class": "free" }
        }]);
        let grant = signed_grant(&[("message.send", "urn:sidged:capability:message.send")]);
        let mut input = hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            Some(&grant),
        );
        // Spec 0007 R2: the real execute entry point cannot override the environment.
        if std::env::var_os("EXECUTE_LOCAL_CHILD").is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::local_egress_is_refused_and_audited"])
                .env("EXECUTE_LOCAL_CHILD", "1")
                .env("SIDGED_LOCAL", "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        input.local = false;
        let error = execute(&input).unwrap_err();
        assert!(error.message.contains("local mode"), "{}", error.message);
        assert_eq!(error.events.len(), 1);
        assert!(error.events.iter().all(|event| event.decision == "deny"));
    }

    #[test]
    fn a_consequential_step_is_denied_without_a_person() {
        let plan = serde_json::json!({
            "v": "0.1",
            "steps": [{
                "id": "send",
                "kind": "call",
                "capability": "urn:sidged:capability:message.send",
                "approval": true,
                "args": { "body": { "lit": "hi" } }
            }]
        });
        let catalog = serde_json::json!([{
            "id": "urn:sidged:capability:message.send",
            "effects": ["egress"],
            "data_classes": ["communications.content"],
            "consequential": true,
            "residency": {"tags": ["unrestricted"]},
            "cost": { "class": "free" }
        }]);
        let grant = signed_grant(&[("message.send", "urn:sidged:capability:message.send")]);
        let error = execute(&hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            Some(&grant),
        ))
        .unwrap_err();
        assert!(
            error.message.contains("approval denied"),
            "{}",
            error.message
        );
        assert_eq!(error.events.len(), 1);
        assert_eq!(error.events[0].decision, "deny");
        assert_eq!(error.events[0].actor, "non-interactive");
        assert_eq!(error.events[0].at, NOW);
        assert!(error.events.iter().all(|event| event.decision != "allow"));

        struct BadResponse(&'static str);
        impl super::ApprovalChannel for BadResponse {
            fn decide(
                &self,
                request: &super::ApprovalRequest,
                now: &str,
            ) -> super::approval::ApprovalDecision {
                let mut echo = request.clone();
                match self.0 {
                    "step" => echo.step = "other".into(),
                    "capability" => echo.capability = "other".into(),
                    "args digest" => echo.args_digest = "wrong".into(),
                    "nonce" => echo.nonce = "used-nonce".into(),
                    _ => {}
                }
                let line = if self.0 == "timeout" {
                    String::new()
                } else {
                    format!(
                        "approve ada {} {} {} {} {}\n",
                        echo.step, echo.capability, echo.args_digest, echo.nonce, echo.plan_digest
                    )
                };
                super::approval::decide_from_lines(&line, request, now).0
            }
        }
        for case in ["step", "capability", "args digest", "nonce", "timeout"] {
            let channel = BadResponse(case);
            let mut input = hosted(
                &plan,
                &catalog,
                "permit(principal, action, resource);",
                Some(&grant),
            );
            input.approval = &channel;
            let error = execute(&input).unwrap_err();
            let event = error.events.last().unwrap();
            assert_eq!(event.decision, "deny");
            let reason = event.reason.as_deref().unwrap();
            assert!(
                reason.contains(if case == "nonce" { "timeout" } else { case }),
                "{reason}"
            );
            assert!(reason.contains("args_sha256="), "{reason}");
            assert!(!reason.contains("nonce="), "{reason}");
        }
    }

    #[test]
    fn a_second_step_is_denied_when_the_message_budget_is_spent() {
        let plan = serde_json::json!({
            "v": "0.1",
            "steps": [
                {
                    "id": "one",
                    "kind": "call",
                    "capability": "urn:sidged:capability:calendar.free_slots",
                    "args": { "range": { "lit": "a" } }
                },
                {
                    "id": "two",
                    "kind": "call",
                    "capability": "urn:sidged:capability:calendar.free_slots",
                    "args": { "range": { "lit": "b" } }
                }
            ]
        });
        let catalog = serde_json::json!([{
            "id": "urn:sidged:capability:calendar.free_slots",
            "effects": ["read"],
            "data_classes": ["calendar.availability"],
            "consequential": false,
            "residency": {"tags": ["unrestricted"]},
            "cost": { "class": "free" }
        }]);
        let owner = party("rfc8032-test-1");
        let holder = party("rfc8032-test-2");
        let grant = sidged_grant::attach_signature(
            &serde_json::json!({
                "v": "0.1",
                "id": "tok-budget-0001",
                "iss": owner.did,
                "sub": holder.did,
                "aud": "did:example:hosted",
                "iat": "2026-10-14T12:00:00Z",
                "exp": "2026-10-14T12:30:00Z",
                "cnf": { "kid": holder.did, "jkt": holder.jkt },
                "rights": [{ "action": "calendar.free_slots", "resource": "urn:sidged:capability:calendar.free_slots" }],
                "budget": { "messages": 1 },
                "chain": []
            }),
            &owner.seed,
            &owner.did,
        );
        let error = execute(&hosted(
            &plan,
            &catalog,
            "permit(principal, action, resource);",
            Some(&grant),
        ))
        .unwrap_err();
        assert!(error.message.contains("grant budget"), "{}", error.message);
        assert_eq!(error.events.len(), 2);
        assert_eq!(error.events[0].decision, "allow");
        assert_eq!(error.events[0].step, "one");
        assert_eq!(error.events[1].decision, "deny");
        assert_eq!(error.events[1].step, "two");
    }

    #[test]
    fn run_requires_a_policy_file() {
        if std::env::var_os("LOCAL_ISOLATED").is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::run_requires_a_policy_file"])
                .env("LOCAL_ISOLATED", "1")
                .env_remove("SIDGED_LOCAL")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let error =
            parse_run_args(["run".into(), "plan.json".into(), "catalog.json".into()]).unwrap_err();
        assert!(error.contains("--policy"));
        let parsed = parse_run_args([
            "run".into(),
            "plan.json".into(),
            "catalog.json".into(),
            "--policy".into(),
            "policy.cedar".into(),
            "--grant".into(),
            "grant.json".into(),
            "--trusted-issuer".into(),
            "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw".into(),
            "--audience".into(),
            "did:example:ch-residency".into(),
            "--now".into(),
            "2026-10-14T12:10:00Z".into(),
            "--provider".into(),
            "https://api.example".into(),
            "--profile".into(),
            "P2".into(),
            "--local".into(),
        ])
        .unwrap();
        assert_eq!(parsed.policy, "policy.cedar");
        assert_eq!(parsed.grant, "grant.json");
        assert_eq!(
            parsed.trusted_issuers,
            vec!["did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw".to_string()]
        );
        assert_eq!(parsed.now.as_deref(), Some("2026-10-14T12:10:00Z"));
        assert_eq!(parsed.audience, "did:example:ch-residency");
        assert_eq!(parsed.provider, "https://api.example");
        assert_eq!(parsed.profile, "P2");
        assert!(parsed.local);
        let missing = parse_run_args([
            "run".into(),
            "plan.json".into(),
            "catalog.json".into(),
            "--policy".into(),
            "policy.cedar".into(),
        ])
        .unwrap_err();
        assert!(missing.contains("--grant"));
    }

    /// 0003 R1, R6: `sidged run` reads the plan with the verifier's parser, so a
    /// shape the verifier would not accept is refused, never filled in with a default.
    #[test]
    fn the_run_path_refuses_what_the_verifier_parser_refuses() {
        let catalog = serde_json::json!([
            {
                "id": "urn:sidged:capability:calendar.free_slots",
                "effects": ["read"],
                "data_classes": ["calendar.availability"],
                "consequential": false,
                "residency": {"tags": ["unrestricted"]},
                "cost": { "class": "free" }
            },
            {
                "id": "urn:sidged:capability:web.lookup",
                "effects": ["read"],
                "data_classes": [],
                "consequential": false,
                "residency": {"tags": ["unrestricted"]},
                "cost": { "class": "metered", "max": { "amount": "0.01", "currency": "CHF" } }
            }
        ]);
        let plan = serde_json::json!({
            "v": "0.1",
            "budget": { "max": { "amount": "0.10", "currency": "CHF" } },
            "steps": [
                {"id": "free", "kind": "call",
                 "capability": "urn:sidged:capability:calendar.free_slots",
                 "args": {"range": {"lit": "next_week"}}},
                {"id": "pick", "kind": "expr", "expr": "free.slots"},
                {"id": "look", "kind": "map", "over": {"ref": "free"}, "bound": 2,
                 "capability": "urn:sidged:capability:web.lookup",
                 "args": {"q": {"item": true}}}
            ]
        });
        super::check_plan(&plan, &catalog).unwrap();

        let mut version = plan.clone();
        version["v"] = serde_json::json!("0.2");
        let mut no_expr = plan.clone();
        no_expr["steps"][1].as_object_mut().unwrap().remove("expr");
        let mut wide_bound = plan.clone();
        wide_bound["steps"][2]["bound"] = serde_json::json!(4_294_967_297u64);
        let mut no_amount = plan.clone();
        no_amount["budget"]["max"]
            .as_object_mut()
            .unwrap()
            .remove("amount");
        let mut over_field = plan.clone();
        over_field["steps"][2]["over"] = serde_json::json!({"ref": "free", "field": "slots"});
        for (name, bad) in [
            ("v 0.2", version),
            ("expr step without expr", no_expr),
            ("bound 4294967297", wide_bound),
            ("budget without amount", no_amount),
            ("map over with a field", over_field),
        ] {
            assert!(super::check_plan(&bad, &catalog).is_err(), "{name}");
        }
    }
}
