//! CH residency scenario.
//!
//! A test web app is a set of MCP capabilities. A planner proposes a plan.
//! The runtime checks Cedar and declared residency constraints, and writes a privacy report for egress.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use vaikor_cli::engine::{HolderKey, Presenter};
use vaikor_cli::{execute_with_chain, ApprovalChannel, RunInput};
use vaikor_core::AuditEvent;
use vaikor_grant::{add_rfc3339_z, attach_signature, did_key, format_rfc3339_z, jwk_thumbprint};
use vaikor_log::Chain;
use vaikor_model::Planner;

#[derive(Clone, Copy)]
pub struct LogTarget<'a> {
    pub path: &'a Path,
    pub seed: &'a [u8; 32],
}

#[derive(Debug)]
pub struct GuardReport {
    pub capabilities: usize,
    pub approvals: usize,
    pub privacy_reports: usize,
    pub audit_events: usize,
    pub residency: Vec<String>,
    pub events: Vec<AuditEvent>,
}

// The hosted prompt includes the entire catalog. Preserve every declared restriction.
fn planner_residency(dir: &Path) -> Result<Vec<String>, String> {
    let catalog: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(dir.join("tools.json")).map_err(|err| err.to_string())?,
    )
    .map_err(|err| err.to_string())?;
    let registry = vaikor_mcp::registry_from_tools(&catalog)?;
    let mut inputs = Vec::new();
    for tool in catalog["tools"].as_array().ok_or("missing tools")? {
        let id = tool["_meta"]["com.vaikor/capability"]["id"]
            .as_str()
            .ok_or("missing id")?;
        inputs.push(
            registry
                .get(id)
                .ok_or("missing capability")?
                .residency
                .clone(),
        );
    }
    vaikor_core::derive_residency(&inputs)
}

#[cfg(test)]
#[test]
fn planner_catalog_preserves_swiss_restrictions_and_allows_public_weather() {
    let demos = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../demo");
    assert_eq!(
        planner_residency(&demos.join("ch-residency")).unwrap(),
        vec!["CH"]
    );
    assert_eq!(
        planner_residency(&demos.join("public-weather")).unwrap(),
        vec!["unrestricted"]
    );
}

pub fn run_from_env(
    dir: &Path,
    provider: &str,
    base_url: Option<&str>,
    model: Option<&str>,
    api_key: Option<&str>,
    approval: &dyn ApprovalChannel,
    log: Option<LogTarget<'_>>,
) -> Result<GuardReport, String> {
    run_from_env_with_keys(dir, provider, base_url, model, api_key, approval, log, None)
}

/// Planner for the local model endpoint (0004 R9d).
struct LocalPlanner {
    model: vaikor_gateway::local_model::LocalModel,
    name: String,
}

impl Planner for LocalPlanner {
    fn is_local_model(&self) -> bool {
        true
    }
    fn start_note(&self) -> Option<String> {
        self.model.endpoint().risk_note()
    }
    fn plan(&self, prompt: &str) -> Result<String, String> {
        let body = serde_json::json!({
            "model": self.name,
            "messages": [{"role": "user", "content": prompt}],
        });
        let reply: serde_json::Value =
            serde_json::from_str(&self.model.complete(&body.to_string())?)
                .map_err(|_| "local model: reply is not JSON".to_string())?;
        reply["choices"][0]["message"]["content"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| "local model: reply has no choices[0].message.content".into())
    }
}

#[allow(clippy::too_many_arguments)] // public entry point; signature kept stable
pub fn run_from_env_with_keys(
    dir: &Path,
    provider: &str,
    base_url: Option<&str>,
    model: Option<&str>,
    api_key: Option<&str>,
    approval: &dyn ApprovalChannel,
    log: Option<LogTarget<'_>>,
    keys: Option<&Path>,
) -> Result<GuardReport, String> {
    let credential = api_key
        .filter(|key| !key.is_empty())
        .map(vaikor_gateway::KeySource::fixed);
    run_from_env_with_credential(
        dir, provider, base_url, model, credential, approval, log, keys,
    )
}

/// Guard with a planner credential **reference** (0007 R10a). The key is not
/// read here: the gateway reads it at send time, after the §5 order (local
/// latch, audit log lock, destination check, grant and reservation, approval,
/// signed intent). A run refused before that never opens the key file.
#[allow(clippy::too_many_arguments)]
pub fn run_from_env_with_credential(
    dir: &Path,
    provider: &str,
    base_url: Option<&str>,
    model: Option<&str>,
    credential: Option<vaikor_gateway::KeySource>,
    approval: &dyn ApprovalChannel,
    log: Option<LogTarget<'_>>,
    keys: Option<&Path>,
) -> Result<GuardReport, String> {
    let config: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(dir.join("config.json")).map_err(|err| err.to_string())?,
    )
    .map_err(|err| err.to_string())?;
    let local = resolve_local(&config)?;
    let chain = open_log(log)?;
    let planner: Box<dyn Planner> = match provider {
        "stub" | "" => {
            let document =
                fs::read_to_string(dir.join("stub-plan.json")).map_err(|err| err.to_string())?;
            Box::new(vaikor_model::StubPlanner { document })
        }
        "openai" => {
            let base_url =
                base_url.ok_or("VAIKOR_BASE_URL is required for the OpenAI-compatible provider")?;
            let model = model
                .unwrap_or(
                    config["model"]
                        .as_str()
                        .or(config["model"]["name"].as_str())
                        .unwrap_or("apertus"),
                )
                .to_string();
            let mut planner = vaikor_model::OpenAiPlanner::new(
                base_url,
                model,
                None,
                planner_residency(dir)?,
                config["provider_region"]
                    .as_str()
                    .ok_or("provider_region is required")?,
                config["provider_id"]
                    .as_str()
                    .ok_or("provider_id is required")?,
            )
            .without_retries();
            if planner.provider_project.is_none() {
                planner.provider_project = config["provider_project"].as_str().map(str::to_string);
            }
            planner.credential = credential;
            planner.local = local;
            planner.profile = config["provider_profile"]
                .as_str()
                .unwrap_or("P0")
                .to_string();
            Box::new(planner)
        }
        // 0004 R9d: local mode's only model is the statically configured
        // endpoint (AF_UNIX + SO_PEERCRED by default). Its reply is an
        // untrusted plan: verify, grant, Cedar and approval still apply.
        "local" => {
            if !local {
                return Err(
                    "provider local requires local mode (VAIKOR_LOCAL=1, --local or config local)"
                        .into(),
                );
            }
            let endpoint = vaikor_gateway::local_model::model_endpoint(&config)?
                .ok_or("provider local requires config model.endpoint")?;
            Box::new(LocalPlanner {
                model: vaikor_gateway::local_model::LocalModel::new(endpoint),
                name: model
                    .unwrap_or(
                        config["model"]
                            .as_str()
                            .or(config["model"]["name"].as_str())
                            .unwrap_or("local"),
                    )
                    .to_string(),
            })
        }
        #[cfg(test)]
        "reporting-test" => Box::new(tests::ReportingFixture {
            document: fs::read_to_string(dir.join("stub-plan.json"))
                .map_err(|err| err.to_string())?,
            called: false.into(),
        }),
        other => return Err(format!("unknown provider {other}")),
    };
    run_prepared(
        dir,
        planner.as_ref(),
        approval,
        chain,
        local,
        log,
        keys,
        None,
    )
}

pub fn run_dir(
    dir: &Path,
    planner: &dyn Planner,
    approval: &dyn ApprovalChannel,
    log: Option<LogTarget<'_>>,
) -> Result<GuardReport, String> {
    run_dir_presented(dir, planner, approval, log, None)
}

/// [`run_dir`] with another presenter than the holder key the grant names: the tests of
/// proof of possession (0002 R25) present with a wrong key, for another plan, or a replay.
fn run_dir_presented(
    dir: &Path,
    planner: &dyn Planner,
    approval: &dyn ApprovalChannel,
    log: Option<LogTarget<'_>>,
    presenter: Option<&dyn Presenter>,
) -> Result<GuardReport, String> {
    let config: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(dir.join("config.json")).map_err(|err| err.to_string())?,
    )
    .map_err(|err| err.to_string())?;
    let local = resolve_local(&config)?;
    let chain = open_log(log)?;
    run_prepared(dir, planner, approval, chain, local, log, None, presenter)
}

fn open_log(log: Option<LogTarget<'_>>) -> Result<Option<Chain>, String> {
    let target = log.ok_or("guard requires a signed audit log target and key")?;
    eprintln!("audit log: {}", target.path.display());
    Chain::open(target.path, target.seed).map(Some)
}

#[allow(clippy::too_many_arguments)]
fn run_prepared(
    dir: &Path,
    planner: &dyn Planner,
    approval: &dyn ApprovalChannel,
    mut chain: Option<Chain>,
    local: bool,
    log: Option<LogTarget<'_>>,
    keys: Option<&Path>,
    presenter: Option<&dyn Presenter>,
) -> Result<GuardReport, String> {
    let result = run_prepared_inner(
        dir, planner, approval, &mut chain, local, log, keys, presenter,
    );
    // 0004 R9: stop the listener, then audit every SO_PEERCRED rejection
    // on every exit path (planner errors and invalid plans included).
    approval.shutdown();
    // The result store may have taken and released the shared chain.
    if chain.is_none() {
        chain = open_log(log)?;
    }
    if let Some(chain) = chain.as_mut() {
        vaikor_cli::standing::check_revocations(chain, approval, &utc_now())?;
        vaikor_cli::audit_rejected_peers(approval, chain, "approval", &utc_now())?;
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn run_prepared_inner(
    dir: &Path,
    planner: &dyn Planner,
    approval: &dyn ApprovalChannel,
    chain: &mut Option<Chain>,
    local: bool,
    log: Option<LogTarget<'_>>,
    keys: Option<&Path>,
    presenter: Option<&dyn Presenter>,
) -> Result<GuardReport, String> {
    let history_len = chain
        .as_mut()
        .map(|chain| chain.read_events())
        .transpose()?
        .unwrap_or_default()
        .len();
    let catalog_text = fs::read_to_string(dir.join("tools.json")).map_err(|err| err.to_string())?;
    let catalog: serde_json::Value =
        serde_json::from_str(&catalog_text).map_err(|err| err.to_string())?;
    let policy = fs::read_to_string(dir.join("policy.cedar")).map_err(|err| err.to_string())?;
    let config: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(dir.join("config.json")).map_err(|err| err.to_string())?,
    )
    .map_err(|err| err.to_string())?;
    resolve_local(&config)?;
    let audience = config["audience"]
        .as_str()
        .unwrap_or("did:example:ch-residency");
    let provider_id = config["provider_id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .ok_or("provider_id is required")?;
    let region = config["provider_region"].as_str().unwrap_or("");
    let example = fs::read_to_string(dir.join("stub-plan.json")).unwrap_or_default();
    let task = config["task"]
        .as_str()
        .unwrap_or("moderate comment c1 and start monitoring.");
    // Interpolate task as a value so literal braces remain unchanged.
    let prompt = format!(
        "You plan actions for this scenario. Reply with ONLY a JSON plan document, no prose, no code fences.\n\
         Format (Vaikor plan v0.1), example:\n{example}\n\
         Use only capabilities from this catalog:\n{catalog_text}\n\
         The plan MUST include an outbound step whose capability is tag:vaikor.com,2026:capability:model.complete. \
         That egress is what produces the privacy report and the residency tag.\n\
         Task: {task}"
    );
    if let Err(error) = planner.preflight(&prompt) {
        chain
            .as_mut()
            .ok_or("planner requires audit")?
            .append(&planner_event("deny", Some(error.clone())))?;
        return Err(error);
    }
    let before = planner.reports().len();
    let mut reservation_denied = false;
    let authorization = (|| {
        let now = utc_now();
        let (grant, holder) = presented_grant_with_keys(dir, audience, &now, keys)?;
        let trusted = vec![grant["iss"].as_str().ok_or("grant issuer")?.to_owned()];
        let trusted_refs: Vec<&str> = trusted.iter().map(String::as_str).collect();
        let planner_plan = serde_json::json!({"v":"0.1", "steps":[{
            "id":"planner", "kind":"call", "capability":"tag:vaikor.com,2026:capability:model.complete",
            "approval":true, "args":{"prompt":{"lit":prompt}}
        }]});
        // 0004 R9d: the local model is not egress; only the remote planner
        // call needs the egress reservation (and its approval).
        let holder = HolderKey::new(holder);
        if planner.is_local_model() {
            return Ok::<_, String>((trusted, grant, holder));
        }
        vaikor_cli::reserve_planner(
            &RunInput {
                audit: None,
                dry_run: false,
                plan: &planner_plan,
                catalog: &catalog,
                policy: &policy,
                audience,
                grant: Some(&grant),
                holder: Some(presenter.unwrap_or(&holder)),
                now: Some(&now),
                region: Some(region),
                trusted_issuers: &trusted_refs,
                approval,
                provider: provider_id,
                profile: config["provider_profile"].as_str().unwrap_or("P0"),
                local,
            },
            planner.destination().as_deref().unwrap_or(provider_id),
            chain,
        )
        .map_err(|e| {
            reservation_denied = !e.events.is_empty();
            e.message
        })?;
        Ok::<_, String>((trusted, grant, holder))
    })();
    let (trusted, grant, holder) = match authorization {
        Ok(value) => value,
        Err(error) => {
            if !reservation_denied {
                if let Some(chain) = chain.as_mut() {
                    chain.append(&planner_event("deny", Some(error.clone())))?;
                }
            }
            return Err(error);
        }
    };
    let mut standing_binding = None;
    // 0007 R8c: the Core fixes the task type, never the model text.
    if !planner.is_local_model() && planner.destination().is_some() {
        let now = utc_now();
        let planner_plan = serde_json::json!({"v":"0.1", "steps":[{
            "id":"planner", "kind":"call", "capability":"tag:vaikor.com,2026:capability:model.complete",
            "approval":true, "args":{"prompt":{"lit":prompt}}
        }]});
        let request = vaikor_cli::ApprovalRequest::new(
            &vaikor_cli::plan_digest(&planner_plan)?,
            "planner",
            "tag:vaikor.com,2026:capability:model.complete",
            &planner_plan["steps"][0]["args"],
        )?;
        let expiry = grant["exp"].as_str().ok_or("grant expiry")?;
        // Strict default: one call when the grant declares no message count.
        let calls = grant["budget"]["messages"].as_u64().unwrap_or(1).max(1);
        let scope = serde_json::json!({"standing":true,"provider":provider_id,"task_type":"planner",
            "limit":{"calls":calls},"expiry":expiry});
        standing_binding = vaikor_cli::standing::authorize_planner(
            chain.as_mut().ok_or("planner requires audit")?,
            approval,
            request,
            &scope,
            grant["iss"].as_str().ok_or("grant owner")?,
            expiry,
            &now,
        )?;
    }
    if let (Some(note), Some(chain)) = (planner.start_note(), chain.as_mut()) {
        eprintln!("warning: {note}");
        chain.append(&AuditEvent {
            usage: None,
            reason: Some(note),
            privacy_report: None,
            step: "planner".into(),
            capability: "tag:vaikor.com,2026:capability:model.complete".into(),
            effects: Vec::new(),
            data_classes: Vec::new(),
            decision: "allow".into(),
            actor: "core".into(),
            at: utc_now(),
            approval: None,
        })?;
    }
    if !planner.is_local_model() && planner.destination().is_some() {
        let payload = planner
            .request_body(&prompt)
            .ok_or("planner request body unavailable")?;
        let tags = planner_residency(dir)?;
        // Core input roles: task text is a query; scenario catalog and example
        // are documents. This path reads no data Records or model-supplied classes.
        let checked =
            vaikor_gateway::egress_check::egress_check(&vaikor_gateway::egress_check::Check::new(
                provider_id,
                region,
                &["query", "documents.text"],
                &tags,
                &payload,
            ));
        let mut record = checked.record;
        record["standing_approval_digest"] = standing_binding
            .as_ref()
            .map(|b| b["approval_digest"].clone())
            .unwrap_or(serde_json::Value::Null);
        record["scope_digest"] = standing_binding
            .as_ref()
            .map(|b| b["scope_digest"].clone())
            .unwrap_or(serde_json::Value::Null);
        record["subscription_reference"] = serde_json::Value::Null;
        let mut event = planner_event(
            if checked.refusal.is_some() {
                "deny"
            } else {
                "permit"
            },
            checked.refusal.clone(),
        );
        event.privacy_report = Some(record.to_string());
        chain
            .as_mut()
            .ok_or("planner requires audit")?
            .append(&event)?;
        if let Some(reason) = checked.refusal {
            return Err(reason);
        }
    }
    let intent = planner_event("attempt", None);
    if let Some(chain) = chain.as_mut() {
        chain.append(&intent)?;
    }
    if !planner.is_local_model()
        && planner.destination().is_some()
        && vaikor_cli::standing::check_revocations(
            chain.as_mut().ok_or("planner requires audit")?,
            approval,
            &utc_now(),
        )?
    {
        return Err("planner standing approval revoked".into());
    }
    let planned = planner.plan_checked(&prompt);
    let now = utc_now();
    // Read reports even when planning fails (including HTTP and parse failures).
    let mut planner_events = Vec::new();
    for document in planner.reports().into_iter().skip(before) {
        planner_events.push(AuditEvent {
            usage: None,
            reason: None,
            privacy_report: Some(document),
            step: "planner".into(),
            capability: "tag:vaikor.com,2026:capability:model.complete".into(),
            effects: vec!["egress".into()],
            data_classes: vec!["communications.content".into()],
            decision: "privacy-report".into(),
            actor: "gateway".into(),
            at: utc_now(),
            approval: None,
        });
    }
    let planner_report_count = planner_events.len();
    if let Err(error) = &planned {
        planner_events.push(AuditEvent {
            usage: None,
            reason: Some(
                if error.kind == vaikor_gateway::EgressErrorKind::Credential {
                    "credential-unavailable"
                } else {
                    "planner-failed"
                }
                .into(),
            ),
            privacy_report: None,
            step: "planner".into(),
            capability: "tag:vaikor.com,2026:capability:model.complete".into(),
            effects: vec!["egress".into()],
            data_classes: vec!["communications.content".into()],
            decision: "deny".into(),
            actor: "core".into(),
            at: utc_now(),
            approval: None,
        });
    }
    if let Some(chain) = chain.as_mut() {
        for event in &planner_events {
            chain.append(event)?;
        }
    }
    let plan_text = planned.map_err(|error| error.message)?;
    let plan_text = strip_fences(&plan_text);
    let checked = serde_json::from_str(plan_text)
        .map_err(|err| format!("planner did not return plan JSON: {err}"))
        .and_then(|plan| {
            vaikor_cli::check_plan(&plan, &catalog)?;
            Ok(plan)
        });
    let plan: serde_json::Value = match checked {
        Ok(plan) => plan,
        Err(error) => {
            if let Some(chain) = chain.as_mut() {
                chain.append(&planner_event("deny", Some(error.clone())))?;
            }
            return Err(error);
        }
    };
    let trusted_refs: Vec<&str> = trusted.iter().map(String::as_str).collect();
    let executed = execute_with_chain(
        &RunInput {
            audit: None,
            dry_run: false,
            plan: &plan,
            catalog: &catalog,
            policy: &policy,
            audience,
            grant: Some(&grant),
            holder: Some(presenter.unwrap_or(&holder)),
            now: Some(&now),
            region: Some(region),
            trusted_issuers: &trusted_refs,
            approval,
            provider: provider_id,
            profile: config["provider_profile"].as_str().unwrap_or("P0"),
            local,
        },
        chain,
    );
    let report = executed.map_err(|err| err.message)?;
    let residency = report
        .reports
        .first()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
        .map(|document| {
            document["residency"]["tags"]
                .as_array()
                .map(|tags| {
                    tags.iter()
                        .filter_map(|tag| tag.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        })
        .unwrap_or_default();
    planner_events.insert(0, intent);
    planner_events.extend(report.events);
    // Include the shared ledger's reservation entries in the returned audit view.
    if let Some(chain) = chain.as_mut() {
        planner_events = chain.read_events()?.into_iter().skip(history_len).collect();
    }
    if config["record_result"] == true {
        let target = log.ok_or("record result requires log key")?;
        // Release the plan ledger before handing the same chain to the store.
        drop(chain.take());
        let root = record_store_path(None)?;
        eprintln!("record store: {}", root.display());
        let mut store = vaikor_record::store::Store::open_with_log(
            &root,
            target.path,
            target.seed,
            record_anchors(&config)?,
        )?;
        let cedar = vaikor_grant::CedarEvaluator::parse(&policy).map_err(|e| e.to_string())?;
        let access = vaikor_record::store::Access {
            grant: Some(&grant),
            holder: grant["sub"].as_str().ok_or("grant holder")?,
            audience,
            policy: &cedar,
        };
        // These are Core execution observations, never labels proposed by the planner.
        let registry = vaikor_mcp::registry_from_tools(&catalog)?;
        let mut labels = Vec::new();
        for id in &report.capabilities {
            let cap = registry.get(id).ok_or("missing executed capability")?;
            for class in &cap.data_classes {
                labels.push((class.clone(), cap.residency.clone()));
            }
        }
        let (class, tags) = vaikor_record::derive_record_labels(&labels)?;
        let results = report
            .results
            .iter()
            .map(|(step, value)| {
                serde_json::from_str::<serde_json::Value>(value).map(|value| (step.clone(), value))
            })
            .collect::<Result<serde_json::Map<String, serde_json::Value>, _>>()
            .map_err(|e| e.to_string())?;
        let result = serde_json::json!({"capabilities":report.capabilities,"privacy_reports":report.reports,"results":results});
        let value = serde_json::json!({"v":"0.1","type":"application/vnd.vaikor.execution+json","class":class,
            "owner":null,"provenance":{"source":null,"created":null,"derived_from":[],"plan":null},
            "residency":{"tags":tags},"retention":{"until":null,"on_expiry":"delete"},"content":result});
        let plan_digest =
            serde_json::json!(vaikor_record::digest(&plan).map_err(|e| e.to_string())?);
        let core = vaikor_grant::did_key(&vaikor_log::public_key(target.seed));
        let initial = store.begin_step(&core, plan_digest.clone());
        let source = store.write(value.clone(), &initial, &access)?;
        let mut reads = store.begin_step(&core, plan_digest);
        store.read(&mut reads, &source, &access)?;
        let mut derived = value;
        derived["type"] = serde_json::json!("application/vnd.vaikor.weather-result+json");
        let digest = store.write(derived, &reads, &access)?;
        eprintln!("result record: {digest}");
        planner_events = store
            .audit_events()?
            .into_iter()
            .skip(history_len)
            .collect();
    }
    Ok(GuardReport {
        capabilities: report.capabilities.len(),
        approvals: report.approvals.len(),
        privacy_reports: planner_report_count + report.reports.len(),
        audit_events: planner_events.len(),
        residency,
        events: planner_events,
    })
}

fn resolve_local(config: &serde_json::Value) -> Result<bool, String> {
    let local = match config.get("local") {
        None => false,
        Some(serde_json::Value::Bool(value)) => *value,
        _ => return Err("config.local must be a boolean".into()),
    };
    vaikor_gateway::resolve_local(local)
}

fn planner_event(decision: &str, reason: Option<String>) -> AuditEvent {
    AuditEvent {
        privacy_report: None,
        usage: None,
        reason,
        step: "planner".into(),
        capability: "tag:vaikor.com,2026:capability:model.complete".into(),
        effects: vec!["egress".into()],
        data_classes: vec!["communications.content".into()],
        decision: decision.into(),
        actor: "core".into(),
        at: utc_now(),
        approval: None,
    }
}

fn strip_fences(text: &str) -> &str {
    let t = text.trim();
    let t = t
        .strip_prefix("```json")
        .or_else(|| t.strip_prefix("```"))
        .unwrap_or(t);
    t.strip_suffix("```").unwrap_or(t).trim()
}

fn record_anchors(config: &serde_json::Value) -> Result<Vec<String>, String> {
    match config.get("record_anchors") {
        None => Ok(Vec::new()),
        Some(value) => value
            .as_array()
            .ok_or("config record_anchors must be an array")?
            .iter()
            .map(|item| {
                let key = item
                    .as_str()
                    .ok_or("config record_anchors must contain did:key strings")?;
                vaikor_grant::resolve_did_key(key).map_err(|e| e.to_string())?;
                Ok(key.to_owned())
            })
            .collect(),
    }
}

#[test]
fn record_anchors_are_independent_of_grant_issuers() {
    let key = vaikor_grant::did_key(&vaikor_log::public_key(&[42; 32]));
    assert!(
        record_anchors(&serde_json::json!({"trusted_issuers": [key]}))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        record_anchors(&serde_json::json!({"record_anchors": [key]})).unwrap(),
        vec![key]
    );
    assert!(record_anchors(&serde_json::json!({"record_anchors": [42]})).is_err());
}

fn utc_now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    format_rfc3339_z(seconds)
}

#[cfg(test)]
fn presented_grant(dir: &Path, audience: &str, now: &str) -> Result<serde_json::Value, String> {
    presented_grant_with_keys(dir, audience, now, None).map(|(grant, _)| grant)
}

fn presented_grant_with_keys(
    dir: &Path,
    audience: &str,
    now: &str,
    keys: Option<&Path>,
) -> Result<(serde_json::Value, [u8; 32]), String> {
    let template: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(dir.join("grant.json")).map_err(|err| err.to_string())?,
    )
    .map_err(|err| err.to_string())?;
    let party = |field: &str, role: &str| -> Result<Party, String> {
        let name = template[field].as_str().ok_or("grant key reference")?;
        if name.starts_with("rfc8032-") {
            #[cfg(test)]
            return rfc_party(name);
            #[cfg(not(test))]
            return Err(
                "RFC 8032 test keys are forbidden for demo grants; use vaikor keygen and --keys"
                    .into(),
            );
        }
        if let Some(keys) = keys {
            return file_party(&keys.join(format!("{role}.key")));
        }
        #[cfg(test)]
        return rfc_party(if role == "issuer" {
            "rfc8032-test-1"
        } else {
            "rfc8032-test-2"
        });
        #[cfg(not(test))]
        return scenario_key(dir, name, role);
    };
    let issuer = party("issuer_key", "issuer")?;
    let holder = party("holder_key", "holder")?;
    let exp = add_rfc3339_z(now, 1800).ok_or("grant clock")?;
    let unsigned = serde_json::json!({
        "v": "0.1",
        "id": template["id"].as_str().unwrap_or("ch-residency-demo"),
        "iss": issuer.did,
        "sub": holder.did,
        "aud": audience,
        "iat": now,
        "exp": exp,
        "cnf": { "kid": holder.did, "jkt": holder.jkt },
        "rights": template.get("rights").cloned().ok_or("grant rights")?,
        "budget": template.get("budget").cloned().unwrap_or(serde_json::Value::Null),
        "chain": []
    });
    // The holder presents the grant with its key (0002 R25).
    Ok((
        attach_signature(&unsigned, &issuer.seed, &issuer.did),
        holder.seed,
    ))
}

struct Party {
    seed: [u8; 32],
    did: String,
    jkt: String,
}

/// Resolve the generated issuer used as the trust anchor for a pre-signed grant.
pub fn issuer_from_keys(dir: &Path) -> Result<String, String> {
    Ok(file_party(&dir.join("issuer.key"))?.did)
}

/// Resolve a scenario key reference without `--keys`. Only the fixed name
/// `keys/<role>.key` is accepted; the key must be a regular file (no symlink)
/// inside `<scenario>/keys/`. Scenario input never chooses an arbitrary path.
#[cfg_attr(test, allow(dead_code))]
fn scenario_key(dir: &Path, name: &str, role: &str) -> Result<Party, String> {
    let expected = format!("keys/{role}.key");
    if name != expected {
        return Err(format!(
            "grant key reference must be {expected}; use vaikor keygen and --keys"
        ));
    }
    let keys = dir.join("keys");
    let path = keys.join(format!("{role}.key"));
    for p in [&keys, &path] {
        let meta = fs::symlink_metadata(p).map_err(|e| {
            format!(
                "cannot read key {}: {e}; use vaikor keygen and --keys",
                p.display()
            )
        })?;
        if meta.file_type().is_symlink() {
            return Err(format!("key path {} is a symlink; refused", p.display()));
        }
    }
    let base = fs::canonicalize(&keys).map_err(|e| e.to_string())?;
    let real = fs::canonicalize(&path).map_err(|e| e.to_string())?;
    if real.parent() != Some(base.as_path()) || !real.is_file() {
        return Err(format!(
            "key path {} escapes the scenario keys directory",
            path.display()
        ));
    }
    file_party(&real)
}

pub const RFC8032_TEST_PUBLIC_KEYS: [&str; 5] = [
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    // RFC 8032 section 7.1 TEST 1024 and TEST SHA(abc).
    "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
];

/// True when `seed` derives to one of the five published RFC 8032 section 7.1
/// Ed25519 test public keys.
pub fn is_rfc8032_test_seed(seed: &[u8; 32]) -> bool {
    let public: String = vaikor_log::public_key(seed)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    RFC8032_TEST_PUBLIC_KEYS.contains(&public.as_str())
}

fn file_party(path: &Path) -> Result<Party, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| {
        format!(
            "cannot read key {}: {e}; use vaikor keygen and --keys",
            path.display()
        )
    })?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(format!(
            "key path {} is a symlink or not a regular file; refused",
            path.display()
        ));
    }
    let text = fs::read_to_string(path).map_err(|e| {
        format!(
            "cannot read key {}: {e}; use vaikor keygen and --keys",
            path.display()
        )
    })?;
    let seed = hex32(text.trim())?;
    let public = vaikor_log::public_key(&seed);
    // Reject the public RFC vector keys even if supplied through a private-key file.
    if is_rfc8032_test_seed(&seed) {
        return Err("RFC 8032 test keys are forbidden for demo grants".into());
    }
    Ok(Party {
        seed,
        did: did_key(&public),
        jkt: jwk_thumbprint(&public),
    })
}

#[cfg(test)]
fn rfc_party(name: &str) -> Result<Party, String> {
    let file: serde_json::Value = serde_json::from_str(include_str!(
        "../../../spec/test-vectors/keys/rfc8032-test-keys.json"
    ))
    .map_err(|err| err.to_string())?;
    let key = file["keys"]
        .as_array()
        .ok_or("test keys")?
        .iter()
        .find(|item| item["name"] == name)
        .ok_or_else(|| format!("missing test key {name}"))?;
    let seed = hex32(key["secret_key_hex"].as_str().ok_or("secret")?)?;
    let public = hex32(key["public_key_hex"].as_str().ok_or("public")?)?;
    Ok(Party {
        did: did_key(&public),
        jkt: jwk_thumbprint(&public),
        seed,
    })
}

fn hex32(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 || !text.is_ascii() {
        return Err("key hex".into());
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|err| err.to_string())?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Mutex;

    use vaikor_model::{Planner, StubPlanner};

    use super::run_dir;
    use super::strip_fences;

    #[test]
    fn planner_grant_denials_never_connect_or_spend() {
        for case in ["missing", "uncovered", "uses", "budget", "cedar"] {
            let dir = scratch(&format!("planner-{case}"));
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let mut grant: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(dir.join("grant.json")).unwrap())
                    .unwrap();
            match case {
                "missing" => {
                    std::fs::remove_file(dir.join("grant.json")).unwrap();
                }
                "uncovered" => {
                    grant["rights"]
                        .as_array_mut()
                        .unwrap()
                        .retain(|r| r["action"] != "model.complete");
                }
                "uses" => {
                    grant["rights"]
                        .as_array_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|right| right["action"] == "model.complete")
                        .unwrap()["constraints"] = serde_json::json!({"max_uses":0});
                }
                "budget" => {
                    grant["budget"] = serde_json::json!({"messages":0});
                }
                "cedar" => {
                    std::fs::write(
                        dir.join("policy.cedar"),
                        "forbid(principal, action, resource);",
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            if case != "missing" {
                std::fs::write(dir.join("grant.json"), grant.to_string()).unwrap();
            }
            let path = dir.join("audit.log");
            let seed = [61; 32];
            struct ConnectingPlanner(std::net::SocketAddr);
            impl Planner for ConnectingPlanner {
                fn plan(&self, _: &str) -> Result<String, String> {
                    std::net::TcpStream::connect(self.0).unwrap();
                    Err("mock connected".into())
                }
            }
            let planner = ConnectingPlanner(address);
            assert!(run_dir(
                &dir,
                &planner,
                &vaikor_cli::NonInteractive,
                Some(super::LogTarget {
                    path: &path,
                    seed: &seed
                })
            )
            .is_err());
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "{case}"
            );
            let events = vaikor_log::read_events(&path, &vaikor_log::public_key(&seed)).unwrap();
            assert!(events.iter().any(|e| e.decision == "deny"), "{case}");
            assert!(events.iter().all(|e| e.usage.is_none()), "{case}");
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn planner_reservation_is_durable_before_connect_and_survives_restart() {
        for limit in ["uses", "budget"] {
            let dir = scratch(&format!("planner-reservation-{limit}"));
            let mut grant: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(dir.join("grant.json")).unwrap())
                    .unwrap();
            if limit == "uses" {
                grant["rights"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|right| right["action"] == "model.complete")
                    .unwrap()["constraints"] = serde_json::json!({"max_uses":1});
            }
            grant["budget"] = serde_json::json!({"messages":2});
            std::fs::write(dir.join("grant.json"), grant.to_string()).unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let path = dir.join("audit.log");
            let seed = [62; 32];
            struct CheckedPlanner<'a> {
                path: &'a std::path::Path,
                seed: &'a [u8; 32],
                address: std::net::SocketAddr,
            }
            impl Planner for CheckedPlanner<'_> {
                fn plan(&self, _: &str) -> Result<String, String> {
                    let events =
                        vaikor_log::read_events(self.path, &vaikor_log::public_key(self.seed))
                            .unwrap();
                    let spends: Vec<_> = events.iter().filter_map(|e| e.usage.as_ref()).collect();
                    assert_eq!(spends.len(), 1);
                    assert_eq!(spends[0].2, 1);
                    assert_eq!(
                        events
                            .iter()
                            .map(|e| e.decision.as_str())
                            .collect::<Vec<_>>(),
                        ["spend", "reserve", "attempt"]
                    );
                    std::net::TcpStream::connect(self.address).unwrap();
                    Ok(serde_json::json!({"v":"0.1", "steps":[{"id":"moderate", "kind":"call", "capability":"tag:vaikor.com,2026:capability:guard.moderate", "approval":true, "args":{"comment":{"lit":"c1"}}}]}).to_string())
                }
            }
            let planner = CheckedPlanner {
                path: &path,
                seed: &seed,
                address: listener.local_addr().unwrap(),
            };
            let approval = vaikor_cli::FixedApproval {
                granted: true,
                actor: "owner".into(),
            };
            run_dir(
                &dir,
                &planner,
                &approval,
                Some(super::LogTarget {
                    path: &path,
                    seed: &seed,
                }),
            )
            .unwrap();
            listener.accept().unwrap();
            // Reopening the chain must replay the prior reservation, despite a freshly signed presentation.
            assert!(run_dir(
                &dir,
                &planner,
                &approval,
                Some(super::LogTarget {
                    path: &path,
                    seed: &seed
                })
            )
            .is_err());
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            let events = vaikor_log::read_events(&path, &vaikor_log::public_key(&seed)).unwrap();
            assert_eq!(
                events
                    .iter()
                    .filter(|e| e.step == "planner" && e.usage.is_some())
                    .count(),
                1
            );
            assert_eq!(
                events
                    .iter()
                    .filter_map(|e| e.usage.as_ref())
                    .map(|u| u.2)
                    .sum::<u64>(),
                2
            );
            assert_eq!(events.iter().filter(|e| e.decision == "attempt").count(), 1);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn audit_must_be_available_before_planning() {
        struct Never;
        impl Planner for Never {
            fn plan(&self, _: &str) -> Result<String, String> {
                panic!("planner ran without audit");
            }
        }
        assert!(
            super::run_dir(&demo(), &Never, &vaikor_cli::NonInteractive, None)
                .unwrap_err()
                .contains("audit log")
        );
        let path = demo(); // A directory cannot be opened as an audit file.
        assert!(super::run_dir(
            &demo(),
            &Never,
            &vaikor_cli::NonInteractive,
            Some(super::LogTarget {
                path: &path,
                seed: &[8; 32]
            })
        )
        .is_err());
    }

    #[test]
    fn planner_reports_and_refusal_are_audited_in_order() {
        struct Failed(std::sync::atomic::AtomicBool);
        impl Planner for Failed {
            fn plan(&self, _: &str) -> Result<String, String> {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
                Err("planner refused".into())
            }
            fn reports(&self) -> Vec<String> {
                if self.0.load(std::sync::atomic::Ordering::SeqCst) {
                    vec![r#"{"id":"planner-attempt"}"#.into()]
                } else {
                    vec![]
                }
            }
        }
        let path =
            std::env::temp_dir().join(format!("guard-planner-refusal-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(super::run_dir(
            &demo(),
            &Failed(std::sync::atomic::AtomicBool::new(false)),
            &vaikor_cli::NonInteractive,
            Some(super::LogTarget {
                path: &path,
                seed: &[8; 32]
            })
        )
        .is_err());
        let events = vaikor_log::read_events(&path, &vaikor_log::public_key(&[8; 32])).unwrap();
        assert_eq!(
            events
                .iter()
                .map(|e| e.decision.as_str())
                .collect::<Vec<_>>(),
            ["spend", "reserve", "attempt", "privacy-report", "deny"]
        );
        let report = &events[3];
        assert_eq!(
            report.privacy_report.as_deref(),
            Some(r#"{"id":"planner-attempt"}"#)
        );
        assert_eq!(events.last().unwrap().decision, "deny");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn signed_intent_precedes_planner_call() {
        struct Inspect(std::path::PathBuf);
        impl Planner for Inspect {
            fn plan(&self, _: &str) -> Result<String, String> {
                let events =
                    vaikor_log::read_events(&self.0, &vaikor_log::public_key(&[17; 32])).unwrap();
                assert_eq!(
                    events
                        .iter()
                        .map(|e| e.decision.as_str())
                        .collect::<Vec<_>>(),
                    ["spend", "reserve", "attempt"]
                );
                assert_eq!(events.last().unwrap().step, "planner");
                Err("stop after checking durable intent".into())
            }
        }
        let audit = TestAudit::new();
        assert!(run_dir(
            &demo(),
            &Inspect(audit.0.clone()),
            &vaikor_cli::NonInteractive,
            audit.target()
        )
        .is_err());
    }

    #[test]
    fn rejected_planner_documents_have_signed_denials() {
        for document in [
            "invalid JSON",
            r#"{"steps":[{"id":"bad","kind":"call","capability":"unknown","args":{}}]}"#,
        ] {
            let audit = TestAudit::new();
            let error = run_dir(
                &demo(),
                &StubPlanner {
                    document: document.into(),
                },
                &vaikor_cli::NonInteractive,
                audit.target(),
            )
            .unwrap_err();
            let events =
                vaikor_log::read_events(&audit.0, &vaikor_log::public_key(&[17; 32])).unwrap();
            let deny = events.last().unwrap();
            assert_eq!(deny.step, "planner", "{error}");
            assert_eq!(deny.decision, "deny");
            assert_eq!(deny.reason.as_deref(), Some(error.as_str()));
        }
    }

    // Deterministic provider fixture for the environment entrypoint; no socket.
    pub(super) struct ReportingFixture {
        pub document: String,
        pub called: std::sync::atomic::AtomicBool,
    }
    impl Planner for ReportingFixture {
        fn plan(&self, _: &str) -> Result<String, String> {
            self.called.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(self.document.clone())
        }
        fn reports(&self) -> Vec<String> {
            if self.called.load(std::sync::atomic::Ordering::SeqCst) {
                vec![r#"{"id":"planner-report","sent":{"fields":["messages"]}}"#.into()]
            } else {
                vec![]
            }
        }
    }

    #[test]
    fn successful_planner_report_is_audited_through_run_from_env() {
        let dir = scratch("env-report");
        let path = dir.join("audit.log");
        let seed = [45; 32];
        let approval = vaikor_cli::FixedApproval {
            granted: true,
            actor: "ada".into(),
        };
        let report = super::run_from_env(
            &dir,
            "reporting-test",
            None,
            None,
            None,
            &approval,
            Some(super::LogTarget {
                path: &path,
                seed: &seed,
            }),
        )
        .unwrap();
        let events = vaikor_log::read_events(&path, &vaikor_log::public_key(&seed)).unwrap();
        assert_eq!(
            events[..4]
                .iter()
                .map(|e| e.decision.as_str())
                .collect::<Vec<_>>(),
            ["spend", "reserve", "attempt", "privacy-report"]
        );
        let planner_report = &events[3];
        let privacy_report: serde_json::Value =
            serde_json::from_str(planner_report.privacy_report.as_ref().unwrap()).unwrap();
        assert_eq!(privacy_report["id"], "planner-report");
        assert!(events.len() > 1);
        assert_eq!(report.privacy_reports, 2);
        assert_eq!(report.events, events);
        assert_eq!(report.audit_events, events.len());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn guard_local_latch_precedes_log_open_and_survives_later_config() {
        const CHILD: &str = "VAIKOR_REVIEW34_LOCAL_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::guard_local_latch_precedes_log_open_and_survives_later_config",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stdout)
            );
            return;
        }
        let dir = scratch("latch");
        let mut config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap())
                .unwrap();
        config["local"] = true.into();
        std::fs::write(dir.join("config.json"), config.to_string()).unwrap();
        let seed = [46; 32];
        let mut grant: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("grant.json")).unwrap())
                .unwrap();
        grant["rights"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|right| right["action"] == "model.complete")
            .unwrap()["constraints"] = serde_json::json!({"max_uses":1});
        std::fs::write(dir.join("grant.json"), grant.to_string()).unwrap();
        let error = super::run_from_env(
            &dir,
            "openai",
            Some("https://api.openai.com"),
            None,
            None,
            &vaikor_cli::NonInteractive,
            Some(super::LogTarget {
                path: &dir,
                seed: &seed,
            }),
        )
        .unwrap_err();
        assert!(!error.contains("local mode")); // Log open failed after the latch was set.
        config["local"] = false.into();
        std::fs::write(dir.join("config.json"), config.to_string()).unwrap();
        let audit = TestAudit::new();
        let mut grant: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("grant.json")).unwrap())
                .unwrap();
        grant["rights"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|right| right["action"] == "model.complete")
            .unwrap()["constraints"] = serde_json::json!({"max_uses":1});
        std::fs::write(dir.join("grant.json"), grant.to_string()).unwrap();
        let error = super::run_from_env(
            &dir,
            "openai",
            Some("https://api.openai.com"),
            None,
            None,
            &vaikor_cli::NonInteractive,
            audit.target(),
        )
        .unwrap_err();
        assert!(error.contains("local mode"), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_provider_id_refuses_before_planning() {
        let audit = TestAudit::new();
        let dir = scratch("provider-required");
        let mut config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap())
                .unwrap();
        config.as_object_mut().unwrap().remove("provider_id");
        std::fs::write(dir.join("config.json"), config.to_string()).unwrap();
        let error = super::run_from_env(
            &dir,
            "stub",
            None,
            None,
            None,
            &vaikor_cli::NonInteractive,
            audit.target(),
        )
        .unwrap_err();
        assert!(error.contains("provider_id is required"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn scratch(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("vaikor-review34-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        for name in [
            "tools.json",
            "policy.cedar",
            "stub-plan.json",
            "grant.json",
            "config.json",
        ] {
            std::fs::copy(demo().join(name), path.join(name)).unwrap();
        }
        path
    }

    #[test]
    fn planner_refusal_is_audited_through_run_from_env() {
        let dir = scratch("denial");
        std::fs::write(
            dir.join("policy.cedar"),
            "permit(principal, action, resource);",
        )
        .unwrap();
        let path = dir.join("audit.log");
        let seed = [42; 32];
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let destination = format!("http://{}", listener.local_addr().unwrap());
        let mut config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap())
                .unwrap();
        config["provider_id"] = destination.clone().into();
        config["provider_region"] = "GLOBAL".into();
        config["provider_profile"] = "P0".into();
        std::fs::write(dir.join("config.json"), config.to_string()).unwrap();
        let mut catalog: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("tools.json")).unwrap())
                .unwrap();
        for tool in catalog["tools"].as_array_mut().unwrap() {
            tool["_meta"]["com.vaikor/capability"]["residency"]["tags"] =
                serde_json::json!(["unrestricted"]);
        }
        std::fs::write(dir.join("tools.json"), catalog.to_string()).unwrap();
        let mut grant: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("grant.json")).unwrap())
                .unwrap();
        grant["rights"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|right| right["action"] == "model.complete")
            .unwrap()["constraints"] = serde_json::json!({"max_uses":1});
        std::fs::write(dir.join("grant.json"), grant.to_string()).unwrap();
        let error = super::run_from_env(
            &dir,
            "openai",
            Some("https://api.openai.com"),
            None,
            None,
            &vaikor_cli::NonInteractive,
            Some(super::LogTarget {
                path: &path,
                seed: &seed,
            }),
        )
        .unwrap_err();
        assert!(error.contains("destination does not match provider"));
        let events = vaikor_log::read_events(&path, &vaikor_log::public_key(&seed)).unwrap();
        assert_eq!(
            events
                .iter()
                .map(|e| e.decision.as_str())
                .collect::<Vec<_>>(),
            ["deny"]
        );
        assert_eq!(
            events
                .iter()
                .filter_map(|e| e.usage.as_ref())
                .map(|u| u.2)
                .sum::<u64>(),
            0
        );
        assert!(events.iter().all(|e| e.decision != "spend"));
        let plan = serde_json::json!({"v":"0.1", "steps":[{
            "id":"moderate", "kind":"call", "capability":"tag:vaikor.com,2026:capability:guard.moderate",
            "approval":true, "args":{"comment":{"lit":"c1"}}}]})
        .to_string();
        let server = std::thread::spawn(move || {
            use std::io::{BufRead, Read, Write};
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut reader = std::io::BufReader::new(&mut socket);
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            reader.read_exact(&mut vec![0; length]).unwrap();
            let body = serde_json::json!({"choices":[{"message":{"content":plan}}]}).to_string();
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        super::run_from_env(
            &dir,
            "openai",
            Some(&destination),
            None,
            None,
            &vaikor_cli::FixedApproval {
                granted: true,
                actor: "owner".into(),
            },
            Some(super::LogTarget {
                path: &path,
                seed: &seed,
            }),
        )
        .unwrap();
        server.join().unwrap();
        let events = vaikor_log::read_events(&path, &vaikor_log::public_key(&seed)).unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|e| e.step == "planner" && e.usage.is_some())
                .count(),
            1
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reports_survive_a_planner_error_and_invalid_plan() {
        struct ReportingPlanner {
            failed: bool,
        }
        impl Planner for ReportingPlanner {
            fn plan(&self, _: &str) -> Result<String, String> {
                if self.failed {
                    Err("provider failed".into())
                } else {
                    Ok("invalid JSON".into())
                }
            }
        }
        struct ReportsAfterCall {
            called: std::sync::atomic::AtomicBool,
            inner: ReportingPlanner,
        }
        impl Planner for ReportsAfterCall {
            fn plan(&self, prompt: &str) -> Result<String, String> {
                self.called.store(true, std::sync::atomic::Ordering::SeqCst);
                self.inner.plan(prompt)
            }
            fn reports(&self) -> Vec<String> {
                if self.called.load(std::sync::atomic::Ordering::SeqCst) {
                    vec![r#"{"id":"planner-report"}"#.into()]
                } else {
                    vec![]
                }
            }
        }
        for failed in [false, true] {
            let dir = scratch(if failed {
                "error-report"
            } else {
                "success-report"
            });
            let path = dir.join("audit.log");
            let seed = [43; 32];
            let planner = ReportsAfterCall {
                called: false.into(),
                inner: ReportingPlanner { failed },
            };
            assert!(run_dir(
                &dir,
                &planner,
                &vaikor_cli::NonInteractive,
                Some(super::LogTarget {
                    path: &path,
                    seed: &seed
                })
            )
            .is_err());
            let events = vaikor_log::read_events(&path, &vaikor_log::public_key(&seed)).unwrap();
            assert_eq!(
                events[3].privacy_report.as_deref(),
                Some(r#"{"id":"planner-report"}"#)
            );
            assert_eq!(
                events
                    .iter()
                    .map(|e| e.decision.as_str())
                    .collect::<Vec<_>>(),
                ["spend", "reserve", "attempt", "privacy-report", "deny"]
            );
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn unavailable_or_locked_log_prevents_planning() {
        struct NeverPlan;
        impl Planner for NeverPlan {
            fn plan(&self, _: &str) -> Result<String, String> {
                panic!("planner called without writable locked audit")
            }
        }
        let dir = scratch("log-first");
        let seed = [44; 32];
        assert!(run_dir(
            &dir,
            &NeverPlan,
            &vaikor_cli::NonInteractive,
            Some(super::LogTarget {
                path: &dir,
                seed: &seed
            })
        )
        .is_err());
        let path = dir.join("audit.log");
        let _locked = vaikor_log::Chain::open(&path, &seed).unwrap();
        assert!(run_dir(
            &dir,
            &NeverPlan,
            &vaikor_cli::NonInteractive,
            Some(super::LogTarget {
                path: &path,
                seed: &seed
            })
        )
        .is_err());
    }

    #[test]
    fn planner_url_must_match_the_configured_provider() {
        let audit = TestAudit::new();
        let error = super::run_from_env(
            &demo(),
            "openai",
            Some("https://api.openai.com"),
            None,
            Some("test-key"),
            &vaikor_cli::NonInteractive,
            audit.target(),
        )
        .unwrap_err();
        assert!(
            error.contains("destination does not match provider"),
            "{error}"
        );
    }

    struct TestAudit(std::path::PathBuf);
    impl TestAudit {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "vaikor-guard-audit-{}-{}.log",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let _ = std::fs::remove_file(&path);
            Self(path)
        }
        fn target(&self) -> Option<super::LogTarget<'_>> {
            Some(super::LogTarget {
                path: &self.0,
                seed: &[17; 32],
            })
        }
    }
    impl Drop for TestAudit {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn strip_fences_leaves_plain_json() {
        assert_eq!(strip_fences("{\"v\":\"0.1\"}"), "{\"v\":\"0.1\"}");
        assert_eq!(strip_fences("\n  {\"v\":\"0.1\"}\n"), "{\"v\":\"0.1\"}");
    }

    #[test]
    fn strip_fences_removes_a_json_code_fence() {
        assert_eq!(
            strip_fences("```json\n{\"v\":\"0.1\"}\n```"),
            "{\"v\":\"0.1\"}"
        );
        assert_eq!(
            strip_fences("\n```json\n{\"v\":\"0.1\"}\n```\n"),
            "{\"v\":\"0.1\"}"
        );
    }

    #[test]
    fn strip_fences_removes_a_bare_code_fence() {
        assert_eq!(strip_fences("```\n{\"v\":\"0.1\"}\n```"), "{\"v\":\"0.1\"}");
        assert_eq!(strip_fences("```json{\"v\":\"0.1\"}```"), "{\"v\":\"0.1\"}");
    }

    struct RecordingPlanner {
        seen: Mutex<String>,
        document: String,
    }

    impl Planner for RecordingPlanner {
        fn plan(&self, prompt: &str) -> Result<String, String> {
            *self.seen.lock().unwrap() = prompt.to_string();
            Ok(self.document.clone())
        }
    }

    #[test]
    fn task_braces_are_preserved_in_the_planner_prompt() {
        let dir = scratch("task-braces");
        let mut config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap())
                .unwrap();
        let task = r#"Return {"files": []}; preserve {task}, {{braces}}, and an unmatched }."#;
        config["task"] = task.into();
        std::fs::write(dir.join("config.json"), config.to_string()).unwrap();
        let planner = RecordingPlanner {
            seen: Mutex::new(String::new()),
            document: std::fs::read_to_string(dir.join("stub-plan.json")).unwrap(),
        };
        let audit = TestAudit::new();
        run_dir(
            &dir,
            &planner,
            &vaikor_cli::FixedApproval {
                granted: true,
                actor: "ada".into(),
            },
            audit.target(),
        )
        .unwrap();
        assert!(planner.seen.lock().unwrap().ends_with(task));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_planner_prompt_requires_json_and_the_outbound_model_step() {
        let dir = demo();
        let document = std::fs::read_to_string(dir.join("stub-plan.json")).unwrap();
        let example = document.clone();
        let catalog = std::fs::read_to_string(dir.join("tools.json")).unwrap();
        let planner = RecordingPlanner {
            seen: Mutex::new(String::new()),
            document,
        };
        let approval = vaikor_cli::FixedApproval {
            granted: true,
            actor: "ada".into(),
        };
        let audit = TestAudit::new();
        let report = run_dir(&dir, &planner, &approval, audit.target()).unwrap();
        let prompt = planner.seen.lock().unwrap().clone();
        assert!(prompt.contains("ONLY a JSON plan"), "{prompt}");
        assert!(prompt.contains("no code fences"), "{prompt}");
        assert!(
            prompt.contains(example.trim()),
            "prompt is missing the stub plan example"
        );
        assert!(
            prompt.contains(catalog.trim()),
            "prompt is missing the capability catalog"
        );
        assert!(prompt.contains("MUST include"), "{prompt}");
        assert!(
            prompt.contains("tag:vaikor.com,2026:capability:model.complete"),
            "{prompt}"
        );
        assert!(prompt.contains("privacy report"), "{prompt}");
        assert!(prompt.contains("residency"), "{prompt}");
        assert_eq!(report.privacy_reports, 1);
        assert_eq!(report.residency, vec!["CH".to_string()]);
    }

    #[test]
    fn a_fenced_plan_still_writes_the_privacy_report() {
        let document = std::fs::read_to_string(demo().join("stub-plan.json")).unwrap();
        let planner = StubPlanner {
            document: format!("```json\n{document}\n```"),
        };
        let approval = vaikor_cli::FixedApproval {
            granted: true,
            actor: "ada".into(),
        };
        let audit = TestAudit::new();
        let report = run_dir(&demo(), &planner, &approval, audit.target()).unwrap();
        assert_eq!(report.privacy_reports, 1);
        assert_eq!(report.residency, vec!["CH".to_string()]);
    }

    fn demo() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../demo/ch-residency")
    }

    #[test]
    fn the_scenario_presents_a_signed_grant() {
        let now = "2026-10-14T12:10:00Z";
        let grant = super::presented_grant(&demo(), "did:example:ch-residency", now).unwrap();
        let issuer = grant["iss"].as_str().unwrap();
        vaikor_grant::accept_presented(&grant, now, &[issuer]).unwrap();
        let mut tampered = grant.clone();
        tampered["rights"][0]["resource"] = serde_json::json!("tag:vaikor.com,2026:capability/*");
        assert!(vaikor_grant::accept_presented(&tampered, now, &[issuer]).is_err());
    }

    /// 0002 R25 on `vaikor guard`: a grant presented with a wrong key, for another plan, or
    /// with a proof replayed from an earlier run reserves nothing and runs no step.
    #[test]
    fn a_grant_without_a_valid_proof_has_no_effect_on_vaikor_guard() {
        use vaikor_cli::engine::Presenter;
        struct Signs([u8; 32], Option<&'static str>);
        impl Presenter for Signs {
            fn prove(
                &self,
                token: &serde_json::Value,
                aud: &str,
                digest: &str,
                nonce: &str,
            ) -> [u8; 64] {
                vaikor_grant::sign_pop(&self.0, token, aud, self.1.unwrap_or(digest), nonce)
            }
        }
        /// Signs and keeps every proof; once `replaying`, hands them out again in order.
        #[derive(Default)]
        struct Replay(std::sync::Mutex<(Vec<[u8; 64]>, Option<usize>)>);
        impl Presenter for Replay {
            fn prove(
                &self,
                token: &serde_json::Value,
                aud: &str,
                digest: &str,
                nonce: &str,
            ) -> [u8; 64] {
                let mut state = self.0.lock().unwrap();
                let (proofs, replaying) = &mut *state;
                match replaying {
                    Some(next) => {
                        *next += 1;
                        proofs[(*next - 1).min(proofs.len() - 1)]
                    }
                    None => {
                        let holder = super::rfc_party("rfc8032-test-2").unwrap().seed;
                        let proof = vaikor_grant::sign_pop(&holder, token, aud, digest, nonce);
                        proofs.push(proof);
                        proof
                    }
                }
            }
        }
        let holder = super::rfc_party("rfc8032-test-2").unwrap().seed;
        let stranger = super::rfc_party("rfc8032-test-3").unwrap().seed;
        let document = std::fs::read_to_string(demo().join("stub-plan.json")).unwrap();
        let planner = StubPlanner { document };
        let approval = vaikor_cli::FixedApproval {
            granted: true,
            actor: "ada".into(),
        };
        let effects = |audit: &TestAudit| {
            let events =
                vaikor_log::read_events(&audit.0, &vaikor_log::public_key(&[17; 32])).unwrap();
            events
                .iter()
                .filter(|e| {
                    matches!(
                        e.decision.as_str(),
                        "spend" | "allow" | "approve" | "reserve"
                    )
                })
                .count()
        };
        for (case, presenter) in [
            ("wrong key", Signs(stranger, None)),
            ("other plan", Signs(holder, Some("another-plan-digest"))),
        ] {
            let audit = TestAudit::new();
            let result = super::run_dir_presented(
                &demo(),
                &planner,
                &approval,
                audit.target(),
                Some(&presenter),
            );
            assert!(result.is_err(), "{case}: {result:?}");
            assert_eq!(effects(&audit), 0, "{case}");
        }
        let replay = Replay::default();
        let audit = TestAudit::new();
        super::run_dir_presented(&demo(), &planner, &approval, audit.target(), Some(&replay))
            .unwrap();
        let before = effects(&audit);
        assert!(before > 0);
        replay.0.lock().unwrap().1 = Some(0);
        let result =
            super::run_dir_presented(&demo(), &planner, &approval, audit.target(), Some(&replay));
        assert!(result.is_err(), "replay: {result:?}");
        assert_eq!(effects(&audit), before, "replay");
    }

    #[test]
    fn the_stub_moderates_and_writes_a_report() {
        let document = std::fs::read_to_string(demo().join("stub-plan.json")).unwrap();
        let planner = StubPlanner { document };
        let approval = vaikor_cli::FixedApproval {
            granted: true,
            actor: "ada".into(),
        };
        let audit = TestAudit::new();
        let report = run_dir(&demo(), &planner, &approval, audit.target()).unwrap();
        assert!(report.capabilities >= 3);
        assert!(report.approvals >= 1);
        assert_eq!(report.privacy_reports, 1);
        assert!(report.audit_events >= 3);
        assert_eq!(report.residency, vec!["CH".to_string()]);
    }

    #[test]
    fn the_default_provider_is_the_stub() {
        let error = super::run_from_env(
            &demo(),
            "stub",
            None,
            None,
            None,
            &vaikor_cli::NonInteractive,
            None,
        )
        .unwrap_err();
        assert!(error.contains("audit log"), "{error}");
        let error = super::run_from_env(
            &demo(),
            "openai",
            None,
            None,
            None,
            &vaikor_cli::NonInteractive,
            None,
        )
        .unwrap_err();
        assert!(error.contains("audit log"));
    }

    #[test]
    fn the_plan_is_verified_before_residency_reads_its_fields() {
        let dir = demo();
        let scratch = std::env::temp_dir().join("vaikor-guard-verify-first");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        for name in ["tools.json", "policy.cedar", "stub-plan.json", "grant.json"] {
            std::fs::copy(dir.join(name), scratch.join(name)).unwrap();
        }
        let mut config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap())
                .unwrap();
        config["provider_region"] = serde_json::json!("CH");
        // Keep a residency conflict on the returned capability while allowing the planner.
        let mut tools: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(scratch.join("tools.json")).unwrap())
                .unwrap();
        for tool in tools["tools"].as_array_mut().unwrap() {
            let record = &mut tool["_meta"]["com.vaikor/capability"];
            if record["id"] == "tag:vaikor.com,2026:capability:guard.moderate" {
                record["residency"]["tags"] = serde_json::json!(["EU"]);
            }
        }
        std::fs::write(scratch.join("tools.json"), tools.to_string()).unwrap();
        std::fs::write(
            scratch.join("config.json"),
            serde_json::to_string(&config).unwrap(),
        )
        .unwrap();
        let document = r#"{
            "v": "0.1",
            "steps": [{
                "id": "moderate",
                "kind": "call",
                "capability": "tag:vaikor.com,2026:capability:guard.moderate",
                "args": { "comment": { "lit": "c1" } }
            }]
        }"#;
        let audit = TestAudit::new();
        let error = run_dir(
            &scratch,
            &StubPlanner {
                document: document.into(),
            },
            &vaikor_cli::NonInteractive,
            audit.target(),
        )
        .unwrap_err();
        assert!(error.contains("approval"), "{error}");
        assert!(!error.contains("residency"), "{error}");
    }

    #[test]
    fn a_non_swiss_provider_is_refused() {
        let dir = demo();
        let mut config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap())
                .unwrap();
        config["provider_region"] = serde_json::json!("EU");
        let scratch = std::env::temp_dir().join("vaikor-guard-eu");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        for name in ["tools.json", "policy.cedar", "stub-plan.json", "grant.json"] {
            std::fs::copy(dir.join(name), scratch.join(name)).unwrap();
        }
        std::fs::write(
            scratch.join("config.json"),
            serde_json::to_string(&config).unwrap(),
        )
        .unwrap();
        let document = std::fs::read_to_string(dir.join("stub-plan.json")).unwrap();
        let audit = TestAudit::new();
        let error = run_dir(
            &scratch,
            &StubPlanner { document },
            &vaikor_cli::NonInteractive,
            audit.target(),
        )
        .unwrap_err();
        assert!(error.contains("not allowed in EU"), "{error}");
    }
}

#[cfg(test)]
#[test]
fn planner_derived_residency_drops_unrestricted_but_refuses_malformed_items() {
    let dir = std::env::temp_dir().join(format!("residency-derived-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../demo/public-weather/tools.json");
    let mut catalog: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(source).unwrap()).unwrap();
    catalog["tools"][1]["_meta"]["com.vaikor/capability"]["residency"]["tags"] =
        serde_json::json!(["CH"]);
    fs::write(dir.join("tools.json"), catalog.to_string()).unwrap();
    assert_eq!(planner_residency(&dir).unwrap(), vec!["CH"]);
    catalog["tools"][0]["_meta"]["com.vaikor/capability"]["residency"]["tags"] =
        serde_json::json!(["unrestricted", "CH"]);
    fs::write(dir.join("tools.json"), catalog.to_string()).unwrap();
    let result = planner_residency(&dir);
    fs::remove_dir_all(dir).unwrap();
    assert_eq!(result.unwrap_err(), "malformed residency declaration");
}

/// Resolve the Core-owned record directory, including the XDG fallback.
pub fn record_store_path(explicit: Option<&str>) -> Result<std::path::PathBuf, String> {
    let root = match explicit {
        Some(path) => std::path::PathBuf::from(path),
        None => {
            let state = std::env::var_os("XDG_STATE_HOME")
                .filter(|p| !p.is_empty())
                .map(std::path::PathBuf::from)
                .or_else(|| {
                    std::env::var_os("HOME")
                        .map(|h| std::path::PathBuf::from(h).join(".local/state"))
                })
                .ok_or("no state directory")?;
            state.join("vaikor/records")
        }
    };
    std::path::absolute(root).map_err(|e| e.to_string())
}
