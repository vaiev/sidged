// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Turnkey 1-Command OS Bootstrap & Task Runner (WP 5: `vaikor init --workspace` & `vaikor task`).

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use vaikor_grant::did_key;
use vaikor_log::{public_key, Chain};
use vaikor_record::artifact::{
    build_result_surface, sign_artifact_record, ArtifactPayload, FlowBadgeSpec, SolutionArtifact,
    StepTimelineItem, MIME_ARTIFACT_SOLUTION,
};
use vaikor_record::store::{Access, Store};
use vaikor_record::Record;
use vaikor_verify::flow::CedarFlowPolicy;

use crate::engine::{Flow, GrantSource, HolderKey, Presenter, Stage};
use crate::init::Terminal;
use crate::intent_plan::plan_for_intent;
use crate::linguist::{IntentCatalog, LinguistModel, LocalLinguist, VerifiedIntent};
use crate::node_exec::{run_plan, NoTrustedUi, NodeExecutors};
use crate::node_grant::{
    default_mandate_rights, grant_denial, issue_mandate, DEFAULT_MANDATE_MESSAGES,
};

pub const DEFAULT_IMAGE_DIGEST: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The flow policy a new workspace starts with: the specified `default-flow` (0013 §4 R9):
/// flows are permitted unless the class is sensitive; `secrets.*` never reaches egress
/// (R10, enforced before Cedar). The owner adds permits or forbids to this file.
pub const DEFAULT_TURNKEY_FLOW_POLICY: &str = vaikor_verify::flow::DEFAULT_FLOW_POLICY;

/// The owner mandate in a workspace (0002 R23), next to `policy.cedar`, mode 0600.
pub const MANDATE_FILE: &str = "mandate.json";
/// The grant policy in a workspace (0002 R18), evaluated for every step of a task token.
pub const GRANT_POLICY_FILE: &str = "grant.cedar";
/// A mandate from `vaikor init` or `vaikor mandate renew` lives 30 days (R23).
pub const MANDATE_SECONDS: i64 = vaikor_grant::MAX_MANDATE_SECONDS;

/// The grant policy a new workspace starts with: a step is permitted only when its request
/// names this node as the audience. The owner adds forbids to this file.
pub fn default_grant_policy(node_did: &str) -> String {
    format!(
        "// Grant policy (0002 R18): every step of a task token on this node is checked here.\n\
         permit(principal, action, resource) when {{ context.audience == \"{node_did}\" }};\n"
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceManifest {
    pub workspace_dir: String,
    pub owner_did: String,
    pub edge1_did: String,
    pub worker_dids: Vec<String>,
    pub adapter_did: String,
    pub log_pubkey_hex: String,
    pub image_digest: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TurnkeyTaskSummary {
    pub clarification_needed: bool,
    pub clarification_question: Option<String>,
    pub canonical_intent: String,
    pub artifact_mime: String,
    pub record_id: Option<String>,
    pub plan_digest: Option<String>,
    pub record_path: Option<String>,
    pub surface_path: Option<String>,
    pub flow_badge_label: Option<String>,
    /// Steps that completed; the full outcome per step is in `steps`.
    pub steps_executed: usize,
    /// Why the Core refused to plan this intent (stage, step, deciding policies).
    pub plan_refusal: Option<String>,
    pub steps: Vec<crate::node_exec::StepOutcome>,
    /// Why the audit log stopped the run (a step's decision or outcome was not recorded).
    pub audit_failure: Option<String>,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_seed_file(path: &Path) -> Result<[u8; 32], String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {}", path.display(), e))?;
    let trimmed = text.trim();
    if trimmed.len() != 64 {
        return Err(format!("{}: expected 64 hex chars", path.display()));
    }
    let mut seed = [0u8; 32];
    for (i, slot) in seed.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(seed)
}

fn write_or_load_seed(path: &Path) -> Result<[u8; 32], String> {
    if path.exists() {
        return read_seed_file(path);
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| e.to_string())?;
    if seed.iter().all(|&b| b == 0) {
        seed[0] = 0x5a;
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {}", path.display(), e))?;
    writeln!(f, "{}", hex_encode(&seed)).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    Ok(seed)
}

/// VKR-L1 capability descriptors a new workspace starts with (`assets/capability-catalog.json`,
/// validated against `capability-descriptor.schema.json` by spec/validate).
pub const DEFAULT_CAPABILITY_CATALOG: &str = include_str!("../assets/capability-catalog.json");

pub fn default_catalog() -> Value {
    serde_json::from_str(DEFAULT_CAPABILITY_CATALOG).expect("built-in capability catalog is JSON")
}

/// Initialize a complete Vaikor Personal AI OS workspace with one call (`vaikor init --workspace <dir>`).
pub fn bootstrap_workspace(workspace_dir: &Path) -> Result<WorkspaceManifest, String> {
    if !workspace_dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(workspace_dir)
            .map_err(|e| e.to_string())?;
    } else {
        fs::set_permissions(workspace_dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
    }
    for sub in ["keys", "records", "views", "logs"] {
        let p = workspace_dir.join(sub);
        if !p.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&p)
                .map_err(|e| e.to_string())?;
        }
    }

    let keys_dir = workspace_dir.join("keys");
    // R23: only the act that creates the owner key signs the node's first mandate.
    let fresh = !keys_dir.join("owner.key").exists();
    let owner_seed = write_or_load_seed(&keys_dir.join("owner.key"))?;
    let edge1_seed = write_or_load_seed(&keys_dir.join("edge1.key"))?;
    let adapter_seed = write_or_load_seed(&keys_dir.join("adapter.key"))?;
    let log_seed = write_or_load_seed(&keys_dir.join("log.key"))?;

    let owner_did = did_key(&public_key(&owner_seed));
    let edge1_did = did_key(&public_key(&edge1_seed));
    let adapter_did = did_key(&public_key(&adapter_seed));
    let log_pubkey_hex = hex_encode(&public_key(&log_seed));

    let policy_path = workspace_dir.join("policy.cedar");
    if !policy_path.exists() {
        fs::write(
            &policy_path,
            format!("{}\n", DEFAULT_TURNKEY_FLOW_POLICY.trim()),
        )
        .map_err(|e| e.to_string())?;
    }
    let catalog_path = workspace_dir.join("catalog.json");
    if !catalog_path.exists() {
        let cat = serde_json::to_string_pretty(&default_catalog()).map_err(|e| e.to_string())?;
        fs::write(&catalog_path, cat).map_err(|e| e.to_string())?;
    }

    let log_path = workspace_dir.join("logs").join("audit.log");
    // Opening the chain creates the empty audit log the node appends to.
    Chain::open(&log_path, &log_seed)?;

    let grant_policy_path = workspace_dir.join(GRANT_POLICY_FILE);
    if !grant_policy_path.exists() {
        fs::write(&grant_policy_path, default_grant_policy(&edge1_did))
            .map_err(|e| e.to_string())?;
    }

    let manifest = WorkspaceManifest {
        workspace_dir: workspace_dir.display().to_string(),
        owner_did,
        edge1_did,
        worker_dids: Vec::new(),
        adapter_did,
        log_pubkey_hex,
        image_digest: DEFAULT_IMAGE_DIGEST.into(),
    };
    let manifest_json = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?;
    fs::write(workspace_dir.join("manifest.json"), manifest_json).map_err(|e| e.to_string())?;

    // R23: initialisation is where the owner signs the node's first mandate. An existing
    // workspace without one is refused until the owner runs `vaikor mandate renew`.
    if fresh && !workspace_dir.join(MANDATE_FILE).exists() {
        issue_default_mandate(workspace_dir, &vaikor_gateway::utc_stamp())?;
    }
    Ok(manifest)
}

/// Write `bytes` to `path` with mode 0600, replacing it atomically.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("{}: {}", tmp.display(), e))?;
    f.write_all(bytes).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| format!("{}: {}", path.display(), e))
}

/// R23: the owner key (`keys/owner.key`) signs a mandate for the node's executor key
/// (`keys/edge1.key`), audience the node's DID from the manifest, and writes it to
/// [`MANDATE_FILE`]. Callers are owner actions: `vaikor init` and `vaikor mandate renew`.
pub fn issue_workspace_mandate(
    workspace_dir: &Path,
    rights: Vec<Value>,
    budget: Value,
    now: &str,
    seconds: i64,
) -> Result<Value, String> {
    let manifest: WorkspaceManifest = serde_json::from_str(
        &fs::read_to_string(workspace_dir.join("manifest.json"))
            .map_err(|e| format!("manifest.json: {e}"))?,
    )
    .map_err(|e| format!("manifest.json: {e}"))?;
    let keys_dir = workspace_dir.join("keys");
    let owner_seed = read_seed_file(&keys_dir.join("owner.key"))?;
    let edge1_seed = read_seed_file(&keys_dir.join("edge1.key"))?;
    if did_key(&public_key(&edge1_seed)) != manifest.edge1_did {
        return Err("keys/edge1.key is not the node the manifest names".into());
    }
    let mandate = issue_mandate(
        &owner_seed,
        &edge1_seed,
        &manifest.edge1_did,
        rights,
        budget,
        now,
        seconds,
    )?;
    let text = serde_json::to_string_pretty(&mandate).map_err(|e| e.to_string())?;
    write_private(&workspace_dir.join(MANDATE_FILE), text.as_bytes())?;
    Ok(mandate)
}

/// The default mandate: one right per capability of the workspace catalog, the default
/// message budget, 30 days from `now`.
fn issue_default_mandate(workspace_dir: &Path, now: &str) -> Result<Value, String> {
    let catalog: Value = serde_json::from_str(
        &fs::read_to_string(workspace_dir.join("catalog.json"))
            .map_err(|e| format!("catalog.json: {e}"))?,
    )
    .map_err(|e| format!("catalog.json: {e}"))?;
    issue_workspace_mandate(
        workspace_dir,
        default_mandate_rights(&catalog),
        serde_json::json!({"messages": DEFAULT_MANDATE_MESSAGES}),
        now,
        MANDATE_SECONDS,
    )
}

/// `vaikor mandate renew --workspace <dir>`: the owner re-issues the node's mandate for 30
/// days after a typed confirmation, and restores a missing default grant policy. An owner
/// action on an interactive terminal only (the caller checks the TTY, as `vaikor init`
/// does); renewal through the Trusted UI is WP 17.
pub fn renew_mandate(term: &mut dyn Terminal, workspace_dir: &Path) -> Result<Value, String> {
    let manifest: WorkspaceManifest = serde_json::from_str(
        &fs::read_to_string(workspace_dir.join("manifest.json"))
            .map_err(|e| format!("manifest.json: {e}"))?,
    )
    .map_err(|e| format!("manifest.json: {e}"))?;
    let now = vaikor_gateway::utc_stamp();
    let until = vaikor_grant::add_rfc3339_z(&now, MANDATE_SECONDS).ok_or("clock")?;
    term.say(&format!(
        "vaikor mandate renew: the owner key signs the node's mandate.\n\
         node (executor and audience): {}\n\
         rights: every capability in {}\n\
         budget: {DEFAULT_MANDATE_MESSAGES} messages until {until}",
        manifest.edge1_did,
        workspace_dir.join("catalog.json").display()
    ));
    let answer = term.ask("Type renew to sign this mandate: ")?;
    if answer.trim() != "renew" {
        return Err("not confirmed; the mandate is unchanged".into());
    }
    let mandate = issue_default_mandate(workspace_dir, &now)?;
    let policy = workspace_dir.join(GRANT_POLICY_FILE);
    if !policy.exists() {
        fs::write(&policy, default_grant_policy(&manifest.edge1_did)).map_err(|e| e.to_string())?;
        term.say(&format!(
            "wrote the default grant policy {}",
            policy.display()
        ));
    }
    term.say(&format!(
        "wrote {} (0600), valid until {until}",
        workspace_dir.join(MANDATE_FILE).display()
    ));
    Ok(mandate)
}

/// The audience of the grant under which the Core imports a task record into its store.
const TASK_RECORD_AUDIENCE: &str = "tag:vaikor.com,2026:node:records";
/// The record store's signed audit chain (log key), next to the node's `audit.log`.
pub const RECORD_LOG_FILE: &str = "records.log";

/// ROADMAP 11g: the record of a run goes into the node's record store
/// ([`vaikor_record::store`]): the workspace is its root, `records/<digest>` the immutable
/// entry, the import audited on the store's own chain ([`RECORD_LOG_FILE`], log key; the
/// store holds it locked while open), the executor key
/// the trusted record signer. The Core imports under a grant it issues itself for exactly
/// this import (one right, the record's class, one minute). `records/latest-record.json`
/// only points to the entry. Returns the entry's path.
fn store_task_record(
    workspace_dir: &Path,
    manifest: &WorkspaceManifest,
    log_seed: &[u8; 32],
    record: &Record,
) -> Result<PathBuf, String> {
    let core = did_key(&public_key(log_seed));
    let now = vaikor_gateway::utc_stamp();
    let grant = vaikor_grant::attach_signature(
        &serde_json::json!({
            "v": "0.1",
            "id": format!("task-record-{}", crate::engine::fresh_hex(16)?),
            "iss": core, "sub": core, "aud": TASK_RECORD_AUDIENCE,
            "iat": now,
            "exp": vaikor_grant::add_rfc3339_z(&now, 60).ok_or("clock")?,
            "cnf": {"kid": core},
            "chain": [],
            "rights": [{"action": "import", "resource": record.resource().map_err(|e| e.to_string())?}],
        }),
        log_seed,
        &core,
    );
    let mut store = Store::open_with_owner_and_log(
        workspace_dir,
        &workspace_dir.join("logs").join(RECORD_LOG_FILE),
        log_seed,
        vec![manifest.edge1_did.clone()],
        &manifest.owner_did,
    )?;
    // The grant is the whole authority: one import of this record's class, issued above.
    let access = Access {
        grant: Some(&grant),
        holder: &core,
        audience: TASK_RECORD_AUDIENCE,
        policy: &vaikor_grant::PermitAll,
    };
    let digest = store.import(
        &record.canonical_bytes().map_err(|e| e.to_string())?,
        &access,
    )?;
    drop(store);
    let pointer = serde_json::json!({"record": format!("tag:vaikor.com,2026:record:{digest}")});
    write_private(
        &workspace_dir.join("records").join("latest-record.json"),
        serde_json::to_string_pretty(&pointer)
            .map_err(|e| e.to_string())?
            .as_bytes(),
    )?;
    Ok(workspace_dir.join("records").join(digest))
}

/// A workspace file that may be missing: `None` when it does not exist.
fn read_optional(path: &Path) -> Result<Option<String>, String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Run a natural-language task end-to-end (`vaikor task "<Prompt>" [--workspace <dir>] [--hybrid]`)
/// with the node's Model -1 (`model.endpoint` in the workspace `config.json`).
pub fn execute_turnkey_task(
    workspace_dir: &Path,
    utterance: &str,
    hybrid: bool,
) -> Result<TurnkeyTaskSummary, String> {
    if !workspace_dir.join("manifest.json").exists() {
        bootstrap_workspace(workspace_dir)?;
    }
    let config: Value = match fs::read_to_string(workspace_dir.join("config.json")) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| format!("config.json: {e}"))?,
        Err(_) => Value::Object(Default::default()),
    };
    let model = LocalLinguist::from_config(&config)?.ok_or(
        "model-not-configured: serve Model -1 with scripts/serve-local-linguist.sh --workspace <dir>",
    )?;
    execute_turnkey_task_with(workspace_dir, utterance, hybrid, &model)
}

/// Run a task with a given linguist. The intent comes from the catalog as verified by the
/// Core (0017 L2); residency comes from the Core, never from the model.
pub fn execute_turnkey_task_with(
    workspace_dir: &Path,
    utterance: &str,
    hybrid: bool,
    model: &dyn LinguistModel,
) -> Result<TurnkeyTaskSummary, String> {
    execute_turnkey_task_presented(workspace_dir, utterance, hybrid, model, None)
}

/// [`execute_turnkey_task_with`] with another presenter than the node's executor key: the
/// tests of proof of possession (0002 R25) present with a wrong key, for another plan, or a
/// replayed proof.
#[doc(hidden)]
pub fn execute_turnkey_task_presented(
    workspace_dir: &Path,
    utterance: &str,
    hybrid: bool,
    model: &dyn LinguistModel,
    presenter: Option<&dyn Presenter>,
) -> Result<TurnkeyTaskSummary, String> {
    if !workspace_dir.join("manifest.json").exists() {
        bootstrap_workspace(workspace_dir)?;
    }

    let catalog = IntentCatalog::builtin()?;
    let verified = catalog.understand(model, utterance)?;
    if verified.needs_clarification() {
        let envelope = verified.envelope;
        return Ok(TurnkeyTaskSummary {
            clarification_needed: true,
            clarification_question: envelope.clarification_question_local,
            canonical_intent: envelope.canonical_intent_en.unwrap_or_default(),
            ..TurnkeyTaskSummary::default()
        });
    }
    if hybrid {
        return Err("hybrid-planning-unavailable: catalog intents are planned on this node; cloud planning \
            applies to model-planned intents (roadmap WP 11d)"
            .into());
    }
    run_verified_intent_presented(workspace_dir, &catalog, &verified, presenter)
}

/// Plan a complete, Core-verified intent from the catalog and run it on this node
/// (0017 PL1-PL5, X1-X5): no automatic approval, every step audited, and a signed record
/// whose content is exactly the step outcomes. Shared by `vaikor task` and the companion.
pub fn run_verified_intent(
    workspace_dir: &Path,
    catalog: &IntentCatalog,
    verified: &VerifiedIntent,
) -> Result<TurnkeyTaskSummary, String> {
    run_verified_intent_presented(workspace_dir, catalog, verified, None)
}

/// [`run_verified_intent`] with another presenter than the node's executor key (tests of
/// 0002 R25).
#[doc(hidden)]
pub fn run_verified_intent_presented(
    workspace_dir: &Path,
    catalog: &IntentCatalog,
    verified: &VerifiedIntent,
    presenter: Option<&dyn Presenter>,
) -> Result<TurnkeyTaskSummary, String> {
    if verified.needs_clarification() {
        return Err("clarification-needed: the intent is not complete".into());
    }
    let read_json = |name: &str| -> Result<Value, String> {
        serde_json::from_str(
            &fs::read_to_string(workspace_dir.join(name)).map_err(|e| format!("{name}: {e}"))?,
        )
        .map_err(|e| format!("{name}: {e}"))
    };
    let manifest: WorkspaceManifest =
        serde_json::from_value(read_json("manifest.json")?).map_err(|e| e.to_string())?;
    let capabilities = read_json("catalog.json")?;
    let config = read_json("config.json").unwrap_or_else(|_| Value::Object(Default::default()));
    let policy_src =
        fs::read_to_string(workspace_dir.join("policy.cedar")).map_err(|e| e.to_string())?;
    let flow_policy = CedarFlowPolicy::from_sources(&[&policy_src])?;
    let canonical = verified
        .envelope
        .canonical_intent_en
        .clone()
        .unwrap_or_default();

    let checked = match plan_for_intent(
        catalog,
        verified,
        &capabilities,
        &flow_policy,
        &manifest.owner_did,
    ) {
        Ok(checked) => checked,
        Err(refusal) => {
            return Ok(TurnkeyTaskSummary {
                canonical_intent: canonical,
                plan_refusal: Some(refusal.to_string()),
                ..TurnkeyTaskSummary::default()
            })
        }
    };

    // Invariant 9: the chain is opened and verified before the first step, and each step's
    // decision is appended before its effect. A locked, corrupt or unwritable log stops here.
    let keys_dir = workspace_dir.join("keys");
    let edge1_seed = read_seed_file(&keys_dir.join("edge1.key"))?;
    let log_seed = read_seed_file(&keys_dir.join("log.key"))?;
    let mut chain = Chain::open(&workspace_dir.join("logs").join("audit.log"), &log_seed)?;

    let now = vaikor_gateway::utc_stamp();
    let executors = NodeExecutors::for_workspace(workspace_dir, &config)?;

    // Invariant 2, 0002 §6a: no step runs without a task token the owner's mandate covers,
    // its period budget replayed from this chain, presented with the executor key (R25).
    // A refusal is audited and nothing runs.
    let files = read_optional(&workspace_dir.join(MANDATE_FILE))
        .and_then(|text| {
            text.map(|text| {
                serde_json::from_str::<Value>(&text).map_err(|e| format!("owner mandate: {e}"))
            })
            .transpose()
        })
        .and_then(|mandate| {
            Ok((
                mandate,
                read_optional(&workspace_dir.join(GRANT_POLICY_FILE))?,
            ))
        });
    let (mandate, grant_policy) = match files {
        Ok(files) => files,
        Err(reason) => {
            chain.append(&grant_denial(&reason, &now))?;
            return Err(format!("grant-denied: {reason}"));
        }
    };
    let executor_key = HolderKey::new(edge1_seed);

    // `vaikor task` has no Trusted UI channel: consequential steps are denied, never auto-approved.
    let report = run_plan(
        &checked,
        &capabilities,
        &executors,
        &NoTrustedUi,
        GrantSource::Mandate {
            mandate: mandate.as_ref(),
            policy: grant_policy.as_deref(),
            owner: &manifest.owner_did,
            audience: &manifest.edge1_did,
            executor_seed: &edge1_seed,
            presenter: presenter.unwrap_or(&executor_key),
        },
        Flow::Cedar {
            policy: &flow_policy,
            owner: &manifest.owner_did,
        },
        &mut chain,
        &now,
    );
    drop(chain);
    let report = match report {
        Ok(report) => report,
        Err(refusal) if refusal.stage == Stage::Grant => {
            return Err(format!("grant-denied: {}", refusal.message))
        }
        Err(refusal) => return Err(refusal.message),
    };

    let mut timeline = Vec::new();
    let mut body = String::new();
    for step in &report.steps {
        let gate = checked.approvals.contains(&step.id);
        timeline.push(StepTimelineItem {
            step_id: step.id.clone(),
            label: step
                .capability
                .trim_start_matches("tag:vaikor.com,2026:capability:")
                .to_string(),
            status: if step.status == "denied" {
                "refused".into()
            } else {
                step.status.clone()
            },
            worker_id: None,
            requires_owner_gate: gate,
        });
        body.push_str(&format!(
            "- `{}` {}: **{}**\n",
            step.id, step.capability, step.status
        ));
        if let Some(reason) = &step.reason {
            body.push_str(&format!("  - {reason}\n"));
        }
        if let Some(output) = &step.output {
            let text = serde_json::to_string_pretty(output).map_err(|e| e.to_string())?;
            let text: String = text.chars().take(4000).collect();
            body.push_str(&format!("\n```json\n{text}\n```\n"));
        }
    }
    let completed = report
        .steps
        .iter()
        .filter(|s| s.status == "completed")
        .count();
    if let Some(failure) = &report.audit_failure {
        body.push_str(&format!("\n**Audit:** {failure}\n"));
    }
    let payload = ArtifactPayload::Solution(SolutionArtifact {
        title: canonical.clone(),
        summary: format!(
            "{completed} of {} steps completed on this node",
            report.steps.len()
        ),
        markdown_body: body,
        reusable_plan_digest: checked.digest.clone(),
    });
    let source = report
        .steps
        .iter()
        .rev()
        .find(|s| s.status == "completed")
        .or(report.steps.first())
        .map(|s| s.capability.clone())
        .unwrap_or_default();
    let record = sign_artifact_record(
        &payload,
        &manifest.owner_did,
        &source,
        &now,
        vec![],
        Some(checked.digest.clone()),
        vec!["CH".into()],
        &edge1_seed,
    )
    .map_err(|e| e.code().to_string())?;
    // The badge reports what happened, not what the plan intended.
    let has = |status: &str| report.steps.iter().any(|s| s.status == status);
    let grant_denied = report.steps.iter().any(|s| {
        s.status == "denied"
            && s.reason
                .as_deref()
                .is_some_and(|r| r.starts_with("grant denied"))
    });
    let label = if report.audit_failure.is_some() {
        "Stopped: the audit log did not record a step"
    } else if grant_denied {
        "Stopped: the owner's mandate does not allow a step"
    } else if report.completed {
        "Planned and run on this node"
    } else if has("denied") {
        "Stopped: a consequential step needs Trusted UI approval"
    } else if has("refused") {
        "Stopped: a step has no backend on this node"
    } else {
        "Stopped before every step ran"
    };
    let badge = FlowBadgeSpec {
        mode: "local".into(),
        label: label.into(),
        residency: vec!["CH".into()],
    };
    let surface = build_result_surface(&record, &canonical, 0, &badge, &timeline)
        .map_err(|e| e.code().to_string())?;

    let record_id = record.identifier().map_err(|e| e.code().to_string())?;
    let record_path = store_task_record(workspace_dir, &manifest, &log_seed, &record)?;
    let surface_path: PathBuf = workspace_dir.join("views").join("latest-surface.json");
    fs::write(
        &surface_path,
        serde_json::to_string_pretty(&surface).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    Ok(TurnkeyTaskSummary {
        canonical_intent: canonical,
        artifact_mime: MIME_ARTIFACT_SOLUTION.into(),
        record_id: Some(record_id),
        plan_digest: Some(checked.digest),
        record_path: Some(record_path.display().to_string()),
        surface_path: Some(surface_path.display().to_string()),
        flow_badge_label: Some(label.into()),
        steps_executed: completed,
        audit_failure: report.audit_failure,
        steps: report.steps,
        ..TurnkeyTaskSummary::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn default_catalog_is_vkr_l1_with_schemas_and_spec_effect_names() {
        let catalog = default_catalog();
        vaikor_capability::Registry::from_descriptors(&catalog).unwrap();
        for descriptor in catalog.as_array().unwrap() {
            let id = descriptor["id"].as_str().unwrap();
            assert_eq!(descriptor["input_schema"]["type"], "object", "{id}");
            assert!(descriptor["cost"]["class"].is_string(), "{id}");
            for effect in descriptor["effects"].as_array().unwrap() {
                assert!(
                    ["read", "write", "delete", "execute", "egress"]
                        .contains(&effect.as_str().unwrap()),
                    "{id}: {effect}"
                );
            }
        }
        // The verifier and the Cedar flow check see message.send as egress of its data class.
        let send = catalog
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["id"] == "tag:vaikor.com,2026:capability:message.send")
            .unwrap();
        assert_eq!(send["effects"], json!(["egress"]));
        assert_eq!(send["data_classes"], json!(["communications.content"]));
    }
}
