// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! The node's executors (WP 11b), the backend of the one engine ([`crate::engine`]) on
//! `sidged task` and the companion.
//!
//! Each step's arguments are resolved (`lit`, or an earlier step's output for `ref`),
//! checked against the capability `input_schema`, executed by the node's executor for that
//! capability, and the output is checked against `output_schema`. A capability with no
//! backend on this node refuses. Nothing is invented: the run report holds exactly what
//! executors returned. Grant, approval and audit order are the engine's.
//!
//! The owner's files live under `<workspace>/files/`; the node's keys, logs and records
//! are outside that root and unreachable for every executor: the root is one directory
//! handle and every file operation resolves beneath it ([`crate::contained`]). Timers and
//! reminders are node state next to the root, changed under a lock and replaced atomically.

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sidged_capability::{schema, Registry};
use sidged_core::AuditEvent;
use sidged_gateway::local_model::{model_endpoint, LocalModel, ModelEndpoint};
use sidged_verify::{Arg, Plan, Step};

use crate::approval::{ApprovalChannel, ApprovalDecision, ApprovalRequest};
use crate::contained::{Dir, Kind};
pub use crate::engine::StepOutcome;
use crate::engine::{
    Admit, AuditSink, Backend, Dispatched, EngineInput, Flow, GrantSource, Preflight, Refusal,
    StepCall,
};
use crate::intent_plan::CheckedIntentPlan;
use crate::linguist::reply_from_response;

const MAX_READ_BYTES: u64 = 1024 * 1024;
const MAX_FIND_ENTRIES: usize = 2000;
const MAX_MATCHES: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RunReport {
    pub plan_digest: String,
    pub completed: bool,
    pub steps: Vec<StepOutcome>,
    /// Why the audit sink stopped the run: a step's decision or outcome was not recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_failure: Option<String>,
}

/// The approval channel of a node without a Trusted UI: every consequential step is denied.
pub struct NoTrustedUi;

impl ApprovalChannel for NoTrustedUi {
    fn decide(&self, _request: &ApprovalRequest, now: &str) -> ApprovalDecision {
        ApprovalDecision {
            granted: false,
            actor: "no Trusted UI channel on this node".into(),
            at: now.into(),
        }
    }
}

/// The local executors of a node workspace.
pub struct NodeExecutors {
    workspace: PathBuf,
    files: Dir,
    generator: Option<ModelEndpoint>,
    timezone: Option<chrono_tz::Tz>,
}

fn text_arg<'a>(args: &'a Value, name: &str) -> Result<&'a str, String> {
    args.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("argument {name} is missing"))
}

/// Word forms of durations (`assets/duration-lexicon.json`, en/de/gsw).
pub const DURATION_LEXICON_JSON: &str = include_str!("../assets/duration-lexicon.json");

const MAX_DURATION_SECONDS: f64 = 30.0 * 86400.0;

enum DurationWord {
    Unit(f64),
    Article,
    Number(f64),
    Fraction(f64),
    Connector,
    Filler,
}

fn duration_lexicon() -> &'static std::collections::HashMap<String, DurationWord> {
    static LEXICON: std::sync::OnceLock<std::collections::HashMap<String, DurationWord>> =
        std::sync::OnceLock::new();
    LEXICON.get_or_init(|| {
        let doc: Value = serde_json::from_str(DURATION_LEXICON_JSON).expect("duration lexicon");
        let mut words = std::collections::HashMap::new();
        let mut keyed = |section: &str, make: fn(f64) -> DurationWord| {
            for (value, forms) in doc[section].as_object().expect("lexicon section") {
                let value: f64 = value.parse().expect("lexicon value");
                for form in forms.as_array().expect("lexicon forms") {
                    words.insert(form.as_str().expect("form").to_string(), make(value));
                }
            }
        };
        keyed("units", DurationWord::Unit);
        keyed("numbers", DurationWord::Number);
        keyed("fractions", DurationWord::Fraction);
        type Make = fn() -> DurationWord;
        let plain: [(&str, Make); 3] = [
            ("articles", || DurationWord::Article),
            ("connectors", || DurationWord::Connector),
            ("fillers", || DurationWord::Filler),
        ];
        for (section, make) in plain {
            for form in doc[section].as_array().expect("lexicon list") {
                words.insert(form.as_str().expect("form").to_string(), make());
            }
        }
        words
    })
}

/// Split `10min`, `1,5h` and `zwänzg-minute` into number and word tokens.
fn duration_tokens(text: &str) -> Vec<String> {
    let (mut tokens, mut cur, mut digits) = (Vec::new(), String::new(), false);
    for c in text.to_lowercase().chars() {
        let decimal = (c == ',' || c == '.') && digits;
        if c.is_whitespace() || c == '-' || (c == ',' && !decimal) {
            tokens.extend((!cur.is_empty()).then(|| std::mem::take(&mut cur)));
            continue;
        }
        let numeric = c.is_ascii_digit() || decimal;
        if !cur.is_empty() && numeric != digits {
            tokens.push(std::mem::take(&mut cur));
        }
        digits = numeric;
        cur.push(c);
    }
    tokens.extend((!cur.is_empty()).then_some(cur));
    tokens
}

/// Seconds in a duration slot: ISO 8601 `PT…`, or a sum of `[number|article] [fraction]
/// unit` groups in the lexicon's word forms (`10 minutes`, `e haubi Stund`,
/// `1 Stunde und 30 Minuten`). Anything the lexicon does not cover is refused.
pub fn duration_seconds(text: &str) -> Option<u64> {
    let iso = text.trim().to_ascii_uppercase();
    if let Some(rest) = iso.strip_prefix("PT") {
        return iso_duration(rest);
    }
    let lexicon = duration_lexicon();
    let mut total = 0.0;
    let mut amount: Option<f64> = None;
    for token in duration_tokens(text) {
        if let Ok(n) = token.replace(',', ".").parse::<f64>() {
            if amount.is_some() {
                return None;
            }
            amount = Some(n);
            continue;
        }
        match lexicon.get(token.as_str())? {
            DurationWord::Number(n) => {
                amount = match amount {
                    None => Some(*n),
                    // `twenty five`
                    Some(tens) if tens >= 20.0 && tens % 10.0 == 0.0 && *n < 10.0 => Some(tens + n),
                    Some(_) => return None,
                }
            }
            DurationWord::Article => {
                amount.get_or_insert(1.0);
            }
            DurationWord::Fraction(f) => amount = Some(amount.unwrap_or(1.0) * f),
            DurationWord::Unit(seconds) => total += amount.take()? * seconds,
            DurationWord::Connector => {
                if amount.is_some() {
                    return None;
                }
            }
            DurationWord::Filler => {}
        }
    }
    if amount.is_some() || !(total > 0.0 && total <= MAX_DURATION_SECONDS) {
        return None;
    }
    Some(total.round() as u64)
}

fn iso_duration(rest: &str) -> Option<u64> {
    let (mut total, mut number) = (0u64, String::new());
    for c in rest.chars() {
        if c.is_ascii_digit() {
            number.push(c);
            continue;
        }
        let factor = match c {
            'H' => 3600,
            'M' => 60,
            'S' => 1,
            _ => return None,
        };
        total = total.checked_add(number.parse::<u64>().ok()?.checked_mul(factor)?)?;
        number.clear();
    }
    (number.is_empty() && total > 0 && total as f64 <= MAX_DURATION_SECONDS).then_some(total)
}

fn add_seconds(now: &str, seconds: u64) -> Option<String> {
    sidged_grant::add_rfc3339_z(now, i64::try_from(seconds).ok()?)
}

impl NodeExecutors {
    /// Executors for a node workspace; `config` is its `config.json` (an optional
    /// `generator` endpoint enables `text.generate_local`; `timezone`, an IANA name,
    /// lets reminders resolve clock times). The files root is opened here, once: a root
    /// that is a symlink or not a directory of the Core uid is refused.
    pub fn for_workspace(workspace: &Path, config: &Value) -> Result<Self, String> {
        let generator = model_endpoint(
            &json!({"model": config.get("generator").cloned().unwrap_or(Value::Null)}),
        )?;
        let timezone = match config.get("timezone") {
            None | Some(Value::Null) => None,
            Some(Value::String(name)) => {
                Some(crate::when::parse_timezone(name).map_err(|e| format!("config.json: {e}"))?)
            }
            Some(_) => return Err("config.json: timezone must be a string".into()),
        };
        Ok(Self {
            workspace: workspace.to_path_buf(),
            files: Dir::files_of(workspace)?,
            generator,
            timezone,
        })
    }

    /// Add `entry` to the node state list `name` under its lock file, with an id that
    /// never repeats (random), and replace the list atomically: a concurrent writer waits,
    /// a reader sees the old or the new list, never a part.
    fn append_state(&self, name: &str, entry: Value) -> Result<String, String> {
        let path = self.workspace.join(name);
        let _lock = lock_state(&self.workspace.join(format!("{name}.lock")))?;
        let mut list: Vec<Value> = match read_state(&path)? {
            Some(text) => serde_json::from_str(&text).map_err(|e| format!("{name}: {e}"))?,
            None => Vec::new(),
        };
        let id = format!(
            "{}-{}",
            name.trim_end_matches(".json"),
            crate::engine::fresh_hex(16)?
        );
        let mut entry = entry;
        entry["id"] = json!(id);
        list.push(entry);
        let text = serde_json::to_string_pretty(&list).map_err(|e| e.to_string())?;
        replace_state(&path, text.as_bytes())?;
        Ok(id)
    }

    /// Execute one capability with checked arguments.
    pub fn execute(&self, capability: &str, args: &Value, now: &str) -> Result<Value, String> {
        let name = capability
            .strip_prefix("urn:sidged:capability:")
            .ok_or("not a sidged capability")?;
        match name {
            "workspace.read" => {
                let rel = text_arg(args, "path")?;
                let file = self.files.open_read(rel)?;
                let meta = file.metadata().map_err(|e| e.to_string())?;
                if meta.len() > MAX_READ_BYTES {
                    return Err("not a regular file of at most 1 MiB".into());
                }
                let mut text = String::new();
                file.take(MAX_READ_BYTES)
                    .read_to_string(&mut text)
                    .map_err(|_| "file is not UTF-8 text".to_string())?;
                Ok(json!({"path": rel, "text": text}))
            }
            "workspace.write" => {
                let rel = text_arg(args, "path")?;
                let text = text_arg(args, "text")?;
                let mut file = self.files.open_write(rel, false)?;
                file.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
                Ok(json!({"path": rel, "bytes": text.len()}))
            }
            "notes.append" => {
                let rel = "notes/inbox.md";
                let line = format!("- {now} {}\n", text_arg(args, "text")?.replace('\n', " "));
                let mut file = self.files.open_write(rel, true)?;
                file.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
                Ok(json!({"path": rel, "bytes": line.len()}))
            }
            "workspace.find" => {
                let tokens: Vec<String> = text_arg(args, "query")?
                    .to_lowercase()
                    .split(|c: char| !c.is_alphanumeric())
                    .filter(|t| t.len() >= 3 && !["the", "and", "for", "from", "with"].contains(t))
                    .map(str::to_string)
                    .collect();
                // Every directory is opened by its whole path from the files root, never from
                // a handle of a parent that may have moved; links are skipped. One entry
                // budget covers the whole walk, and the walk stops when it is spent.
                let start = match args.get("folder").and_then(Value::as_str) {
                    Some(folder) => {
                        let folder = folder.trim_end_matches('/');
                        self.files.subdir(folder)?;
                        Some(folder.to_string())
                    }
                    None => None,
                };
                let mut matches = Vec::new();
                let mut budget = MAX_FIND_ENTRIES;
                let mut stack = vec![start];
                while let Some(prefix) = stack.pop() {
                    if budget == 0 || matches.len() >= MAX_MATCHES {
                        break;
                    }
                    let dir = match &prefix {
                        Some(path) => self.files.subdir(path),
                        None => self.files.subdir_self(),
                    };
                    let Ok((entries, examined)) = dir.and_then(|dir| dir.entries(budget)) else {
                        continue;
                    };
                    budget -= examined;
                    for (name, kind) in entries {
                        if matches.len() >= MAX_MATCHES {
                            break;
                        }
                        let rel = match &prefix {
                            Some(path) => format!("{path}/{name}"),
                            None => name,
                        };
                        match kind {
                            Kind::Dir => stack.push(Some(rel)),
                            Kind::File => {
                                let lower = rel.to_lowercase();
                                if !tokens.is_empty()
                                    && tokens.iter().any(|t| lower.contains(t.as_str()))
                                {
                                    matches.push(json!({"path": rel}));
                                }
                            }
                            Kind::Other => {}
                        }
                    }
                }
                matches.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
                Ok(json!({"matches": matches}))
            }
            "timer.start" => {
                let duration = text_arg(args, "duration")?;
                let ends_at = duration_seconds(duration)
                    .and_then(|s| add_seconds(now, s))
                    .ok_or_else(|| format!("cannot read the duration {duration:?}"))?;
                let mut entry =
                    json!({"duration": duration, "started_at": now, "ends_at": ends_at});
                if let Some(label) = args.get("label") {
                    entry["label"] = label.clone();
                }
                let id = self.append_state("timers.json", entry)?;
                Ok(json!({"timer_id": id, "ends_at": ends_at}))
            }
            "reminder.create" => {
                let time = text_arg(args, "time")?;
                let tz = match self.timezone {
                    Some(tz) => tz,
                    None if crate::when::is_relative(time) => chrono_tz::UTC,
                    None => {
                        return Err("the node has no time zone (timezone in config.json)".into())
                    }
                };
                let now_utc = chrono::DateTime::parse_from_rfc3339(now)
                    .map_err(|e| format!("clock: {e}"))?
                    .with_timezone(&chrono::Utc);
                let due_at = crate::when::resolve(time, now_utc, tz)
                    .ok_or_else(|| format!("cannot read the time {time:?}"))?
                    .to_rfc3339();
                let id = self.append_state(
                    "reminders.json",
                    json!({"subject": text_arg(args, "subject")?, "time": time, "due_at": due_at, "created_at": now}),
                )?;
                Ok(json!({"reminder_id": id, "due_at": due_at}))
            }
            "text.generate_local" => {
                let endpoint = self.generator.clone().ok_or(
                    "no local generator model is configured on this node (config.json generator)",
                )?;
                let mut prompt = text_arg(args, "instruction")?.to_string();
                if let Some(text) = args.get("text").and_then(Value::as_str) {
                    prompt.push_str("\n\n");
                    prompt.push_str(text);
                }
                let body = json!({
                    "messages": [
                        {"role": "system", "content": "Follow the instruction. Reply with the result only."},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                    "max_tokens": 1024,
                    "stream": false,
                    "chat_template_kwargs": {"enable_thinking": false},
                });
                let raw = LocalModel::new(endpoint).complete(&body.to_string())?;
                Ok(json!({"text": reply_from_response(&raw)?}))
            }
            other => Err(format!("no backend for {other} on this node")),
        }
    }
}

/// The exclusive lock of one node state file, held until the returned file is dropped.
fn lock_state(path: &Path) -> Result<fs::File, String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    loop {
        // SAFETY: flock on an open descriptor owned by `file`.
        if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) } == 0 {
            return Ok(file);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(format!("{}: {err}", path.display()));
        }
    }
}

/// A node state file, `None` when it does not exist yet; a symlink is refused.
fn read_state(path: &Path) -> Result<Option<String>, String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path);
    let mut file = match file {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Some(text))
}

/// Replace `path` with `bytes`: a 0600 temporary file, synced, renamed over it, and the
/// directory synced. The caller holds the state lock, so the temporary name is its own.
fn replace_state(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let name = path.file_name().ok_or("state file name")?.to_string_lossy();
    let dir = path.parent().ok_or("state directory")?;
    let tmp = dir.join(format!(".{name}.tmp"));
    let _ = fs::remove_file(&tmp);
    let written = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        fs::File::open(dir)?.sync_all()
    })();
    written.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("{}: {e}", path.display())
    })
}

fn descriptor<'a>(catalog: &'a Value, id: &str) -> Option<&'a Value> {
    catalog.as_array()?.iter().find(|d| d["id"] == id)
}

/// The node backend: the local executors under the node's capability catalog.
struct NodeBackend<'a> {
    executors: &'a NodeExecutors,
    capabilities: &'a Value,
}

impl Backend for NodeBackend<'_> {
    fn preflight(&mut self, _: &Plan, _: &Registry, _: &str) -> Result<(), Preflight> {
        Ok(())
    }

    fn admit(&self, step: &Step) -> Admit {
        match step {
            Step::Call { .. } => Admit::Run,
            Step::Map { .. } => Admit::Refuse("a map step does not run on this node".into()),
            Step::Expr { .. } => Admit::Refuse("an expr step does not run on this node".into()),
        }
    }

    /// 0003 R4a: exactly the referenced value, the whole output or the named member; an
    /// argument without one refuses the step rather than taking a substitute.
    fn arguments(&self, call: &StepCall, outputs: &[(String, Value)]) -> Result<Value, String> {
        let mut args = serde_json::Map::new();
        for (name, arg) in call.args {
            let value =
                match arg {
                    Arg::Lit(value) => Some(value.clone()),
                    Arg::Ref { step, field } => outputs.iter().find(|(k, _)| k == step).and_then(
                        |(_, output)| match field {
                            None => Some(output.clone()),
                            Some(field) => output.get(field).cloned(),
                        },
                    ),
                    Arg::Item => None,
                };
            let value = value.ok_or_else(|| match arg {
                Arg::Ref {
                    step,
                    field: Some(field),
                } => format!("argument {name}: {step} has no output member {field}"),
                Arg::Ref { step, .. } => format!("argument {name}: {step} has no output"),
                _ => format!("argument {name} has no value outside a map"),
            })?;
            args.insert(name.clone(), value);
        }
        let args = Value::Object(args);
        let desc = descriptor(self.capabilities, call.capability).ok_or("no descriptor")?;
        let problems = schema::validate(&desc["input_schema"], &args);
        if !problems.is_empty() {
            return Err(format!("input: {}", problems.join("; ")));
        }
        Ok(args)
    }

    fn intent_report(&self, _: &StepCall, _: &Value) -> Result<Option<(String, bool)>, String> {
        Ok(None)
    }

    fn dispatch(&self, call: &StepCall, args: &Value) -> Dispatched {
        let (status, output, reason) = match self.executors.execute(call.capability, args, call.now)
        {
            Ok(output) => {
                let problems = descriptor(self.capabilities, call.capability)
                    .and_then(|d| d.get("output_schema"))
                    .map(|s| schema::validate(s, &output))
                    .unwrap_or_default();
                if problems.is_empty() {
                    ("completed", Some(output), None)
                } else {
                    (
                        "failed",
                        None,
                        Some(format!("output: {}", problems.join("; "))),
                    )
                }
            }
            Err(reason) => {
                let status = if reason.starts_with("no backend")
                    || reason.starts_with("no local generator")
                {
                    "refused"
                } else {
                    "failed"
                };
                (status, None, Some(reason))
            }
        };
        Dispatched {
            status,
            outcome: Some(AuditEvent {
                privacy_report: None,
                usage: None,
                reason: reason.clone(),
                step: call.id.into(),
                capability: call.capability.into(),
                effects: call.record.effects.clone(),
                data_classes: call.record.data_classes.clone(),
                decision: status.into(),
                actor: "core".into(),
                at: call.now.into(),
                approval: None,
            }),
            output,
            reason,
            report: None,
        }
    }
}

/// Run a checked plan on this node through the one engine (invariant 2, 0002 §6a, 0005 R5a):
/// the grant from `grant`, every step authorised and reserved before its decision, the
/// decision on `audit` before the executor runs, the outcome after it; a failed append stops
/// the plan (`RunReport::audit_failure`). The error is a refusal before the first step,
/// already recorded on `audit`.
#[allow(clippy::too_many_arguments)]
pub fn run_plan(
    checked: &CheckedIntentPlan,
    capabilities: &Value,
    executors: &NodeExecutors,
    approver: &dyn ApprovalChannel,
    grant: GrantSource,
    flow: Flow,
    audit: &mut dyn AuditSink,
    now: &str,
) -> Result<RunReport, Refusal> {
    let report = crate::engine::run(
        &EngineInput {
            plan: &checked.plan,
            catalog: capabilities,
            flow,
            grant,
            approval: approver,
            dry_run: false,
            reserve_only: false,
            now,
        },
        &mut NodeBackend {
            executors,
            capabilities,
        },
        audit,
    );
    if let Some(refusal) = report.refusal {
        return Err(refusal);
    }
    Ok(RunReport {
        plan_digest: checked.digest.clone(),
        completed: report.audit_failure.is_none()
            && report.steps.iter().all(|o| o.status == "completed"),
        steps: report.steps,
        audit_failure: report.audit_failure,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::FixedApproval;
    use crate::intent_plan::plan_for_intent;
    use crate::linguist::{IntentCatalog, Ordered};
    use crate::turnkey::default_catalog;
    use sidged_verify::flow::{CedarFlowPolicy, DEFAULT_FLOW_POLICY};

    const NOW: &str = "2026-10-20T08:00:00Z";

    /// The engine without the grant layer: these tests cover audit order, references and
    /// executors on the node backend; tests/node_grant.rs covers the grant on both entry
    /// points. A plan refused before its first step fails the test.
    fn run_plan(
        checked: &CheckedIntentPlan,
        capabilities: &Value,
        executors: &NodeExecutors,
        approver: &dyn ApprovalChannel,
        audit: &mut dyn AuditSink,
        now: &str,
    ) -> RunReport {
        super::run_plan(
            checked,
            capabilities,
            executors,
            approver,
            GrantSource::Unchecked,
            Flow::Structural,
            audit,
            now,
        )
        .unwrap()
    }

    /// Events kept in memory in append order, standing in for the signed chain.
    #[derive(Debug, Default)]
    struct MemoryAudit {
        events: Vec<AuditEvent>,
    }

    impl AuditSink for MemoryAudit {
        fn decision(&mut self, event: &AuditEvent) -> Result<(), String> {
            self.events.push(event.clone());
            Ok(())
        }

        fn outcome(&mut self, event: &AuditEvent) -> Result<(), String> {
            self.events.push(event.clone());
            Ok(())
        }

        fn durable(&self) -> bool {
            true
        }

        fn history(&mut self) -> Result<Vec<AuditEvent>, String> {
            Ok(self.events.clone())
        }
    }
    const OWNER: &str = "did:key:z6MkwSD8dBdqcXQzKJZQFPy2hh2izzxskndKCjdmC2dBpfME";

    fn checked(intent: &str, slots: &[(&str, &str)]) -> CheckedIntentPlan {
        let intents = IntentCatalog::builtin().unwrap();
        let slots = Ordered(
            slots
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        );
        let envelope = intents.derive("en", Some(intent), &slots).unwrap();
        let verified = intents
            .verify_proposal(&serde_json::to_string(&envelope).unwrap())
            .unwrap();
        let policy = CedarFlowPolicy::from_sources(&[DEFAULT_FLOW_POLICY]).unwrap();
        plan_for_intent(&intents, &verified, &default_catalog(), &policy, OWNER).unwrap()
    }

    /// Executors create directories; other tests in this crate change the process-wide
    /// umask while binding the approval socket (0004 R9c), so these tests hold its lock.
    fn umask_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::approval::UMASK_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn workspace(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sidged-exec-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("files")).unwrap();
        fs::create_dir_all(dir.join("keys")).unwrap();
        fs::write(dir.join("keys/owner.key"), "secret").unwrap();
        dir
    }

    #[test]
    fn reminders_resolve_the_spoken_time_in_the_node_time_zone() {
        let _umask = umask_guard();
        let dir = workspace("remind");
        let plan = checked(
            "scheduling.remind",
            &[("subject", "the tax return"), ("time", "morn am füfi")],
        );
        let zurich =
            NodeExecutors::for_workspace(&dir, &json!({"timezone": "Europe/Zurich"})).unwrap();
        let report = run_plan(
            &plan,
            &default_catalog(),
            &zurich,
            &NoTrustedUi,
            &mut MemoryAudit::default(),
            NOW,
        );
        assert!(report.completed, "{report:?}");
        assert_eq!(
            report.steps[0].output.as_ref().unwrap()["due_at"],
            "2026-10-21T17:00:00+02:00"
        );
        let stored = fs::read_to_string(dir.join("reminders.json")).unwrap();
        assert!(stored.contains("morn am füfi") && stored.contains("2026-10-21T17:00:00+02:00"));

        // Without a time zone only relative times resolve; unknown words are refused.
        let plain = NodeExecutors::for_workspace(&dir, &json!({})).unwrap();
        let report = run_plan(
            &plan,
            &default_catalog(),
            &plain,
            &NoTrustedUi,
            &mut MemoryAudit::default(),
            NOW,
        );
        assert!(!report.completed);
        let relative = checked(
            "scheduling.remind",
            &[("subject", "the tea"), ("time", "in 20 minutes")],
        );
        let report = run_plan(
            &relative,
            &default_catalog(),
            &plain,
            &NoTrustedUi,
            &mut MemoryAudit::default(),
            NOW,
        );
        assert_eq!(
            report.steps[0].output.as_ref().unwrap()["due_at"],
            "2026-10-20T08:20:00+00:00"
        );
        let vague = checked(
            "scheduling.remind",
            &[("subject", "x"), ("time", "sometime soon")],
        );
        let report = run_plan(
            &vague,
            &default_catalog(),
            &zurich,
            &NoTrustedUi,
            &mut MemoryAudit::default(),
            NOW,
        );
        assert!(!report.completed, "{report:?}");
        assert!(NodeExecutors::for_workspace(&dir, &json!({"timezone": "Mars/Base"})).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn local_steps_run_and_the_report_holds_their_real_outputs() {
        let _umask = umask_guard();
        let dir = workspace("local");
        let exec = NodeExecutors::for_workspace(&dir, &json!({})).unwrap();
        let report = run_plan(
            &checked(
                "timer.set",
                &[("duration", "10 minutes"), ("label", "the tea")],
            ),
            &default_catalog(),
            &exec,
            &NoTrustedUi,
            &mut MemoryAudit::default(),
            NOW,
        );
        assert!(report.completed, "{report:?}");
        assert_eq!(
            report.steps[0].output.as_ref().unwrap()["ends_at"],
            "2026-10-20T08:10:00Z"
        );
        let report = run_plan(
            &checked("task.note", &[("content", "buy milk")]),
            &default_catalog(),
            &exec,
            &NoTrustedUi,
            &mut MemoryAudit::default(),
            NOW,
        );
        assert!(report.completed);
        let inbox = fs::read_to_string(dir.join("files/notes/inbox.md")).unwrap();
        assert_eq!(inbox, "- 2026-10-20T08:00:00Z buy milk\n");
        let report = run_plan(
            &checked("files.find", &[("query", "the inbox notes")]),
            &default_catalog(),
            &exec,
            &NoTrustedUi,
            &mut MemoryAudit::default(),
            NOW,
        );
        assert_eq!(
            report.steps[0].output.as_ref().unwrap()["matches"][0]["path"],
            "notes/inbox.md"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn consequential_steps_are_denied_without_a_trusted_ui_and_nothing_follows() {
        let _umask = umask_guard();
        let dir = workspace("deny");
        let exec = NodeExecutors::for_workspace(&dir, &json!({})).unwrap();
        fs::write(dir.join("files/report.md"), "quarterly numbers").unwrap();
        let report = run_plan(
            &checked(
                "share.offer",
                &[("item", "report.md"), ("recipient", "Anna")],
            ),
            &default_catalog(),
            &exec,
            &NoTrustedUi,
            &mut MemoryAudit::default(),
            NOW,
        );
        assert!(!report.completed);
        assert_eq!(report.steps[0].status, "completed");
        assert_eq!(
            report.steps[0].output.as_ref().unwrap()["text"],
            "quarterly numbers"
        );
        assert_eq!(report.steps[1].status, "denied");
        // Even with an approval the node has no message transport: an honest refusal.
        let approve = FixedApproval {
            granted: true,
            actor: "test".into(),
        };
        let report = run_plan(
            &checked(
                "share.offer",
                &[("item", "report.md"), ("recipient", "Anna")],
            ),
            &default_catalog(),
            &exec,
            &approve,
            &mut MemoryAudit::default(),
            NOW,
        );
        assert_eq!(report.steps[1].status, "refused");
        assert!(report.steps[1]
            .reason
            .as_deref()
            .unwrap()
            .starts_with("no backend"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn executors_cannot_reach_the_node_keys_and_missing_generators_refuse() {
        let _umask = umask_guard();
        let dir = workspace("keys");
        let exec = NodeExecutors::for_workspace(&dir, &json!({})).unwrap();
        let err = exec
            .execute(
                "urn:sidged:capability:workspace.read",
                &json!({"path": "../keys/owner.key"}),
                NOW,
            )
            .unwrap_err();
        assert!(err.contains("traversal"), "{err}");
        let report = run_plan(
            &checked("task.code", &[("description", "a CSV parser")]),
            &default_catalog(),
            &exec,
            &NoTrustedUi,
            &mut MemoryAudit::default(),
            NOW,
        );
        assert_eq!(report.steps[0].status, "refused");
        assert!(report.steps[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("generator"));
        let _ = fs::remove_dir_all(dir);
    }

    const READ: &str = "urn:sidged:capability:workspace.read";
    const WRITE: &str = "urn:sidged:capability:workspace.write";

    /// The node key outside the files root still holds what [`workspace`] wrote, and no
    /// file appeared next to it.
    fn assert_keys_untouched(dir: &Path) {
        assert_eq!(
            fs::read_to_string(dir.join("keys/owner.key")).unwrap(),
            "secret"
        );
        let names: Vec<_> = fs::read_dir(dir.join("keys"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["owner.key"], "a file was written outside files/");
    }

    #[test]
    fn no_read_or_write_leaves_the_files_root() {
        let _umask = umask_guard();
        let dir = workspace("contain");
        let exec = NodeExecutors::for_workspace(&dir, &json!({})).unwrap();
        let read = |path: &str| exec.execute(READ, &json!({"path": path}), NOW);
        let write = |path: &str| exec.execute(WRITE, &json!({"path": path, "text": "pwned"}), NOW);
        let absolute = dir.join("keys/owner.key").display().to_string();
        for path in [
            "../keys/owner.key",
            "docs/../../keys/owner.key",
            "/etc/passwd",
            absolute.as_str(),
            "",
        ] {
            assert!(read(path).is_err(), "read {path:?}");
            assert!(write(path).is_err(), "write {path:?}");
        }

        // A symlink swapped into the tree between two operations: the first goes to the
        // real directory, the second meets the link and is refused.
        assert!(write("docs/a.md").is_ok());
        assert_eq!(read("docs/a.md").unwrap()["text"], "pwned");
        fs::remove_dir_all(dir.join("files/docs")).unwrap();
        std::os::unix::fs::symlink(dir.join("keys"), dir.join("files/docs")).unwrap();
        for path in ["docs/owner.key", "docs/new.md", "docs/sub/new.md"] {
            assert!(read(path).is_err(), "read {path:?}");
            assert!(write(path).is_err(), "write {path:?}");
        }
        // A link as the last component, and a folder link for find.
        std::os::unix::fs::symlink(dir.join("keys/owner.key"), dir.join("files/key.md")).unwrap();
        assert!(read("key.md").is_err());
        assert!(write("key.md").is_err());
        let find = |folder: Option<&str>| {
            let mut args = json!({"query": "owner key"});
            if let Some(folder) = folder {
                args["folder"] = json!(folder);
            }
            exec.execute("urn:sidged:capability:workspace.find", &args, NOW)
        };
        assert_eq!(find(None).unwrap()["matches"], json!([]));
        assert!(find(Some("docs")).is_err());
        assert_keys_untouched(&dir);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_symlink_raced_into_the_tree_during_operations_never_leads_outside() {
        let _umask = umask_guard();
        let dir = workspace("race");
        let exec = NodeExecutors::for_workspace(&dir, &json!({})).unwrap();
        let files = dir.join("files");
        fs::create_dir(files.join("real")).unwrap();
        std::os::unix::fs::symlink(dir.join("keys"), files.join("link")).unwrap();
        let stop = std::sync::atomic::AtomicBool::new(false);
        let mut leaked = false;
        std::thread::scope(|s| {
            // `docs` flips between a real directory and a link to the node keys.
            s.spawn(|| {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = fs::rename(files.join("real"), files.join("docs"));
                    let _ = fs::rename(files.join("docs"), files.join("real"));
                    let _ = fs::rename(files.join("link"), files.join("docs"));
                    let _ = fs::rename(files.join("docs"), files.join("link"));
                }
            });
            let until = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !leaked && std::time::Instant::now() < until {
                let _ = exec.execute(
                    WRITE,
                    &json!({"path": "docs/owner.key", "text": "pwned"}),
                    NOW,
                );
                leaked = exec
                    .execute(READ, &json!({"path": "docs/owner.key"}), NOW)
                    .is_ok_and(|out| out["text"] == "secret");
            }
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        assert!(!leaked, "a read left the files root");
        assert_eq!(
            fs::read_to_string(dir.join("keys/owner.key")).unwrap(),
            "secret"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_files_root_that_is_a_symlink_is_refused() {
        let _umask = umask_guard();
        let dir = workspace("root-link");
        fs::remove_dir(dir.join("files")).unwrap();
        std::os::unix::fs::symlink(dir.join("keys"), dir.join("files")).unwrap();
        let leaked = NodeExecutors::for_workspace(&dir, &json!({})).and_then(|exec| {
            exec.execute(READ, &json!({"path": "owner.key"}), NOW)?;
            exec.execute(WRITE, &json!({"path": "new.md", "text": "pwned"}), NOW)
        });
        let err = leaked.unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        assert_keys_untouched(&dir);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_parent_moved_out_of_the_root_during_a_write_creates_nothing_outside() {
        let _umask = umask_guard();
        let dir = workspace("relocate");
        let exec = NodeExecutors::for_workspace(&dir, &json!({})).unwrap();
        let files = dir.join("files");
        let deep = "docs/a/b/c/d/e/f";
        let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut escaped = None;
        let mut round = 0;
        while escaped.is_none() && std::time::Instant::now() < until {
            round += 1;
            let out = dir.join(format!("out-{round}"));
            fs::create_dir_all(files.join(deep)).unwrap();
            let stop = std::sync::atomic::AtomicBool::new(false);
            let writes = std::sync::atomic::AtomicUsize::new(0);
            std::thread::scope(|s| {
                s.spawn(|| {
                    while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                        let n = writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let path = format!("{deep}/n{n}.txt");
                        let _ = exec.execute(WRITE, &json!({"path": path, "text": "x"}), NOW);
                    }
                });
                while writes.load(std::sync::atomic::Ordering::SeqCst) < 2 {
                    std::hint::spin_loop();
                }
                // `docs` leaves the root, then its leaf is renamed away: a write that still
                // holds a handle of the moved tree would recreate `f` outside the root.
                fs::rename(files.join("docs"), &out).unwrap();
                fs::rename(out.join("a/b/c/d/e/f"), out.join("f-moved")).unwrap();
                stop.store(true, std::sync::atomic::Ordering::SeqCst);
            });
            if out.join("a/b/c/d/e/f").exists() {
                escaped = Some(out.clone());
            }
            let _ = fs::remove_dir_all(&out);
        }
        assert_eq!(escaped, None, "a write created a directory outside files/");
        assert_keys_untouched(&dir);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn concurrent_writers_lose_no_timer_or_reminder_and_never_corrupt_the_state() {
        let _umask = umask_guard();
        let dir = workspace("concurrent");
        const WRITERS: usize = 8;
        const EACH: usize = 15;
        std::thread::scope(|s| {
            for writer in 0..WRITERS {
                let dir = &dir;
                s.spawn(move || {
                    // One executor per writer, as two processes on one node would have.
                    let exec = NodeExecutors::for_workspace(dir, &json!({})).unwrap();
                    for n in 0..EACH {
                        let label = format!("{writer}-{n}");
                        exec.execute(
                            "urn:sidged:capability:timer.start",
                            &json!({"duration": "10 minutes", "label": label}),
                            NOW,
                        )
                        .unwrap();
                        exec.execute(
                            "urn:sidged:capability:reminder.create",
                            &json!({"subject": label, "time": "in 20 minutes"}),
                            NOW,
                        )
                        .unwrap();
                    }
                });
            }
        });
        for (file, key) in [("timers.json", "label"), ("reminders.json", "subject")] {
            let list: Vec<Value> =
                serde_json::from_str(&fs::read_to_string(dir.join(file)).unwrap()).unwrap();
            assert_eq!(list.len(), WRITERS * EACH, "{file}");
            let ids: std::collections::BTreeSet<&str> =
                list.iter().map(|e| e["id"].as_str().unwrap()).collect();
            assert_eq!(ids.len(), list.len(), "{file}: an id repeats");
            let labels: std::collections::BTreeSet<&str> =
                list.iter().map(|e| e[key].as_str().unwrap()).collect();
            assert_eq!(labels.len(), list.len(), "{file}: an entry was lost");
        }
        // Nothing half-written is left behind.
        for entry in fs::read_dir(&dir).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(!name.ends_with(".tmp"), "{name}");
        }
        let _ = fs::remove_dir_all(dir);
    }

    /// Records events like [`MemoryAudit`] but fails the n-th decision or outcome append
    /// (counted from 1), as a locked, full or broken log would.
    #[derive(Default)]
    struct FailingAudit {
        fail_decision: Option<usize>,
        fail_outcome: Option<usize>,
        decisions: usize,
        outcomes: usize,
        recorded: MemoryAudit,
    }

    impl AuditSink for FailingAudit {
        fn decision(&mut self, event: &AuditEvent) -> Result<(), String> {
            self.decisions += 1;
            if self.fail_decision == Some(self.decisions) {
                return Err("disk full".into());
            }
            self.recorded.decision(event)
        }

        fn outcome(&mut self, event: &AuditEvent) -> Result<(), String> {
            self.outcomes += 1;
            if self.fail_outcome == Some(self.outcomes) {
                return Err("disk full".into());
            }
            self.recorded.outcome(event)
        }

        fn durable(&self) -> bool {
            true
        }

        fn history(&mut self) -> Result<Vec<AuditEvent>, String> {
            self.recorded.history()
        }
    }

    /// Three steps that each leave a trace on disk: a note, a timer and a written file
    /// (consequential, so it needs an approval).
    fn three_effects() -> CheckedIntentPlan {
        let plan = json!({"v": "0.1", "steps": [
            {"id": "note", "kind": "call", "capability": "urn:sidged:capability:notes.append",
             "args": {"text": {"lit": "buy milk"}}},
            {"id": "timer", "kind": "call", "capability": "urn:sidged:capability:timer.start",
             "args": {"duration": {"lit": "10 minutes"}}},
            {"id": "write", "kind": "call", "capability": "urn:sidged:capability:workspace.write",
             "approval": true,
             "args": {"path": {"lit": "out.md"}, "text": {"lit": "hello"}}},
        ]});
        CheckedIntentPlan {
            digest: sidged_verify::stored::plan_digest(&plan).unwrap(),
            plan,
            capabilities: Vec::new(),
            approvals: vec!["write".into()],
            egress: Vec::new(),
        }
    }

    fn approve() -> FixedApproval {
        FixedApproval {
            granted: true,
            actor: "owner".into(),
        }
    }

    fn statuses(report: &RunReport) -> Vec<&str> {
        report.steps.iter().map(|s| s.status.as_str()).collect()
    }

    fn trail(events: &[AuditEvent]) -> Vec<(&str, &str)> {
        events
            .iter()
            .map(|e| (e.step.as_str(), e.decision.as_str()))
            .collect()
    }

    #[test]
    fn every_step_is_decided_before_its_effect_and_its_outcome_follows() {
        let _umask = umask_guard();
        let dir = workspace("audit-order");
        let exec = NodeExecutors::for_workspace(&dir, &json!({})).unwrap();
        let mut audit = MemoryAudit::default();
        let report = run_plan(
            &three_effects(),
            &default_catalog(),
            &exec,
            &approve(),
            &mut audit,
            NOW,
        );
        assert!(report.completed, "{report:?}");
        assert_eq!(report.audit_failure, None);
        assert_eq!(
            trail(&audit.events),
            [
                ("note", "allow"),
                ("note", "completed"),
                ("timer", "allow"),
                ("timer", "completed"),
                ("write", "approve"),
                ("write", "completed"),
            ]
        );
        // 0004 R11: the approval names who decided, binds the arguments, and carries the
        // R9c fields; plain decisions are the Core's and carry none.
        let approved = &audit.events[4];
        assert_eq!(approved.actor, "owner");
        assert!(approved.approval.is_some());
        assert!(approved
            .reason
            .as_deref()
            .unwrap()
            .contains(&format!("plan_digest={}", three_effects().digest)));
        assert_eq!(audit.events[0].actor, "core");
        assert_eq!(audit.events[0].effects, ["write"]);
        assert!(audit.events[0].approval.is_none());
        assert_eq!(
            fs::read_to_string(dir.join("files/out.md")).unwrap(),
            "hello"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_decision_that_is_not_recorded_stops_the_plan_before_that_step_acts() {
        let _umask = umask_guard();
        for failing in 1..=3 {
            let dir = workspace(&format!("audit-decision-{failing}"));
            let exec = NodeExecutors::for_workspace(&dir, &json!({})).unwrap();
            let mut audit = FailingAudit {
                fail_decision: Some(failing),
                ..FailingAudit::default()
            };
            let report = run_plan(
                &three_effects(),
                &default_catalog(),
                &exec,
                &approve(),
                &mut audit,
                NOW,
            );
            assert!(!report.completed);
            let failure = report.audit_failure.as_deref().unwrap();
            assert!(failure.contains("did not run"), "{failure}");
            let step = &report.steps[failing - 1];
            assert_eq!(step.status, "refused");
            assert!(step.reason.as_deref().unwrap().contains("disk full"));
            assert!(report.steps[failing..]
                .iter()
                .all(|s| s.status == "skipped"));
            // Step N and every later step left nothing on disk; earlier steps did.
            let effects = [
                dir.join("files/notes/inbox.md").exists(),
                dir.join("timers.json").exists(),
                dir.join("files/out.md").exists(),
            ];
            for (n, happened) in effects.iter().enumerate() {
                assert_eq!(
                    *happened,
                    n + 1 < failing,
                    "step {} with decision {failing} failing",
                    n + 1
                );
            }
            // Only the earlier steps are in the log, each decided before its outcome.
            assert_eq!(audit.recorded.events.len(), 2 * (failing - 1));
            let _ = fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn an_outcome_that_is_not_recorded_stops_the_plan_and_the_report_says_it_is_unaudited() {
        let _umask = umask_guard();
        let dir = workspace("audit-outcome");
        let exec = NodeExecutors::for_workspace(&dir, &json!({})).unwrap();
        let mut audit = FailingAudit {
            fail_outcome: Some(1),
            ..FailingAudit::default()
        };
        let report = run_plan(
            &three_effects(),
            &default_catalog(),
            &exec,
            &approve(),
            &mut audit,
            NOW,
        );
        assert!(!report.completed);
        assert_eq!(statuses(&report), ["completed", "skipped", "skipped"]);
        // The note was written before the outcome append failed; the report says so.
        assert!(dir.join("files/notes/inbox.md").exists());
        assert!(report.steps[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("outcome is unaudited"));
        assert!(report
            .audit_failure
            .as_deref()
            .unwrap()
            .contains("outcome is unaudited"));
        assert!(!dir.join("timers.json").exists());
        assert!(!dir.join("files/out.md").exists());
        assert_eq!(trail(&audit.recorded.events), [("note", "allow")]);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn denied_and_refused_steps_are_audited_as_decisions_without_an_outcome() {
        let _umask = umask_guard();
        let dir = workspace("audit-deny");
        let exec = NodeExecutors::for_workspace(&dir, &json!({})).unwrap();
        // No Trusted UI: the consequential write is denied, never logged as allow (0005 R6).
        let mut audit = MemoryAudit::default();
        let report = run_plan(
            &three_effects(),
            &default_catalog(),
            &exec,
            &NoTrustedUi,
            &mut audit,
            NOW,
        );
        assert_eq!(statuses(&report), ["completed", "completed", "denied"]);
        let denial = audit.events.last().unwrap();
        assert_eq!(
            (denial.step.as_str(), denial.decision.as_str()),
            ("write", "deny")
        );
        assert!(denial.approval.is_some());
        assert_eq!(audit.events.len(), 5);
        assert!(!dir.join("files/out.md").exists());

        // Arguments that fail the input schema: a denial with the reason, nothing runs.
        let mut bad = three_effects();
        bad.plan["steps"][0]["args"] = json!({});
        let mut audit = MemoryAudit::default();
        let report = run_plan(&bad, &default_catalog(), &exec, &approve(), &mut audit, NOW);
        assert_eq!(statuses(&report), ["refused", "skipped", "skipped"]);
        assert_eq!(trail(&audit.events), [("note", "deny")]);
        assert!(audit.events[0]
            .reason
            .as_deref()
            .unwrap()
            .starts_with("input:"));
        let _ = fs::remove_dir_all(dir);
    }

    /// A file read followed by a note whose text is the given argument (0003 R4a).
    fn read_then_note(text: Value) -> CheckedIntentPlan {
        CheckedIntentPlan {
            plan: json!({"v": "0.1", "steps": [
                {"id": "read", "kind": "call", "capability": "urn:sidged:capability:workspace.read",
                 "args": {"path": {"lit": "report.md"}}},
                {"id": "note", "kind": "call", "capability": "urn:sidged:capability:notes.append",
                 "args": {"text": text}},
            ]}),
            digest: "plan-digest".into(),
            capabilities: Vec::new(),
            approvals: Vec::new(),
            egress: Vec::new(),
        }
    }

    #[test]
    fn a_ref_passes_exactly_the_referenced_value_or_the_step_is_refused() {
        let _umask = umask_guard();
        let dir = workspace("projection");
        let exec = NodeExecutors::for_workspace(&dir, &json!({})).unwrap();
        fs::write(dir.join("files/report.md"), "quarterly numbers").unwrap();
        let inbox = dir.join("files/notes/inbox.md");
        let run = |text: Value| {
            run_plan(
                &read_then_note(text),
                &default_catalog(),
                &exec,
                &NoTrustedUi,
                &mut MemoryAudit::default(),
                NOW,
            )
        };

        // The named member, not the member that happens to share the argument's name.
        let report = run(json!({"ref": "read", "field": "path"}));
        assert!(report.completed, "{report:?}");
        assert_eq!(
            fs::read_to_string(&inbox).unwrap(),
            "- 2026-10-20T08:00:00Z report.md\n"
        );
        fs::remove_file(&inbox).unwrap();
        let report = run(json!({"ref": "read", "field": "text"}));
        assert!(report.completed, "{report:?}");
        assert_eq!(
            fs::read_to_string(&inbox).unwrap(),
            "- 2026-10-20T08:00:00Z quarterly numbers\n"
        );
        fs::remove_file(&inbox).unwrap();

        // A bare ref is the whole output, an object: the consumer's input schema refuses it,
        // with no fallback to the output's `text` or its JSON.
        let report = run(json!({"ref": "read"}));
        assert_eq!(statuses(&report), ["completed", "refused"]);
        assert!(report.steps[1]
            .reason
            .as_deref()
            .unwrap()
            .starts_with("input:"));
        // A member the output does not declare is refused, not replaced: the verifier, which
        // now reads the executed plan, refuses it before any step (R4a).
        let refused = super::run_plan(
            &read_then_note(json!({"ref": "read", "field": "bytes"})),
            &default_catalog(),
            &exec,
            &NoTrustedUi,
            GrantSource::Unchecked,
            Flow::Structural,
            &mut MemoryAudit::default(),
            NOW,
        )
        .unwrap_err();
        assert_eq!(refused.stage, crate::engine::Stage::Plan, "{refused:?}");
        assert!(!inbox.exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn durations_are_read_or_refused() {
        assert_eq!(duration_seconds("10 minutes"), Some(600));
        assert_eq!(duration_seconds("1 hour"), Some(3600));
        assert_eq!(duration_seconds("half an hour"), Some(1800));
        assert_eq!(duration_seconds("an hour"), Some(3600));
        assert_eq!(duration_seconds("90 seconds"), Some(90));
        assert_eq!(duration_seconds("a while"), None);
        assert_eq!(duration_seconds("10 Minuten"), Some(600));
        assert_eq!(duration_seconds("zäh Minute"), Some(600));
        assert_eq!(duration_seconds("e haubi Stund"), Some(1800));
        assert_eq!(duration_seconds("es Viertustündli"), Some(900));
        assert_eq!(duration_seconds("anderthalb Stunden"), Some(5400));
        assert_eq!(duration_seconds("1 Stunde und 30 Minuten"), Some(5400));
        assert_eq!(duration_seconds("zwöi Stund u füfzäh Minute"), Some(8100));
        assert_eq!(duration_seconds("a quarter of an hour"), Some(900));
        assert_eq!(duration_seconds("twenty five minutes"), Some(1500));
        assert_eq!(duration_seconds("10min"), Some(600));
        assert_eq!(duration_seconds("1,5h"), Some(5400));
        assert_eq!(duration_seconds("PT1H30M"), Some(5400));
        // Refused: no unit, unknown words, a dangling number, beyond 30 days.
        assert_eq!(duration_seconds("10"), None);
        assert_eq!(duration_seconds("10 Minuten oder so"), None);
        assert_eq!(duration_seconds("1 Stunde 30"), None);
        assert_eq!(duration_seconds("40 Tage"), None);
        assert_eq!(duration_seconds("PT"), None);
    }

    #[test]
    fn duration_lexicon_forms_are_lowercase_and_unique() {
        let doc: Value = serde_json::from_str(DURATION_LEXICON_JSON).unwrap();
        let mut seen = std::collections::BTreeSet::new();
        for section in [
            "units",
            "numbers",
            "fractions",
            "articles",
            "connectors",
            "fillers",
        ] {
            let lists: Vec<&Value> = match &doc[section] {
                Value::Object(map) => map.values().collect(),
                list => vec![list],
            };
            for form in lists.into_iter().flat_map(|l| l.as_array().unwrap()) {
                let form = form.as_str().unwrap();
                assert_eq!(form, form.to_lowercase(), "{form}");
                assert!(seen.insert(form.to_string()), "{form} occurs twice");
            }
        }
    }
}
