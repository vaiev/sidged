// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! The companion IPC command allowlist. The Tauri shells expose exactly these commands to
//! their webview; each takes and returns JSON. No command approves, signs, pairs or sends,
//! and no command confirms a consequential step.
//!
//! `node.init` turns the app's own data directory into a Sidged workspace once
//! (`sidged_cli::turnkey::bootstrap_workspace`) and returns only public identifiers.
//! `intent.run` runs a complete, Core-verified intent's catalog plan on this node
//! (`sidged_cli::turnkey::run_verified_intent`, 0017 X1-X5); consequential steps are
//! denied, because the webview is not a Trusted UI (invariant 4).

use std::path::PathBuf;
use std::sync::RwLock;

use serde_json::{json, Value};
use sidged_cli::linguist::{IntentCatalog, LinguistOutput, LocalLinguist, Ordered, VerifiedIntent};
use sidged_gateway::local_model::{model_endpoint, ModelEndpoint};

use crate::catalog::A2uiCatalog;
use crate::{schema, surface};

pub const COMMANDS: [&str; 12] = [
    "catalog.describe",
    "node.status",
    "node.init",
    "intent.list",
    "intent.run",
    "linguist.prompt",
    "linguist.run",
    "linguist.verify",
    "surface.capability_input",
    "surface.capability_output",
    "surface.input_submit",
    "surface.clarification_submit",
];

/// One companion node's view of the catalogs and of the capabilities it may show.
pub struct CompanionCore {
    pub a2ui: A2uiCatalog,
    pub intents: IntentCatalog,
    capabilities: RwLock<Vec<Value>>,
    workspace: Option<PathBuf>,
}

fn text<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("argument {key} must be a string"))
}

impl CompanionCore {
    /// `capabilities` is a JSON array of SDG-L1 descriptors (e.g. a workspace catalog.json).
    pub fn new(capabilities: &Value) -> Result<Self, String> {
        sidged_capability::Registry::from_descriptors(capabilities)?;
        Ok(Self {
            a2ui: A2uiCatalog::builtin()?,
            intents: IntentCatalog::builtin()?,
            capabilities: RwLock::new(capabilities.as_array().cloned().unwrap_or_default()),
            workspace: None,
        })
    }

    /// A node backed by a workspace directory (it need not exist yet; see `node.init`).
    /// Capabilities come from its `catalog.json` when that is a valid SDG-L1 catalog.
    pub fn with_workspace(workspace: PathBuf) -> Result<Self, String> {
        let core = Self {
            workspace: Some(workspace),
            ..Self::new(&Value::Array(Vec::new()))?
        };
        core.reload_capabilities();
        Ok(core)
    }

    fn reload_capabilities(&self) {
        let loaded = self
            .workspace
            .as_ref()
            .and_then(|dir| std::fs::read_to_string(dir.join("catalog.json")).ok())
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .filter(|catalog| sidged_capability::Registry::from_descriptors(catalog).is_ok())
            .and_then(|catalog| catalog.as_array().cloned())
            .unwrap_or_default();
        if let Ok(mut capabilities) = self.capabilities.write() {
            *capabilities = loaded;
        }
    }

    fn capability(&self, id: &str) -> Result<Value, String> {
        self.capabilities
            .read()
            .map_err(|_| "capability table unavailable".to_string())?
            .iter()
            .find(|d| d.get("id").and_then(Value::as_str) == Some(id))
            .cloned()
            .ok_or_else(|| format!("unknown capability {id}"))
    }

    fn capability_ids(&self) -> Vec<Value> {
        self.capabilities
            .read()
            .map(|c| c.iter().filter_map(|d| d.get("id").cloned()).collect())
            .unwrap_or_default()
    }

    /// The node's local model endpoint (`model.endpoint` in the workspace `config.json`,
    /// the same syntax as the runtime: `unix:<path>` with `uid`, or `tcp:127.0.0.1:<port>`).
    fn model(&self) -> Result<Option<ModelEndpoint>, String> {
        let Some(path) = self.workspace.as_ref().map(|dir| dir.join("config.json")) else {
            return Ok(None);
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Ok(None);
        };
        let config: Value = serde_json::from_str(&text).map_err(|e| format!("config.json: {e}"))?;
        model_endpoint(&config)
    }

    /// Model -1 behind that endpoint, asked for the form `model.output` selects (0017 L3a).
    fn linguist(&self) -> Result<Option<LocalLinguist>, String> {
        let Some(path) = self.workspace.as_ref().map(|dir| dir.join("config.json")) else {
            return Ok(None);
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Ok(None);
        };
        let config: Value = serde_json::from_str(&text).map_err(|e| format!("config.json: {e}"))?;
        LocalLinguist::from_config_for(&self.intents, &config)
    }

    /// The output form `model.output` selects (0017 L3a); full without a node config.
    fn linguist_output(&self) -> Result<LinguistOutput, String> {
        let Some(path) = self.workspace.as_ref().map(|dir| dir.join("config.json")) else {
            return Ok(LinguistOutput::Full);
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Ok(LinguistOutput::Full);
        };
        let config: Value = serde_json::from_str(&text).map_err(|e| format!("config.json: {e}"))?;
        LinguistOutput::from_config(&config)
    }

    /// A verified intent with the surface that follows from it. A complete intent on a
    /// node also shows the plan the Core would run, or why it refuses to plan it.
    fn with_surface(&self, verified: VerifiedIntent) -> Result<Value, String> {
        let mut refusal = Value::Null;
        let next = if verified.needs_clarification() {
            surface::clarification(&self.a2ui, &self.intents, &verified)?
        } else {
            let mut ready = surface::intent_ready(&self.a2ui, &self.intents, &verified)?;
            match self.plan_preview(&verified) {
                Some(Ok(steps)) => {
                    ready["nodes"]
                        .as_array_mut()
                        .ok_or("surface without nodes")?
                        .push(json!({"primitive": "StepTimeline", "props": {"steps": steps}}));
                    let problems = self.a2ui.validate_surface(&ready);
                    if !problems.is_empty() {
                        return Err(format!("surface-invalid: {}", problems.join("; ")));
                    }
                }
                Some(Err(why)) => refusal = json!(why),
                None => {}
            }
            ready
        };
        Ok(json!({
            "envelope": verified.envelope,
            "corrections": verified.corrections,
            "surface": next,
            "plan_refusal": refusal,
            "runnable": refusal.is_null() && !verified.needs_clarification() && self.initialized(),
        }))
    }

    fn initialized(&self) -> bool {
        self.workspace
            .as_ref()
            .is_some_and(|dir| dir.join("manifest.json").exists())
    }

    /// The steps the Core would run for a complete intent on this node, as StepTimeline items.
    fn plan_preview(&self, verified: &VerifiedIntent) -> Option<Result<Vec<Value>, String>> {
        let dir = self.workspace.as_ref().filter(|_| self.initialized())?;
        let load = || -> Result<_, String> {
            let read = |name: &str| {
                std::fs::read_to_string(dir.join(name)).map_err(|e| format!("{name}: {e}"))
            };
            let capabilities: Value =
                serde_json::from_str(&read("catalog.json")?).map_err(|e| e.to_string())?;
            let manifest: Value =
                serde_json::from_str(&read("manifest.json")?).map_err(|e| e.to_string())?;
            let policy =
                sidged_verify::flow::CedarFlowPolicy::from_sources(&[&read("policy.cedar")?])?;
            Ok((capabilities, manifest, policy))
        };
        Some(load().and_then(|(capabilities, manifest, policy)| {
            let owner = manifest["owner_did"].as_str().unwrap_or("");
            sidged_cli::intent_plan::plan_for_intent(&self.intents, verified, &capabilities, &policy, owner)
                .map_err(|refusal| refusal.to_string())
                .map(|checked| {
                    checked.plan["steps"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|step| {
                            let id = step["id"].as_str().unwrap_or("");
                            json!({
                                "step_id": id,
                                "label": step["capability"].as_str().unwrap_or("").trim_start_matches("urn:sidged:capability:"),
                                "status": "pending",
                                "requires_owner_gate": checked.approvals.iter().any(|a| a == id),
                            })
                        })
                        .collect()
                })
        }))
    }

    /// The Core-verified intent for explicit slots (catalog questions answered on the canvas).
    /// Keep the device's IANA time zone (sent by the canvas) in the workspace `config.json`,
    /// so reminders resolve clock times; other config members are left as they are.
    fn remember_timezone(&self, dir: &std::path::Path, args: &Value) -> Result<(), String> {
        let Some(name) = args.get("timezone") else {
            return Ok(());
        };
        let name = name.as_str().ok_or("timezone must be a string")?;
        sidged_cli::when::parse_timezone(name)?;
        let path = dir.join("config.json");
        let mut config: Value = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).map_err(|e| format!("config.json: {e}"))?,
            Err(_) => json!({}),
        };
        let object = config
            .as_object_mut()
            .ok_or("config.json must be an object")?;
        if object.get("timezone").and_then(Value::as_str) == Some(name) {
            return Ok(());
        }
        object.insert("timezone".into(), json!(name));
        std::fs::write(&path, config.to_string()).map_err(|e| e.to_string())
    }

    fn verified_from_slots(&self, args: &Value) -> Result<VerifiedIntent, String> {
        let lang = text(args, "lang")?;
        let intent = args.get("intent").and_then(Value::as_str);
        let mut slots: Ordered<String> = Ordered::default();
        for source in ["slots", "answers"] {
            for (name, value) in args
                .get(source)
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
            {
                let value = value
                    .as_str()
                    .ok_or_else(|| format!("{source}.{name} must be a string"))?
                    .trim();
                if value.is_empty() || value.chars().any(char::is_control) {
                    continue;
                }
                slots.0.retain(|(k, _)| k != name);
                slots.0.push((name.clone(), value.to_string()));
            }
        }
        // §2c: follow-ups come back as `then` [{intent, slots}]; an answer named
        // then.<i>.<slot> fills that follow-up's slot.
        let mut then: Vec<(String, Ordered<String>)> = Vec::new();
        for (index, item) in args
            .get("then")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
            .take(sidged_cli::linguist::MAX_FOLLOW_UPS)
        {
            let next = item["intent"]
                .as_str()
                .ok_or("then[].intent must be a string")?;
            let mut given: Ordered<String> = Ordered::default();
            let prefix = format!("then.{index}.");
            let answers = args.get("answers").and_then(Value::as_object);
            let own = item
                .get("slots")
                .and_then(Value::as_object)
                .into_iter()
                .flatten();
            let answered = answers.into_iter().flatten().filter_map(|(k, v)| {
                k.strip_prefix(&prefix)
                    .map(|slot| (slot.to_string(), v.clone()))
            });
            for (name, value) in own.map(|(k, v)| (k.clone(), v.clone())).chain(answered) {
                let value = value
                    .as_str()
                    .ok_or("then slots must be strings")?
                    .trim()
                    .to_string();
                if value.is_empty() || value.chars().any(char::is_control) {
                    continue;
                }
                given.0.retain(|(k, _)| *k != name);
                given.0.push((name, value));
            }
            then.push((next.to_string(), given));
        }
        slots.0.retain(|(k, _)| !k.starts_with("then."));
        let envelope = self.intents.derive_with_then(lang, intent, &slots, &then)?;
        let raw = serde_json::to_string(&envelope).map_err(|e| e.to_string())?;
        self.intents.verify_proposal(&raw)
    }

    /// Public identity of the node, if it has been created.
    fn node_status(&self) -> Value {
        let manifest = self
            .workspace
            .as_ref()
            .and_then(|dir| std::fs::read_to_string(dir.join("manifest.json")).ok())
            .and_then(|text| serde_json::from_str::<Value>(&text).ok());
        match manifest {
            Some(m) => json!({
                "initialized": true,
                "owner_did": m["owner_did"],
                "edge_did": m["edge1_did"],
                "workers": m["worker_dids"].as_array().map_or(0, Vec::len),
                "log_public_key": m["log_pubkey_hex"],
                "capabilities": self.capability_ids().len(),
                "model": matches!(self.model(), Ok(Some(_))),
            }),
            None => json!({"initialized": false, "can_initialize": self.workspace.is_some()}),
        }
    }

    /// Run one allowlisted command.
    pub fn dispatch(&self, command: &str, args: &Value) -> Result<Value, String> {
        match command {
            "catalog.describe" => Ok(json!({
                "commands": COMMANDS,
                "primitives": self.a2ui.primitives.iter().map(|p| json!({
                    "name": p.name, "role": p.role, "tokens": p.tokens,
                })).collect::<Vec<_>>(),
                "locales": self.intents.locales,
                "capabilities": self.capability_ids(),
            })),
            "node.status" => Ok(self.node_status()),
            "node.init" => {
                let dir = self.workspace.as_ref().ok_or("node-without-workspace")?;
                if dir.join("manifest.json").exists() {
                    return Err("node-exists: this device is already a Sidged node".into());
                }
                sidged_cli::turnkey::bootstrap_workspace(dir)?;
                self.remember_timezone(dir, args)?;
                self.reload_capabilities();
                Ok(self.node_status())
            }
            "intent.list" => Ok(json!({
                "locales": self.intents.locales,
                "intents": self.intents.intents.iter().map(|entry| json!({
                    "intent": entry.intent,
                    "title": entry.title,
                    "route": entry.route,
                    "data_classes": entry.data_classes,
                    "required": entry.slots_schema.required,
                })).collect::<Vec<_>>(),
            })),
            "linguist.prompt" => {
                // The prompt the model is asked with: the form `linguist.run` uses.
                let (system, user) = self.intents.render_prompt_as(
                    self.linguist_output()?,
                    text(args, "utterance")?,
                    None,
                )?;
                Ok(json!({"system": system, "user": user}))
            }
            "linguist.verify" => {
                let reply = text(args, "reply")?;
                let verified = match args.get("utterance").and_then(Value::as_str) {
                    Some(utterance) => self.intents.verify_proposal_for(utterance, reply)?,
                    None => self.intents.verify_proposal(reply)?,
                };
                self.with_surface(verified)
            }
            "linguist.run" => {
                // The endpoint is node configuration: no node, no model.
                if !self.node_status()["initialized"].as_bool().unwrap_or(false) {
                    return Err(
                        "node-not-initialized: create the node before asking the model".into(),
                    );
                }
                let model = self.linguist()?.ok_or(
                    "model-not-configured: set model.endpoint in the workspace config.json",
                )?;
                // AF_UNIX with the peer-uid check is not egress and needs no local mode (0004 R9d).
                self.with_surface(self.intents.understand(&model, text(args, "utterance")?)?)
            }
            "surface.capability_input" => {
                surface::capability_input(&self.a2ui, &self.capability(text(args, "capability")?)?)
            }
            "surface.capability_output" => surface::capability_output(
                &self.a2ui,
                &self.capability(text(args, "capability")?)?,
                args.get("result").ok_or("argument result is missing")?,
            ),
            "surface.input_submit" => {
                let id = text(args, "capability")?;
                let descriptor = self.capability(id)?;
                let values = args.get("values").ok_or("argument values is missing")?;
                let problems = schema::validate(&descriptor["input_schema"], values);
                if !problems.is_empty() {
                    return Err(format!("input-invalid: {}", problems.join("; ")));
                }
                Ok(json!({
                    "status": "pending-plan",
                    "capability": id,
                    "args": values,
                    "consequential": descriptor.get("consequential").cloned().unwrap_or(json!(true)),
                }))
            }
            "surface.clarification_submit" => self.with_surface(self.verified_from_slots(args)?),
            "intent.run" => {
                let verified = self.verified_from_slots(args)?;
                let dir = self
                    .workspace
                    .as_ref()
                    .filter(|_| self.initialized())
                    .ok_or("node-not-initialized: create the node before running an intent")?;
                self.remember_timezone(dir, args)?;
                let summary =
                    sidged_cli::turnkey::run_verified_intent(dir, &self.intents, &verified)?;
                let surface = match &summary.surface_path {
                    Some(path) => {
                        let legacy: Value = serde_json::from_str(
                            &std::fs::read_to_string(path).map_err(|e| e.to_string())?,
                        )
                        .map_err(|e| e.to_string())?;
                        surface::from_result_surface(&self.a2ui, &legacy)?
                    }
                    None => Value::Null,
                };
                Ok(json!({"summary": summary, "surface": surface}))
            }
            other => Err(format!("command-not-allowed: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core() -> CompanionCore {
        let descriptor: Value = serde_json::from_str(include_str!(
            "../../../spec/examples/capability-descriptor.time-convert.json"
        ))
        .unwrap();
        CompanionCore::new(&json!([descriptor])).unwrap()
    }

    #[test]
    fn allowlist_has_no_consequential_command() {
        for command in COMMANDS {
            for banned in ["approv", "grant", "sign", "exec", "send", "pair", "key"] {
                assert!(!command.contains(banned), "{command}");
            }
        }
        let err = core()
            .dispatch("capability.execute", &json!({}))
            .unwrap_err();
        assert!(err.starts_with("command-not-allowed"));
    }

    #[test]
    fn input_submit_validates_against_the_input_schema_and_never_executes() {
        let core = core();
        let id = "urn:sidged:capability:convert_time";
        let ok = core
            .dispatch(
                "surface.input_submit",
                &json!({"capability": id, "values": {"source_timezone": "Europe/Zurich",
                        "time": "09:30", "target_timezone": "Asia/Tokyo"}}),
            )
            .unwrap();
        assert_eq!(ok["status"], "pending-plan");
        let err = core
            .dispatch(
                "surface.input_submit",
                &json!({"capability": id, "values": {"time": 930}}),
            )
            .unwrap_err();
        assert!(err.starts_with("input-invalid"), "{err}");
    }

    #[test]
    fn a_composition_asks_for_the_follow_up_slot_and_keeps_both_intents() {
        let core = core();
        let raw = json!({
            "v": "0.1", "lang": "gsw", "intent": "task.summarize",
            "slots": {"source": "protokoll.docx"}, "missing_slots": [],
            "clarification_needed": false, "clarification_question_local": null,
            "canonical_intent_en": null, "suggested_route": "edge-local",
            "required_data_classes": [], "then": [{"intent": "messaging.send", "slots": {}}]
        });
        let first = core
            .dispatch("linguist.verify", &json!({"reply": raw.to_string()}))
            .unwrap();
        assert_eq!(first["surface"]["kind"], "clarification");
        let names: Vec<&str> = first["surface"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|n| n["props"]["fields"].as_array().into_iter().flatten())
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"then.0.recipient"), "{names:?}");
        let done = core
            .dispatch(
                "surface.clarification_submit",
                &json!({"lang": "gsw", "intent": "task.summarize",
                        "slots": {"source": "protokoll.docx"},
                        "then": [{"intent": "messaging.send", "slots": {}}],
                        "answers": {"then.0.recipient": "Marco"}}),
            )
            .unwrap();
        assert_eq!(done["surface"]["kind"], "output");
        assert_eq!(done["envelope"]["then"][0]["slots"]["recipient"], "Marco");
        assert!(
            done["surface"]["nodes"][0]["props"]["title"]
                .as_str()
                .unwrap_or("")
                .contains("then Send a message to Marco"),
            "{}",
            done["surface"]["nodes"][0]
        );
    }

    #[test]
    fn clarification_round_trip_reaches_a_complete_intent() {
        let core = core();
        let raw = serde_json::to_string(
            &core
                .intents
                .derive("de", Some("timer.set"), &Ordered::default())
                .unwrap(),
        )
        .unwrap();
        let first = core
            .dispatch("linguist.verify", &json!({"reply": raw}))
            .unwrap();
        assert_eq!(first["surface"]["kind"], "clarification");
        let done = core
            .dispatch(
                "surface.clarification_submit",
                &json!({"lang": "de", "intent": "timer.set", "slots": {},
                        "answers": {"duration": "10 minutes"}}),
            )
            .unwrap();
        assert_eq!(done["surface"]["kind"], "output");
        assert_eq!(done["surface"]["nodes"][0]["props"]["status"], "ready");
        assert_eq!(done["envelope"]["suggested_route"], "edge-local");
        assert_eq!(
            done["envelope"]["canonical_intent_en"],
            "Start a timer for 10 minutes"
        );
    }

    #[test]
    fn node_init_creates_a_node_once_and_returns_only_public_identifiers() {
        let dir =
            std::env::temp_dir().join(format!("sidged-companion-node-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let core = CompanionCore::with_workspace(dir.clone()).unwrap();
        assert_eq!(
            core.dispatch("node.status", &json!({})).unwrap()["initialized"],
            false
        );
        let created = core.dispatch("node.init", &json!({})).unwrap();
        assert_eq!(created["initialized"], true);
        assert!(created["owner_did"]
            .as_str()
            .unwrap()
            .starts_with("did:key:z"));
        let text = created.to_string();
        for secret in ["seed", "secret", "private"] {
            assert!(!text.contains(secret), "{text}");
        }
        let again = core.dispatch("node.init", &json!({})).unwrap_err();
        assert!(again.starts_with("node-exists"), "{again}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn linguist_prompt_follows_model_output() {
        use sidged_cli::linguist::{SYSTEM_PROMPT, SYSTEM_PROMPT_COMPACT};
        let dir =
            std::env::temp_dir().join(format!("sidged-companion-prompt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let core = CompanionCore::with_workspace(dir.clone()).unwrap();
        let args = json!({"utterance": "Stell en Timer uf 5 Minute"});
        let prompt = core.dispatch("linguist.prompt", &args).unwrap();
        assert_eq!(prompt["system"], SYSTEM_PROMPT);
        std::fs::write(
            dir.join("config.json"),
            json!({"model": {"output": "compact"}}).to_string(),
        )
        .unwrap();
        let prompt = core.dispatch("linguist.prompt", &args).unwrap();
        assert_eq!(prompt["system"], SYSTEM_PROMPT_COMPACT);
        let (_, user) = core
            .intents
            .render_prompt("Stell en Timer uf 5 Minute", None)
            .unwrap();
        assert_eq!(prompt["user"], user);
        std::fs::write(
            dir.join("config.json"),
            json!({"model": {"output": "v0.2"}}).to_string(),
        )
        .unwrap();
        assert!(core.dispatch("linguist.prompt", &args).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn linguist_run_needs_a_node_first() {
        let err = core()
            .dispatch("linguist.run", &json!({"utterance": "hi"}))
            .unwrap_err();
        assert!(err.starts_with("node-not-initialized"), "{err}");
    }

    #[test]
    fn a_ready_intent_shows_its_plan_and_runs_on_the_node_without_approving_anything() {
        let dir = std::env::temp_dir().join(format!("sidged-companion-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let core = CompanionCore::with_workspace(dir.clone()).unwrap();
        core.dispatch("node.init", &json!({})).unwrap();

        let timer = json!({"lang": "de", "intent": "timer.set",
                           "slots": {"duration": "10 minutes", "label": "the tea"}});
        let ready = core
            .dispatch("surface.clarification_submit", &timer)
            .unwrap();
        assert_eq!(ready["runnable"], true);
        let nodes = ready["surface"]["nodes"].as_array().unwrap();
        let steps = &nodes.last().unwrap()["props"]["steps"];
        assert_eq!(steps[0]["label"], "timer.start");
        assert_eq!(steps[0]["requires_owner_gate"], false);
        let run = core.dispatch("intent.run", &timer).unwrap();
        assert_eq!(run["summary"]["steps_executed"], 1);
        assert_eq!(run["surface"]["kind"], "output");
        assert!(dir.join("timers.json").exists());

        // The message would leave the device: the preview marks the gate, and running it
        // never sends from the canvas (no generator, and no Trusted UI in the webview).
        let message = json!({"lang": "de", "intent": "messaging.send",
                             "slots": {"recipient": "Anna", "topic": "dinner on Friday"}});
        let ready = core
            .dispatch("surface.clarification_submit", &message)
            .unwrap();
        let steps = &ready["surface"]["nodes"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["props"]["steps"];
        assert_eq!(steps[1]["requires_owner_gate"], true);
        let run = core.dispatch("intent.run", &message).unwrap();
        assert_eq!(run["summary"]["steps_executed"], 0);
        let statuses: Vec<&str> = run["summary"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["status"].as_str().unwrap())
            .collect();
        assert!(!statuses.contains(&"completed"), "{statuses:?}");

        // A reminder resolves the words as said in the device's time zone.
        let remind = json!({"lang": "gsw", "intent": "scheduling.remind", "timezone": "Europe/Zurich",
                            "slots": {"subject": "the tax return", "time": "morn am füfi"}});
        let run = core.dispatch("intent.run", &remind).unwrap();
        assert_eq!(run["summary"]["steps_executed"], 1, "{run}");
        let config = std::fs::read_to_string(dir.join("config.json")).unwrap();
        assert!(config.contains("Europe/Zurich"), "{config}");
        let reminders = std::fs::read_to_string(dir.join("reminders.json")).unwrap();
        assert!(reminders.contains("T17:00:00+0"), "{reminders}");
        let bad = json!({"lang": "en", "intent": "timer.set", "timezone": "Mars/Base",
                         "slots": {"duration": "10 minutes"}});
        assert!(core.dispatch("intent.run", &bad).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn intent_list_comes_from_the_catalog() {
        let listed = core().dispatch("intent.list", &json!({})).unwrap();
        let intents = listed["intents"].as_array().unwrap();
        assert_eq!(intents.len(), core().intents.intents.len());
        assert!(intents
            .iter()
            .all(|i| i["route"] == "edge-local" || i["route"] == "swarm-worker"));
    }

    #[test]
    fn describe_lists_commands_primitives_and_capabilities() {
        let described = core().dispatch("catalog.describe", &json!({})).unwrap();
        assert_eq!(
            described["commands"].as_array().unwrap().len(),
            COMMANDS.len()
        );
        assert_eq!(
            described["capabilities"],
            json!(["urn:sidged:capability:convert_time"])
        );
    }
}
