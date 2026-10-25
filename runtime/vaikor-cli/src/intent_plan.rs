// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Intent plans (0017 §2b): the Core instantiates the VKR-L3 plan an intent declares in the
//! catalog from the Core-verified slots, then checks it like any other plan.
//!
//! No intent has a code path of its own. The checks, in order:
//! 1. the intent is complete and declares a plan;
//! 2. every step uses a capability the intent names and the capability catalog describes;
//! 3. every literal comes from a verified slot or the canonical intent (grounding);
//! 4. every literal satisfies the capability's `input_schema` property, unknown arguments
//!    are refused, and required arguments are present (a `ref` counts as present);
//! 5. the VKR-L3 verifier (structure, budgets, approval for consequential steps) and the
//!    Cedar information-flow policy of the owner.

use serde_json::{json, Map, Value};
use vaikor_capability::schema;
use vaikor_verify::flow::{check_plan_flows, CedarFlowPolicy, FlowRefusal};
use vaikor_verify::{stored, DeferToCedar};

use std::collections::HashMap;

use crate::linguist::{IntentCatalog, Ordered, PlanTemplate, TemplateArg, VerifiedIntent};

/// Why an intent plan was refused, with the stage that decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanRefusal {
    pub stage: &'static str,
    pub reason: String,
    pub step: Option<String>,
    pub deciding_policies: Vec<String>,
}

impl PlanRefusal {
    fn new(stage: &'static str, reason: impl Into<String>, step: Option<&str>) -> Self {
        Self {
            stage,
            reason: reason.into(),
            step: step.map(str::to_string),
            deciding_policies: Vec::new(),
        }
    }
}

impl std::fmt::Display for PlanRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "plan-refused at {}: {}", self.stage, self.reason)?;
        if let Some(step) = &self.step {
            write!(f, " (step {step})")?;
        }
        if !self.deciding_policies.is_empty() {
            write!(f, " [{}]", self.deciding_policies.join(", "))?;
        }
        Ok(())
    }
}

/// A plan that passed every check, with the verifier's summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedIntentPlan {
    pub plan: Value,
    pub digest: String,
    pub capabilities: Vec<String>,
    pub approvals: Vec<String>,
    pub egress: Vec<String>,
}

fn descriptor<'a>(catalog: &'a Value, id: &str) -> Option<&'a Value> {
    catalog
        .as_array()?
        .iter()
        .find(|d| d.get("id").and_then(Value::as_str) == Some(id))
}

/// Instantiate the intent's catalog plan from the verified envelope (checks 1 to 3).
pub fn instantiate(
    intents: &IntentCatalog,
    verified: &VerifiedIntent,
) -> Result<Value, PlanRefusal> {
    let envelope = &verified.envelope;
    if envelope.clarification_needed {
        return Err(PlanRefusal::new("intent", "clarification-needed", None));
    }
    let id = envelope
        .intent
        .as_deref()
        .ok_or_else(|| PlanRefusal::new("intent", "no intent", None))?;
    let entry = intents
        .intent(id)
        .ok_or_else(|| PlanRefusal::new("intent", format!("unknown intent {id}"), None))?;
    let template = entry
        .plan
        .as_ref()
        .ok_or_else(|| PlanRefusal::new("intent", format!("{id} declares no plan"), None))?;
    let canonical = envelope.canonical_intent_en.clone().unwrap_or_default();
    let mut steps = Vec::new();
    let mut emitted = emit(
        template,
        &envelope.slots,
        &canonical,
        "",
        &HashMap::new(),
        &mut steps,
    );
    // §2c K4: each follow-up's plan, prefixed, with replaced steps referring back.
    let mut previous = id.to_string();
    let mut goal = canonical.clone();
    for (index, follow_up) in envelope.then.iter().enumerate() {
        let composition = intents
            .composition(&previous, &follow_up.intent)
            .ok_or_else(|| PlanRefusal::new("intent", "composition-undeclared", None))?;
        let template = intents
            .intent(&follow_up.intent)
            .and_then(|entry| entry.plan.as_ref())
            .ok_or_else(|| {
                PlanRefusal::new(
                    "intent",
                    format!("{} declares no plan", follow_up.intent),
                    None,
                )
            })?;
        let replaced: HashMap<String, String> = composition
            .replaces
            .0
            .iter()
            .filter_map(|(step, by)| emitted.get(by).map(|id| (step.clone(), id.clone())))
            .collect();
        emitted = emit(
            template,
            &follow_up.slots,
            &follow_up.canonical_intent_en,
            &format!("t{}_", index + 1),
            &replaced,
            &mut steps,
        );
        goal.push_str("; then ");
        goal.push_str(&follow_up.canonical_intent_en);
        previous = follow_up.intent.clone();
    }
    Ok(json!({"v": "0.1", "goal": goal, "steps": steps}))
}

/// Instantiate one catalog plan into `steps` with step ids prefixed by `prefix`; a step in
/// `replaced` is not emitted and refers to the given earlier step. Returns the template id
/// of every step mapped to the id it has in the plan.
fn emit(
    template: &PlanTemplate,
    slots: &Ordered<String>,
    canonical: &str,
    prefix: &str,
    replaced: &HashMap<String, String>,
    steps: &mut Vec<Value>,
) -> HashMap<String, String> {
    let mut ids = replaced.clone();
    for step in &template.steps {
        if replaced.contains_key(&step.id) {
            continue;
        }
        let mut args = Map::new();
        for (name, value) in &step.args.0 {
            let arg = match value {
                TemplateArg::Slot(slot) => match slots.get(slot) {
                    Some(text) => json!({"lit": text}),
                    // An optional slot the utterance did not give is left out.
                    None => continue,
                },
                TemplateArg::Intent(_) => json!({"lit": canonical}),
                TemplateArg::Ref { step, field } => {
                    let earlier = ids.get(step).cloned().unwrap_or_else(|| step.clone());
                    match field {
                        Some(field) => json!({"ref": earlier, "field": field}),
                        None => json!({"ref": earlier}),
                    }
                }
            };
            args.insert(name.clone(), arg);
        }
        let id = format!("{prefix}{}", step.id);
        let mut out = json!({
            "id": id,
            "kind": "call",
            "capability": step.capability,
            "args": args,
        });
        if step.approval {
            out["approval"] = json!(true);
        }
        steps.push(out);
        ids.insert(step.id.clone(), id);
    }
    ids
}

/// Instantiate and check the plan of a verified intent against the capability catalog and
/// the owner's flow policy.
pub fn plan_for_intent(
    intents: &IntentCatalog,
    verified: &VerifiedIntent,
    capabilities: &Value,
    flow_policy: &CedarFlowPolicy,
    owner_did: &str,
) -> Result<CheckedIntentPlan, PlanRefusal> {
    let plan = instantiate(intents, verified)?;
    check_plan(
        plan,
        intents,
        verified,
        capabilities,
        flow_policy,
        owner_did,
    )
}

/// Check any plan for a verified intent (from the catalog or proposed by a planner model):
/// checks 2 to 5 of the module documentation.
pub fn check_plan(
    plan: Value,
    intents: &IntentCatalog,
    verified: &VerifiedIntent,
    capabilities: &Value,
    flow_policy: &CedarFlowPolicy,
    owner_did: &str,
) -> Result<CheckedIntentPlan, PlanRefusal> {
    let entry = verified
        .envelope
        .intent
        .as_deref()
        .and_then(|id| intents.intent(id))
        .ok_or_else(|| PlanRefusal::new("intent", "no intent", None))?;
    let envelope = &verified.envelope;
    // §2c K5: a composition is bound by every intent's capabilities and grounded in every
    // intent's verified slots and canonical text.
    let mut bound: Vec<&String> = entry.capabilities.iter().collect();
    let mut grounded: Vec<&str> = envelope.slots.0.iter().map(|(_, v)| v.as_str()).collect();
    if let Some(canonical) = envelope.canonical_intent_en.as_deref() {
        grounded.push(canonical);
    }
    for follow_up in &envelope.then {
        if let Some(next) = intents.intent(&follow_up.intent) {
            bound.extend(next.capabilities.iter());
        }
        grounded.extend(follow_up.slots.0.iter().map(|(_, v)| v.as_str()));
        grounded.push(&follow_up.canonical_intent_en);
    }
    for step in plan["steps"].as_array().into_iter().flatten() {
        let id = step["id"].as_str().unwrap_or("");
        let capability = step["capability"].as_str().unwrap_or("");
        if !bound.iter().any(|c| *c == capability) {
            return Err(PlanRefusal::new(
                "bound",
                format!("{capability} is not named by the intent"),
                Some(id),
            ));
        }
        let desc = descriptor(capabilities, capability).ok_or_else(|| {
            PlanRefusal::new(
                "catalog",
                format!("no descriptor for {capability}"),
                Some(id),
            )
        })?;
        let input = &desc["input_schema"];
        let properties = input.get("properties").and_then(Value::as_object);
        let args = step["args"].as_object().cloned().unwrap_or_default();
        for (name, arg) in &args {
            let property = properties.and_then(|p| p.get(name)).ok_or_else(|| {
                PlanRefusal::new(
                    "schema",
                    format!("argument {name} is not in the input schema"),
                    Some(id),
                )
            })?;
            if let Some(literal) = arg.get("lit") {
                if !literal
                    .as_str()
                    .is_some_and(|text| grounded.contains(&text))
                {
                    return Err(PlanRefusal::new(
                        "grounding",
                        format!("argument {name} is not a verified slot value"),
                        Some(id),
                    ));
                }
                let problems = schema::validate(property, literal);
                if !problems.is_empty() {
                    return Err(PlanRefusal::new(
                        "schema",
                        format!("argument {name}: {}", problems.join("; ")),
                        Some(id),
                    ));
                }
            }
        }
        for required in input
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = required.as_str().unwrap_or("");
            if !args.contains_key(name) {
                return Err(PlanRefusal::new(
                    "schema",
                    format!("required argument {name} is missing"),
                    Some(id),
                ));
            }
        }
    }
    let parsed =
        stored::parse_plan(&plan).map_err(|e| PlanRefusal::new("structure", e.code(), None))?;
    let caps = stored::parse_catalog(capabilities)
        .map_err(|e| PlanRefusal::new("catalog", e.code(), None))?;
    let summary = vaikor_verify::verify(&parsed, &caps, &DeferToCedar)
        .map_err(|problems| PlanRefusal::new("verifier", problems.join("; "), None))?;
    let digest =
        stored::plan_digest(&plan).map_err(|e| PlanRefusal::new("structure", e.code(), None))?;
    check_plan_flows(&parsed, &digest, capabilities, owner_did, flow_policy).map_err(
        |flow: FlowRefusal| PlanRefusal {
            stage: "flow",
            reason: format!("{}: {} -> {}", flow.reason, flow.class, flow.capability),
            step: Some(flow.step),
            deciding_policies: flow.deciding_policies,
        },
    )?;
    Ok(CheckedIntentPlan {
        digest,
        plan,
        capabilities: summary.capabilities,
        approvals: summary.approvals,
        egress: summary.egress,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linguist::Ordered;
    use crate::turnkey::default_catalog;
    use vaikor_verify::flow::DEFAULT_FLOW_POLICY;

    const OWNER: &str = "did:key:z6MkwSD8dBdqcXQzKJZQFPy2hh2izzxskndKCjdmC2dBpfME";

    fn verified(intent: &str, slots: &[(&str, &str)]) -> VerifiedIntent {
        let catalog = IntentCatalog::builtin().unwrap();
        let slots = Ordered(
            slots
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        );
        let envelope = catalog.derive("en", Some(intent), &slots).unwrap();
        catalog
            .verify_proposal(&serde_json::to_string(&envelope).unwrap())
            .unwrap()
    }

    fn sample_slots(intent: &str) -> Vec<(&'static str, &'static str)> {
        match intent {
            "messaging.send" => vec![("recipient", "Anna"), ("topic", "dinner on Friday")],
            "scheduling.propose" => vec![("participant", "Anna"), ("timeframe", "next week")],
            "scheduling.remind" => vec![("subject", "the laundry"), ("time", "tomorrow at 08:00")],
            "timer.set" => vec![("duration", "10 minutes")],
            "control.set" => vec![("device", "the heating"), ("setting", "21 degrees")],
            "task.note" => vec![("content", "buy milk")],
            "task.code" => vec![("description", "a CSV parser"), ("language", "Rust")],
            "task.summarize" => vec![("source", "notes.md")],
            "task.translate" => vec![("source", "notes.md"), ("target_language", "French")],
            "query.search" => vec![("subject", "heat pumps")],
            "files.find" => vec![("query", "the tax documents")],
            "share.offer" => vec![("item", "report.pdf"), ("recipient", "Anna")],
            other => panic!("no sample for {other}"),
        }
    }

    #[test]
    fn every_catalog_intent_plan_passes_verifier_and_default_flow() {
        let intents = IntentCatalog::builtin().unwrap();
        let policy = CedarFlowPolicy::from_sources(&[DEFAULT_FLOW_POLICY]).unwrap();
        let capabilities = default_catalog();
        for entry in &intents.intents {
            let checked = plan_for_intent(
                &intents,
                &verified(&entry.intent, &sample_slots(&entry.intent)),
                &capabilities,
                &policy,
                OWNER,
            )
            .unwrap_or_else(|e| panic!("{}: {e}", entry.intent));
            assert!(checked.digest.len() > 20, "{}", entry.intent);
            assert!(!checked.capabilities.is_empty(), "{}", entry.intent);
        }
    }

    #[test]
    fn a_composition_chains_the_declared_plans_and_the_result_feeds_the_send() {
        let intents = IntentCatalog::builtin().unwrap();
        let policy = CedarFlowPolicy::from_sources(&[DEFAULT_FLOW_POLICY]).unwrap();
        let reply = serde_json::json!({
            "v": "0.1", "lang": "gsw", "intent": "task.summarize",
            "slots": {"source": "protokoll.docx"}, "missing_slots": [],
            "clarification_needed": false, "clarification_question_local": null,
            "canonical_intent_en": null, "suggested_route": "edge-local",
            "required_data_classes": [],
            "then": [{"intent": "messaging.send", "slots": {"recipient": "Marco"}}]
        });
        let verified = intents
            .verify_proposal_for(
                "Fass protokoll.docx zäme und schick's em Marco",
                &reply.to_string(),
            )
            .unwrap();
        assert!(!verified.envelope.clarification_needed);
        let checked =
            plan_for_intent(&intents, &verified, &default_catalog(), &policy, OWNER).unwrap();
        let ids: Vec<&str> = checked.plan["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["id"].as_str().unwrap())
            .collect();
        // The send's own draft step is replaced by the summary (K4).
        assert_eq!(ids, ["read", "summary", "t1_send"]);
        let send = &checked.plan["steps"][2];
        // 0003 R4a: the send takes the summary's `text` member, as the catalog declares.
        assert_eq!(
            send["args"]["body"],
            serde_json::json!({"ref": "summary", "field": "text"})
        );
        assert_eq!(send["args"]["to"], serde_json::json!({"lit": "Marco"}));
        assert_eq!(checked.approvals, ["t1_send"]);
        // An undeclared pair is dropped before planning (K2).
        let mut undeclared = reply.clone();
        undeclared["then"][0]["intent"] = serde_json::json!("timer.set");
        let verified = intents.verify_proposal(&undeclared.to_string()).unwrap();
        assert!(verified.envelope.then.is_empty());
        assert!(verified
            .corrections
            .contains(&"composition-undeclared".to_string()));
    }

    #[test]
    fn consequential_steps_carry_approval_and_egress_is_reported() {
        let intents = IntentCatalog::builtin().unwrap();
        let policy = CedarFlowPolicy::from_sources(&[DEFAULT_FLOW_POLICY]).unwrap();
        let checked = plan_for_intent(
            &intents,
            &verified("messaging.send", &sample_slots("messaging.send")),
            &default_catalog(),
            &policy,
            OWNER,
        )
        .unwrap();
        assert_eq!(checked.approvals, ["send"]);
        assert_eq!(
            checked.egress,
            ["tag:vaikor.com,2026:capability:message.send"]
        );
        assert_eq!(
            checked.plan["steps"][1]["args"]["to"],
            json!({"lit": "Anna"})
        );
        assert_eq!(
            checked.plan["steps"][1]["args"]["body"],
            json!({"ref": "draft", "field": "text"})
        );
    }

    #[test]
    fn an_owner_policy_can_forbid_a_flow_and_names_itself() {
        let intents = IntentCatalog::builtin().unwrap();
        let forbid = r#"@id("owner-no-file-sharing")
forbid (principal, action == Vaikor::Action::"flow", resource == Vaikor::Capability::"tag:vaikor.com,2026:capability:message.send")
when { context.class == "documents.text" };"#;
        let policy = CedarFlowPolicy::from_sources(&[DEFAULT_FLOW_POLICY, forbid]).unwrap();
        let refusal = plan_for_intent(
            &intents,
            &verified("share.offer", &sample_slots("share.offer")),
            &default_catalog(),
            &policy,
            OWNER,
        )
        .unwrap_err();
        assert_eq!(refusal.stage, "flow");
        assert_eq!(refusal.deciding_policies, ["owner-no-file-sharing"]);
    }

    #[test]
    fn literals_must_satisfy_the_capability_schema_and_be_grounded() {
        let intents = IntentCatalog::builtin().unwrap();
        let policy = CedarFlowPolicy::from_sources(&[DEFAULT_FLOW_POLICY]).unwrap();
        // A path the workspace adapter would refuse never becomes a plan.
        let refusal = plan_for_intent(
            &intents,
            &verified("task.summarize", &[("source", "/etc/passwd")]),
            &default_catalog(),
            &policy,
            OWNER,
        )
        .unwrap_err();
        assert_eq!(refusal.stage, "schema");
        // A plan (for example from a planner model) whose literal is not a verified slot
        // value is refused, and so is a step outside the intent's capabilities.
        let good = verified("timer.set", &sample_slots("timer.set"));
        let mut plan = instantiate(&intents, &good).unwrap();
        plan["steps"][0]["args"]["duration"] = json!({"lit": "999 hours"});
        let refusal =
            check_plan(plan, &intents, &good, &default_catalog(), &policy, OWNER).unwrap_err();
        assert_eq!(refusal.stage, "grounding");
        let mut plan = instantiate(&intents, &good).unwrap();
        plan["steps"][0]["capability"] = json!("tag:vaikor.com,2026:capability:message.send");
        let refusal =
            check_plan(plan, &intents, &good, &default_catalog(), &policy, OWNER).unwrap_err();
        assert_eq!(refusal.stage, "bound");
        let incomplete = verified("timer.set", &[]);
        assert_eq!(
            instantiate(&intents, &incomplete).unwrap_err().reason,
            "clarification-needed"
        );
    }

    /// 0003 R4a: the executor passes exactly the referenced value, so each catalog `ref`
    /// must name a value whose declared type is the type the consumer's argument declares;
    /// otherwise the intent verifies but its step is refused at run time.
    #[test]
    fn every_catalog_ref_passes_a_value_the_consumer_accepts() {
        let intents = IntentCatalog::builtin().unwrap();
        let capabilities = default_catalog();
        let mut checked = 0;
        for entry in &intents.intents {
            let Some(plan) = &entry.plan else { continue };
            for step in &plan.steps {
                for (name, arg) in &step.args.0 {
                    let TemplateArg::Ref { step: from, field } = arg else {
                        continue;
                    };
                    let producer = plan.steps.iter().find(|s| &s.id == from).unwrap();
                    let output =
                        &descriptor(&capabilities, &producer.capability).unwrap()["output_schema"];
                    let value = match field {
                        Some(field) => &output["properties"][field],
                        None => output,
                    };
                    let wanted = &descriptor(&capabilities, &step.capability).unwrap()
                        ["input_schema"]["properties"][name]["type"];
                    assert!(
                        value["type"].is_string() && value["type"] == *wanted,
                        "{}: {}.{name} wants {wanted}, {from}{} is {}",
                        entry.intent,
                        step.id,
                        field
                            .as_deref()
                            .map(|f| format!(".{f}"))
                            .unwrap_or_default(),
                        value["type"]
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked >= 6, "{checked}");
    }
}
