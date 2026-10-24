//! Cedar Information Flow Control (IFC) policy evaluator for SDG-L3 plans (Spec 0013 §4, R8–R11).
//!
//! Evaluates one Cedar request per egress step and reaching data-class label:
//! - `principal`: `Sidged::Owner::"<owner did>"`
//! - `action`:    `Sidged::Action::"flow"`
//! - `resource`:  `Sidged::Capability::"<egress capability id>"`
//! - `context`:   `{ class, sensitive, destination, step, plan }`
//!
//! Enforces:
//! - R8: Core derives every context field (`class`, `sensitive`, `destination`, `step`, `plan`).
//! - R9: Built-in `@id("default-flow")` policy permits non-sensitive flows.
//! - R10: `secrets` and `secrets.*` are NEVER permitted to reach egress even with a matching
//!   owner `permit` and no `forbid`; `forbid` always overrides `permit`; empty policy set denies all.
//! - R11: Refusals report `"data-class-forbidden"` with `class`, `capability`, `step`, and deciding
//!   Cedar policy IDs (`default-flow` or the owner's `@id(...)`).

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityId, EntityTypeName, EntityUid, PolicySet,
    Request,
};
use serde_json::{json, Value};

use crate::stored::{plan_digest, read_plan};
use crate::{Arg, Plan, Step};

/// Built-in default flow policy (Spec 0013 §4 R9).
pub const DEFAULT_FLOW_POLICY: &str = r#"@id("default-flow")
permit (principal, action == Sidged::Action::"flow", resource)
unless { context.sensitive };"#;

/// Structured refusal for an IFC violation (Spec 0013 §4 R11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRefusal {
    pub reason: &'static str,
    pub step: String,
    pub capability: String,
    pub class: String,
    pub destination: String,
    pub deciding_policies: Vec<String>,
}

/// Compiled Cedar flow policy set with @id mapping for R11 audit attribution.
#[derive(Debug, Clone)]
pub struct CedarFlowPolicy {
    policies: PolicySet,
    id_map: HashMap<String, String>,
    has_default_flow: bool,
}

impl CedarFlowPolicy {
    /// Parse a list of Cedar policy source strings (each optionally annotated with `@id("...")`).
    pub fn from_sources(sources: &[&str]) -> Result<Self, String> {
        let combined = sources.join("\n");
        let policies = if combined.trim().is_empty() {
            PolicySet::new()
        } else {
            PolicySet::from_str(&combined).map_err(|e| e.to_string())?
        };
        let mut id_map = HashMap::new();
        let mut has_default_flow = false;
        for policy in policies.policies() {
            let pid = policy.id().to_string();
            let friendly = policy
                .annotation("id")
                .map(str::to_owned)
                .unwrap_or_else(|| pid.clone());
            if friendly == "default-flow" {
                has_default_flow = true;
            }
            id_map.insert(pid, friendly);
        }
        Ok(Self {
            policies,
            id_map,
            has_default_flow,
        })
    }

    /// Built-in default policy set (Spec 0013 §4 R9).
    pub fn default_set() -> Self {
        Self::from_sources(&[DEFAULT_FLOW_POLICY]).expect("valid built-in default-flow policy")
    }

    /// Evaluate a single (step, capability, class, destination, plan_digest) flow request.
    #[allow(clippy::result_large_err)]
    pub fn check_single_flow(
        &self,
        owner_did: &str,
        step_id: &str,
        capability: &str,
        class: &str,
        destination: &str,
        plan_hash: &str,
    ) -> Result<(), FlowRefusal> {
        // R10: `secrets` and `secrets.*` MUST NEVER reach egress even with an owner permit.
        if is_secrets_class(class) {
            return Err(FlowRefusal {
                reason: "data-class-forbidden",
                step: step_id.to_owned(),
                capability: capability.to_owned(),
                class: class.to_owned(),
                destination: destination.to_owned(),
                deciding_policies: vec!["r10-secrets-never-egress".to_owned()],
            });
        }

        let is_sens = is_sensitive_class(class);
        let ctx_result = Context::from_json_value(
            json!({
                "class": class,
                "sensitive": is_sens,
                "destination": destination,
                "step": step_id,
                "plan": plan_hash,
            }),
            None,
        );
        let Ok(context) = ctx_result else {
            return Err(FlowRefusal {
                reason: "data-class-forbidden",
                step: step_id.to_owned(),
                capability: capability.to_owned(),
                class: class.to_owned(),
                destination: destination.to_owned(),
                deciding_policies: Vec::new(),
            });
        };

        let Ok(principal) = sidged_uid("Sidged::Owner", owner_did) else {
            return Err(FlowRefusal {
                reason: "data-class-forbidden",
                step: step_id.to_owned(),
                capability: capability.to_owned(),
                class: class.to_owned(),
                destination: destination.to_owned(),
                deciding_policies: Vec::new(),
            });
        };
        let Ok(action) = sidged_uid("Sidged::Action", "flow") else {
            return Err(FlowRefusal {
                reason: "data-class-forbidden",
                step: step_id.to_owned(),
                capability: capability.to_owned(),
                class: class.to_owned(),
                destination: destination.to_owned(),
                deciding_policies: Vec::new(),
            });
        };
        let Ok(resource) = sidged_uid("Sidged::Capability", capability) else {
            return Err(FlowRefusal {
                reason: "data-class-forbidden",
                step: step_id.to_owned(),
                capability: capability.to_owned(),
                class: class.to_owned(),
                destination: destination.to_owned(),
                deciding_policies: Vec::new(),
            });
        };

        let Ok(request) = Request::new(principal, action, resource, context, None) else {
            return Err(FlowRefusal {
                reason: "data-class-forbidden",
                step: step_id.to_owned(),
                capability: capability.to_owned(),
                class: class.to_owned(),
                destination: destination.to_owned(),
                deciding_policies: Vec::new(),
            });
        };

        let response =
            Authorizer::new().is_authorized(&request, &self.policies, &Entities::empty());
        if response.decision() == Decision::Allow {
            Ok(())
        } else {
            let mut deciding: Vec<String> = response
                .diagnostics()
                .reason()
                .map(|pid| {
                    self.id_map
                        .get(&pid.to_string())
                        .cloned()
                        .unwrap_or_else(|| pid.to_string())
                })
                .collect();
            if deciding.is_empty() && self.has_default_flow {
                deciding.push("default-flow".to_owned());
            }
            deciding.sort();
            deciding.dedup();
            Err(FlowRefusal {
                reason: "data-class-forbidden",
                step: step_id.to_owned(),
                capability: capability.to_owned(),
                class: class.to_owned(),
                destination: destination.to_owned(),
                deciding_policies: deciding,
            })
        }
    }
}

/// Exact dot-boundary sensitivity rule (Spec 0013 §4 R8, `plan.flow.010`).
pub fn is_sensitive_class(name: &str) -> bool {
    name == "health.records" || name.starts_with("health.records.") || is_secrets_class(name)
}

/// R10 rule: `secrets` and `secrets.*` can never reach egress.
pub fn is_secrets_class(name: &str) -> bool {
    name == "secrets" || name.starts_with("secrets.")
}

fn sidged_uid(type_str: &str, id: &str) -> Result<EntityUid, String> {
    let t = EntityTypeName::from_str(type_str).map_err(|e| e.to_string())?;
    let eid = EntityId::from_str(id).map_err(|e| e.to_string())?;
    Ok(EntityUid::from_type_name_and_id(t, eid))
}

/// Evaluate all information flows of a parsed plan against the catalog and `CedarFlowPolicy`
/// (Spec 0013 §4 R8–R11). The plan is the one [`crate::stored::read_plan`] returned, so the
/// flow check, the verifier and the engine read the same representation (ROADMAP 11f);
/// `plan_digest` is that document's 0013 R2 digest.
#[allow(clippy::result_large_err)]
pub fn check_plan_flows(
    plan: &Plan,
    plan_digest: &str,
    catalog: &Value,
    owner_did: &str,
    flow_policy: &CedarFlowPolicy,
) -> Result<(), FlowRefusal> {
    let Some(cat_arr) = catalog.as_array() else {
        return Err(FlowRefusal {
            reason: "data-class-forbidden",
            step: String::new(),
            capability: String::new(),
            class: String::new(),
            destination: String::new(),
            deciding_policies: Vec::new(),
        });
    };
    let mut caps: HashMap<String, (Vec<String>, Vec<String>)> = HashMap::new();
    for entry in cat_arr {
        if let Some(id) = entry["id"].as_str() {
            let effects = entry["effects"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let classes = entry["data_classes"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            caps.insert(id.to_owned(), (effects, classes));
        }
    }

    let mut step_labels: HashMap<String, Vec<String>> = HashMap::new();
    let extend = |into: &mut Vec<String>, labels: Option<&Vec<String>>| {
        for c in labels.into_iter().flatten() {
            if !into.contains(c) {
                into.push(c.clone());
            }
        }
    };

    for step in &plan.steps {
        let (step_id, cap_id, over, args) = match step {
            Step::Expr { id, expr } => {
                let mut acc = Vec::new();
                if let Ok(prog) = crate::plan::compile_expr(expr) {
                    for var in prog.references().variables() {
                        extend(&mut acc, step_labels.get(var));
                    }
                }
                step_labels.insert(id.clone(), acc);
                continue;
            }
            Step::Call {
                id,
                capability,
                args,
                ..
            } => (id, capability, None, args),
            Step::Map {
                id,
                capability,
                over,
                args,
                ..
            } => (id, capability, Some(over), args),
        };
        let Some((effects, cap_classes)) = caps.get(cap_id.as_str()) else {
            continue;
        };
        let mut reaching = Vec::new();
        if let Some(over) = over {
            extend(&mut reaching, step_labels.get(over));
        }
        for (_, arg) in args {
            if let Arg::Ref { step, .. } = arg {
                extend(&mut reaching, step_labels.get(step));
            }
        }
        extend(&mut reaching, Some(cap_classes));

        if effects.iter().any(|e| e == "egress") {
            // R8: destination from the step's literal `to` argument, or `""` when `to` is not a literal.
            let destination = args
                .iter()
                .find_map(|(name, arg)| match arg {
                    Arg::Lit(Value::String(to)) if name == "to" => Some(to.as_str()),
                    _ => None,
                })
                .unwrap_or("");
            let mut checked_classes = HashSet::new();
            for class in &reaching {
                if checked_classes.insert(class.clone()) {
                    flow_policy.check_single_flow(
                        owner_did,
                        step_id,
                        cap_id,
                        class,
                        destination,
                        plan_digest,
                    )?;
                }
            }
        }
        step_labels.insert(step_id.clone(), reaching);
    }
    Ok(())
}

/// [`check_plan_flows`] on a JSON plan: read with the one plan parser, refused as
/// `malformed` when it does not parse.
#[allow(clippy::result_large_err)]
pub fn check_json_plan_flows(
    plan: &Value,
    catalog: &Value,
    owner_did: &str,
    flow_policy: &CedarFlowPolicy,
) -> Result<(), FlowRefusal> {
    let refused = || FlowRefusal {
        reason: "malformed",
        step: String::new(),
        capability: String::new(),
        class: String::new(),
        destination: String::new(),
        deciding_policies: Vec::new(),
    };
    let parsed = read_plan(plan).map_err(|_| refused())?;
    let digest = plan_digest(plan).map_err(|_| refused())?;
    check_plan_flows(&parsed, &digest, catalog, owner_did, flow_policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_ten_dcbor_signed_flow_check_vectors_pass() {
        let data: Value = serde_json::from_str(include_str!(
            "../../../spec/test-vectors/plan/dcbor-signed.json"
        ))
        .unwrap();
        let mut count = 0;
        for vec_entry in data["vectors"].as_array().unwrap() {
            if vec_entry["operation"].as_str() != Some("flow-check") {
                continue;
            }
            count += 1;
            let id = vec_entry["id"].as_str().unwrap();
            let input = &vec_entry["input"];
            let sources: Vec<&str> = input["policies"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            let policy = CedarFlowPolicy::from_sources(&sources).unwrap();
            let res = check_json_plan_flows(
                &input["plan"],
                &input["catalog"],
                "did:key:z6MkwSD8dBdqcXQzKJZQFPy2hh2izzxskndKCjdmC2dBpfME",
                &policy,
            );
            let actual = match res {
                Ok(()) => json!({"result": "accept"}),
                Err(refusal) => json!({"result": "refuse", "reason": refusal.reason}),
            };
            assert_eq!(actual, vec_entry["expected"], "vector {id} failed");
        }
        assert_eq!(count, 10, "all 10 plan.flow.001..010 vectors must execute");
    }

    #[test]
    fn a_projected_member_carries_the_producers_labels_to_egress() {
        let catalog = json!([
            {"id": "urn:sidged:capability:records.read", "effects": ["read"],
             "data_classes": ["health.records.notes"]},
            {"id": "urn:sidged:capability:message.send", "effects": ["egress"],
             "data_classes": []}
        ]);
        let plan = |body: Value| {
            json!({"v": "0.1", "steps": [
                {"id": "notes", "kind": "call", "capability": "urn:sidged:capability:records.read",
                 "args": {}},
                {"id": "send", "kind": "call", "capability": "urn:sidged:capability:message.send",
                 "approval": true, "args": {"to": {"lit": "contact:bea"}, "body": body}}
            ]})
        };
        let policy = CedarFlowPolicy::default_set();
        let owner = "did:example:owner";
        for body in [
            json!({"ref": "notes", "field": "text"}),
            json!({"ref": "notes"}),
        ] {
            let err =
                check_json_plan_flows(&plan(body.clone()), &catalog, owner, &policy).unwrap_err();
            assert_eq!(err.class, "health.records.notes", "{body}");
        }
        check_json_plan_flows(&plan(json!({"lit": "hi"})), &catalog, owner, &policy).unwrap();
    }

    #[test]
    fn r11_refusal_reports_deciding_policy_ids() {
        let forbid_src = r#"@id("owner-forbid-health")
forbid (principal, action == Sidged::Action::"flow", resource)
when { context.class == "health.records.notes" };"#;
        let policy = CedarFlowPolicy::from_sources(&[DEFAULT_FLOW_POLICY, forbid_src]).unwrap();
        let err = policy
            .check_single_flow(
                "did:key:z6MkwSD8dBdqcXQzKJZQFPy2hh2izzxskndKCjdmC2dBpfME",
                "send1",
                "urn:sidged:capability:message.send",
                "health.records.notes",
                "contact:dr-meier",
                "planDigest123",
            )
            .unwrap_err();
        assert_eq!(err.reason, "data-class-forbidden");
        assert_eq!(err.deciding_policies, vec!["owner-forbid-health"]);
    }
}
