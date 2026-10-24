// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Property tests for information-flow control: random plans over a mixed catalog, checked
//! against an independent reference of the label rules (0003 R7, R10, R11; 0013 R8–R10).
//!
//! Each property is an equivalence, so it fails both on a leak (a sensitive class reaches
//! egress and the plan is accepted) and on over-refusal (a clean plan is refused):
//! - the verifier with `DenySensitive` accepts exactly the plans with no sensitive class at an
//!   egress step and an approval on every consequential step;
//! - the Cedar stage with `default-flow` accepts exactly the plans with no sensitive class at
//!   an egress step;
//! - with an owner `permit` for every flow, it still refuses exactly the plans where `secrets`
//!   reach egress (R10);
//! - the verifier with `DeferToCedar` accepts exactly the plans whose approvals are complete.

use std::collections::BTreeSet;

use serde_json::{json, Value};
use sidged_verify::flow::{check_plan_flows, CedarFlowPolicy, DEFAULT_FLOW_POLICY};
use sidged_verify::{stored, DeferToCedar, DenySensitive};

#[path = "../../fuzz/mutate.rs"]
mod mutate;

struct Capability {
    id: &'static str,
    class: &'static str,
    egress: bool,
    consequential: bool,
}

const CATALOG: &[Capability] = &[
    Capability {
        id: "urn:x:health.read",
        class: "health.records.notes",
        egress: false,
        consequential: false,
    },
    Capability {
        id: "urn:x:vault.read",
        class: "secrets.token",
        egress: false,
        consequential: false,
    },
    Capability {
        id: "urn:x:calendar.read",
        class: "calendar.availability",
        egress: false,
        consequential: false,
    },
    Capability {
        id: "urn:x:look.alike",
        class: "health.recordsx",
        egress: false,
        consequential: false,
    },
    Capability {
        id: "urn:x:note.write",
        class: "notes.content",
        egress: false,
        consequential: true,
    },
    Capability {
        id: "urn:x:message.send",
        class: "communications.content",
        egress: true,
        consequential: true,
    },
    Capability {
        id: "urn:x:web.search",
        class: "query.general",
        egress: true,
        consequential: true,
    },
];

fn catalog_json() -> Value {
    Value::Array(
        CATALOG
            .iter()
            .map(|c| {
                json!({
                    "id": c.id,
                    "effects": [if c.egress { "egress" } else { "read" }],
                    "data_classes": [c.class],
                    "consequential": c.consequential,
                    "cost": {"class": "free"},
                })
            })
            .collect(),
    )
}

fn sensitive(class: &str) -> bool {
    ["health.records", "secrets"]
        .iter()
        .any(|root| class == *root || class.starts_with(&format!("{root}.")))
}

/// A random plan and the reference verdicts for it.
#[derive(Debug)]
struct Case {
    plan: Value,
    sensitive_egress: bool,
    secret_egress: bool,
    missing_approval: bool,
}

fn random_case(rng: &mut mutate::Rng) -> Case {
    let mut steps = Vec::new();
    let mut labels: Vec<BTreeSet<String>> = Vec::new();
    let (mut sensitive_egress, mut secret_egress, mut missing_approval) = (false, false, false);
    for index in 0..1 + rng.below(7) {
        let id = format!("s{index}");
        let refs: Vec<usize> = (0..index).filter(|_| rng.below(3) == 0).collect();
        let mut reaching: BTreeSet<String> = refs
            .iter()
            .flat_map(|r| labels[*r].iter().cloned())
            .collect();
        let kind = if index == 0 { 0 } else { rng.below(3) };
        if kind == 1 {
            // expr: the labels of the steps it names (R10).
            let expr = if refs.is_empty() {
                "1".to_string()
            } else {
                refs.iter()
                    .map(|r| format!("s{r}.value"))
                    .collect::<Vec<_>>()
                    .join(" + ")
            };
            steps.push(json!({"id": id, "kind": "expr", "expr": expr}));
            labels.push(reaching);
            continue;
        }
        let cap = rng.pick(CATALOG);
        let mut args = serde_json::Map::new();
        for (n, r) in refs.iter().enumerate() {
            args.insert(format!("a{n}"), json!({"ref": format!("s{r}")}));
        }
        if rng.below(2) == 0 {
            args.insert("to".into(), json!({"lit": "contact:bea"}));
        }
        let approval = if cap.consequential {
            rng.below(10) != 0
        } else {
            rng.below(2) == 0
        };
        let mut step = json!({"id": id, "kind": "call", "capability": cap.id, "args": args});
        if kind == 2 {
            // map: the list's labels reach the step, item or not (R10).
            let over = rng.below(index);
            reaching.extend(labels[over].iter().cloned());
            step["kind"] = json!("map");
            step["over"] = json!({"ref": format!("s{over}")});
            step["bound"] = json!(1 + rng.below(32));
            if rng.below(2) == 0 {
                step["args"]["item"] = json!({"item": true});
            }
        }
        if approval {
            step["approval"] = json!(true);
        }
        reaching.insert(cap.class.to_string());
        if cap.egress {
            sensitive_egress |= reaching.iter().any(|c| sensitive(c));
            secret_egress |= reaching
                .iter()
                .any(|c| c == "secrets" || c.starts_with("secrets."));
        }
        missing_approval |= cap.consequential && !approval;
        steps.push(step);
        labels.push(reaching);
    }
    Case {
        plan: json!({"v": "0.1", "steps": steps}),
        sensitive_egress,
        secret_egress,
        missing_approval,
    }
}

#[test]
fn verifier_and_cedar_stage_agree_with_the_reference_label_rules() {
    let catalog_value = catalog_json();
    let catalog = stored::parse_catalog(&catalog_value).unwrap();
    let default_flow = CedarFlowPolicy::default_set();
    let permit_all = CedarFlowPolicy::from_sources(&[
        DEFAULT_FLOW_POLICY,
        r#"@id("owner-permits-all")
permit (principal, action == Sidged::Action::"flow", resource);"#,
    ])
    .unwrap();
    let owner = "did:key:z6MkwSD8dBdqcXQzKJZQFPy2hh2izzxskndKCjdmC2dBpfME";
    let mut rng = mutate::Rng(0x1fc0_0000_0000_0001);
    let mut seen = [0usize; 3];
    for case_index in 0..mutate::iterations(3000) {
        let case = random_case(&mut rng);
        let plan = stored::parse_plan(&case.plan).unwrap();
        let strict = sidged_verify::verify(&plan, &catalog, &DenySensitive);
        assert_eq!(
            strict.is_ok(),
            !case.sensitive_egress && !case.missing_approval,
            "case {case_index} DenySensitive {strict:?}: {case:?}"
        );
        let structural = sidged_verify::verify(&plan, &catalog, &DeferToCedar);
        assert_eq!(
            structural.is_ok(),
            !case.missing_approval,
            "case {case_index} DeferToCedar {structural:?}: {case:?}"
        );
        let digest = stored::plan_digest(&case.plan).unwrap();
        let cedar = check_plan_flows(&plan, &digest, &catalog_value, owner, &default_flow);
        assert_eq!(
            cedar.is_ok(),
            !case.sensitive_egress,
            "case {case_index} default-flow {cedar:?}: {case:?}"
        );
        let permitted = check_plan_flows(&plan, &digest, &catalog_value, owner, &permit_all);
        assert_eq!(
            permitted.is_ok(),
            !case.secret_egress,
            "case {case_index} owner permit {permitted:?}: {case:?}"
        );
        seen[0] += usize::from(case.sensitive_egress);
        seen[1] += usize::from(case.secret_egress);
        seen[2] += usize::from(!case.sensitive_egress && !case.missing_approval);
    }
    // The generator must exercise every verdict, or the equivalences above say little.
    assert!(seen.iter().all(|n| *n > 50), "verdict coverage {seen:?}");
}
