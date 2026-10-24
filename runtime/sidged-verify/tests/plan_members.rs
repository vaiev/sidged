//! One reader of the plan (ROADMAP 11f, 0003 §1): the parser refuses every member that
//! `spec/schemas/plan.schema.json` does not allow, so the Rust path, which never runs the
//! JSON Schema, reads exactly the documents the schema accepts.

use serde_json::{json, Value};
use sidged_verify::stored::{parse_plan, Error};

fn plan() -> Value {
    json!({
        "v": "0.1",
        "goal": "Look at each free slot",
        "budget": {"max": {"amount": "0.10", "currency": "CHF"}},
        "steps": [
            {"id": "free", "kind": "call", "capability": "urn:sidged:capability:calendar.free_slots",
             "approval": false, "args": {"range": {"lit": "next_week"}}},
            {"id": "pick", "kind": "expr", "expr": "free.slots"},
            {"id": "each", "kind": "map", "over": {"ref": "free"}, "bound": 2, "approval": false,
             "capability": "urn:sidged:capability:calendar.free_slots", "args": {"range": {"item": true}}}
        ]
    })
}

#[test]
fn every_member_the_schema_allows_is_read() {
    parse_plan(&plan()).unwrap();
}

#[test]
fn a_member_the_schema_does_not_allow_is_refused() {
    type Change = fn(&mut Value);
    let cases: [(&str, Change); 11] = [
        ("top level", |p| p["extra"] = json!(true)),
        ("goal that is not a string", |p| p["goal"] = json!(1)),
        ("budget", |p| p["budget"]["cap"] = json!(1)),
        ("budget.max", |p| p["budget"]["max"]["note"] = json!("x")),
        ("call step", |p| p["steps"][0]["retry"] = json!(3)),
        ("call step with expr", |p| {
            p["steps"][0]["expr"] = json!("true")
        }),
        ("call step with bound", |p| {
            p["steps"][0]["bound"] = json!(2)
        }),
        ("expr step with approval", |p| {
            p["steps"][1]["approval"] = json!(true)
        }),
        ("expr step with args", |p| p["steps"][1]["args"] = json!({})),
        ("map step", |p| p["steps"][2]["note"] = json!("x")),
        ("map step with expr", |p| {
            p["steps"][2]["expr"] = json!("true")
        }),
    ];
    for (name, change) in cases {
        let mut bad = plan();
        change(&mut bad);
        assert_eq!(parse_plan(&bad).err(), Some(Error::Malformed), "{name}");
    }
}
