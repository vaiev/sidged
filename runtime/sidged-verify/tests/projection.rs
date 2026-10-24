//! 0003 R4a: a `ref` with `field` names a property the producer's `output_schema` declares,
//! and the projected value keeps the producer's labels.

use serde_json::{json, Value};
use sidged_verify::{stored, DenySensitive};

fn catalog() -> Value {
    json!([
        {
            "id": "urn:sidged:capability:workspace.read",
            "effects": ["read"],
            "data_classes": ["files.content"],
            "consequential": false,
            "cost": {"class": "free"},
            "output_schema": {"type": "object", "properties": {"path": {"type": "string"}, "text": {"type": "string"}}}
        },
        {
            "id": "urn:sidged:capability:health.read",
            "effects": ["read"],
            "data_classes": ["health.records.notes"],
            "consequential": false,
            "cost": {"class": "free"},
            "output_schema": {"type": "object", "properties": {"text": {"type": "string"}}}
        },
        {
            "id": "urn:sidged:capability:notes.append",
            "effects": ["write"],
            "data_classes": [],
            "consequential": false,
            "cost": {"class": "free"}
        },
        {
            "id": "urn:sidged:capability:message.send",
            "effects": ["egress"],
            "data_classes": ["communications.content"],
            "consequential": true,
            "cost": {"class": "free"}
        }
    ])
}

fn plan(producer: &str, arg: Value) -> Value {
    json!({
        "v": "0.1",
        "steps": [
            {"id": "read", "kind": "call", "capability": producer,
             "args": {"path": {"lit": "report.md"}}},
            {"id": "pick", "kind": "expr", "expr": "read.text"},
            {"id": "note", "kind": "call", "capability": "urn:sidged:capability:notes.append",
             "args": {"text": arg}}
        ]
    })
}

fn check(plan: &Value) -> Result<(), String> {
    let parsed = stored::parse_plan(plan).map_err(|e| e.code().to_string())?;
    let caps = stored::parse_catalog(&catalog()).map_err(|e| e.code().to_string())?;
    sidged_verify::verify(&parsed, &caps, &DenySensitive)
        .map(|_| ())
        .map_err(|problems| problems.join("; "))
}

const READ: &str = "urn:sidged:capability:workspace.read";

#[test]
fn a_declared_field_is_accepted() {
    check(&plan(READ, json!({"ref": "read", "field": "text"}))).unwrap();
    check(&plan(READ, json!({"ref": "read", "field": "path"}))).unwrap();
    check(&plan(READ, json!({"ref": "read"}))).unwrap();
}

#[test]
fn an_undeclared_field_is_refused() {
    let err = check(&plan(READ, json!({"ref": "read", "field": "body"}))).unwrap_err();
    assert!(err.contains("body"), "{err}");
}

#[test]
fn a_field_of_a_step_without_an_output_schema_is_refused() {
    // An expression and a capability without `output_schema` declare no members.
    check(&plan(READ, json!({"ref": "pick", "field": "text"}))).unwrap_err();
    let mut no_schema = plan(READ, json!({"ref": "read"}));
    no_schema["steps"][2]["args"]["text"] = json!({"lit": "x"});
    no_schema["steps"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "again", "kind": "call",
            "capability": "urn:sidged:capability:notes.append",
            "args": {"text": {"ref": "note", "field": "text"}}}));
    check(&no_schema).unwrap_err();
}

#[test]
fn a_field_has_the_shape_of_a_name() {
    for bad in [
        json!({"ref": "read", "field": 1}),
        json!({"ref": "read", "field": ""}),
        json!({"ref": "read", "field": "text", "extra": true}),
        json!({"field": "text"}),
        json!({"lit": "x", "field": "text"}),
    ] {
        assert!(check(&plan(READ, bad.clone())).is_err(), "{bad}");
    }
}

#[test]
fn a_projected_member_keeps_the_producers_labels() {
    let send = |arg: Value| {
        json!({
            "v": "0.1",
            "steps": [
                {"id": "read", "kind": "call", "capability": "urn:sidged:capability:health.read",
                 "args": {}},
                {"id": "send", "kind": "call", "capability": "urn:sidged:capability:message.send",
                 "approval": true, "args": {"to": {"lit": "contact:bea"}, "body": arg}}
            ]
        })
    };
    let err = check(&send(json!({"ref": "read", "field": "text"}))).unwrap_err();
    assert!(err.contains("health.records.notes"), "{err}");
    check(&send(json!({"ref": "read"}))).unwrap_err();
}
