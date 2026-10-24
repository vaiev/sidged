// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Morphing surface composer: builds `@vaiev/ui` v4 surfaces from capability descriptors
//! (SDG-L1 `input_schema` / `output_schema`), from linguist clarifications (intent-catalog
//! slots) and from signed artifact result surfaces. Which primitive renders a value is
//! decided by the catalog binds, never by the capability or intent name. Every surface
//! is validated against the catalog before it is returned.

use serde_json::{json, Map, Value};
use sidged_cli::linguist::{IntentCatalog, VerifiedIntent};

use crate::catalog::{A2uiCatalog, Primitive, SURFACE_VERSION};

const FIELD_NAME_MAX: usize = 64;

fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// `source_timezone` -> `Source timezone`.
fn humanize(name: &str) -> String {
    let spaced = name.replace(['_', '-', '.'], " ");
    let mut chars = spaced.trim().chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => name.to_string(),
    }
}

/// Maximum string length a primitive's props schema allows at `pointer`, if declared.
fn max_len(primitive: &Primitive, pointer: &str) -> usize {
    primitive
        .props_schema
        .pointer(pointer)
        .and_then(|s| s.get("maxLength"))
        .and_then(Value::as_u64)
        .map_or(4096, |n| n as usize)
}

fn max_items(primitive: &Primitive, pointer: &str) -> usize {
    primitive
        .props_schema
        .pointer(pointer)
        .and_then(|s| s.get("maxItems"))
        .and_then(Value::as_u64)
        .map_or(64, |n| n as usize)
}

fn node(primitive: &Primitive, props: Value) -> Value {
    json!({"primitive": primitive.name, "props": props})
}

/// The JSON Schema shape of a value without a declared schema.
fn infer_schema(value: &Value) -> Value {
    match value {
        Value::Array(items) => match items.first() {
            Some(first) => json!({"type": "array", "items": infer_schema(first)}),
            None => json!({"type": "array", "items": {}}),
        },
        Value::Object(members) => {
            let properties: Map<String, Value> = members
                .iter()
                .map(|(k, v)| (k.clone(), infer_schema(v)))
                .collect();
            json!({"type": "object", "properties": properties})
        }
        Value::String(_) => json!({"type": "string"}),
        Value::Bool(_) => json!({"type": "boolean"}),
        Value::Number(n) if n.is_i64() || n.is_u64() => json!({"type": "integer"}),
        Value::Number(_) => json!({"type": "number"}),
        Value::Null => json!({"type": "null"}),
    }
}

fn field_kind(schema: &Value) -> (&'static str, Option<Vec<Value>>) {
    if let Some(options) = schema.get("enum").and_then(Value::as_array) {
        if options.iter().all(Value::is_string) {
            return ("choice", Some(options.clone()));
        }
    }
    let kind = match schema.get("type").and_then(Value::as_str) {
        Some("string") => "text",
        Some("integer") => "integer",
        Some("number") => "number",
        Some("boolean") => "boolean",
        Some("array")
            if schema.pointer("/items/type").and_then(Value::as_str) == Some("string") =>
        {
            "text-list"
        }
        _ => "json",
    };
    (kind, None)
}

/// FormSurface fields for an object schema, optionally carrying values (readonly mode).
fn fields_from_schema(
    form: &Primitive,
    object_schema: &Value,
    values: Option<&Map<String, Value>>,
) -> Result<Vec<Value>, String> {
    let required: Vec<&str> = object_schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let empty = Map::new();
    let properties = object_schema
        .get("properties")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let field_ptr = "/properties/fields/items/properties";
    let mut fields = Vec::new();
    for (name, schema) in properties {
        if name.chars().count() > FIELD_NAME_MAX {
            return Err(format!("field name {name} is too long"));
        }
        let (kind, options) = field_kind(schema);
        let label = schema
            .get("title")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| humanize(name));
        let mut field = json!({
            "name": name,
            "label": clip(&label, max_len(form, &format!("{field_ptr}/label"))),
            "kind": kind,
            "required": required.contains(&name.as_str()),
        });
        if let Some(description) = schema.get("description").and_then(Value::as_str) {
            field["description"] = json!(clip(
                description,
                max_len(form, &format!("{field_ptr}/description"))
            ));
        }
        if let Some(options) = options {
            field["options"] = json!(options);
        }
        if let Some(value) = values.and_then(|v| v.get(name)) {
            field["value"] = value.clone();
        }
        fields.push(field);
    }
    if fields.len() > max_items(form, "/properties/fields") {
        return Err("too many fields for one FormSurface".into());
    }
    Ok(fields)
}

fn checked(catalog: &A2uiCatalog, surface: Value) -> Result<Value, String> {
    let problems = catalog.validate_surface(&surface);
    if problems.is_empty() {
        Ok(surface)
    } else {
        Err(format!("surface-invalid: {}", problems.join("; ")))
    }
}

fn header(
    catalog: &A2uiCatalog,
    title: &str,
    subtitle: Option<&str>,
    status: &str,
) -> Result<Value, String> {
    let primitive = catalog.by_role("header")?;
    let mut props = json!({
        "title": clip(title, max_len(primitive, "/properties/title")),
        "status": status,
    });
    if let Some(subtitle) = subtitle.filter(|s| !s.is_empty()) {
        props["subtitle"] = json!(clip(subtitle, max_len(primitive, "/properties/subtitle")));
    }
    Ok(node(primitive, props))
}

fn string_list(value: Option<&Value>) -> Vec<Value> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|v| v.is_string())
        .cloned()
        .collect()
}

/// Where a capability's data may flow, as declared by its descriptor.
fn capability_flow(catalog: &A2uiCatalog, descriptor: &Value) -> Result<Value, String> {
    let primitive = catalog.by_role("provenance")?;
    let egress = string_list(descriptor.get("effects")).contains(&json!("egress"));
    let (mode, label) = if egress {
        (
            "gateway",
            "Leaves this device only through the Privacy Gateway",
        )
    } else {
        ("local", "Stays on this device")
    };
    Ok(node(
        primitive,
        json!({
            "mode": mode,
            "label": label,
            "residency": string_list(descriptor.pointer("/residency/tags")),
            "data_classes": string_list(descriptor.get("data_classes")),
        }),
    ))
}

fn descriptor_source(descriptor: &Value) -> Result<(String, String, Option<String>), String> {
    let id = descriptor
        .get("id")
        .and_then(Value::as_str)
        .ok_or("capability descriptor has no id")?;
    let title = descriptor
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or(id);
    let description = descriptor
        .get("description")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok((id.to_string(), title.to_string(), description))
}

/// The input surface of one capability: header, flow badge and a form from `input_schema`.
pub fn capability_input(catalog: &A2uiCatalog, descriptor: &Value) -> Result<Value, String> {
    let (id, title, description) = descriptor_source(descriptor)?;
    let input_schema = descriptor
        .get("input_schema")
        .ok_or("capability descriptor has no input_schema")?;
    let form = catalog
        .bind_schema(input_schema)
        .filter(|p| p.role == "form")
        .ok_or("no primitive binds this input_schema as a form")?;
    let fields = fields_from_schema(form, input_schema, None)?;
    let surface = json!({
        "v": SURFACE_VERSION,
        "kind": "input",
        "source": {"capability": id},
        "nodes": [
            header(catalog, &title, description.as_deref(), "ready")?,
            capability_flow(catalog, descriptor)?,
            node(form, json!({"mode": "input", "fields": fields})),
        ],
    });
    checked(catalog, surface)
}

/// Rows and columns for a collection primitive, projected onto scalar cells.
fn table_props(table: &Primitive, item_schema: &Value, rows: &[Value]) -> Value {
    let mut keys: Vec<String> = item_schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|p| p.keys().cloned().collect())
        .unwrap_or_default();
    if keys.is_empty() {
        for row in rows.iter().take(20) {
            for key in row.as_object().into_iter().flat_map(|o| o.keys()) {
                if !keys.contains(key) {
                    keys.push(key.clone());
                }
            }
        }
    }
    keys.truncate(max_items(table, "/properties/columns"));
    let columns: Vec<Value> = keys
        .iter()
        .map(|k| json!({"key": k, "label": humanize(k)}))
        .collect();
    let cells: Vec<Value> = rows
        .iter()
        .take(max_items(table, "/properties/rows"))
        .map(|row| {
            let projected: Map<String, Value> = keys
                .iter()
                .filter_map(|k| row.get(k).map(|v| (k.clone(), v)))
                .map(|(k, v)| {
                    let cell = match v {
                        Value::Object(_) | Value::Array(_) => json!(clip(&v.to_string(), 512)),
                        other => other.clone(),
                    };
                    (k, cell)
                })
                .collect();
            Value::Object(projected)
        })
        .collect();
    json!({"columns": columns, "rows": cells})
}

/// Items projected onto the member names the primitive's item schema declares.
fn project_items(primitive: &Primitive, list_pointer: &str, items: &[Value]) -> Vec<Value> {
    let allowed: Vec<String> = primitive
        .props_schema
        .pointer(&format!("{list_pointer}/items/properties"))
        .and_then(Value::as_object)
        .map(|p| p.keys().cloned().collect())
        .unwrap_or_default();
    items
        .iter()
        .take(max_items(primitive, list_pointer))
        .map(|item| {
            let kept: Map<String, Value> = item
                .as_object()
                .into_iter()
                .flatten()
                .filter(|(k, v)| allowed.contains(k) && !v.is_null())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            Value::Object(kept)
        })
        .collect()
}

/// The output surface of one capability result, bound by `output_schema` (or the value's shape).
pub fn capability_output(
    catalog: &A2uiCatalog,
    descriptor: &Value,
    result: &Value,
) -> Result<Value, String> {
    let (id, title, description) = descriptor_source(descriptor)?;
    let schema = descriptor
        .get("output_schema")
        .cloned()
        .unwrap_or_else(|| infer_schema(result));
    let primitive = catalog
        .bind_schema(&schema)
        .ok_or("no primitive binds this output")?;
    let body = match primitive.role.as_str() {
        "progress" => {
            let items = result.as_array().ok_or("result is not a list")?;
            json!({"steps": project_items(primitive, "/properties/steps", items)})
        }
        "collection" => {
            let rows = result.as_array().ok_or("result is not a list")?;
            let item_schema = schema.get("items").cloned().unwrap_or(json!({}));
            let item_schema = if item_schema.get("properties").is_some() {
                item_schema
            } else {
                rows.first().map(infer_schema).unwrap_or(item_schema)
            };
            table_props(primitive, &item_schema, rows)
        }
        "form" => {
            let values = result.as_object().ok_or("result is not an object")?;
            let schema = if schema.get("properties").is_some() {
                schema.clone()
            } else {
                infer_schema(result)
            };
            json!({"mode": "readonly", "fields": fields_from_schema(primitive, &schema, Some(values))?})
        }
        role => {
            return Err(format!(
                "primitive role {role} cannot render a capability result"
            ))
        }
    };
    let surface = json!({
        "v": SURFACE_VERSION,
        "kind": "output",
        "source": {"capability": id},
        "nodes": [
            header(catalog, &title, description.as_deref(), "completed")?,
            capability_flow(catalog, descriptor)?,
            node(primitive, body),
        ],
    });
    checked(catalog, surface)
}

/// The clarification surface for a verified linguist envelope: the question as header and
/// one form field per slot, missing slots labelled with the catalog question.
pub fn clarification(
    catalog: &A2uiCatalog,
    intents: &IntentCatalog,
    verified: &VerifiedIntent,
) -> Result<Value, String> {
    let envelope = &verified.envelope;
    let form = catalog.by_role("form")?;
    let field_ptr = "/properties/fields/items/properties";
    let question = envelope
        .clarification_question_local
        .clone()
        .unwrap_or_default();
    let mut fields = Vec::new();
    let title = match envelope.intent.as_deref().and_then(|id| intents.intent(id)) {
        Some(entry) => {
            for (name, spec) in &entry.slots_schema.properties.0 {
                let missing = envelope.missing_slots.contains(name);
                let label = if missing {
                    spec.ask
                        .get(&envelope.lang)
                        .cloned()
                        .unwrap_or_else(|| humanize(name))
                } else {
                    humanize(name)
                };
                let mut field = json!({
                    "name": name,
                    "label": clip(&label, max_len(form, &format!("{field_ptr}/label"))),
                    "kind": "text",
                    "required": entry.slots_schema.required.contains(name),
                    "description": clip(&spec.description, max_len(form, &format!("{field_ptr}/description"))),
                });
                if let Some(value) = envelope.slots.get(name) {
                    field["value"] = json!(value);
                }
                fields.push(field);
            }
            // §2c: each follow-up's slots, named then.<i>.<slot> so the answers find their way back.
            for (index, follow_up) in envelope.then.iter().enumerate() {
                let Some(next) = intents.intent(&follow_up.intent) else {
                    continue;
                };
                for (name, spec) in &next.slots_schema.properties.0 {
                    let missing = follow_up.missing_slots.contains(name);
                    if !missing && follow_up.slots.get(name).is_none() {
                        continue;
                    }
                    let asked = if missing {
                        spec.ask
                            .get(&envelope.lang)
                            .cloned()
                            .unwrap_or_else(|| humanize(name))
                    } else {
                        humanize(name)
                    };
                    let label = format!("{}: {asked}", next.title);
                    let mut field = json!({
                        "name": format!("then.{index}.{name}"),
                        "label": clip(&label, max_len(form, &format!("{field_ptr}/label"))),
                        "kind": "text",
                        "required": missing,
                        "description": clip(&spec.description, max_len(form, &format!("{field_ptr}/description"))),
                    });
                    if let Some(value) = follow_up.slots.get(name) {
                        field["value"] = json!(value);
                    }
                    fields.push(field);
                }
            }
            entry.title.clone()
        }
        None => {
            fields.push(json!({"name": "utterance", "label": clip(&question, 256),
                               "kind": "text", "required": true}));
            question.clone()
        }
    };
    let flow = catalog.by_role("provenance")?;
    let mut head = header(catalog, &title, Some(&question), "clarifying")?;
    head["props"]["lang"] = json!(envelope.lang);
    let surface = json!({
        "v": SURFACE_VERSION,
        "kind": "clarification",
        "source": {"intent": envelope.intent, "lang": envelope.lang},
        "nodes": [
            head,
            node(flow, json!({
                "mode": "undecided",
                "label": "Nothing leaves this device until the intent is complete",
                "residency": [],
                "data_classes": envelope.required_data_classes,
            })),
            node(form, json!({"mode": "input", "fields": fields})),
        ],
    });
    checked(catalog, surface)
}

/// The surface of a complete intent: the canonical English intent as header, where it will
/// be planned, and the slot values. Nothing has run; the planner and the Trusted UI follow.
pub fn intent_ready(
    catalog: &A2uiCatalog,
    intents: &IntentCatalog,
    verified: &VerifiedIntent,
) -> Result<Value, String> {
    let envelope = &verified.envelope;
    let entry = envelope
        .intent
        .as_deref()
        .and_then(|id| intents.intent(id))
        .ok_or("intent-ready needs a catalog intent")?;
    let form = catalog.by_role("form")?;
    let flow = catalog.by_role("provenance")?;
    let fields: Vec<Value> = entry
        .slots_schema
        .properties
        .0
        .iter()
        .filter_map(|(name, spec)| {
            envelope.slots.get(name).map(|value| {
                json!({"name": name, "label": humanize(name), "kind": "text",
                       "required": entry.slots_schema.required.contains(name),
                       "description": clip(&spec.description, 512), "value": value})
            })
        })
        .collect();
    let mut fields = fields;
    let mut canonical = envelope.canonical_intent_en.clone().unwrap_or_default();
    for (index, follow_up) in envelope.then.iter().enumerate() {
        canonical.push_str(", then ");
        canonical.push_str(&follow_up.canonical_intent_en);
        let Some(next) = intents.intent(&follow_up.intent) else {
            continue;
        };
        for (name, spec) in &next.slots_schema.properties.0 {
            if let Some(value) = follow_up.slots.get(name) {
                fields.push(json!({"name": format!("then.{index}.{name}"),
                                   "label": format!("{}: {}", next.title, humanize(name)),
                                   "kind": "text", "required": next.slots_schema.required.contains(name),
                                   "description": clip(&spec.description, 512), "value": value}));
            }
        }
    }
    // Until device pairing (WP 19) every plan runs on this node, whatever route the catalog
    // suggests for later; the preview says what will happen, not what is planned for the future.
    let label = "Ready: the plan runs on this node";
    let surface = json!({
        "v": SURFACE_VERSION,
        "kind": "output",
        "source": {"intent": envelope.intent, "lang": envelope.lang},
        "nodes": [
            header(catalog, &canonical, Some(&entry.title), "ready")?,
            node(flow, json!({
                "mode": "local",
                "label": label,
                "residency": [],
                "data_classes": envelope.required_data_classes,
            })),
            node(form, json!({"mode": "readonly", "fields": fields})),
        ],
    });
    checked(catalog, surface)
}

/// Convert a signed-record `ResultSurface` (sidged-record) into a v4 surface. Primitives
/// keep their names; members a v4 primitive does not declare are dropped, and the
/// consequential action is reduced to its capability id (the gate lives in the Core).
pub fn from_result_surface(catalog: &A2uiCatalog, legacy: &Value) -> Result<Value, String> {
    let props = legacy.get("props").ok_or("not a ResultSurface")?;
    let mut nodes = Vec::new();
    for item in props
        .get("primitives")
        .and_then(Value::as_array)
        .ok_or("ResultSurface without primitives")?
    {
        let name = item.get("primitive").and_then(Value::as_str).unwrap_or("");
        let primitive = catalog
            .primitive(name)
            .ok_or_else(|| format!("unknown primitive {name}"))?;
        let declared: Vec<&String> = primitive
            .props_schema
            .get("properties")
            .and_then(Value::as_object)
            .map(|p| p.keys().collect())
            .unwrap_or_default();
        let mut kept: Map<String, Value> = item
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(k, v)| declared.contains(k) && !v.is_null())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        if let Some(cap) = item.pointer("/consequential_action/capability") {
            if declared.iter().any(|k| *k == "consequential_capability") {
                kept.insert("consequential_capability".into(), cap.clone());
            }
        }
        if let Some(Value::Array(steps)) = kept.get("steps").cloned() {
            kept.insert(
                "steps".into(),
                json!(project_items(primitive, "/properties/steps", &steps)),
            );
        }
        // Long texts (a run report) are shortened to the primitive's limits, not refused.
        for (key, value) in kept.iter_mut() {
            if let Value::String(text) = value {
                let limit = max_len(primitive, &format!("/properties/{key}"));
                if text.chars().count() > limit {
                    *value = json!(clip(text, limit));
                }
            }
        }
        if primitive.role == "header" && !kept.contains_key("status") {
            kept.insert("status".into(), json!("completed"));
        }
        if primitive.role == "provenance" && !kept.contains_key("data_classes") {
            kept.insert("data_classes".into(), json!([]));
        }
        if primitive.role == "artifact" {
            if let Some(Value::Array(files)) = kept.get("files").cloned() {
                kept.insert(
                    "files".into(),
                    json!(project_items(primitive, "/properties/files", &files)),
                );
            }
        }
        nodes.push(node(primitive, Value::Object(kept)));
    }
    let surface = json!({
        "v": SURFACE_VERSION,
        "kind": "output",
        "source": {"record_id": props.get("record_id").cloned().unwrap_or(Value::Null)},
        "nodes": nodes,
    });
    checked(catalog, surface)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sidged_cli::linguist::Ordered;

    fn catalog() -> A2uiCatalog {
        A2uiCatalog::builtin().unwrap()
    }

    fn time_convert() -> Value {
        serde_json::from_str(include_str!(
            "../../../spec/examples/capability-descriptor.time-convert.json"
        ))
        .unwrap()
    }

    #[test]
    fn input_surface_is_built_from_the_input_schema() {
        let surface = capability_input(&catalog(), &time_convert()).unwrap();
        assert_eq!(surface["kind"], "input");
        let nodes = surface["nodes"].as_array().unwrap();
        assert_eq!(nodes[0]["primitive"], "IntentHeader");
        assert_eq!(nodes[1]["props"]["mode"], "local");
        let fields = nodes[2]["props"]["fields"].as_array().unwrap();
        let names: Vec<&str> = fields.iter().map(|f| f["name"].as_str().unwrap()).collect();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"source_timezone"));
        assert!(fields
            .iter()
            .all(|f| f["required"] == true && f["kind"] == "text"));
        let label = fields
            .iter()
            .find(|f| f["name"] == "source_timezone")
            .unwrap()["label"]
            .clone();
        assert_eq!(label, "Source timezone");
    }

    #[test]
    fn output_surfaces_follow_the_catalog_binds() {
        let catalog = catalog();
        let object = capability_output(
            &catalog,
            &time_convert(),
            &json!({"source": {"tz": "UTC"}, "target": {"tz": "CET"}, "time_difference": "+1h"}),
        )
        .unwrap();
        assert_eq!(object["nodes"][2]["primitive"], "FormSurface");
        assert_eq!(object["nodes"][2]["props"]["mode"], "readonly");

        let mut lister = time_convert();
        lister["id"] = json!("urn:sidged:capability:files.list");
        lister["effects"] = json!(["read", "egress"]);
        lister["residency"] = json!({"tags": ["CH"]});
        lister["output_schema"] = json!({"type": "array", "items": {"type": "object",
            "properties": {"path": {"type": "string"}, "size": {"type": "integer"}}}});
        let table = capability_output(
            &catalog,
            &lister,
            &json!([{"path": "a.txt", "size": 3, "secret_extra": {"x": 1}}]),
        )
        .unwrap();
        assert_eq!(table["nodes"][1]["props"]["mode"], "gateway");
        assert_eq!(table["nodes"][2]["primitive"], "DataTable");
        assert_eq!(
            table["nodes"][2]["props"]["rows"][0],
            json!({"path": "a.txt", "size": 3})
        );

        lister["output_schema"] = json!({"type": "array", "items": {"type": "object",
            "required": ["step_id", "label", "status"]}});
        let steps = capability_output(
            &catalog,
            &lister,
            &json!([{"step_id": "s1", "label": "fetch", "status": "completed", "html": "<b>"}]),
        )
        .unwrap();
        assert_eq!(steps["nodes"][2]["primitive"], "StepTimeline");
        assert_eq!(
            steps["nodes"][2]["props"]["steps"][0],
            json!({"step_id": "s1", "label": "fetch", "status": "completed"})
        );

        lister["output_schema"] = json!({"type": "string"});
        assert!(capability_output(&catalog, &lister, &json!("plain")).is_err());
    }

    #[test]
    fn clarification_surface_asks_the_catalog_question() {
        let intents = IntentCatalog::builtin().unwrap();
        let envelope = intents
            .derive(
                "gsw",
                Some("scheduling.remind"),
                &Ordered(vec![("subject".into(), "the laundry".into())]),
            )
            .unwrap();
        let verified = VerifiedIntent {
            envelope,
            corrections: vec![],
        };
        let surface = clarification(&catalog(), &intents, &verified).unwrap();
        assert_eq!(surface["kind"], "clarification");
        assert_eq!(surface["nodes"][0]["props"]["status"], "clarifying");
        assert_eq!(
            surface["nodes"][0]["props"]["subtitle"],
            "Wänn söll ich di erinnere?"
        );
        let fields = surface["nodes"][2]["props"]["fields"].as_array().unwrap();
        assert_eq!(fields[0]["value"], "the laundry");
        assert_eq!(fields[1]["name"], "time");
        assert_eq!(fields[1]["label"], "Wänn söll ich di erinnere?");
        assert!(fields[1].get("value").is_none());
    }

    #[test]
    fn legacy_result_surface_converts_without_extra_members() {
        let legacy = json!({"component": "ResultSurface", "props": {"record_id": "r1", "record_digest": "d",
        "primitives": [
            {"primitive": "IntentHeader", "title": "Mail", "active_workers": 2, "status": "completed"},
            {"primitive": "FlowBadge", "mode": "local", "label": "100% Local Processing", "residency": ["CH"]},
            {"primitive": "ArtifactCard", "artifact_type": "application/vnd.sidged.artifact.mail+json",
             "record_id": "r1", "title": "Mail Draft: x", "subtitle": "To: a", "body": "b", "attachments": [],
             "consequential_action": {"capability": "urn:sidged:capability:message.send", "gate_hint": "x"}},
            {"primitive": "StepTimeline", "steps": [{"step_id": "s", "label": "l", "status": "completed",
             "worker_id": null, "requires_owner_gate": true}]}
        ]}});
        let surface = from_result_surface(&catalog(), &legacy).unwrap();
        let card = &surface["nodes"][2]["props"];
        assert_eq!(
            card["consequential_capability"],
            "urn:sidged:capability:message.send"
        );
        assert!(card.get("attachments").is_none());
        assert_eq!(surface["nodes"][1]["props"]["data_classes"], json!([]));
    }
}
