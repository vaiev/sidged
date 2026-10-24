// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! A small JSON Schema 2020-12 subset validator (capability input/output schemas, UI props).
//!
//! It checks the keywords listed in `SUPPORTED` and refuses every other keyword, so a
//! catalog or form schema can never rely on a rule that is silently not enforced.
//! Annotation keywords (`title`, `description`, ...) are accepted and ignored.

use regex::Regex;
use serde_json::Value;

pub const SUPPORTED: [&str; 16] = [
    "type",
    "enum",
    "const",
    "required",
    "properties",
    "additionalProperties",
    "items",
    "minItems",
    "maxItems",
    "minLength",
    "maxLength",
    "pattern",
    "minimum",
    "maximum",
    "minProperties",
    "maxProperties",
];
const ANNOTATIONS: [&str; 6] = [
    "title",
    "description",
    "default",
    "examples",
    "$comment",
    "x-ask",
];

/// Every keyword in `schema` (recursively) that this validator does not enforce.
pub fn unsupported_keywords(schema: &Value) -> Vec<String> {
    let mut found = Vec::new();
    walk_keywords(schema, "", &mut found);
    found
}

fn walk_keywords(schema: &Value, path: &str, found: &mut Vec<String>) {
    let Some(object) = schema.as_object() else {
        if !schema.is_boolean() {
            found.push(format!("{path}: schema is not an object"));
        }
        return;
    };
    for (key, value) in object {
        if ANNOTATIONS.contains(&key.as_str()) {
            continue;
        }
        if !SUPPORTED.contains(&key.as_str()) {
            found.push(format!("{path}/{key}"));
            continue;
        }
        match key.as_str() {
            "properties" => {
                for (name, sub) in value.as_object().into_iter().flatten() {
                    walk_keywords(sub, &format!("{path}/properties/{name}"), found);
                }
            }
            "items" | "additionalProperties" => {
                walk_keywords(value, &format!("{path}/{key}"), found)
            }
            _ => {}
        }
    }
}

fn type_matches(name: &str, value: &Value) -> bool {
    match name {
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.as_f64().is_some_and(|n| n.fract() == 0.0),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "null" => value.is_null(),
        _ => false,
    }
}

/// Validate `value` against `schema`; returns problems as `path: message`.
pub fn validate(schema: &Value, value: &Value) -> Vec<String> {
    let mut problems = unsupported_keywords(schema)
        .into_iter()
        .map(|k| format!("unsupported schema keyword {k}"))
        .collect::<Vec<_>>();
    if problems.is_empty() {
        check(schema, value, "", &mut problems);
    }
    problems
}

fn check(schema: &Value, value: &Value, path: &str, out: &mut Vec<String>) {
    let at = if path.is_empty() { "(root)" } else { path };
    let Some(rules) = schema.as_object() else {
        if schema == &Value::Bool(false) {
            out.push(format!("{at}: not allowed"));
        }
        return;
    };
    if let Some(kind) = rules.get("type") {
        let ok = match kind {
            Value::String(name) => type_matches(name, value),
            Value::Array(names) => names
                .iter()
                .any(|n| n.as_str().is_some_and(|n| type_matches(n, value))),
            _ => false,
        };
        if !ok {
            out.push(format!("{at}: expected type {kind}"));
            return;
        }
    }
    if let Some(options) = rules.get("enum").and_then(Value::as_array) {
        if !options.contains(value) {
            out.push(format!("{at}: not one of the allowed values"));
        }
    }
    if let Some(expected) = rules.get("const") {
        if expected != value {
            out.push(format!("{at}: must be {expected}"));
        }
    }
    if let Some(text) = value.as_str() {
        let length = text.chars().count() as u64;
        if rules
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|min| length < min)
        {
            out.push(format!("{at}: shorter than minLength"));
        }
        if rules
            .get("maxLength")
            .and_then(Value::as_u64)
            .is_some_and(|max| length > max)
        {
            out.push(format!("{at}: longer than maxLength"));
        }
        if let Some(pattern) = rules.get("pattern").and_then(Value::as_str) {
            match Regex::new(pattern) {
                Ok(re) if re.is_match(text) => {}
                Ok(_) => out.push(format!("{at}: does not match pattern")),
                Err(_) => out.push(format!("{at}: invalid pattern in schema")),
            }
        }
    }
    if let Some(number) = value.as_f64() {
        if rules
            .get("minimum")
            .and_then(Value::as_f64)
            .is_some_and(|min| number < min)
        {
            out.push(format!("{at}: below minimum"));
        }
        if rules
            .get("maximum")
            .and_then(Value::as_f64)
            .is_some_and(|max| number > max)
        {
            out.push(format!("{at}: above maximum"));
        }
    }
    if let Some(items) = value.as_array() {
        let count = items.len() as u64;
        if rules
            .get("minItems")
            .and_then(Value::as_u64)
            .is_some_and(|min| count < min)
        {
            out.push(format!("{at}: fewer than minItems"));
        }
        if rules
            .get("maxItems")
            .and_then(Value::as_u64)
            .is_some_and(|max| count > max)
        {
            out.push(format!("{at}: more than maxItems"));
        }
        if let Some(item_schema) = rules.get("items") {
            for (index, item) in items.iter().enumerate() {
                check(item_schema, item, &format!("{path}/{index}"), out);
            }
        }
    }
    if let Some(object) = value.as_object() {
        let count = object.len() as u64;
        if rules
            .get("minProperties")
            .and_then(Value::as_u64)
            .is_some_and(|min| count < min)
        {
            out.push(format!("{at}: fewer than minProperties"));
        }
        if rules
            .get("maxProperties")
            .and_then(Value::as_u64)
            .is_some_and(|max| count > max)
        {
            out.push(format!("{at}: more than maxProperties"));
        }
        for name in rules
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if !object.contains_key(name) {
                out.push(format!("{at}: missing required member {name}"));
            }
        }
        let properties = rules.get("properties").and_then(Value::as_object);
        for (name, member) in object {
            let sub_path = format!("{path}/{name}");
            match properties.and_then(|p| p.get(name)) {
                Some(sub) => check(sub, member, &sub_path, out),
                None => match rules.get("additionalProperties") {
                    Some(Value::Bool(false)) => out.push(format!("{at}: unexpected member {name}")),
                    Some(extra) => check(extra, member, &sub_path, out),
                    None => {}
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn checks_the_supported_keywords() {
        let schema = json!({
            "type": "object", "additionalProperties": false, "required": ["n", "tags"],
            "properties": {
                "n": {"type": "integer", "minimum": 1, "maximum": 3},
                "tags": {"type": "array", "maxItems": 2, "items": {"type": "string", "pattern": "^[a-z]+$"}},
                "mode": {"enum": ["a", "b"]}
            }
        });
        assert!(validate(&schema, &json!({"n": 2, "tags": ["ok"]})).is_empty());
        let problems = validate(&schema, &json!({"n": 4.5, "tags": ["A", "b", "c"], "x": 1}));
        assert!(problems.iter().any(|p| p.contains("expected type")));
        assert!(problems.iter().any(|p| p.contains("more than maxItems")));
        assert!(problems
            .iter()
            .any(|p| p.contains("does not match pattern")));
        assert!(problems.iter().any(|p| p.contains("unexpected member x")));
        assert!(!validate(&schema, &json!({"n": 1, "tags": [], "mode": "c"})).is_empty());
        assert!(!validate(&schema, &json!({"tags": []})).is_empty());
    }

    #[test]
    fn unknown_keywords_fail_closed() {
        let schema =
            json!({"type": "object", "properties": {"a": {"anyOf": [{"type": "string"}]}}});
        let problems = validate(&schema, &json!({"a": 1}));
        assert_eq!(problems, ["unsupported schema keyword /properties/a/anyOf"]);
    }
}
