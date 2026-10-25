//! RFC 8785 JSON Canonicalization Scheme for the values in the test vectors.
//!
//! Object keys sort by UTF-16 code units. Strings escape quotes, backslashes,
//! and controls. Non-ASCII characters stay as UTF-8. Numbers in these vectors
//! are integers, so they are written as plain decimals.

use std::cmp::Ordering;

use serde_json::Value;

pub fn canonicalize(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

/// Signing input for canon `jcs`: RFC 8785 of the object with `sig` removed.
pub fn signing_input(value: &Value) -> String {
    let mut without = value.clone();
    if let Some(object) = without.as_object_mut() {
        object.remove("sig");
    }
    canonicalize(&without)
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|left, right| utf16_cmp(left, right));
            out.push('{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, &map[*key]);
            }
            out.push('}');
        }
    }
}

fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", ch as u32));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

fn utf16_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

#[cfg(test)]
mod tests {
    use super::canonicalize;
    use serde_json::json;

    #[test]
    fn sorts_nested_members_and_keeps_array_order() {
        let value = json!({"z": [3, 1, 2], "a": {"d": true, "c": null}});
        assert_eq!(
            canonicalize(&value),
            r#"{"a":{"c":null,"d":true},"z":[3,1,2]}"#
        );
    }
}
