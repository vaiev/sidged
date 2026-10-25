//! Capability registry. Looks up a descriptor by `tag:vaikor.com,2026:capability:…`.

use std::collections::HashMap;

pub mod schema;

use vaikor_core::CapabilityRecord;

#[derive(Debug, Default, Clone)]
pub struct Registry {
    records: HashMap<String, CapabilityRecord>,
}

impl Registry {
    /// Insert a descriptor, rejecting duplicate IDs without replacing the original.
    pub fn insert(&mut self, record: CapabilityRecord) -> Result<(), String> {
        validate_record(&record)?;
        match self.records.entry(record.id.clone()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(record);
                Ok(())
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                Err(format!("duplicate capability id: {}", record.id))
            }
        }
    }

    pub fn get(&self, id: &str) -> Option<&CapabilityRecord> {
        self.records.get(id)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Load descriptors from a JSON array of VKR-L1 documents.
    pub fn from_descriptors(document: &serde_json::Value) -> Result<Self, String> {
        let items = document.as_array().ok_or("catalog must be an array")?;
        let mut registry = Self::default();
        for item in items {
            registry.insert(record_from(item)?)?;
        }
        Ok(registry)
    }
}

fn validate_record(record: &CapabilityRecord) -> Result<(), String> {
    if record.is_egress() && !record.consequential {
        return Err("egress capability requires consequential: true".into());
    }
    if record
        .residency
        .iter()
        .any(|tag| !vaikor_core::valid_residency_tag(tag))
    {
        return Err("residency-unknown-tag".into());
    }
    if record.effects.iter().any(|effect| effect == "egress") && record.residency.is_empty() {
        return Err("egress capability requires nonempty residency.tags".into());
    }
    if record.residency.len() > 1 && record.residency.iter().any(|tag| tag == "unrestricted") {
        return Err("malformed residency declaration".into());
    }
    Ok(())
}

/// Effect codes of `spec/registries/effects.md` (0001 R6).
const EFFECTS: [&str; 5] = ["read", "write", "delete", "execute", "egress"];
/// Registered top-level data classes of `spec/registries/data-classes.md` (0001 R7).
const CLASS_ROOTS: [&str; 17] = [
    "identity",
    "contacts",
    "communications",
    "calendar",
    "location",
    "health",
    "biometric",
    "finance",
    "documents",
    "media",
    "home",
    "device",
    "query",
    "usage",
    "adaptation",
    "memory",
    "secrets",
];
const ID_PREFIX: &str = "tag:vaikor.com,2026:capability:";

/// 0001 R7: a registered class, a dotted subclass of one, or a private `x-` class.
pub fn valid_data_class(class: &str) -> bool {
    let mut parts = class.split('.');
    let root = parts.next().unwrap_or("");
    let root_ok = CLASS_ROOTS.contains(&root)
        || root.strip_prefix("x-").is_some_and(|rest| {
            rest.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                && rest
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        });
    class.len() <= 128
        && root_ok
        && parts.all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        })
}

fn decimal_amount(text: &str) -> bool {
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    match text.split_once('.') {
        Some((integer, fraction)) => digits(integer) && digits(fraction),
        None => digits(text),
    }
}

/// The semantic descriptor rules a Core enforces before it uses a capability (0001 R20):
/// R1 identifier, R3 version, R4/R5 schema shapes, R6 effects, R7 data classes, R9
/// consequential effects, R10 egress names a class, R11 cost. Members the JSON Schema
/// requires but these rules do not read (`title`, for example) are checked by `spec/validate`.
pub fn check_descriptor(item: &serde_json::Value) -> Result<(), String> {
    let id = item["id"].as_str().ok_or("capability is missing id")?;
    let name = id.strip_prefix(ID_PREFIX).unwrap_or("");
    if name.is_empty()
        || name.len() > 128
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(format!(
            "capability id is not tag:vaikor.com,2026:capability:<name>: {id}"
        ));
    }
    if let Some(v) = item.get("v") {
        if v != "0.1" {
            return Err(format!("{id}: unsupported descriptor version"));
        }
    }
    for key in ["input_schema", "output_schema"] {
        if let Some(schema) = item.get(key) {
            let Some(object) = schema.as_object() else {
                return Err(format!("{id}: {key} is not an object"));
            };
            if object.get("type").is_some_and(|t| t != "object") {
                return Err(format!("{id}: {key}.type must be object"));
            }
        }
    }
    let effects = strings(&item["effects"])?;
    if effects.is_empty() {
        return Err(format!("{id}: effects is empty"));
    }
    for (index, effect) in effects.iter().enumerate() {
        if !EFFECTS.contains(&effect.as_str()) {
            return Err(format!("{id}: unregistered effect {effect}"));
        }
        if effects[..index].contains(effect) {
            return Err(format!("{id}: effect {effect} repeated"));
        }
    }
    let classes = strings(&item["data_classes"])?;
    if let Some(class) = classes.iter().find(|c| !valid_data_class(c)) {
        return Err(format!("{id}: unregistered data class {class}"));
    }
    let consequential = item["consequential"]
        .as_bool()
        .ok_or("consequential must be a bool")?;
    if !consequential
        && effects
            .iter()
            .any(|e| matches!(e.as_str(), "delete" | "execute" | "egress"))
    {
        return Err(format!(
            "{id}: delete, execute and egress capabilities require consequential: true"
        ));
    }
    if effects.iter().any(|e| e == "egress") && classes.is_empty() {
        return Err(format!(
            "{id}: an egress capability names at least one data class"
        ));
    }
    if let Some(cost) = item.get("cost") {
        let max = cost.get("max");
        match cost["class"].as_str() {
            Some("free") if max.is_none() => {}
            Some("metered") => {
                let amount = max.and_then(|m| m["amount"].as_str()).unwrap_or("");
                let currency = max.and_then(|m| m["currency"].as_str()).unwrap_or("");
                if !decimal_amount(amount)
                    || currency.len() != 3
                    || !currency.bytes().all(|b| b.is_ascii_uppercase())
                {
                    return Err(format!(
                        "{id}: a metered cost needs max with a decimal amount and an ISO 4217 currency"
                    ));
                }
            }
            _ => {
                return Err(format!(
                    "{id}: cost is free without max, or metered with max"
                ))
            }
        }
    }
    Ok(())
}

fn record_from(item: &serde_json::Value) -> Result<CapabilityRecord, String> {
    check_descriptor(item)?;
    let id = item["id"]
        .as_str()
        .ok_or("capability is missing id")?
        .to_string();
    let effects = strings(&item["effects"])?;
    let data_classes = strings(&item["data_classes"])?;
    let consequential = item["consequential"]
        .as_bool()
        .ok_or("consequential must be a bool")?;
    // Non-egress capabilities may omit residency. Egress must declare it at load.
    let residency = match item.get("residency").and_then(|value| value.get("tags")) {
        Some(tags) => strings(tags)?,
        None => Vec::new(),
    };
    // check_descriptor has refused a metered cost without a valid max.
    let max = &item["cost"]["max"];
    let (cost_amount, cost_currency) = if item["cost"]["class"] == "metered" {
        (
            max["amount"].as_str().map(str::to_string),
            max["currency"].as_str().map(str::to_string),
        )
    } else {
        (None, None)
    };
    Ok(CapabilityRecord {
        id,
        effects,
        data_classes,
        consequential,
        cost_amount,
        cost_currency,
        residency,
    })
}

fn strings(value: &serde_json::Value) -> Result<Vec<String>, String> {
    value
        .as_array()
        .ok_or("expected an array of strings")?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| "expected a string".to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_requires_consequential_at_catalog_load() {
        let item = serde_json::json!({"id":"tag:vaikor.com,2026:capability:send", "effects":["egress"], "data_classes":[], "residency":{"tags":["unrestricted"]}, "consequential":false});
        assert!(Registry::from_descriptors(&serde_json::json!([item]))
            .unwrap_err()
            .contains("consequential"));
    }

    #[test]
    fn duplicate_ids_are_rejected_without_replacing_the_record() {
        let descriptor = serde_json::json!({
            "id": "tag:vaikor.com,2026:capability:read", "effects": ["read"],
            "data_classes": [], "consequential": false
        });
        let mut registry = Registry::default();
        registry.insert(record_from(&descriptor).unwrap()).unwrap();
        let mut replacement = record_from(&descriptor).unwrap();
        replacement.consequential = true;
        assert!(registry.insert(replacement).is_err());
        assert_eq!(registry.len(), 1);
        assert!(
            !registry
                .get(descriptor["id"].as_str().unwrap())
                .unwrap()
                .consequential
        );
        assert!(
            Registry::from_descriptors(&serde_json::json!([descriptor.clone(), descriptor]))
                .is_err()
        );
    }

    #[test]
    fn loads_the_time_server_descriptors() {
        let raw =
            include_str!("../../../spec/examples/capability-descriptor.time-get-current.json");
        let convert =
            include_str!("../../../spec/examples/capability-descriptor.time-convert.json");
        let document = serde_json::json!([
            serde_json::from_str::<serde_json::Value>(raw).unwrap(),
            serde_json::from_str::<serde_json::Value>(convert).unwrap()
        ]);
        let registry = Registry::from_descriptors(&document).unwrap();
        let found = registry
            .get("tag:vaikor.com,2026:capability:get_current_time")
            .unwrap();
        assert_eq!(found.effects, vec!["read".to_string()]);
        assert!(!found.is_egress());
        assert!(registry
            .get("tag:vaikor.com,2026:capability:convert_time")
            .is_some());
    }
    #[test]
    fn insert_checks_residency() {
        for (effects, tags, valid) in [
            (vec!["egress"], vec![], false),
            (vec!["egress"], vec!["unrestricted", "CH"], false),
            (vec!["read"], vec!["unrestricted", "unrestricted"], false),
            (vec!["read"], vec!["unknown"], false),
            (vec!["read"], vec![], true),
            (vec!["egress"], vec!["CH"], true),
            (vec!["egress"], vec!["unrestricted"], true),
        ] {
            let mut registry = Registry::default();
            let record = CapabilityRecord {
                id: "tag:vaikor.com,2026:capability:test".into(),
                effects: effects.into_iter().map(str::to_string).collect(),
                residency: tags.into_iter().map(str::to_string).collect(),
                data_classes: vec![],
                consequential: true,
                cost_amount: None,
                cost_currency: None,
            };
            assert_eq!(registry.insert(record).is_ok(), valid);
            assert_eq!(registry.len(), usize::from(valid));
        }
    }

    #[test]
    fn residency_is_checked_at_catalog_load() {
        for tags in [
            serde_json::Value::Null,
            serde_json::json!([]),
            serde_json::json!(["unrestricted", "CH"]),
            serde_json::json!(["unrestricted", "unrestricted"]),
            serde_json::json!(["unknown"]),
            serde_json::json!("CH"),
        ] {
            let mut item = serde_json::json!({
                "id": "tag:vaikor.com,2026:capability:send", "effects": ["egress"],
                "data_classes": ["communications.content"], "consequential": true
            });
            if !tags.is_null() {
                item["residency"] = serde_json::json!({"tags": tags});
            }
            assert!(Registry::from_descriptors(&serde_json::json!([item])).is_err());
        }
        for tags in [
            serde_json::json!(["CH"]),
            serde_json::json!(["unrestricted"]),
        ] {
            let item = serde_json::json!({
                "id": "tag:vaikor.com,2026:capability:send", "effects": ["egress"],
                "data_classes": ["communications.content"], "consequential": true,
                "residency": {"tags": tags}
            });
            assert!(Registry::from_descriptors(&serde_json::json!([item])).is_ok());
        }
    }

    #[test]
    fn local_capabilities_may_omit_tags_but_cannot_mix_unrestricted() {
        let mut item = serde_json::json!({
            "id": "tag:vaikor.com,2026:capability:read", "effects": ["read"],
            "data_classes": [], "consequential": false
        });
        assert!(Registry::from_descriptors(&serde_json::json!([item.clone()])).is_ok());
        item["residency"] = serde_json::json!({"tags": ["unrestricted", "CH"]});
        assert!(Registry::from_descriptors(&serde_json::json!([item])).is_err());
    }
}
