use serde_json::Value;
use vaikor_record::{class_resource, decode, Error, Record};

fn record() -> Value {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../spec/test-vectors/records/records.json"
    ))
    .unwrap();
    vectors["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "record.check.001")
        .unwrap()["input"]["record"]
        .clone()
}

#[test]
fn residency_uses_core_syntax_including_owner_tags() {
    for tag in [
        "CH",
        "EU",
        "CH-EU",
        "unrestricted",
        "x-owner",
        "x-",
        "x-INVALID",
        "Mars",
    ] {
        let mut v = record();
        v["residency"]["tags"] = serde_json::json!([tag]);
        assert_eq!(
            Record::parse(v).is_ok(),
            vaikor_core::valid_residency_tag(tag),
            "{tag}"
        );
    }
}

#[test]
fn class_roots_match_registry_exactly() {
    let registry = include_str!("../../../spec/registries/data-classes.md");
    let roots: Vec<_> = registry
        .lines()
        .filter_map(|line| {
            line.strip_prefix("| `")?
                .split_once('`')
                .map(|(root, _)| root)
        })
        .collect();
    assert!(!roots.is_empty());
    for root in &roots {
        assert!(class_resource(root).is_ok(), "{root}");
        assert!(class_resource(&format!("{root}.example")).is_ok());
    }
    assert!(class_resource("unregistered.example").is_err());
    assert!(class_resource("x-owner.example").is_ok());
}

#[test]
fn record_timestamps_remain_strict_utc_calendar_dates() {
    for stamp in [
        "2024-02-29T00:00:00Z",
        "1969-12-31T23:59:59Z",
        "2023-02-29T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-01-01T00:00:60Z",
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:00.0Z",
    ] {
        let mut v = record();
        v["provenance"]["created"] = stamp.into();
        assert_eq!(
            Record::parse(v).is_ok(),
            matches!(stamp, "2024-02-29T00:00:00Z" | "1969-12-31T23:59:59Z"),
            "{stamp}"
        );
    }
}

#[test]
fn truncated_integer_arguments_are_malformed() {
    for head in [0x19, 0x1a, 0x1b] {
        let width = match head {
            0x19 => 2,
            0x1a => 4,
            _ => 8,
        };
        for n in 0..width {
            let mut bytes = vec![head];
            bytes.extend(vec![0; n]);
            assert_eq!(decode(&bytes), Err(Error::Malformed));
        }
    }
}

#[test]
fn owner_residency_tags_require_owner_mapping_at_egress() {
    let mut v = record();
    v["residency"]["tags"] = serde_json::json!(["x-owner"]);
    let r = Record::parse(v).unwrap();
    let tags: Vec<String> =
        serde_json::from_value(r.as_value()["residency"]["tags"].clone()).unwrap();
    assert!(vaikor_gateway::provider_allows(&tags, "CH", &Default::default()).is_err());
    let owner_tags = std::collections::HashMap::from([("x-owner".into(), vec!["CH".into()])]);
    assert!(vaikor_gateway::provider_allows(&tags, "CH", &owner_tags).unwrap());
    assert!(!vaikor_gateway::provider_allows(&tags, "EU", &owner_tags).unwrap());
}
