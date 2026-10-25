use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use vaikor_gateway::allowed_regions;

#[test]
fn shared_residency_vectors() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/test-vectors/residency/intersection.json");
    let file: serde_json::Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    for vector in file["vectors"].as_array().unwrap() {
        if vector["operation"] != "residency-regions" {
            continue;
        }
        let tags = vector["input"].get("tags").map(strings).unwrap_or_default();
        let mut owner = HashMap::new();
        if let Some(map) = vector["input"]
            .get("owner_tags")
            .and_then(|item| item.as_object())
        {
            for (key, value) in map {
                owner.insert(key.clone(), strings(value));
            }
        }
        if let Some(region) = vector["input"]["provider_region"].as_str() {
            assert_eq!(
                vaikor_gateway::provider_allows(&tags, region, &owner).unwrap_or(false),
                vector["expected"]["allowed"].as_bool().unwrap(),
                "{}",
                vector["id"]
            );
        }
        let got = allowed_regions(&tags, &owner);
        let expected = &vector["expected"];
        if expected.get("result").and_then(|item| item.as_str()) == Some("refuse") {
            assert!(got.is_err(), "{}", vector["id"]);
        } else if expected["value"] == "any" {
            assert!(got.unwrap().is_none(), "{}", vector["id"]);
        } else {
            let regions = strings(&expected["value"]);
            assert_eq!(got.unwrap().unwrap(), regions, "{}", vector["id"]);
        }
    }
}

fn strings(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn all_destination_vectors() {
    let file: serde_json::Value = serde_json::from_str(include_str!(
        "../../../spec/test-vectors/residency/destination.json"
    ))
    .unwrap();
    let vectors = file["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 21);
    for vector in vectors {
        assert_eq!(vector["operation"], "residency-destination");
        let tags = vector["input"].get("tags").map(strings).unwrap_or_default();
        let got = vaikor_gateway::residency_destination(
            &tags,
            vector["input"]["destination"].as_str().unwrap(),
            &HashMap::new(),
        );
        if vector["expected"]["result"] == "accept" {
            assert!(got.is_ok(), "{}: {got:?}", vector["id"]);
        } else {
            assert_eq!(
                got.unwrap_err(),
                vector["expected"]["reason"].as_str().unwrap(),
                "{}",
                vector["id"]
            );
        }
    }
}

#[test]
fn all_record_derivation_vectors() {
    let file: serde_json::Value = serde_json::from_str(include_str!(
        "../../../spec/test-vectors/records/records.json"
    ))
    .unwrap();
    let mut count = 0;
    for vector in file["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["operation"] == "record-derive")
    {
        count += 1;
        let inputs: Vec<_> = vector["input"]["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                (
                    v["class"].as_str().unwrap().to_string(),
                    v.get("tags").map(strings).unwrap_or_default(),
                )
            })
            .collect();
        let got = vaikor_core::derive_record_labels(&inputs);
        if vector["expected"]["result"] == "refuse" {
            assert_eq!(
                got.unwrap_err(),
                vector["expected"]["reason"].as_str().unwrap(),
                "{}",
                vector["id"]
            );
        } else {
            let (class, tags) = got.unwrap();
            assert_eq!(
                class, vector["expected"]["value"]["class"],
                "{}",
                vector["id"]
            );
            assert_eq!(
                tags,
                strings(&vector["expected"]["value"]["tags"]),
                "{}",
                vector["id"]
            );
            let regions = if tags.is_empty() {
                Some(Vec::new())
            } else {
                allowed_regions(&tags, &HashMap::new()).unwrap()
            };
            let expected = &vector["expected"]["value"]["regions"];
            if expected == "any" {
                assert!(regions.is_none(), "{}", vector["id"]);
            } else {
                assert_eq!(regions.unwrap(), strings(expected), "{}", vector["id"]);
            }
            if tags.is_empty() {
                for destination in ["CH", "EU", "GLOBAL"] {
                    assert!(vaikor_gateway::residency_destination(
                        &tags,
                        destination,
                        &HashMap::new()
                    )
                    .is_err());
                }
            }
        }
    }
    assert_eq!(count, 7);
}

#[test]
fn missing_derivation_tags_fail_closed() {
    let inputs = vec![
        ("health".into(), vec!["unrestricted".into()]),
        ("health".into(), vec![]),
    ];
    assert!(vaikor_core::derive_record_labels(&inputs)
        .unwrap()
        .1
        .is_empty());
    assert!(vaikor_core::derive_record_labels(&[]).is_err());
}

#[test]
fn all_tag_syntax_vectors() {
    let file: serde_json::Value = serde_json::from_str(include_str!(
        "../../../spec/test-vectors/residency/tag-syntax.json"
    ))
    .unwrap();
    for vector in file["vectors"].as_array().unwrap() {
        assert_eq!(vector["operation"], "residency-tag-syntax");
        assert_eq!(
            vaikor_core::valid_residency_tag(vector["input"]["tag"].as_str().unwrap()),
            vector["expected"]["value"].as_bool().unwrap(),
            "{}",
            vector["id"]
        );
    }
}
