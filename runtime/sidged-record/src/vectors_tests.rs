use crate::*;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::Path,
};
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn run(op: &str, i: &Value, keys: &Value) -> Result<Value> {
    Ok(match op {
        "dcbor-encode" => json!({"value": hex(&encode(&i["value"])?) }),
        "dcbor-decode" => json!({"value": decode(&unhex(i["hex"].as_str().unwrap()))?}),
        "record-digest" => {
            let b = signing_input(&i["record"])?;
            json!({"value":{"digest":digest(&i["record"])?,"dcbor_hex":hex(&b)}})
        }
        "record-check" => {
            let trusted: Vec<_> = i["trusted_core_keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(|name| {
                    let k = keys["keys"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|k| k["name"] == *name)
                        .unwrap();
                    sidged_grant::did_key(
                        &unhex(k["public_key_hex"].as_str().unwrap())
                            .try_into()
                            .unwrap(),
                    )
                })
                .collect();
            Record::check(i["record"].clone(), &trusted)?;
            json!({"result":"accept"})
        }
        "record-retention" => {
            json!({"value":if Record::parse(i["record"].clone())?.expired_at(i["now"].as_str().unwrap())? {"expired"} else {"live"}})
        }
        "record-resource" => json!({"value":class_resource(i["class"].as_str().unwrap())?}),
        "resource-covers" => {
            json!({"value":sidged_grant::resource_covers(i["right"].as_str().unwrap(),i["resource"].as_str().unwrap())})
        }
        "record-derive" => {
            let inputs = i["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    (
                        v["class"].as_str().unwrap().to_owned(),
                        serde_json::from_value(v["tags"].clone()).unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            let (class, tags) =
                derive_record_labels(&inputs).map_err(|_| Error::DataClassForbidden)?;
            let regions = if tags.is_empty() {
                json!([])
            } else {
                sidged_gateway::allowed_regions(&tags, &HashMap::new())
                    .unwrap()
                    .map_or(json!("any"), |v| json!(v))
            };
            json!({"value":{"class":class,"tags":tags,"regions":regions}})
        }
        _ => panic!("unsupported operation {op}"),
    })
}
fn visit(p: &Path, keys: &Value, counts: &mut BTreeMap<String, usize>) {
    for entry in fs::read_dir(p).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            visit(&p, keys, counts)
        } else if p.extension().is_some_and(|e| e == "json") {
            let d: Value = serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
            if let Some(vs) = d["vectors"].as_array() {
                for v in vs {
                    let Some(op) = v["operation"].as_str() else {
                        continue;
                    };
                    if !(op.starts_with("dcbor-")
                        || op.starts_with("record-")
                        || v["id"].as_str().unwrap().starts_with("record.coverage."))
                    {
                        continue;
                    }
                    // No unavailable profiles: all selected vectors must execute.
                    for profile in v["requires"].as_array().into_iter().flatten() {
                        assert!(
                            ["dcbor", "EdDSA"].contains(&profile.as_str().unwrap()),
                            "unavailable profile: {v}"
                        );
                    }
                    *counts.entry(op.to_owned()).or_default() += 1;
                    let got = run(op, &v["input"], keys)
                        .unwrap_or_else(|e| json!({"result":"refuse","reason":e.code()}));
                    assert_eq!(got, v["expected"], "{} ({})", v["id"], p.display());
                }
            }
        }
    }
}
#[test]
fn all_record_and_dcbor_vectors() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors");
    let keys = serde_json::from_str(
        &fs::read_to_string(root.join("keys/rfc8032-test-keys.json")).unwrap(),
    )
    .unwrap();
    let mut counts = BTreeMap::new();
    visit(&root, &keys, &mut counts);
    assert!(!counts.is_empty());
    eprintln!("vectors per op: {counts:?}; skipped: 0");
}
