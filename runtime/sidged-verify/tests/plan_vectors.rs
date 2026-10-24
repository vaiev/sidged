use std::collections::HashSet;
use std::path::PathBuf;

use sidged_verify::{stored, AllowList, DenySensitive};

#[test]
fn shared_plan_vectors_match() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors/plan/verify.json");
    let file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("vector file")).expect("json");
    for vector in file["vectors"].as_array().expect("vectors") {
        // The one parser (0003 R4a, ROADMAP 11f): a plan it cannot read is refused.
        let parsed = stored::parse_plan(&vector["input"]["plan"])
            .and_then(|plan| Ok((plan, stored::parse_catalog(&vector["input"]["catalog"])?)));
        let allow = allow_from(&vector["input"]["allow"]);
        let expected = vector["expected"]["result"].as_str().unwrap();
        let actual = match parsed {
            Err(error) => Err(vec![error.code().to_string()]),
            Ok((plan, catalog)) if allow.is_empty() => {
                sidged_verify::verify(&plan, &catalog, &DenySensitive)
            }
            Ok((plan, catalog)) => {
                sidged_verify::verify(&plan, &catalog, &AllowList { pairs: allow })
            }
        };
        let result = if actual.is_ok() { "accept" } else { "refuse" };
        assert_eq!(result, expected, "{} {:?}", vector["id"], actual.err());
    }
}

fn allow_from(value: &serde_json::Value) -> HashSet<(String, String)> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    (
                        item["class"].as_str().unwrap().to_string(),
                        item["capability"].as_str().unwrap().to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}
