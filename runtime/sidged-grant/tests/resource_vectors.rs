use std::path::PathBuf;

#[test]
fn shared_resource_vectors_match() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/test-vectors/resource-matching/coverage.json");
    let file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("vector file")).expect("json");
    for vector in file["vectors"].as_array().expect("vectors") {
        let right = vector["input"]["right"].as_str().unwrap();
        let resource = vector["input"]["resource"].as_str().unwrap();
        let expected = vector["expected"]["value"].as_bool().unwrap();
        assert_eq!(
            sidged_grant::resource_covers(right, resource),
            expected,
            "{}",
            vector["id"]
        );
    }
}
