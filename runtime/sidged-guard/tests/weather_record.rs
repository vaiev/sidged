mod common;
use std::fs;
#[test]
fn executed_weather_plan_writes_derived_record_with_r10_residency() {
    let root = std::env::temp_dir().join(format!("weather-record-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    common::keys(&root.join("keys"));
    fs::copy(root.join("keys/issuer.key"), root.join("key")).unwrap();
    let public = sidged_log::public_key(&common::seed(&root.join("key")));
    let scenario = common::report_only_scenario(&root);
    std::env::set_var("XDG_STATE_HOME", &root);
    std::env::remove_var("SIDGED_LOCAL");
    let log = root.join("sidged/audit.log");
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    let out = common::approved_guard(&scenario, &root.join("keys"), &log, &root.join("key"));
    assert!(out.is_ok(), "{out:?}");
    let records: Vec<_> = fs::read_dir(root.join("sidged/records/records"))
        .unwrap()
        .map(|e| sidged_record::decode(&fs::read(e.unwrap().path()).unwrap()).unwrap())
        .collect();
    let derived = records
        .iter()
        .find(|v| {
            !v["provenance"]["derived_from"]
                .as_array()
                .unwrap()
                .is_empty()
        })
        .unwrap();
    for record in &records {
        assert_eq!(
            record["provenance"]["source"],
            sidged_grant::did_key(&public)
        );
    }
    let inputs = derived["provenance"]["derived_from"].as_array().unwrap();
    assert_eq!(inputs.len(), 1);
    assert!(records
        .iter()
        .any(|r| sidged_record::digest(r).unwrap() == inputs[0].as_str().unwrap()));
    assert!(derived["provenance"]["plan"].is_string());
    assert_eq!(
        derived["residency"]["tags"],
        serde_json::json!(["unrestricted"])
    );
    assert!(derived["content"]["privacy_reports"].as_array().is_some());
    assert_eq!(
        derived["content"]["results"]["weather"]["mode"],
        "report-only"
    );
    let events = sidged_log::read_events(&root.join("sidged/audit.log"), &public).unwrap();
    assert!(events.iter().any(|e| e.step == "write"
        && e.capability
            .ends_with(&sidged_record::digest(derived).unwrap())));
    fs::remove_dir_all(root).unwrap();
}
