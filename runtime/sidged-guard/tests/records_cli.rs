mod common;
use serde_json::{json, Value};
use std::{fs, process::Command};
#[test]
fn record_binary_roundtrip_refusals_and_expiry() {
    let dir = std::env::temp_dir().join(format!("record-cli-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    common::keys(&dir.join("keys"));
    let seed = common::seed(&dir.join("keys/issuer.key"));
    let key = sidged_grant::did_key(&sidged_log::public_key(&seed));
    fs::copy(dir.join("keys/issuer.key"), dir.join("key")).unwrap();
    fs::write(dir.join("policy"), "permit(principal, action, resource);").unwrap();
    let now = sidged_grant::format_rfc3339_z(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
    );
    let exp = sidged_grant::add_rfc3339_z(&now, 1800).unwrap();
    let grant = sidged_grant::attach_signature(
        &json!({"v":"0.1","id":"cli","iss":key,"sub":key,"aud":"sidged","iat":now,"exp":exp,"cnf":{"kid":key},"chain":[],"rights": (["read","write","retain","delete","import"].map(|a| json!({"action":a,"resource":"urn:sidged:record:x-demo"})))}),
        &seed,
        &key,
    );
    fs::write(dir.join("grant"), grant.to_string()).unwrap();
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../spec/test-vectors/records/records.json"
    ))
    .unwrap();
    let mut value = vectors["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "record.check.001")
        .unwrap()["input"]["record"]
        .clone();
    value["owner"] = Value::Null;
    value["provenance"]["created"] = Value::Null;
    value["provenance"]["source"] = Value::Null;
    value["provenance"]["plan"] = Value::Null;
    value["class"] = json!("x-demo");
    value["retention"]["until"] = Value::Null;
    fs::write(dir.join("record"), value.to_string()).unwrap();
    fs::write(
        dir.join("retention"),
        r#"{"until":"2020-01-01T00:00:00Z","on_expiry":"delete"}"#,
    )
    .unwrap();
    let run = |args: &[&str], grant: bool, key_flag: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sidged"));
        cmd.current_dir(&dir).args(["record"]).args(args).args([
            "--store",
            "store",
            "--log",
            "audit",
            "--policy",
            "policy",
            "--trusted-issuer",
            &key,
        ]);
        if grant {
            cmd.args(["--grant", "grant"]);
        }
        if key_flag {
            cmd.args(["--log-key", "key"]);
        }
        cmd.output().unwrap()
    };
    assert!(!run(&["write", "record"], true, false).status.success());
    let out = run(&["write", "record"], true, true);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let digest = String::from_utf8(out.stdout).unwrap();
    let digest = digest.trim();
    let read = run(&["read", digest], true, true);
    assert!(read.status.success());
    let stored: Value = serde_json::from_slice(&read.stdout).unwrap();
    assert_eq!(stored["owner"], key);
    assert_eq!(stored["provenance"]["source"], key);
    assert!(stored["provenance"]["plan"].is_null());
    assert!(stored["provenance"]["created"]
        .as_str()
        .unwrap()
        .ends_with('Z'));
    assert!(!run(&["read", digest], false, true).status.success());
    let events =
        sidged_log::read_events(&dir.join("audit"), &sidged_log::public_key(&seed)).unwrap();
    let write = events
        .iter()
        .find(|e| e.step == "write" && e.decision == "allow")
        .unwrap();
    let actor: Value = serde_json::from_str(&write.actor).unwrap();
    assert_eq!(actor["holder"], key);
    assert_eq!(actor["grant_id"], "cli");
    assert_eq!(actor["issuer_kid"], key);
    assert_eq!(write.data_classes, vec!["x-demo"]);
    assert!(events
        .iter()
        .any(|e| e.step == "read" && e.decision == "deny" && e.capability.ends_with(digest)));
    let out = run(&["retention", digest, "retention"], true, true);
    assert!(out.status.success());
    let expired = String::from_utf8(out.stdout).unwrap();
    assert!(run(&["expire"], true, true).status.success());
    assert!(!dir.join("store/records").join(expired.trim()).exists());
    // Import is canonical dCBOR and preserves a trusted Core signature.
    let out = run(&["write", "record"], true, true);
    assert!(out.status.success());
    let imported = String::from_utf8(out.stdout).unwrap();
    fs::copy(
        dir.join("store/records").join(imported.trim()),
        dir.join("import.cbor"),
    )
    .unwrap();
    assert!(run(&["delete", imported.trim()], true, true)
        .status
        .success());
    assert!(run(&["import", "import.cbor"], true, true).status.success());
    assert!(run(&["read", imported.trim()], true, true).status.success());
    let untrusted = Command::new(env!("CARGO_BIN_EXE_sidged"))
        .current_dir(&dir)
        .args([
            "record",
            "read",
            imported.trim(),
            "--store",
            "store",
            "--log",
            "audit",
            "--log-key",
            "key",
            "--grant",
            "grant",
            "--policy",
            "policy",
        ])
        .output()
        .unwrap();
    assert!(!untrusted.status.success());
    assert!(untrusted.stdout.is_empty());
    let default = Command::new(env!("CARGO_BIN_EXE_sidged"))
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args([
            "record",
            "write",
            "record",
            "--log-key",
            "key",
            "--grant",
            "grant",
            "--trusted-issuer",
            &key,
            "--policy",
            "policy",
        ])
        .output()
        .unwrap();
    assert!(
        default.status.success(),
        "{}",
        String::from_utf8_lossy(&default.stderr)
    );
    assert!(String::from_utf8_lossy(&default.stderr)
        .contains(dir.join("state/sidged/records").to_str().unwrap()));
    assert!(dir.join("state/sidged/records/audit.log").exists());
    let external_seed = common::seed(&dir.join("keys/holder.key"));
    let external_key = sidged_grant::did_key(&sidged_log::public_key(&external_seed));
    let external = sidged_record::Record::sign(stored.clone(), &external_seed).unwrap();
    fs::write(
        dir.join("external.cbor"),
        external.canonical_bytes().unwrap(),
    )
    .unwrap();
    let refused = run(
        &["import", "external.cbor", "--trusted-issuer", &external_key],
        true,
        true,
    );
    assert!(
        !refused.status.success(),
        "grant issuers must not anchor Records"
    );
    let accepted = run(
        &[
            "import",
            "external.cbor",
            "--record-anchor",
            &external_key,
            "--record-anchor",
            &key,
        ],
        true,
        true,
    );
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    // The same capped token is presented by separate CLI processes.
    let mut capped = grant.clone();
    capped["id"] = json!("capped-record");
    capped["rights"][1]["constraints"] = json!({"max_uses": 1});
    let capped = sidged_grant::attach_signature(&capped, &seed, &key);
    fs::write(dir.join("grant"), capped.to_string()).unwrap();
    let first = run(&["write", "record"], true, true);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let second = run(&["write", "record"], true, true);
    assert!(!second.status.success());
    let events =
        sidged_log::read_events(&dir.join("audit"), &sidged_log::public_key(&seed)).unwrap();
    let denied = events.last().unwrap();
    assert_eq!(denied.step, "write");
    assert_eq!(denied.decision, "deny");
    assert!(denied.reason.as_deref().unwrap().contains("grant denied"));
    assert!(events
        .iter()
        .any(|e| e.usage == Some((json!([key, "capped-record"]).to_string(), 1, 1))));
    fs::remove_dir_all(dir).unwrap();
}
