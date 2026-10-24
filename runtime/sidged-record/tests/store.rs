fn draft(mut v: Value) -> Value {
    v["owner"] = Value::Null;
    v["provenance"]["created"] = Value::Null;
    v
}
use serde_json::{json, Value};
use sidged_record::store::Access;
use sidged_record::{store::Store, Record};
fn value() -> Value {
    let v: Value = serde_json::from_str(include_str!(
        "../../../spec/test-vectors/records/records.json"
    ))
    .unwrap();
    v["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "record.check.001")
        .unwrap()["input"]["record"]
        .clone()
}
fn rights() -> Access<'static> {
    static GRANT: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    let grant = GRANT.get_or_init(|| {
        let key = sidged_log::public_key(&[42;32]);
        let did = sidged_grant::did_key(&key);
        let seconds = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let rights: Vec<Value> = ["read", "write", "delete", "retain", "import"].iter().map(|a| json!({"action":a,"resource":"urn:sidged:record:health/*"})).collect();
        sidged_grant::attach_signature(&json!({"v":"0.1","id":"record-store-test", "iss":did,"sub":did,"aud":"record-store", "iat":sidged_grant::format_rfc3339_z(seconds), "exp":sidged_grant::format_rfc3339_z(seconds+3600), "cnf":{"kid":did},"chain":[],"rights":rights}), &[42;32], &did)
    });
    Access {
        grant: Some(grant),
        holder: grant["sub"].as_str().unwrap(),
        audience: "record-store",
        policy: &sidged_grant::PermitAll,
    }
}
struct TempDir(std::path::PathBuf);
impl std::ops::Deref for TempDir {
    type Target = std::path::Path;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn dir() -> TempDir {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let p = std::env::temp_dir().join(format!(
        "record-store-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&p).unwrap();
    TempDir(p)
}
#[test]
fn missing_grant_and_untrusted_import_are_logged() {
    let p = dir();
    let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
    assert!(s
        .write(
            draft(value()),
            &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &Access::missing()
        )
        .is_err());
    let r = Record::sign(value(), &[43; 32]).unwrap();
    assert!(s.import(&r.canonical_bytes().unwrap(), &rights()).is_err());
    assert_eq!(s.audit_events().unwrap().len(), 2);
    assert_eq!(std::fs::read_dir(p.join("records")).unwrap().count(), 0);
}
#[test]
fn expired_read_deletes_or_tombstones_without_content() {
    for mode in ["delete", "tombstone"] {
        let p = dir();
        let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
        let mut v = value();
        v["retention"] = json!({"until":null,"on_expiry":mode});
        let d = s
            .write(
                draft(v),
                &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
                &rights(),
            )
            .unwrap();
        // Retention changes produce a new content address.
        let d = s
            .set_retention(
                &d,
                json!({"until":"2000-01-01T00:00:00Z","on_expiry":mode}),
                &rights(),
            )
            .unwrap();
        assert!(s
            .read(
                &mut s.begin_step("urn:sidged:capability:notes.write", Value::Null),
                &d,
                &rights()
            )
            .is_err());
        let path = p.join("records").join(&d);
        if mode == "delete" {
            assert!(!path.exists());
        } else {
            let v = sidged_record::decode(&std::fs::read(path).unwrap()).unwrap();
            assert_eq!(v.as_object().unwrap().len(), 4);
            assert!(v.get("content").is_none());
        }
        assert!(s.audit_events().unwrap().iter().any(|e| e.step == "expire"));
    }
}
#[test]
fn append_failure_leaves_all_operations_unchanged() {
    let p = dir();
    let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
    let mut v = value();
    v["retention"]["until"] = Value::Null;
    let d = s
        .write(
            draft(v.clone()),
            &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &rights(),
        )
        .unwrap();
    let before = std::fs::read(p.join("records").join(&d)).unwrap();
    // Corrupting the locked chain is detected before the next append.
    std::fs::write(p.join("audit.log"), b"corrupt\n").unwrap();
    assert!(s.delete(&d, &rights()).is_err());
    assert!(s
        .read(
            &mut s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &d,
            &rights()
        )
        .is_err());
    assert!(s
        .set_retention(&d, json!({"until":null,"on_expiry":"delete"}), &rights())
        .is_err());
    assert!(s
        .write(
            draft(v),
            &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &rights()
        )
        .is_err());
    assert_eq!(std::fs::read(p.join("records").join(&d)).unwrap(), before);
}
#[test]
fn derived_reads_are_core_recorded_and_residency_fails_closed() {
    let p = dir();
    let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
    let mut ids = vec![];
    for tag in ["CH", "EU"] {
        let mut v = value();
        v["retention"]["until"] = Value::Null;
        v["residency"]["tags"] = json!([tag]);
        ids.push(
            s.write(
                draft(v),
                &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
                &rights(),
            )
            .unwrap(),
        );
    }
    let mut step = s.begin_step("urn:sidged:capability:notes.write", Value::Null);
    for d in &ids {
        s.read(&mut step, d, &rights()).unwrap();
    }
    let mut output = value();
    output["retention"]["until"] = Value::Null;
    output["residency"]["tags"] = json!(["unrestricted"]);
    output["provenance"]["derived_from"] = json!([]);
    let d = s.write(draft(output), &step, &rights()).unwrap();
    let r = s
        .read(
            &mut s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &d,
            &rights(),
        )
        .unwrap();
    assert_eq!(r.as_value()["provenance"]["derived_from"], json!(ids));
    let tags: Vec<String> =
        serde_json::from_value(r.as_value()["residency"]["tags"].clone()).unwrap();
    assert_eq!(tags, vec!["CH", "EU"]);
    assert_eq!(
        sidged_gateway::allowed_regions(&tags, &Default::default()).unwrap(),
        Some(vec![])
    );
    for region in ["CH", "EU", "GLOBAL"] {
        assert!(!sidged_gateway::provider_allows(&tags, region, &Default::default()).unwrap());
    }
}

#[test]
fn sweep_is_durable_and_append_failure_preserves_expired_content() {
    let p = dir();
    let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
    let mut v = value();
    v["retention"]["until"] = Value::Null;
    let d = s
        .write(
            draft(v),
            &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &rights(),
        )
        .unwrap();
    let d = s
        .set_retention(
            &d,
            json!({"until":"2000-01-01T00:00:00Z","on_expiry":"delete"}),
            &rights(),
        )
        .unwrap();
    let before = std::fs::read(p.join("records").join(&d)).unwrap();
    let log = std::fs::read(p.join("audit.log")).unwrap();
    std::fs::write(p.join("audit.log"), b"corrupt\n").unwrap();
    assert!(s
        .read(
            &mut s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &d,
            &rights()
        )
        .is_err());
    assert!(s.expire_sweep().is_err());
    assert!(s.import(&before, &rights()).is_err());
    assert_eq!(std::fs::read(p.join("records").join(&d)).unwrap(), before);
    std::fs::write(p.join("audit.log"), log).unwrap();
    assert_eq!(s.expire_sweep().unwrap(), 1);
    assert!(!p.join("records").join(&d).exists());
    drop(s);
    let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
    assert_eq!(s.expire_sweep().unwrap(), 0);
    assert!(s.audit_events().unwrap().iter().any(|e| e.step == "expire"));
}

#[test]
fn malformed_import_uses_raw_digest_and_signature_relabelling_is_refused() {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let p = dir();
    let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
    let raw = [0xff];
    assert!(s.import(&raw, &rights()).is_err());
    let d = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(raw));
    assert_eq!(
        s.audit_events().unwrap()[0].capability,
        format!("urn:sidged:record:{d}")
    );
    let r = Record::sign(value(), &[42; 32]).unwrap();
    let mut v = r.as_value().clone();
    v["sig"]["kid"] = json!("another-key");
    assert!(s
        .import(&sidged_record::encode(&v).unwrap(), &rights())
        .is_err());
    let mut v = value();
    v["retention"]["until"] = Value::Null;
    let r = Record::sign(v, &[42; 32]).unwrap();
    let d = s.import(&r.canonical_bytes().unwrap(), &rights()).unwrap();
    assert_eq!(
        s.read(
            &mut s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &d,
            &rights()
        )
        .unwrap()
        .as_value(),
        r.as_value()
    );
    s.delete(&d, &rights()).unwrap();
    assert!(!p.join("records").join(&d).exists());
}

#[test]
fn grant_signature_holder_policy_and_action_are_enforced() {
    let p = dir();
    let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
    let valid = rights();
    let mut forged = valid.grant.unwrap().clone();
    forged["rights"][0]["resource"] = json!("urn:sidged:record:*");
    let access = Access {
        grant: Some(&forged),
        ..rights()
    };
    assert!(s
        .write(
            draft(value()),
            &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &access
        )
        .is_err());
    let access = Access {
        holder: "someone-else",
        ..rights()
    };
    assert!(s
        .write(
            draft(value()),
            &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &access
        )
        .is_err());
    let access = Access {
        policy: &sidged_grant::DenyAll,
        ..rights()
    };
    assert!(s
        .write(
            draft(value()),
            &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &access
        )
        .is_err());
    let mut v = value();
    v["retention"]["until"] = Value::Null;
    let d = s
        .write(
            draft(v),
            &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &rights(),
        )
        .unwrap();
    let mut grant = valid.grant.unwrap().clone();
    grant["rights"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["action"] != "read");
    let grant = sidged_grant::attach_signature(&grant, &[42; 32], valid.holder);
    assert!(s
        .read(
            &mut s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &d,
            &Access {
                grant: Some(&grant),
                ..rights()
            }
        )
        .is_err());
    assert_eq!(
        s.audit_events()
            .unwrap()
            .iter()
            .filter(|e| e.decision == "deny")
            .count(),
        4
    );
}

#[test]
fn shared_derivation_cannot_erase_known_residency_or_trust_writer_inputs() {
    let p = dir();
    let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
    let mut ids = vec![];
    for tags in [json!(["CH"]), json!([])] {
        let mut v = value();
        v["retention"]["until"] = Value::Null;
        v["residency"]["tags"] = tags;
        let d = s
            .write(
                draft(v),
                &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
                &rights(),
            )
            .unwrap();
        ids.push(d);
    }
    let mut step = s.begin_step("urn:sidged:capability:notes.write", Value::Null);
    for d in ids {
        s.read(&mut step, &d, &rights()).unwrap();
    }
    assert!(s.write(value(), &step, &rights()).is_err());
    drop(step);
    let mut v = value();
    v["provenance"]["derived_from"] = json!(["writer-supplied"]);
    assert!(s
        .write(
            draft(v),
            &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &rights()
        )
        .is_err());
}

#[test]
fn audit_attributes_presented_holders_and_class() {
    let p = dir();
    let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
    let mut v = value();
    v["retention"]["until"] = Value::Null;
    let d = s
        .write(
            draft(v),
            &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &rights(),
        )
        .unwrap();
    s.read(
        &mut s.begin_step("urn:sidged:capability:notes.write", Value::Null),
        &d,
        &rights(),
    )
    .unwrap();
    assert!(s
        .read(
            &mut s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &d,
            &Access {
                holder: "other-holder",
                ..rights()
            }
        )
        .is_err());
    let holder = sidged_grant::did_key(&sidged_log::public_key(&[77; 32]));
    let mut token = rights().grant.unwrap().clone();
    token["sub"] = json!(holder);
    token["cnf"]["kid"] = json!(holder);
    token["id"] = json!("second-holder-grant");
    let token = sidged_grant::attach_signature(&token, &[42; 32], rights().holder);
    s.read(
        &mut s.begin_step("urn:sidged:capability:notes.write", Value::Null),
        &d,
        &Access {
            grant: Some(&token),
            holder: &holder,
            ..rights()
        },
    )
    .unwrap();
    let events = s.audit_events().unwrap();
    assert_ne!(events[1].actor, events[2].actor);
    assert!(events[2].actor.contains("other-holder"));
    assert_eq!(events[1].data_classes, vec!["health.records.notes"]);
    assert!(events[1].actor.contains("record-store-test"));
    assert!(events[1].actor.contains(rights().holder));
    assert_ne!(events[1].actor, events[3].actor);
    assert_eq!(events[3].decision, "allow");
    let actor: Value = serde_json::from_str(&events[3].actor).unwrap();
    assert_eq!(actor["holder"], holder);
    assert_eq!(actor["grant_id"], "second-holder-grant");
    assert_eq!(actor["issuer_kid"], rights().holder);
}
fn rejects_claim(field: &str) {
    let p = dir();
    let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
    let mut v = draft(value());
    v["retention"]["until"] = Value::Null;
    match field {
        "owner" => v["owner"] = json!(sidged_grant::did_key(&sidged_log::public_key(&[99; 32]))),
        "created" => v["provenance"][field] = json!("1999-01-01T00:00:00Z"),
        "source" => v["provenance"][field] = json!("urn:sidged:capability:owner.trusted-import"),
        "plan" => v["provenance"][field] = json!("forged-plan"),
        _ => unreachable!(),
    }
    assert!(s
        .write(
            v,
            &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &rights()
        )
        .is_err());
}
#[test]
fn refuses_writer_owner() {
    rejects_claim("owner");
}
#[test]
fn refuses_writer_created() {
    rejects_claim("created");
}
#[test]
fn refuses_writer_source() {
    rejects_claim("source");
}
#[test]
fn refuses_writer_plan() {
    rejects_claim("plan");
}
#[test]
fn sweep_continues_after_bad_entry_and_cleans_crash_temporary() {
    let p = dir();
    let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
    let mut v = value();
    v["retention"]["until"] = Value::Null;
    let d = s
        .write(
            draft(v),
            &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &rights(),
        )
        .unwrap();
    let d = s
        .set_retention(
            &d,
            json!({"until":"2000-01-01T00:00:00Z","on_expiry":"delete"}),
            &rights(),
        )
        .unwrap();
    std::fs::write(
        p.join("records/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        b"x",
    )
    .unwrap();
    assert_eq!(s.expire_sweep().unwrap(), 1);
    assert!(!p.join("records").join(d).exists());
    assert!(s
        .audit_events()
        .unwrap()
        .iter()
        .any(|e| e.step == "expire-check" && e.decision == "deny"));
    drop(s);
    let tmp = p.join("records/.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.tmp");
    std::fs::write(&tmp, b"private crash content").unwrap();
    let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
    assert!(!tmp.exists());
    assert!(s
        .audit_events()
        .unwrap()
        .iter()
        .any(|e| e.step == "recover-temp" && e.actor == "intrinsic:R8"));
}

#[test]
fn same_step_read_forces_derivation_even_with_empty_writer_tags() {
    let p = dir();
    let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
    let mut v = draft(value());
    v["retention"]["until"] = Value::Null;
    v["residency"]["tags"] = json!(["CH"]);
    let d = s
        .write(
            v,
            &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &rights(),
        )
        .unwrap();
    let mut step = s.begin_step("urn:sidged:capability:notes.write", Value::Null);
    s.read(&mut step, &d, &rights()).unwrap();
    let mut output = draft(value());
    output["retention"]["until"] = Value::Null;
    output["residency"]["tags"] = json!([]);
    let derived = s.write(output, &step, &rights()).unwrap();
    let r = s
        .read(
            &mut s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &derived,
            &rights(),
        )
        .unwrap();
    assert_eq!(r.as_value()["residency"]["tags"], json!(["CH"]));
    assert_eq!(r.as_value()["provenance"]["derived_from"], json!([d]));
}

#[test]
fn open_recovers_same_digest_temporary_and_import_can_retry() {
    let p = dir();
    let mut v = value();
    v["retention"]["until"] = Value::Null;
    let r = Record::sign(v, &[42; 32]).unwrap();
    let d = r.digest().unwrap();
    let bytes = r.canonical_bytes().unwrap();
    drop(Store::open(&p, &[42; 32], vec![]).unwrap());
    let tmp = p.join("records").join(format!(".{d}.tmp"));
    std::fs::write(&tmp, &bytes).unwrap();
    let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
    assert!(!tmp.exists());
    assert_eq!(s.import(&bytes, &rights()).unwrap(), d);
    assert_eq!(std::fs::read(p.join("records").join(d)).unwrap(), bytes);
}

#[test]
fn core_configuration_supplies_owner_clock_and_step_provenance() {
    let owner = sidged_grant::did_key(&sidged_log::public_key(&[88; 32]));
    let p = dir();
    let mut s = Store::open_with_owner(&p, &[42; 32], vec![], &owner).unwrap();
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let step = s.begin_step("urn:sidged:capability:notes.write", json!("core-plan"));
    let mut v = draft(value());
    v["provenance"]["plan"] = json!("core-plan");
    v["retention"]["until"] = Value::Null;
    let d = s.write(v, &step, &rights()).unwrap();
    let r = s
        .read(
            &mut s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &d,
            &rights(),
        )
        .unwrap();
    let v = r.as_value();
    assert_eq!(v["owner"], owner);
    assert_eq!(
        v["provenance"]["source"],
        "urn:sidged:capability:notes.write"
    );
    assert_eq!(v["provenance"]["plan"], "core-plan");
    let created =
        sidged_grant::parse_rfc3339_z(v["provenance"]["created"].as_str().unwrap()).unwrap();
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(created >= before && created <= after);
}

#[test]
fn second_handle_cannot_launder_reads() {
    let p = dir();
    let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
    let mut v = draft(value());
    v["retention"]["until"] = Value::Null;
    v["residency"]["tags"] = json!(["CH"]);
    let d = s
        .write(
            v.clone(),
            &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &rights(),
        )
        .unwrap();
    let mut a = s.begin_step("urn:sidged:capability:notes.write", Value::Null);
    s.read(&mut a, &d, &rights()).unwrap();
    let b = s.begin_step("urn:sidged:capability:notes.write", Value::Null);
    v["residency"]["tags"] = json!([]);
    let derived = s.write(v, &b, &rights()).unwrap();
    drop(a);
    let r = s
        .read(
            &mut s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &derived,
            &rights(),
        )
        .unwrap();
    assert_eq!(r.as_value()["provenance"]["derived_from"], json!([d]));
    assert_eq!(r.as_value()["residency"]["tags"], json!(["CH"]));
}

#[test]
fn derived_write_reloads_deleted_or_retention_replaced_input() {
    for delete in [true, false] {
        let p = dir();
        let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
        let mut v = draft(value());
        v["retention"]["until"] = Value::Null;
        let d = s
            .write(
                v.clone(),
                &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
                &rights(),
            )
            .unwrap();
        let mut step = s.begin_step("urn:sidged:capability:notes.write", Value::Null);
        s.read(&mut step, &d, &rights()).unwrap();
        if delete {
            s.delete(&d, &rights()).unwrap();
        } else {
            s.set_retention(
                &d,
                json!({"until":"2000-01-01T00:00:00Z","on_expiry":"delete"}),
                &rights(),
            )
            .unwrap();
        }
        assert!(s
            .write(v, &step, &rights())
            .unwrap_err()
            .contains("missing input"));
        assert_eq!(s.audit_events().unwrap().last().unwrap().decision, "deny");
    }
}

#[test]
fn malformed_and_unknown_provenance_are_audited_denials() {
    for provenance in [json!("string"), json!(null), json!([]), {
        let mut p = draft(value())["provenance"].clone();
        p["verified_by"] = json!("did:key:zFAKE");
        p
    }] {
        let p = dir();
        let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
        let mut v = draft(value());
        v["retention"]["until"] = Value::Null;
        v["provenance"] = provenance;
        assert!(s
            .write(
                v,
                &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
                &rights()
            )
            .is_err());
        drop(s);
        let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
        assert_eq!(s.audit_events().unwrap().last().unwrap().decision, "deny");
        assert_eq!(std::fs::read_dir(p.join("records")).unwrap().count(), 0);
    }
}

#[test]
fn reservation_without_completed_effect_survives_reopen() {
    let p = dir();
    let mut grant = rights().grant.unwrap().clone();
    grant["id"] = json!("interrupted-record-write");
    grant["rights"][1]["constraints"] = json!({"max_uses":1});
    let key = grant["iss"].as_str().unwrap().to_owned();
    let grant = sidged_grant::attach_signature(&grant, &[42; 32], &key);
    let access = Access {
        grant: Some(&grant),
        holder: &key,
        audience: "record-store",
        policy: &sidged_grant::PermitAll,
    };
    let mut v = draft(value());
    v["retention"]["until"] = Value::Null;
    let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
    s.write(
        v.clone(),
        &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
        &access,
    )
    .unwrap();
    let events = s.audit_events().unwrap();
    assert_eq!(events[0].decision, "spend");
    assert_eq!(
        events[0].usage,
        Some((json!([key, "interrupted-record-write"]).to_string(), 1, 1))
    );
    assert_eq!(events[1].decision, "allow");
    drop(s);
    // Model a crash after reservation, before the allow and record effect.
    let log = std::fs::read_to_string(p.join("audit.log")).unwrap();
    std::fs::write(
        p.join("audit.log"),
        format!("{}\n", log.lines().next().unwrap()),
    )
    .unwrap();
    for entry in std::fs::read_dir(p.join("records")).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }
    let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
    let err = s
        .write(
            v,
            &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
            &access,
        )
        .unwrap_err();
    assert!(err.contains("grant denied"));
    assert_eq!(std::fs::read_dir(p.join("records")).unwrap().count(), 0);
    let events = s.audit_events().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].decision, "deny");
    assert!(events[1]
        .reason
        .as_deref()
        .unwrap()
        .contains("grant denied"));
}

#[test]
fn refused_expired_operations_do_not_spend_capped_grant() {
    for action in ["write", "import", "read", "retain"] {
        let p = dir();
        let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
        let mut v = value();
        v["retention"] = json!({"until":"2000-01-01T00:00:00Z","on_expiry":"delete"});
        let r = Record::sign(v.clone(), &[42; 32]).unwrap();
        let d = r.digest().unwrap();
        std::fs::write(p.join("records").join(&d), r.canonical_bytes().unwrap()).unwrap();
        let mut grant = rights().grant.unwrap().clone();
        for right in grant["rights"].as_array_mut().unwrap() {
            right["constraints"] = json!({"max_uses":1});
        }
        let grant = sidged_grant::attach_signature(&grant, &[42; 32], rights().holder);
        let access = Access {
            grant: Some(&grant),
            ..rights()
        };
        let result = match action {
            "write" => s.write(
                draft(v),
                &s.begin_step("urn:sidged:capability:notes.write", Value::Null),
                &access,
            ),
            "import" => s.import(&r.canonical_bytes().unwrap(), &access),
            "read" => s
                .read(
                    &mut s.begin_step("urn:sidged:capability:notes.write", Value::Null),
                    &d,
                    &access,
                )
                .map(|_| d.clone()),
            "retain" => s.set_retention(&d, json!({"until":null,"on_expiry":"delete"}), &access),
            _ => unreachable!(),
        };
        assert_eq!(result.unwrap_err(), "expired", "{action}");
        drop(s);
        let mut s = Store::open(&p, &[42; 32], vec![]).unwrap();
        assert!(
            !s.audit_events().unwrap().iter().any(|e| e.usage.is_some()),
            "{action}"
        );
    }
}

#[test]
fn refused_foreign_signer_retention_does_not_spend_capped_grant() {
    let p = dir();
    let foreign = sidged_grant::did_key(&sidged_log::public_key(&[43; 32]));
    let mut s = Store::open(&p, &[42; 32], vec![foreign.clone()]).unwrap();
    let mut v = value();
    v["retention"]["until"] = Value::Null;
    let r = Record::sign(v, &[43; 32]).unwrap();
    let d = s.import(&r.canonical_bytes().unwrap(), &rights()).unwrap();
    let mut grant = rights().grant.unwrap().clone();
    grant["rights"][3]["constraints"] = json!({"max_uses":1});
    let grant = sidged_grant::attach_signature(&grant, &[42; 32], rights().holder);
    let access = Access {
        grant: Some(&grant),
        ..rights()
    };
    assert_eq!(
        s.set_retention(&d, json!({"until":null,"on_expiry":"delete"}), &access)
            .unwrap_err(),
        "imported retention requires original signer"
    );
    drop(s);
    let mut s = Store::open(&p, &[42; 32], vec![foreign]).unwrap();
    assert!(!s.audit_events().unwrap().iter().any(|e| e.usage.is_some()));
    assert!(p.join("records").join(d).exists());
}
