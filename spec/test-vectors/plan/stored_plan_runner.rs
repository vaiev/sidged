// Included as a sidged-verify unit test so the vector clock is not a production API.
use super::*;
use serde_json::json;

fn vectors() -> Value {
    serde_json::from_str(include_str!("dcbor-signed.json")).unwrap()
}
fn owner(name: &str) -> String {
    let keys: Value = serde_json::from_str(include_str!("../keys/rfc8032-test-keys.json")).unwrap();
    let key = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["name"] == name)
        .unwrap();
    let s = key["public_key_hex"].as_str().unwrap();
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    sidged_grant::did_key(&bytes.try_into().unwrap())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn stored_plan_vectors() {
    let mut checked = 0;
    let mut skipped = Vec::new();
    for v in vectors()["vectors"].as_array().unwrap() {
        let i = &v["input"];
        let result = match v["operation"].as_str().unwrap() {
            "plan-digest" => plan_digest(&i["plan"]).map(|digest| json!({"value": {"digest":digest,"dcbor_hex":hex(&sidged_record::encode(&i["plan"]).unwrap())}})),
            "stored-plan-signing-input" => signing_input(&i["stored"]).map(|bytes| json!({"value":hex(&bytes)})),
            "stored-plan-check" => check_at(&i["stored"], &i["catalog"], &owner(i["owner_key"].as_str().unwrap()), "default", &crate::DenySensitive, instant(i["now"].as_str().unwrap()).unwrap()).map(|_| json!({"result":"accept"})),
            "flow-check" => { skipped.push(v["id"].as_str().unwrap().to_owned()); continue; },
            op => panic!("unhandled operation {op}"),
        };
        let actual = result.unwrap_or_else(|e| json!({"result":"refuse","reason":e.code()}));
        assert_eq!(actual, v["expected"], "{}", v["id"]);
        checked += 1;
    }
    assert_eq!(checked, 13);
    assert_eq!(
        skipped,
        (1..=10)
            .map(|n| format!("plan.flow.{n:03}"))
            .collect::<Vec<_>>()
    );
}

fn fixture() -> (Value, Value, String) {
    let v = vectors()["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "plan.signed.001")
        .unwrap()["input"]
        .clone();
    (
        v["stored"].clone(),
        v["catalog"].clone(),
        owner("rfc8032-test-3"),
    )
}
fn resign(s: &mut Value) {
    let keys: Value = serde_json::from_str(include_str!("../keys/rfc8032-test-keys.json")).unwrap();
    let key = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["name"] == "rfc8032-test-3")
        .unwrap();
    let seed = key["secret_key_hex"].as_str().unwrap();
    let seed: Vec<u8> = (0..seed.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&seed[i..i + 2], 16).unwrap())
        .collect();
    s["plan_digest"] = json!(plan_digest(&s["plan"]).unwrap());
    s["sig"]["value"] = json!(URL_SAFE_NO_PAD.encode(sidged_grant::sign(
        &seed.try_into().unwrap(),
        &signing_input(s).unwrap()
    )));
}
fn at(s: &Value, c: &Value, o: &str, now: &str) -> Result<CheckedPlan> {
    check_at(
        s,
        c,
        o,
        "default",
        &crate::DenySensitive,
        instant(now).unwrap(),
    )
}
#[test]
fn missing_members_and_signature_metadata() {
    let (s, c, o) = fixture();
    for member in s.as_object().unwrap().keys() {
        let mut s = s.clone();
        s.as_object_mut().unwrap().remove(member);
        assert_eq!(
            at(&s, &c, &o, "2026-11-01T00:00:00Z").unwrap_err(),
            Error::Malformed,
            "{member}"
        );
    }
    for member in ["owner", "kid", "signer", "alg", "canon", "value"] {
        let mut s = s.clone();
        if member == "owner" {
            s[member] = json!("attacker");
        } else {
            s["sig"][member] = json!("invalid");
        }
        assert_eq!(
            at(&s, &c, &o, "2026-11-01T00:00:00Z").unwrap_err(),
            Error::BadSignature,
            "{member}"
        );
    }
}
#[test]
fn time_boundaries_compare_instants_and_enforce_lifetime() {
    let (mut s, c, o) = fixture();
    s["issued"] = json!("2026-10-15T08:00:00.500Z");
    s["expires"] = json!("2027-10-15T08:00:00.500+00:00");
    resign(&mut s);
    assert!(at(&s, &c, &o, "2026-10-15T08:00:00.500+00:00").is_ok());
    assert_eq!(
        at(&s, &c, &o, "2026-10-15T08:00:00.499Z").unwrap_err(),
        Error::Malformed
    );
    assert!(at(&s, &c, &o, "2027-10-15T08:00:00.499Z").is_ok());
    assert_eq!(
        at(&s, &c, &o, "2027-10-15T08:00:00.500Z").unwrap_err(),
        Error::Expired
    );
    for expires in [
        "2026-10-15T08:00:00.500Z",
        "2026-10-14T08:00:00Z",
        "2027-10-15T08:00:00.501Z",
        "2027-02-30T08:00:00Z",
    ] {
        s["expires"] = json!(expires);
        resign(&mut s);
        assert_eq!(
            at(&s, &c, &o, "2026-11-01T00:00:00Z").unwrap_err(),
            Error::Malformed
        );
    }
}
#[test]
fn current_catalog_and_policy_are_rechecked() {
    let (mut s, mut c, o) = fixture();
    let digest = catalog_digest(&s["plan"], &c).unwrap();
    c.as_array_mut().unwrap().reverse();
    let mut extra = c[0].clone();
    extra["id"] = json!("unrelated");
    c.as_array_mut().unwrap().push(extra);
    assert_eq!(catalog_digest(&s["plan"], &c).unwrap(), digest);
    assert!(at(&s, &c, &o, "2026-11-01T00:00:00Z").is_ok());
    s["flow_policy"] = json!("different");
    resign(&mut s);
    assert_eq!(
        at(&s, &c, &o, "2026-11-01T00:00:00Z").unwrap_err(),
        Error::Malformed
    );
    s["flow_policy"] = json!("default");
    // Re-signing does not exempt the plan from the full static verifier.
    s["plan"]["steps"][2]["approval"] = json!(false);
    resign(&mut s);
    assert_eq!(
        at(&s, &c, &o, "2026-11-01T00:00:00Z").unwrap_err(),
        Error::Malformed
    );
}
#[test]
fn per_run_audit_is_required_and_approval_is_preserved() {
    let (mut s, c, o) = fixture();
    let now = Utc::now();
    s["issued"] = json!((now - chrono::Duration::days(1)).to_rfc3339());
    s["expires"] = json!((now + chrono::Duration::days(1)).to_rfc3339());
    resign(&mut s);
    let mut log = Vec::new();
    for _ in 0..2 {
        let checked = check_for_run(&s, &c, &o, "default", &crate::DenySensitive, |event| {
            assert_eq!(event.decision, Decision::Accept);
            assert_eq!(event.reason, None);
            assert_eq!(event.owner, o);
            assert_eq!(event.kid.as_deref(), Some(o.as_str()));
            assert_eq!(
                event.catalog_digest.as_deref(),
                s["catalog_digest"].as_str()
            );
            assert_eq!(event.flow_policy.as_deref(), Some("default"));
            log.push(event.plan_digest.clone().unwrap());
            Ok(())
        })
        .unwrap();
        assert_eq!(checked.summary.approvals, vec!["send"]);
    }
    assert_eq!(log, vec![s["plan_digest"].as_str().unwrap(); 2]);
    assert_eq!(
        check_for_run(&s, &c, &o, "default", &crate::DenySensitive, |_| Err(
            std::io::Error::other("disk full")
        ))
        .unwrap_err(),
        Error::Malformed
    );
}
#[test]
fn policy_digest_preserves_exact_sources_and_sorts_ids() {
    let mut p = json!([{"id":"b","source":"permit;"},{"id":"a","source":"forbid;"}]);
    let digest = policy_digest(&p).unwrap();
    p.as_array_mut().unwrap().reverse();
    assert_eq!(policy_digest(&p).unwrap(), digest);
    p[0]["source"] = json!("forbid;\n");
    assert_ne!(policy_digest(&p).unwrap(), digest);
}
#[test]
fn stored_signature_is_not_a_grant() {
    let (s, _, o) = fixture();
    assert!(sidged_grant::accept_presented(&s, "2026-11-01T00:00:00Z", &[o.as_str()]).is_err());
}
#[test]
fn malformed_arguments_do_not_gain_a_signature_exemption() {
    let (mut s, c, o) = fixture();
    for arg in [
        json!({"lit":"value","ref":"missing"}),
        json!({"item":false}),
        json!({"lit":{}}),
    ] {
        s["plan"]["steps"][0]["args"]["range"] = arg;
        resign(&mut s);
        assert_eq!(
            at(&s, &c, &o, "2026-11-01T00:00:00Z").unwrap_err(),
            Error::Malformed
        );
    }
}

#[test]
fn resigned_owner_must_equal_provisioned_owner() {
    let (s, c, o) = fixture();
    for changed in [
        json!(owner("rfc8032-test-1")),
        json!(null),
        json!([o.clone()]),
    ] {
        let mut s = s.clone();
        s["owner"] = changed;
        resign(&mut s);
        assert_eq!(
            at(&s, &c, &o, "2026-11-01T00:00:00Z").unwrap_err(),
            Error::BadSignature
        );
    }
}
#[test]
fn resigned_non_utc_instants_are_refused() {
    let (s, c, o) = fixture();
    for member in ["issued", "expires"] {
        for offset in ["+01:00", "-01:00"] {
            let mut s = s.clone();
            s[member] = json!(format!("2026-11-01T00:00:00{offset}"));
            resign(&mut s);
            assert_eq!(
                at(&s, &c, &o, "2026-11-01T00:00:00Z").unwrap_err(),
                Error::Malformed,
                "{member} {offset}"
            );
        }
    }
}
#[test]
fn every_run_refusal_is_audited_even_when_sink_fails() {
    let (mut base, catalog, o) = fixture();
    let now = Utc::now();
    base["issued"] = json!((now - chrono::Duration::days(1)).to_rfc3339());
    base["expires"] = json!((now + chrono::Duration::days(1)).to_rfc3339());
    resign(&mut base);
    for case in [
        "signature",
        "expired",
        "future",
        "catalog",
        "policy",
        "verifier",
        "missing",
        "version",
        "digest",
        "unencodable",
    ] {
        let mut s = base.clone();
        let mut c = catalog.clone();
        let expected = match case {
            "signature" => {
                s["sig"]["value"] = json!("bad");
                Error::BadSignature
            }
            "expired" => {
                s["issued"] = json!((now - chrono::Duration::days(2)).to_rfc3339());
                s["expires"] = json!((now - chrono::Duration::days(1)).to_rfc3339());
                resign(&mut s);
                Error::Expired
            }
            "future" => {
                s["issued"] = json!((now + chrono::Duration::hours(1)).to_rfc3339());
                resign(&mut s);
                Error::Malformed
            }
            "catalog" => {
                c[0]["effects"] = json!(["changed"]);
                Error::Malformed
            }
            "policy" => {
                s["flow_policy"] = json!("changed");
                resign(&mut s);
                Error::Malformed
            }
            "verifier" => {
                s["plan"]["steps"][2]["approval"] = json!(false);
                resign(&mut s);
                Error::Malformed
            }
            "missing" => {
                s.as_object_mut().unwrap().remove("issued");
                Error::Malformed
            }
            "version" => {
                s["v"] = json!("unknown");
                Error::UnsupportedVersion
            }
            "digest" => {
                s["plan_digest"] = json!("wrong");
                Error::Malformed
            }
            "unencodable" => {
                s["plan"]["extension"] = json!(1.5);
                Error::Malformed
            }
            _ => unreachable!(),
        };
        for fail_sink in [false, true] {
            let mut entries = Vec::new();
            let result = check_for_run(&s, &c, &o, "default", &crate::DenySensitive, |event| {
                entries.push(event.clone());
                if fail_sink {
                    Err(std::io::Error::other("disk full"))
                } else {
                    Ok(())
                }
            });
            assert_eq!(result.unwrap_err(), expected, "{case}");
            assert_eq!(entries.len(), 1, "{case}");
            let event = &entries[0];
            assert_eq!(event.decision, Decision::Refuse);
            assert_eq!(event.reason, Some(expected.code()));
            assert_eq!(event.owner, o);
            assert_eq!(event.kid.as_deref(), s["sig"]["kid"].as_str());
            assert_eq!(
                event.catalog_digest.as_deref(),
                s["catalog_digest"].as_str()
            );
            assert_eq!(event.flow_policy.as_deref(), s["flow_policy"].as_str());
            assert_eq!(event.plan_digest, plan_digest(&s["plan"]).ok());
        }
    }
}
