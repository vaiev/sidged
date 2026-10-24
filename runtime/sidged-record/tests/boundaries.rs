use serde_json::{json, Value};
use sidged_record::{decode, encode, Record};

#[test]
fn integer_boundaries_and_canonical_arguments() {
    for value in [
        json!(i64::MIN),
        json!(u64::MAX),
        json!(-24),
        json!(-25),
        json!(255),
        json!(256),
    ] {
        assert_eq!(decode(&encode(&value).unwrap()).unwrap(), value);
    }
    for bytes in [
        vec![0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0],
        vec![0xf7],
        vec![0xf8, 0x14],
        vec![0x78, 1, b'a'],
        vec![0x63, b'e', 0xcc, 0x81],
        vec![0x61, 0xff],
        vec![0x1b],
    ] {
        assert!(decode(&bytes).is_err(), "{bytes:x?}");
    }
    assert!(encode(&json!(1.0)).is_err());
    assert!(decode(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
    assert!(decode(&vec![0x81; 1000]).is_err());
}

#[test]
fn record_dates_and_identity_are_checked() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../spec/test-vectors/records/records.json"
    ))
    .unwrap();
    let value = vectors["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "record.check.001")
        .unwrap()["input"]["record"]
        .clone();
    let r = Record::parse(value.clone()).unwrap();
    assert_eq!(
        r.resource().unwrap(),
        "urn:sidged:record:health/records/notes"
    );
    let mut resigned = value.clone();
    resigned["sig"]["value"] = json!("different");
    assert_eq!(
        r.digest().unwrap(),
        Record::parse(resigned).unwrap().digest().unwrap()
    );
    for stamp in [
        "2027-02-29T08:00:00Z",
        "2026-10-15T08:00:00+00:00",
        "2026-10-15T08:00:00.0Z",
        "2026-10-15T08:00:60Z",
    ] {
        let mut invalid = value.clone();
        invalid["retention"]["until"] = json!(stamp);
        assert!(Record::parse(invalid).is_err(), "{stamp}");
    }
}

#[test]
fn signing_round_trip_and_untrusted_key_refusal() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../spec/test-vectors/records/records.json"
    ))
    .unwrap();
    let value = vectors["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "record.check.001")
        .unwrap()["input"]["record"]
        .clone();
    let record = Record::sign(value, &[42; 32]).unwrap();
    let signer = record.as_value()["sig"]["signer"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(Record::check(record.as_value().clone(), &[]).is_err());
    Record::check(
        decode(&record.canonical_bytes().unwrap()).unwrap(),
        std::slice::from_ref(&signer),
    )
    .unwrap();
    let mut tampered = record.as_value().clone();
    tampered["content"] = json!("tampered");
    assert!(Record::check(tampered, &[signer]).is_err());
    assert!(record
        .identifier()
        .unwrap()
        .starts_with("urn:sidged:record:"));
}
