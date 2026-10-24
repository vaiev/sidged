//! 0007 §5.3 R11-R13: checks A-D before a remote send, against the
//! normative vectors (egress/anonymization.json). Approval/budget vectors
//! (R8/R10) are decided by the Core channel and grant, not by this check.
use sidged_gateway::egress_check::*;

#[test]
fn record_has_r13_fields_and_no_payload() {
    let tags = vec!["unrestricted".to_string()];
    let payload = b"mail anna.muster@example.ch now";
    let out = egress_check(&Check::new("xai", "GLOBAL", &["query"], &tags, payload));
    assert_eq!(out.refusal.as_deref(), Some("data-class-forbidden"));
    let r = &out.record;
    assert_eq!(r["detector_version"], DETECTOR_VERSION);
    assert_eq!(r["matched_detectors"], serde_json::json!(["email"]));
    assert_eq!(r["input_classes"], serde_json::json!(["query"]));
    assert_eq!(r["residency_tags"], serde_json::json!(["unrestricted"]));
    assert_eq!(r["destination_class"], "GLOBAL");
    assert_eq!(r["provider"], "xai");
    assert_eq!(r["payload_sha256"].as_str().unwrap().len(), 64);
    let text = r.to_string();
    assert!(!text.contains("anna") && !text.contains("example.ch"));
}

#[test]
fn default_threshold_is_query_and_documents_text_only() {
    let tags = vec!["unrestricted".to_string()];
    let run = |c: &str| egress_check(&Check::new("xai", "GLOBAL", &[c], &tags, b"ok")).refusal;
    assert_eq!(run("query"), None);
    assert_eq!(run("query.general"), None);
    assert_eq!(run("documents.text"), None);
    assert_eq!(
        run("communications.content").as_deref(),
        Some("data-class-forbidden")
    );
    assert_eq!(run("documents").as_deref(), Some("data-class-forbidden"));
}

#[test]
fn nfkc_and_detectors() {
    let tags = vec!["unrestricted".to_string()];
    let run = |p: &str| {
        egress_check(&Check::new(
            "xai",
            "GLOBAL",
            &["query"],
            &tags,
            p.as_bytes(),
        ))
        .record["matched_detectors"]
            .clone()
    };
    // fullwidth digits/at-sign normalize under NFKC
    assert_eq!(
        run("ａｎｎａ＠ｅｘａｍｐｌｅ．ｃｈ"),
        serde_json::json!(["email"])
    );
    assert_eq!(
        run("token ghp_abcdefghijklmnopqrstuvwxyz"),
        serde_json::json!(["secret"])
    );
    // a non-Luhn 16-digit run is still caught by `phone` (9+ digits), per R12
    assert_eq!(
        run("card 4111 1111 1111 1112"),
        serde_json::json!(["phone"])
    );
    assert_eq!(run("order 12345678 shipped"), serde_json::json!([]));
    assert_eq!(
        run("Give me one tip to finish a demo on time."),
        serde_json::json!([])
    );
}

// 0007 R12 / R12a: sdg.pii/1 `card` is exactly "a run of 13 to 19 digits
// (spaces or dashes allowed) that passes the Luhn check". A digit run is
// checked whole; a card inside a 20+-digit run is NOT a /1 match. Finding
// it needs windowing, a pattern change = sdg.pii/2, deferred.
#[test]
fn card_is_exactly_the_r12_table() {
    // 13..19-digit runs that pass Luhn, with spaces or dashes
    for text in [
        "4111111111111111",
        "pay 4111 1111 1111 1111 now",
        "pay 4111-1111-1111-1111 now",
        "4222222222222",       // 13 digits
        "4111111111111111110", // 19 digits, Luhn-valid whole
    ] {
        assert!(detect(text).contains(&"card"), "{text}");
    }
    // not a /1 card: Luhn fails whole, too short, or a 20+-digit run
    // (windowing inside longer runs is a later sdg.pii/2)
    for text in [
        "ref 1234567890123 end",
        "411111111111",
        "ref 1234111111111111111567 end",
        "ref 12341111 1111 1111 1111567",
        "ref 41111111111111111111 end",
    ] {
        assert!(!detect(text).contains(&"card"), "{text}");
    }
}

// External callers build a Check only via Check::new and the
// detector-version builder; owner policy is not settable from outside
// the crate (owner-policy tests: src/egress_check.rs).
#[test]
fn external_callers_use_check_new() {
    let tags = vec!["unrestricted".to_string()];
    let q: &[&str] = &["query"];
    let base = || {
        Check::new(
            "https://generativelanguage.googleapis.com/",
            "GLOBAL",
            q,
            &tags,
            b"a short public question",
        )
    };
    let ok = egress_check(&base());
    assert_eq!(ok.refusal, None);
    assert_eq!(ok.record["detector_version"], DETECTOR_VERSION);
    assert_eq!(
        egress_check(&base().with_detector_version(Some("sdg.pii/9")))
            .refusal
            .as_deref(),
        Some("policy-denied")
    );
}

#[test]
fn check_fields_are_crate_private() {
    let src = include_str!("../src/egress_check.rs");
    let start = src.find("pub struct Check<'a> {").unwrap();
    let body = &src[start..start + src[start..].find("\n}").unwrap()];
    assert!(!body.contains("    pub "), "public Check field:\n{body}");
    assert!(body.contains("pub(crate) export_threshold"), "{body}");
    assert!(!src.contains("fn with_export_threshold"));
    assert!(src.contains("pub(crate) fn with_max_payload_bytes"));
    assert!(!src.contains("pub fn with_max_payload_bytes"));
}
