//! Issuer helper: an egress.send grant for exactly the Gemini URL (0002 R3: at
//! most 1 h; R6 cnf; R20 messages budget), signed by the issuer key.
use serde_json::Value;
use vaikor_tui::issue::*;
use vaikor_tui::{CLOUD_URL, EGRESS_ACTION};

const ISSUER: [u8; 32] = [3; 32];
const HOLDER: [u8; 32] = [4; 32];
const NOW: &str = "2026-10-17T08:00:00Z";

fn holder_did() -> String {
    vaikor_grant::did_key(&vaikor_log::public_key(&HOLDER))
}
fn issuer_did() -> String {
    vaikor_grant::did_key(&vaikor_log::public_key(&ISSUER))
}
fn opts() -> GrantOptions {
    GrantOptions {
        holder: holder_did(),
        audience: holder_did(),
        now: NOW.into(),
        lifetime_secs: DEFAULT_LIFETIME_SECS,
        messages: 1,
    }
}

#[test]
fn grant_is_accepted_and_covers_exactly_the_gemini_url() {
    let g: Value = issue_cloud_grant(&ISSUER, &opts()).unwrap();
    let t = vaikor_grant::accept_presented(&g, NOW, &[issuer_did().as_str()]).unwrap();
    assert_eq!(t.link.rights.len(), 1);
    assert_eq!(t.link.rights[0].action, EGRESS_ACTION);
    assert_eq!(t.link.rights[0].resource, CLOUD_URL);
    assert_eq!(t.link.budget.messages, Some(1));
    assert_eq!(t.link.sub, holder_did());
    assert_eq!(
        CLOUD_URL,
        "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    );
    // exactly that URL: no sibling path, no other Gemini surface, no xAI
    for other in [
        "https://generativelanguage.googleapis.com/v1beta/openai/",
        "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions/x",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent",
        "https://generativelanguage.googleapis.com/v1beta/files",
        "https://api.x.ai/v1/chat/completions",
    ] {
        assert!(
            !vaikor_grant::resource_covers(&t.link.rights[0].resource, other),
            "{other}"
        );
    }
    assert!(g["id"].as_str().is_some_and(|i| !i.is_empty()));
}

#[test]
fn lifetime_is_at_most_one_hour() {
    let g = issue_cloud_grant(&ISSUER, &opts()).unwrap();
    let iat = vaikor_grant::parse_rfc3339_z(g["iat"].as_str().unwrap()).unwrap();
    let exp = vaikor_grant::parse_rfc3339_z(g["exp"].as_str().unwrap()).unwrap();
    assert!(exp - iat <= 3600 && exp > iat);
    let mut o = opts();
    o.lifetime_secs = 7200; // 2 h requested: refused (0002 R3 wins)
    assert!(issue_cloud_grant(&ISSUER, &o).unwrap_err().contains("R3"));
}

#[test]
fn bad_inputs_refused() {
    let mut o = opts();
    o.messages = 0;
    assert!(issue_cloud_grant(&ISSUER, &o).is_err());
    let mut o = opts();
    o.holder = "did:example:not-a-key".into();
    assert!(issue_cloud_grant(&ISSUER, &o).is_err());
    let mut o = opts();
    o.now = "yesterday".into();
    assert!(issue_cloud_grant(&ISSUER, &o).is_err());
}

#[test]
fn expired_grant_is_refused_by_the_core() {
    let g = issue_cloud_grant(&ISSUER, &opts()).unwrap();
    assert!(
        vaikor_grant::accept_presented(&g, "2026-10-17T09:30:00Z", &[issuer_did().as_str()])
            .is_err()
    );
}

#[test]
fn issuer_seed_parses_hex_only() {
    assert_eq!(*parse_seed_hex(&"03".repeat(32)).unwrap(), ISSUER);
    assert!(parse_seed_hex("zz").is_err());
    assert!(parse_seed_hex(&"03".repeat(31)).is_err());
}

// ---------------- issuer input checks
#[test]
fn no_xai_text_in_the_issuer() {
    let src = include_str!("../src/issue.rs");
    assert!(!src.contains("xAI") && !src.contains("x.ai"));
}

#[test]
fn minutes_are_checked() {
    assert_eq!(minutes_to_secs("1").unwrap(), 60);
    assert_eq!(minutes_to_secs("55").unwrap(), 3300);
    assert_eq!(minutes_to_secs("60").unwrap(), 3600);
    for bad in ["0", "-1", "61", "x", ""] {
        assert!(minutes_to_secs(bad).is_err(), "{bad}");
    }
    // 60 * n overflows i64 (wraps to a small value in release): refused.
    let wraps = (i64::MAX / 60 + 1).to_string();
    assert!(minutes_to_secs(&wraps).unwrap_err().contains("overflow"));
    assert!(minutes_to_secs("153722867280912931").is_err());
}

#[test]
fn url_variants_are_pinned() {
    let g: Value = issue_cloud_grant(&ISSUER, &opts()).unwrap();
    let t = vaikor_grant::accept_presented(&g, NOW, &[issuer_did().as_str()]).unwrap();
    let right = &t.link.rights[0].resource;
    let cedar = vaikor_grant::CedarEvaluator::parse(vaikor_tui::DEMO_POLICY).unwrap();
    let aud = holder_did();
    let ctx = vaikor_grant::AuthContext {
        audience: &aud,
        data_classes: &["query"],
        residency: &["unrestricted"],
    };
    assert!(vaikor_grant::resource_covers(right, CLOUD_URL));
    assert!(cedar
        .permit(&holder_did(), EGRESS_ACTION, CLOUD_URL, ctx)
        .unwrap());
    for other in [
        "https://GenerativeLanguage.googleapis.com/v1beta/openai/chat/completions",
        "https://generativelanguage.googleapis.com:443/v1beta/openai/chat/completions",
        "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions?x=1",
        "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions/",
        "https://generativelanguage.googleapis.com/v1beta/openai/chat%2Fcompletions",
        "https://generativelanguage.googleapis.com/v1beta/openai/chat/%63ompletions",
        "https://user@generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "https://xn--generativelanguage-0db.googleapis.com/v1beta/openai/chat/completions",
        "http://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "https://generativelanguage.googleapis.com/v1beta/openai/embeddings",
        "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions:generateContent",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent",
    ] {
        assert!(!vaikor_grant::resource_covers(right, other), "grant: {other}");
        assert!(
            !cedar.permit(&holder_did(), EGRESS_ACTION, other, ctx).unwrap(),
            "policy: {other}"
        );
    }
}

#[test]
fn issuer_has_no_placeholder_audience() {
    let src = include_str!("../src/issue.rs");
    assert!(!src.contains("did:example"));
    let g = issue_cloud_grant(&ISSUER, &opts()).unwrap();
    assert_eq!(g["aud"], holder_did());
}
