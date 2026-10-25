//! A presented capability token is verified before it can authorise a step.

use serde_json::{json, Value};
use vaikor_grant::{accept_presented, did_key, jwk_thumbprint, sign, signing_input, GrantError};

fn hex32(text: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

fn b64url(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let n = (u32::from(bytes[index]) << 16)
            | (u32::from(bytes[index + 1]) << 8)
            | u32::from(bytes[index + 2]);
        for shift in [18, 12, 6, 0] {
            out.push(TABLE[((n >> shift) & 63) as usize] as char);
        }
        index += 3;
    }
    if index < bytes.len() {
        let mut n = u32::from(bytes[index]) << 16;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        if index + 1 < bytes.len() {
            n |= u32::from(bytes[index + 1]) << 8;
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        } else {
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
        }
    }
    out
}

fn party(secret_hex: &str, public_hex: &str) -> ([u8; 32], String, String) {
    let secret = hex32(secret_hex);
    let public = hex32(public_hex);
    (secret, did_key(&public), jwk_thumbprint(&public))
}

fn key_hex(name: &str) -> (String, String) {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/test-vectors/keys/rfc8032-test-keys.json");
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let key = file["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == name)
        .unwrap();
    (
        key["secret_key_hex"].as_str().unwrap().to_string(),
        key["public_key_hex"].as_str().unwrap().to_string(),
    )
}

fn sign_link(link: &Value, secret: &[u8; 32], issuer: &str) -> Value {
    let mut signed = link.clone();
    let signature = sign(secret, signing_input(&signed).as_bytes());
    signed["sig"] = json!({
        "alg": "EdDSA",
        "kid": issuer,
        "canon": "jcs",
        "value": b64url(&signature)
    });
    signed
}

#[allow(clippy::type_complexity)] // test fixture tuple
fn keys() -> (
    ([u8; 32], String, String),
    ([u8; 32], String, String),
    ([u8; 32], String, String),
) {
    let (owner_secret, owner_public) = key_hex("rfc8032-test-1");
    let (holder_secret, holder_public) = key_hex("rfc8032-test-2");
    let (child_secret, child_public) = key_hex("rfc8032-test-3");
    (
        party(&owner_secret, &owner_public),
        party(&holder_secret, &holder_public),
        party(&child_secret, &child_public),
    )
}

fn root() -> Value {
    let (owner, holder, _) = keys();
    sign_link(
        &json!({
            "v": "0.1",
            "id": "tok-present-root",
            "iss": owner.1,
            "sub": holder.1,
            "aud": "did:example:hosted",
            "iat": "2026-10-14T12:00:00Z",
            "exp": "2026-10-14T12:30:00Z",
            "cnf": { "kid": holder.1, "jkt": holder.2 },
            "rights": [{ "action": "calendar.free_slots", "resource": "tag:vaikor.com,2026:capability:calendar.free_slots" }],
            "budget": { "messages": 2 },
            "chain": []
        }),
        &owner.0,
        &owner.1,
    )
}

fn widened() -> Value {
    let (owner, holder, child) = keys();
    let parent = sign_link(
        &json!({
            "v": "0.1",
            "id": "tok-present-parent",
            "iss": owner.1,
            "sub": holder.1,
            "aud": "did:example:hosted",
            "iat": "2026-10-14T12:00:00Z",
            "exp": "2026-10-14T13:00:00Z",
            "cnf": { "kid": holder.1, "jkt": holder.2 },
            "rights": [{ "action": "calendar.free_slots", "resource": "tag:vaikor.com,2026:capability:calendar.free_slots" }],
            "budget": { "messages": 2 },
            "chain": []
        }),
        &owner.0,
        &owner.1,
    );
    sign_link(
        &json!({
            "v": "0.1",
            "id": "tok-present-child",
            "iss": holder.1,
            "sub": child.1,
            "aud": "did:example:hosted",
            "iat": "2026-10-14T12:05:00Z",
            "exp": "2026-10-14T12:20:00Z",
            "cnf": { "kid": child.1, "jkt": child.2 },
            "rights": [{ "action": "calendar.free_slots", "resource": "tag:vaikor.com,2026:capability/*" }],
            "budget": { "messages": 2 },
            "chain": [parent]
        }),
        &holder.0,
        &holder.1,
    )
}

fn present(token: &Value, now: &str) -> Result<vaikor_grant::Token, GrantError> {
    let root_link = token["chain"]
        .as_array()
        .and_then(|items| items.first())
        .unwrap_or(token);
    let iss = root_link["iss"].as_str().unwrap();
    accept_presented(token, now, &[iss])
}

#[test]
fn a_signed_grant_is_accepted_inside_its_lifetime() {
    let token = root();
    let accepted = present(&token, "2026-10-14T12:10:00Z").unwrap();
    assert_eq!(accepted.link.sub, keys().1 .1);
}

#[test]
fn a_bad_signature_is_refused_before_expiry() {
    let mut token = root();
    let value = token["sig"]["value"].as_str().unwrap().to_string();
    let rest = &value[1..];
    let flipped = if value.starts_with('A') {
        format!("B{rest}")
    } else {
        format!("A{rest}")
    };
    token["sig"]["value"] = json!(flipped);
    token["exp"] = json!("2026-10-14T12:00:00Z");
    assert_eq!(
        present(&token, "2026-10-14T13:00:00Z").unwrap_err(),
        GrantError::Signature
    );
}

#[test]
fn an_expired_grant_is_refused() {
    let token = root();
    assert_eq!(
        present(&token, "2026-10-14T12:30:00Z").unwrap_err(),
        GrantError::Expired
    );
}

#[test]
fn a_holder_who_does_not_match_cnf_is_refused() {
    let (owner, holder, _) = keys();
    let token = sign_link(
        &json!({
            "v": "0.1",
            "id": "tok-present-unbind",
            "iss": owner.1,
            "sub": holder.1,
            "aud": "did:example:hosted",
            "iat": "2026-10-14T12:00:00Z",
            "exp": "2026-10-14T12:30:00Z",
            "cnf": { "kid": owner.1, "jkt": owner.2 },
            "rights": [{ "action": "calendar.free_slots", "resource": "tag:vaikor.com,2026:capability:calendar.free_slots" }],
            "chain": []
        }),
        &owner.0,
        &owner.1,
    );
    assert_eq!(
        present(&token, "2026-10-14T12:10:00Z").unwrap_err(),
        GrantError::Holder
    );
}

#[test]
fn a_widened_delegation_is_refused() {
    assert_eq!(
        present(&widened(), "2026-10-14T12:10:00Z").unwrap_err(),
        GrantError::UncoveredRight
    );
}

#[test]
fn an_unlisted_root_issuer_is_refused() {
    let token = root();
    assert_eq!(
        accept_presented(&token, "2026-10-14T12:10:00Z", &[]).unwrap_err(),
        GrantError::UntrustedIssuer
    );
    assert_eq!(
        accept_presented(&token, "2026-10-14T12:10:00Z", &["did:example:other"]).unwrap_err(),
        GrantError::UntrustedIssuer
    );
}
