//! Signature checks for a capability-token chain.
//!
//! Each link, including the token itself, is signed by its issuer. `sig.kid`
//! is that issuer's Ed25519 `did:key` and must equal `iss`. The signature is
//! Ed25519 over the JCS signing input. `cnf` is bound with `bind_holder`.

use serde_json::Value;

use crate::crypto::verify;
use crate::didkey::{bind_holder, resolve_did_key};
use crate::jcs::signing_input;

/// Ed25519 over the JCS signing input. `sig.kid` is the issuer `did:key`.
pub fn attach_signature(document: &Value, seed: &[u8; 32], issuer_did: &str) -> Value {
    let mut signed = document.clone();
    if let Some(object) = signed.as_object_mut() {
        object.remove("sig");
    }
    let signature = crate::crypto::sign(seed, signing_input(&signed).as_bytes());
    signed["sig"] = serde_json::json!({
        "alg": "EdDSA",
        "kid": issuer_did,
        "canon": "jcs",
        "value": b64url_encode(&signature)
    });
    signed
}

pub fn verify_token_chain(token: &Value) -> Result<(), String> {
    let links = token
        .get("chain")
        .and_then(Value::as_array)
        .ok_or("token has no chain")?;
    for link in links {
        verify_link(link)?;
    }
    verify_link(token)
}

/// Ed25519 over the JCS signing input of `document`, by the key `sig.kid` names.
pub(crate) fn verify_signature(document: &Value) -> Result<(), String> {
    let sig = document.get("sig").ok_or("is missing sig")?;
    if sig["alg"] != "EdDSA" || sig["canon"] != "jcs" {
        return Err("signature must be EdDSA over jcs".into());
    }
    let kid = sig["kid"].as_str().ok_or("sig.kid")?;
    let public = resolve_did_key(kid)?;
    let raw = b64url_decode(sig["value"].as_str().ok_or("sig.value")?)?;
    if raw.len() != 64 {
        return Err("signature has the wrong length".into());
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&raw);
    if !verify(&public, signing_input(document).as_bytes(), &signature) {
        return Err("bad signature".into());
    }
    Ok(())
}

fn verify_link(link: &Value) -> Result<(), String> {
    let iss = link["iss"].as_str().ok_or("link is missing iss")?;
    let sub = link["sub"].as_str().ok_or("link is missing sub")?;
    let sig = link.get("sig").ok_or("link is missing sig")?;
    if sig["alg"] != "EdDSA" || sig["canon"] != "jcs" {
        return Err("link signature must be EdDSA over jcs".into());
    }
    let kid = sig["kid"].as_str().ok_or("sig.kid")?;
    if kid != iss {
        return Err("sig.kid does not name the issuer".into());
    }
    let public = resolve_did_key(kid)?;
    let raw = b64url_decode(sig["value"].as_str().ok_or("sig.value")?)?;
    if raw.len() != 64 {
        return Err("signature has the wrong length".into());
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&raw);
    if !verify(&public, signing_input(link).as_bytes(), &signature) {
        return Err("bad signature".into());
    }
    let jkt = link["cnf"]["jkt"].as_str();
    let cnf_kid = link["cnf"]["kid"].as_str();
    bind_holder(sub, cnf_kid, jkt).map(|_| ())
}

fn b64url_encode(bytes: &[u8]) -> String {
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

fn b64url_decode(text: &str) -> Result<Vec<u8>, String> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for byte in text.bytes() {
        let value = TABLE
            .iter()
            .position(|item| *item == byte)
            .ok_or_else(|| "invalid base64url".to_string())? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Ok(out)
}
