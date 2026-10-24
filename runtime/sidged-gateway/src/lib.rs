//! One privacy report for one egress call. Field names only, never values.
//! HTTP leaves only through `send`.

pub mod egress_check;
mod residency;
mod send;

use sha2::{Digest, Sha256};

pub use residency::{allowed_regions, provider_allows, residency_destination};
pub mod local_model;
pub use send::{
    check_key_file_meta, is_xai, preflight, send, send_get, send_with_credential, utc_stamp,
    validate_destination, ApiKey, EgressError, EgressErrorKind, KeySource, SendRequest,
    SendResponse,
};

/// A process can enter local mode, but can never leave it.
pub fn enable_local() {
    MODE.resolve(true);
}
pub fn is_local() -> bool {
    MODE.resolve(false)
}

/// Resolve startup inputs strictly (0007 R2), then latch local mode.
pub fn resolve_local(requested: bool) -> Result<bool, String> {
    let env = match std::env::var("SIDGED_LOCAL") {
        Err(std::env::VarError::NotPresent) => false,
        Ok(value) if value == "0" => false,
        Ok(value) if value == "1" => true,
        _ => return Err("SIDGED_LOCAL must be unset, 0, or 1".into()),
    };
    if requested || env {
        enable_local();
    }
    Ok(is_local())
}

pub struct Egress<'a> {
    pub id: &'a str,
    pub call_at: &'a str,
    pub provider_id: &'a str,
    pub profile: &'a str,
    pub data_classes: &'a [&'a str],
    pub fields: &'a [&'a str],
    pub payload: &'a [u8],
    pub residency: &'a [&'a str],
}

/// Identifier bound to this call: provider, time, plan step, and payload.
pub fn call_id(provider: &str, call_at: &str, step: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(provider.as_bytes());
    hasher.update(b"\n");
    hasher.update(call_at.as_bytes());
    hasher.update(b"\n");
    hasher.update(step.as_bytes());
    hasher.update(b"\n");
    hasher.update(payload);
    let digest = hasher.finalize();
    let mut out = String::from("pr-");
    for byte in digest.iter().take(8) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub fn known_profile(profile: &str) -> bool {
    matches!(profile, "P0" | "P1" | "P2" | "P3")
}

pub fn report(egress: &Egress) -> serde_json::Value {
    let digest = Sha256::digest(egress.payload);
    serde_json::json!({
        "v": "0.1",
        "id": egress.id,
        "call_at": egress.call_at,
        "provider": { "id": egress.provider_id },
        "provider_profile": { "claimed": egress.profile, "effective": null, "verified": false },
        "gateway_mode": "full",
        "relay": { "used": false },
        "network_identity": "direct",
        "account": { "mode": "anonymous", "linkable": false },
        "sent": {
            "data_classes": egress.data_classes,
            "fields": egress.fields,
            "bytes": egress.payload.len()
        },
        "redacted": { "data_classes": [], "fields": [], "pseudonymised": [] },
        "minimisation": {
            "steps": ["context-selection", "redaction", "no-persistent-id"],
            "payload_digest": { "alg": "sha-256", "value": b64url(&digest) }
        },
        "residency": { "tags": egress.residency },
        "retention": { "declared": "undeclared" }
    })
}

/// Unpadded base64url, which is what the privacy-report digest value requires.
fn b64url(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let chunk = u32::from(bytes[index]) << 16
            | u32::from(bytes[index + 1]) << 8
            | u32::from(bytes[index + 2]);
        for shift in [18, 12, 6, 0] {
            out.push(TABLE[((chunk >> shift) & 63) as usize] as char);
        }
        index += 3;
    }
    let rest = bytes.len() - index;
    if rest == 1 {
        let chunk = u32::from(bytes[index]) << 16;
        out.push(TABLE[((chunk >> 18) & 63) as usize] as char);
        out.push(TABLE[((chunk >> 12) & 63) as usize] as char);
    } else if rest == 2 {
        let chunk = u32::from(bytes[index]) << 16 | u32::from(bytes[index + 1]) << 8;
        out.push(TABLE[((chunk >> 18) & 63) as usize] as char);
        out.push(TABLE[((chunk >> 12) & 63) as usize] as char);
        out.push(TABLE[((chunk >> 6) & 63) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{call_id, report, Egress};

    #[test]
    fn a_report_names_classes_and_not_values() {
        let payload = b"hello";
        let call_at = "2026-10-15T01:00:00Z";
        let provider = "https://models.example";
        let document = report(&Egress {
            id: &call_id(provider, call_at, "send", payload),
            call_at,
            provider_id: provider,
            profile: "P1",
            data_classes: &["communications.content"],
            fields: &["body"],
            payload,
            residency: &["CH"],
        });
        assert_eq!(document["id"], call_id(provider, call_at, "send", payload));
        assert_ne!(document["id"], call_id(provider, call_at, "again", payload));
        assert_eq!(document["call_at"], call_at);
        assert_eq!(document["provider"]["id"], provider);
        assert_ne!(document["id"], call_id(provider, call_at, "send", b"other"));
        assert_eq!(document["residency"]["tags"][0], "CH");
        assert_eq!(
            document["sent"]["data_classes"][0],
            "communications.content"
        );
        assert!(document["sent"].get("body").is_none());
        assert_eq!(document["minimisation"]["payload_digest"]["alg"], "sha-256");
        let digest = document["minimisation"]["payload_digest"]["value"]
            .as_str()
            .unwrap();
        assert_eq!(digest, "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ");
        assert!(digest
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'));
        assert_eq!(document["gateway_mode"], "full");
        assert_eq!(document["provider_profile"]["claimed"], "P1");
        assert!(document["provider_profile"]["effective"].is_null());
        assert_eq!(document["provider_profile"]["verified"], false);
    }
}

/// Gateway-owned one-way latch, shared across the phases of a guard run.
#[derive(Default)]
pub struct GatewayMode(std::sync::atomic::AtomicBool);
impl GatewayMode {
    pub const fn new() -> Self {
        Self(std::sync::atomic::AtomicBool::new(false))
    }
    pub fn resolve(&self, requested: bool) -> bool {
        if requested {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod mode_tests {
    #[test]
    fn local_mode_cannot_be_unset() {
        let mode = super::GatewayMode::new();
        assert!(!mode.resolve(false));
        assert!(mode.resolve(true));
        assert!(mode.resolve(false));
    }
}

static MODE: GatewayMode = GatewayMode::new();
