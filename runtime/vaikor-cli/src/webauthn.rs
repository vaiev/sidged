// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! WebAuthn user-verification approvals (0004 R9w, WP 16).
//!
//! The owner enrolls one platform credential through Trusted UI; a consequential step is
//! approved by an assertion over a challenge that binds the R9 request. The Core checks the
//! client data, the authenticator data (relying party, user present and verified, counter)
//! and the signature, and never trusts a member it can recompute. Platform code only relays
//! the assertion; it cannot produce one without the human passing the operating system's
//! prompt.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::approval::{ApprovalChannel, ApprovalDecision, ApprovalRequest};

/// The audit name of this channel (R9w Audit).
pub const CHANNEL: &str = "webauthn-uv";
pub(crate) const FLAG_USER_PRESENT: u8 = 0x01;
pub(crate) const FLAG_USER_VERIFIED: u8 = 0x04;
/// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410); the key follows.
pub(crate) const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The enrolled credential (R9w Enrollment). `public_key` is SPKI DER, base64url.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub credential_id: String,
    pub alg: String,
    pub public_key: String,
    pub rp_id: String,
    pub origins: Vec<String>,
    pub sign_count: u32,
}

/// What a platform authenticator returns, base64url-encoded as WebAuthn JSON does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
}

/// The challenge for one request: SHA-256 of the RFC 8785 JSON of the R9 binding.
pub fn challenge(request: &ApprovalRequest) -> [u8; 32] {
    let mut binding = json!({
        "plan_digest": request.plan_digest,
        "step": request.step,
        "capability": request.capability,
        "args_digest": request.args_digest,
        "nonce": request.nonce,
    });
    if let Some(scope) = &request.scope_digest {
        binding["scope_digest"] = json!(scope);
    }
    Sha256::digest(vaikor_grant::canonicalize(&binding).as_bytes()).into()
}

pub(crate) fn b64(text: &str, what: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(text.trim_end_matches('='))
        .map_err(|_| format!("{what} is not base64url"))
}

/// Check one assertion against the enrollment and the request; the new counter on success.
pub fn verify(
    enrollment: &Enrollment,
    request: &ApprovalRequest,
    assertion: &Assertion,
) -> Result<u32, String> {
    if assertion.credential_id != enrollment.credential_id {
        return Err("credential is not the enrolled one".into());
    }
    let client_data = b64(&assertion.client_data_json, "clientDataJSON")?;
    let client: Value =
        serde_json::from_slice(&client_data).map_err(|_| "clientDataJSON is not JSON")?;
    if client["type"] != "webauthn.get" {
        return Err("clientDataJSON.type is not webauthn.get".into());
    }
    if client["challenge"] != URL_SAFE_NO_PAD.encode(challenge(request)) {
        return Err("challenge does not bind this request".into());
    }
    let origin = client["origin"].as_str().unwrap_or("");
    if !enrollment.origins.iter().any(|o| o == origin) {
        return Err(format!("origin {origin:?} is not accepted"));
    }
    if client
        .get("crossOrigin")
        .is_some_and(|c| c != &Value::Bool(false))
    {
        return Err("cross-origin assertion".into());
    }
    let auth = b64(&assertion.authenticator_data, "authenticatorData")?;
    if auth.len() < 37 {
        return Err("authenticatorData is too short".into());
    }
    if auth[..32] != Sha256::digest(enrollment.rp_id.as_bytes())[..] {
        return Err("authenticatorData is for another relying party".into());
    }
    let flags = auth[32];
    if flags & FLAG_USER_PRESENT == 0 || flags & FLAG_USER_VERIFIED == 0 {
        return Err("the authenticator did not verify the user".into());
    }
    let count = u32::from_be_bytes([auth[33], auth[34], auth[35], auth[36]]);
    if (count != 0 || enrollment.sign_count != 0) && count <= enrollment.sign_count {
        return Err("signature counter did not increase (cloned authenticator?)".into());
    }
    let mut signed = auth.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data));
    let signature = b64(&assertion.signature, "signature")?;
    let key = b64(&enrollment.public_key, "public key")?;
    match enrollment.alg.as_str() {
        "ES256" => {
            let key = p256::ecdsa::VerifyingKey::from_public_key_der(&key)
                .map_err(|_| "public key is not a P-256 SPKI")?;
            let signature = p256::ecdsa::Signature::from_der(&signature)
                .map_err(|_| "signature is not a DER ECDSA signature")?;
            key.verify(&signed, &signature)
                .map_err(|_| "signature does not verify")?;
        }
        "EdDSA" => {
            let raw = key
                .strip_prefix(&ED25519_SPKI_PREFIX[..])
                .and_then(|k| <[u8; 32]>::try_from(k).ok())
                .ok_or("public key is not an Ed25519 SPKI")?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&raw)
                .map_err(|_| "public key is not an Ed25519 point")?;
            let signature = ed25519_dalek::Signature::from_slice(&signature)
                .map_err(|_| "signature is not an Ed25519 signature")?;
            key.verify_strict(&signed, &signature)
                .map_err(|_| "signature does not verify")?;
        }
        other => return Err(format!("algorithm {other} is not enrolled for approvals")),
    }
    Ok(count)
}

/// Where an assertion comes from: the platform bridge that shows Trusted UI and asks the
/// authenticator. `None` is a timeout or a cancel.
pub trait AssertionSource {
    fn assert(&self, request: &ApprovalRequest, challenge: &[u8; 32]) -> Option<Assertion>;
}

/// The R9w channel: every decision is a verified assertion, everything else denies.
pub struct WebAuthnApproval<S: AssertionSource> {
    enrollment: std::sync::Mutex<Enrollment>,
    source: S,
}

impl<S: AssertionSource> WebAuthnApproval<S> {
    pub fn new(enrollment: Enrollment, source: S) -> Self {
        Self {
            enrollment: std::sync::Mutex::new(enrollment),
            source,
        }
    }

    /// The enrollment with the counter of the last approval (to persist).
    pub fn enrollment(&self) -> Enrollment {
        self.enrollment.lock().expect("enrollment").clone()
    }
}

impl<S: AssertionSource> ApprovalChannel for WebAuthnApproval<S> {
    fn decide(&self, request: &ApprovalRequest, now: &str) -> ApprovalDecision {
        let deny = |actor: &str| ApprovalDecision {
            granted: false,
            actor: actor.into(),
            at: now.into(),
        };
        let Some(assertion) = self.source.assert(request, &challenge(request)) else {
            return deny("timeout");
        };
        let mut enrollment = self.enrollment.lock().expect("enrollment");
        match verify(&enrollment, request, &assertion) {
            Ok(count) => {
                enrollment.sign_count = count;
                ApprovalDecision {
                    granted: true,
                    // R9w Audit: channel, credential and counter.
                    actor: format!("{CHANNEL}:{}#{count}", enrollment.credential_id),
                    at: now.into(),
                }
            }
            Err(_) => deny("invalid webauthn assertion"),
        }
    }

    fn attestation(&self) -> Option<&str> {
        Some("authenticator")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;

    const RP: &str = "vaikor.local";
    const ORIGIN: &str = "https://vaikor.local";

    fn request() -> ApprovalRequest {
        let mut request = ApprovalRequest::new(
            "plan-digest",
            "t1_send",
            "tag:vaikor.com,2026:capability:message.send",
            &json!({"to": "Marco"}),
        )
        .unwrap();
        request.nonce = "00".repeat(32);
        request
    }

    fn hex_bytes(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    struct Authenticator {
        key: p256::ecdsa::SigningKey,
    }

    impl Authenticator {
        fn new() -> Self {
            Self {
                key: p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap(),
            }
        }

        fn enrollment(&self) -> Enrollment {
            // P-256 SubjectPublicKeyInfo: fixed DER header, then the uncompressed point.
            let mut spki = hex_bytes("3059301306072a8648ce3d020106082a8648ce3d030107034200");
            spki.extend_from_slice(self.key.verifying_key().to_encoded_point(false).as_bytes());
            Enrollment {
                credential_id: "cred-1".into(),
                alg: "ES256".into(),
                public_key: URL_SAFE_NO_PAD.encode(&spki),
                rp_id: RP.into(),
                origins: vec![ORIGIN.into()],
                sign_count: 4,
            }
        }

        fn sign(
            &self,
            challenge: &[u8],
            rp: &str,
            origin: &str,
            flags: u8,
            count: u32,
        ) -> Assertion {
            let client = json!({
                "type": "webauthn.get",
                "challenge": URL_SAFE_NO_PAD.encode(challenge),
                "origin": origin,
            })
            .to_string();
            let mut auth = Sha256::digest(rp.as_bytes()).to_vec();
            auth.push(flags);
            auth.extend_from_slice(&count.to_be_bytes());
            let mut signed = auth.clone();
            signed.extend_from_slice(&Sha256::digest(client.as_bytes()));
            let signature: p256::ecdsa::Signature = self.key.sign(&signed);
            Assertion {
                credential_id: "cred-1".into(),
                client_data_json: URL_SAFE_NO_PAD.encode(client.as_bytes()),
                authenticator_data: URL_SAFE_NO_PAD.encode(&auth),
                signature: URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
            }
        }
    }

    #[test]
    fn a_user_verified_assertion_over_the_binding_approves() {
        let device = Authenticator::new();
        let request = request();
        let assertion = device.sign(&challenge(&request), RP, ORIGIN, 0x05, 5);
        assert_eq!(verify(&device.enrollment(), &request, &assertion), Ok(5));
    }

    #[test]
    fn every_binding_flag_origin_and_counter_failure_denies() {
        let device = Authenticator::new();
        let enrollment = device.enrollment();
        let request = request();
        let good = challenge(&request);
        let mut other = request.clone();
        other.args_digest = "different".into();
        let cases = [
            (
                "another request",
                device.sign(&challenge(&other), RP, ORIGIN, 0x05, 5),
            ),
            ("another nonce", {
                let mut replay = request.clone();
                replay.nonce = "11".repeat(32);
                device.sign(&challenge(&replay), RP, ORIGIN, 0x05, 5)
            }),
            (
                "another relying party",
                device.sign(&good, "evil.example", ORIGIN, 0x05, 5),
            ),
            (
                "another origin",
                device.sign(&good, RP, "https://evil.example", 0x05, 5),
            ),
            ("user present only", device.sign(&good, RP, ORIGIN, 0x01, 5)),
            ("no user present", device.sign(&good, RP, ORIGIN, 0x04, 5)),
            ("counter replay", device.sign(&good, RP, ORIGIN, 0x05, 4)),
        ];
        for (what, assertion) in cases {
            assert!(verify(&enrollment, &request, &assertion).is_err(), "{what}");
        }
        let mut tampered = device.sign(&good, RP, ORIGIN, 0x05, 5);
        tampered.authenticator_data = device.sign(&good, RP, ORIGIN, 0x05, 6).authenticator_data;
        assert!(
            verify(&enrollment, &request, &tampered).is_err(),
            "signature over other data"
        );
        let mut foreign = device.sign(&good, RP, ORIGIN, 0x05, 5);
        foreign.credential_id = "cred-2".into();
        assert!(
            verify(&enrollment, &request, &foreign).is_err(),
            "other credential"
        );
        let impostor = Authenticator {
            key: p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap(),
        };
        let forged = impostor.sign(&good, RP, ORIGIN, 0x05, 5);
        assert!(verify(&enrollment, &request, &forged).is_err(), "other key");
    }

    #[test]
    fn the_channel_approves_once_and_a_replay_of_the_same_assertion_denies() {
        struct Replaying(Assertion);
        impl AssertionSource for Replaying {
            fn assert(&self, _: &ApprovalRequest, _: &[u8; 32]) -> Option<Assertion> {
                Some(self.0.clone())
            }
        }
        let device = Authenticator::new();
        let request = request();
        let assertion = device.sign(&challenge(&request), RP, ORIGIN, 0x05, 5);
        let channel = WebAuthnApproval::new(device.enrollment(), Replaying(assertion));
        assert!(channel.decide(&request, "2026-10-22T08:00:00Z").granted);
        assert_eq!(channel.enrollment().sign_count, 5);
        // The same assertion again: the counter no longer increases.
        assert!(!channel.decide(&request, "2026-10-22T08:00:01Z").granted);
        struct Cancelled;
        impl AssertionSource for Cancelled {
            fn assert(&self, _: &ApprovalRequest, _: &[u8; 32]) -> Option<Assertion> {
                None
            }
        }
        let channel = WebAuthnApproval::new(device.enrollment(), Cancelled);
        let decision = channel.decide(&request, "2026-10-22T08:00:02Z");
        assert!(!decision.granted);
        assert_eq!(decision.actor, "timeout");
    }

    #[test]
    fn an_ed25519_credential_verifies_too() {
        let seed = [3u8; 32];
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let mut spki = ED25519_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(key.verifying_key().as_bytes());
        let enrollment = Enrollment {
            credential_id: "cred-ed".into(),
            alg: "EdDSA".into(),
            public_key: URL_SAFE_NO_PAD.encode(&spki),
            rp_id: RP.into(),
            origins: vec![ORIGIN.into()],
            sign_count: 0,
        };
        let request = request();
        let client = json!({"type": "webauthn.get", "challenge": URL_SAFE_NO_PAD.encode(challenge(&request)), "origin": ORIGIN}).to_string();
        let mut auth = Sha256::digest(RP.as_bytes()).to_vec();
        auth.push(0x05);
        auth.extend_from_slice(&0u32.to_be_bytes());
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(client.as_bytes()));
        use ed25519_dalek::Signer as _;
        let assertion = Assertion {
            credential_id: "cred-ed".into(),
            client_data_json: URL_SAFE_NO_PAD.encode(client.as_bytes()),
            authenticator_data: URL_SAFE_NO_PAD.encode(&auth),
            signature: URL_SAFE_NO_PAD.encode(key.sign(&signed).to_bytes()),
        };
        // Counter 0 on both sides is allowed (authenticators without a counter).
        assert_eq!(verify(&enrollment, &request, &assertion), Ok(0));
    }
}
