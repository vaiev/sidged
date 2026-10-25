// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Swarm mode (Spec 0015 S1-S16, 0006 R2/R4): edges of one owner.
//! Experimental (feature `experimental`, ROADMAP v0.5): a v0.1 prototype with its own
//! authorization path, outside the one engine until v0.5 rebuilds it there.
//!
//! Edge 1 holds the owner's state and Trusted UI channel. Edges 2..n are
//! instances of the same signed `vaikor` core image, each with its own device
//! key (`did:key`) and hash-chained audit log.
//!
//! Invariants enforced:
//! - S1/S2: Distinct device keys (`did:key`), no RFC 8032 test keys or shared keys;
//!   enrolled image/binary digest (`sha256:<64-hex>`) verified at enrollment and dispatch.
//! - S4/S5: Joining an edge requires human approval on Edge 1's Trusted UI channel
//!   (0004 R9) and issues an attenuated capability grant (0002) bound to the edge's `did:key`.
//! - S6: Mutual `did:key` Ed25519 challenge-response handshake before any message or
//!   online status.
//! - S7/S8: Every delegated task is a signed capability envelope carrying the grant,
//!   checked against the receiver's Cedar policy (default-deny), and appended to both
//!   Edge 1's and Edge 2's hash-chained audit logs before any effect.
//! - S9: Edges 2..n have no Trusted UI channel and MUST deny consequential steps.
//! - S10: Delegated payloads preserve their data classes and residency tags.
//! - S11: Drift (digest mismatch, `did:key` mismatch, audit chain verification failure,
//!   or measurement refusal) automatically revokes the edge and audits the revocation.
//! - S14: In local mode (`VAIKOR_LOCAL=1`), the mesh is off (no bind, no listen, no connect).

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vaikor_capability::Registry;
use vaikor_core::{valid_residency_tag, AuditEvent};
use vaikor_grant::{
    accept_presented, attach_signature, authorise, canonicalize, did_key, jwk_thumbprint,
    parse_rfc3339_z, resolve_did_key, sign, spend_step, verify, CedarEvaluator, Request,
};
use vaikor_log::{public_key, verify_file, Chain};

use crate::approval::{ApprovalChannel, ApprovalRequest};

pub const ENROLL_CAPABILITY: &str = "tag:vaikor.com,2026:capability:swarm.enroll";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrolledEdge {
    pub edge_id: String,
    pub did: String,
    pub image_digest: String,
    pub enrolled_at: String,
    pub grant: serde_json::Value,
    pub revoked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SwarmState {
    pub owner_did: String,
    pub edge1_did: String,
    pub image_digest: String,
    pub edges: BTreeMap<String, EnrolledEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedEnvelope {
    pub v: String,
    pub id: String,
    pub kind: String,
    pub sender: String,
    pub audience: String,
    pub issued_at: String,
    pub expires_at: String,
    pub capability: String,
    pub residency: Vec<String>,
    pub data_classes: Vec<String>,
    pub args: serde_json::Value,
    pub grant: serde_json::Value,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeasurementReport {
    pub edge_did: String,
    pub image_digest: String,
    pub audit_entries: usize,
    pub audit_ok: bool,
    pub nonce: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvelopeReply {
    pub envelope_id: String,
    pub edge_did: String,
    pub status: String,
    pub output: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub sig: String,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode64(text: &str) -> Result<[u8; 64], String> {
    if text.len() != 128 || !text.is_ascii() {
        return Err("expected 128 hex chars".into());
    }
    let mut out = [0u8; 64];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn valid_image_digest(digest: &str) -> bool {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

fn ensure_not_local(local: bool) -> Result<(), String> {
    if local || vaikor_gateway::is_local() {
        return Err("swarm mesh is off in local mode (0015 S14, 0007 R2)".into());
    }
    Ok(())
}

fn sign_json_domain(
    seed: &[u8; 32],
    domain: &[u8],
    payload: &serde_json::Value,
) -> Result<String, String> {
    let canonical = canonicalize(payload);
    let mut msg = Vec::with_capacity(domain.len() + canonical.len());
    msg.extend_from_slice(domain);
    msg.extend_from_slice(canonical.as_bytes());
    Ok(hex_encode(&sign(seed, &msg)))
}

fn verify_json_domain(
    did: &str,
    domain: &[u8],
    payload: &serde_json::Value,
    sig_hex: &str,
) -> Result<(), String> {
    let pubkey = resolve_did_key(did)?;
    let sig = hex_decode64(sig_hex)?;
    let canonical = canonicalize(payload);
    let mut msg = Vec::with_capacity(domain.len() + canonical.len());
    msg.extend_from_slice(domain);
    msg.extend_from_slice(canonical.as_bytes());
    if !verify(&pubkey, &msg, &sig) {
        return Err(format!("invalid signature from {did}"));
    }
    Ok(())
}

/// Enroll an edge (S1, S2, S4, S5): requires owner approval on Edge 1's Trusted UI channel,
/// verifies the image digest matches Edge 1, refuses shared or placeholder keys, and issues
/// an attenuated grant bound to `edge_did`.
#[allow(clippy::too_many_arguments)]
pub fn enroll_edge(
    state: &mut SwarmState,
    edge_id: &str,
    edge_did: &str,
    edge_image_digest: &str,
    capabilities: &[String],
    max_uses: u32,
    issued_at: &str,
    expires_at: &str,
    owner_seed: &[u8; 32],
    approval: &dyn ApprovalChannel,
    chain: &mut Chain,
    local: bool,
) -> Result<EnrolledEdge, String> {
    ensure_not_local(local)?;
    if !valid_image_digest(&state.image_digest) || !valid_image_digest(edge_image_digest) {
        return Err("image digest must be sha256:<64-hex> (0015 S1)".into());
    }
    if edge_image_digest != state.image_digest {
        return Err(format!(
            "edge image digest {edge_image_digest} does not match Edge 1 digest {} (0015 S1)",
            state.image_digest
        ));
    }
    let edge_pub = resolve_did_key(edge_did)?;
    let edge_pub_hex = hex_encode(&edge_pub);
    if [
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
    ]
    .contains(&edge_pub_hex.as_str())
    {
        return Err("RFC 8032 test keys are forbidden for swarm edges (0015 S2)".into());
    }
    let owner_pub = public_key(owner_seed);
    let owner_did = did_key(&owner_pub);
    if edge_did == owner_did || edge_did == state.edge1_did {
        return Err("edge did:key must be distinct from owner and Edge 1 (0015 S2)".into());
    }
    if state
        .edges
        .values()
        .any(|e| e.did == edge_did && e.edge_id != edge_id)
    {
        return Err("edge did:key is already enrolled on another edge (0015 S2)".into());
    }
    if capabilities.is_empty() || max_uses == 0 {
        return Err(
            "enrollment requires at least one delegated capability and max_uses > 0 (0015 S5)"
                .into(),
        );
    }
    let enroll_args = serde_json::json!({
        "edge_id": edge_id,
        "edge_did": edge_did,
        "image_digest": edge_image_digest,
        "capabilities": capabilities,
        "max_uses": max_uses,
        "expires_at": expires_at,
    });
    let plan_digest = format!(
        "sha256:{}",
        hex_encode(&Sha256::digest(canonicalize(&enroll_args).as_bytes()))
    );
    let req = ApprovalRequest::new(
        &plan_digest,
        &format!("enroll-{edge_id}"),
        ENROLL_CAPABILITY,
        &enroll_args,
    )?;
    let decision = approval.decide(&req, issued_at);
    if decision.granted {
        chain.append(&AuditEvent {
            privacy_report: None,
            usage: None,
            reason: Some(format!("enrolled {edge_did} image={edge_image_digest}")),
            step: format!("enroll-{edge_id}"),
            capability: ENROLL_CAPABILITY.into(),
            effects: vec!["write".into()],
            data_classes: Vec::new(),
            decision: "allow".into(),
            actor: decision.actor,
            at: decision.at,
            approval: None,
        })?;
    } else {
        chain.append(&AuditEvent {
            privacy_report: None,
            usage: None,
            reason: Some("enrollment denied".into()),
            step: format!("enroll-{edge_id}"),
            capability: ENROLL_CAPABILITY.into(),
            effects: vec!["write".into()],
            data_classes: Vec::new(),
            decision: "deny".into(),
            actor: decision.actor,
            at: decision.at,
            approval: None,
        })?;
        return Err("edge enrollment denied (0015 S4)".into());
    }

    let rights: Vec<serde_json::Value> = capabilities
        .iter()
        .map(|cap| {
            serde_json::json!({
                "action": cap.strip_prefix("tag:vaikor.com,2026:capability:").unwrap_or(cap),
                "resource": cap,
                "constraints": {
                    "max_uses": max_uses
                }
            })
        })
        .collect();
    let edge1_pub = resolve_did_key(&state.edge1_did)?;
    let unsigned_grant = serde_json::json!({
        "v": "0.1",
        "jti": format!("tag:vaikor.com,2026:grant:swarm:{edge_id}:{issued_at}"),
        "iss": owner_did,
        "sub": state.edge1_did,
        "aud": edge_did,
        "iat": issued_at,
        "exp": expires_at,
        "cnf": {
            "kid": state.edge1_did,
            "jkt": jwk_thumbprint(&edge1_pub),
        },
        "rights": rights,
        "budget": {
            "messages": max_uses
        },
        "chain": []
    });
    let grant = attach_signature(&unsigned_grant, owner_seed, &owner_did);

    let enrolled = EnrolledEdge {
        edge_id: edge_id.into(),
        did: edge_did.into(),
        image_digest: edge_image_digest.into(),
        enrolled_at: issued_at.into(),
        grant,
        revoked: false,
        revoked_reason: None,
    };
    state.owner_did = owner_did;
    state.edges.insert(edge_id.into(), enrolled.clone());
    Ok(enrolled)
}

/// Sign a capability envelope on Edge 1 for an enrolled edge (S7, S10).
#[allow(clippy::too_many_arguments)]
pub fn create_envelope(
    edge1_seed: &[u8; 32],
    audience_did: &str,
    id: &str,
    capability: &str,
    residency: &[String],
    data_classes: &[String],
    args: serde_json::Value,
    grant: serde_json::Value,
    issued_at: &str,
    expires_at: &str,
) -> Result<SignedEnvelope, String> {
    if residency.is_empty() || !residency.iter().all(|t| valid_residency_tag(t)) {
        return Err("delegated envelope requires valid residency tags (0015 S10)".into());
    }
    let sender_pub = public_key(edge1_seed);
    let sender = did_key(&sender_pub);
    let unsigned = serde_json::json!({
        "v": "0.1",
        "id": id,
        "kind": "f2-action-request",
        "sender": sender,
        "audience": audience_did,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "capability": capability,
        "residency": residency,
        "data_classes": data_classes,
        "args": args,
        "grant": grant,
    });
    let sig = sign_json_domain(edge1_seed, b"vkr.envelope/v0\0", &unsigned)?;
    Ok(SignedEnvelope {
        v: "0.1".into(),
        id: id.into(),
        kind: "f2-action-request".into(),
        sender,
        audience: audience_did.into(),
        issued_at: issued_at.into(),
        expires_at: expires_at.into(),
        capability: capability.into(),
        residency: residency.to_vec(),
        data_classes: data_classes.to_vec(),
        args,
        grant,
        sig,
    })
}

/// Evaluate drift on a measurement report (S11). If drift is detected, marks the edge
/// as revoked and appends a revocation entry to Edge 1's audit chain.
pub fn check_drift(
    state: &mut SwarmState,
    edge_id: &str,
    report: Option<&MeasurementReport>,
    expected_nonce: &str,
    now: &str,
    chain: &mut Chain,
) -> Result<(), String> {
    let Some(edge) = state.edges.get_mut(edge_id) else {
        return Err(format!("unknown edge {edge_id}"));
    };
    if edge.revoked {
        return Err(format!("edge {edge_id} is already revoked"));
    }
    let drift_reason = match report {
        None => Some("measurement request refused or timed out".to_string()),
        Some(rep) => {
            let unsigned = serde_json::json!({
                "edge_did": rep.edge_did,
                "image_digest": rep.image_digest,
                "audit_entries": rep.audit_entries,
                "audit_ok": rep.audit_ok,
                "nonce": rep.nonce,
            });
            if rep.edge_did != edge.did {
                Some(format!(
                    "did:key mismatch: expected {}, got {}",
                    edge.did, rep.edge_did
                ))
            } else if rep.nonce != expected_nonce {
                Some("measurement nonce mismatch".to_string())
            } else if verify_json_domain(&edge.did, b"vkr.measure/v0\0", &unsigned, &rep.sig)
                .is_err()
            {
                Some("invalid measurement signature".to_string())
            } else if rep.image_digest != edge.image_digest
                || rep.image_digest != state.image_digest
            {
                Some(format!(
                    "image digest drift: enrolled {}, reported {}",
                    edge.image_digest, rep.image_digest
                ))
            } else if !rep.audit_ok {
                Some("edge audit chain verification failed".to_string())
            } else {
                None
            }
        }
    };
    if let Some(reason) = drift_reason {
        edge.revoked = true;
        edge.revoked_reason = Some(reason.clone());
        chain.append(&AuditEvent {
            privacy_report: None,
            usage: None,
            reason: Some(format!(
                "drift revocation edge={edge_id} did={}: {reason}",
                edge.did
            )),
            step: format!("drift-{edge_id}"),
            capability: "tag:vaikor.com,2026:capability:swarm.revoke".into(),
            effects: vec!["write".into()],
            data_classes: Vec::new(),
            decision: "revoke".into(),
            actor: "core".into(),
            at: now.into(),
            approval: None,
        })?;
        return Err(format!(
            "edge {edge_id} drifted and was revoked (0015 S11): {reason}"
        ));
    }
    Ok(())
}

/// Produce a signed measurement report on an edge (S11).
pub fn produce_measurement(
    edge_seed: &[u8; 32],
    image_digest: &str,
    log_path: &Path,
    nonce: &str,
) -> Result<MeasurementReport, String> {
    let pubkey = public_key(edge_seed);
    let edge_did = did_key(&pubkey);
    let (audit_entries, audit_ok) = match verify_file(log_path, &pubkey) {
        Ok(n) => (n, true),
        Err(_) => (0, false),
    };
    let unsigned = serde_json::json!({
        "edge_did": edge_did,
        "image_digest": image_digest,
        "audit_entries": audit_entries,
        "audit_ok": audit_ok,
        "nonce": nonce,
    });
    let sig = sign_json_domain(edge_seed, b"vkr.measure/v0\0", &unsigned)?;
    Ok(MeasurementReport {
        edge_did,
        image_digest: image_digest.into(),
        audit_entries,
        audit_ok,
        nonce: nonce.into(),
        sig,
    })
}

/// Handle a received signed capability envelope on Edge 2..n (S3, S6, S7, S8, S9, S10).
#[allow(clippy::too_many_arguments)]
pub fn handle_envelope_on_worker(
    edge_seed: &[u8; 32],
    enrolled_edge1_did: &str,
    owner_did: &str,
    envelope: &SignedEnvelope,
    registry: &Registry,
    cedar_policy: &str,
    chain: &mut Chain,
    now: &str,
    local: bool,
) -> Result<EnvelopeReply, String> {
    ensure_not_local(local)?;
    let edge_pub = public_key(edge_seed);
    let edge_did = did_key(&edge_pub);

    let audit_and_refuse = |chain: &mut Chain, reason: String| -> Result<EnvelopeReply, String> {
        chain.append(&AuditEvent {
            privacy_report: None,
            usage: None,
            reason: Some(reason.clone()),
            step: envelope.id.clone(),
            capability: envelope.capability.clone(),
            effects: Vec::new(),
            data_classes: envelope.data_classes.clone(),
            decision: "deny".into(),
            actor: "core".into(),
            at: now.into(),
            approval: None,
        })?;
        Err(reason)
    };

    if envelope.v != "0.1" || envelope.kind != "f2-action-request" {
        return audit_and_refuse(chain, "unsupported envelope version or kind".into());
    }
    if envelope.sender != enrolled_edge1_did {
        return audit_and_refuse(
            chain,
            format!("unrecognized peer sender {} (0015 S6)", envelope.sender),
        );
    }
    if envelope.audience != edge_did {
        return audit_and_refuse(
            chain,
            format!(
                "envelope audience {} does not match worker {edge_did}",
                envelope.audience
            ),
        );
    }
    let unsigned = serde_json::json!({
        "v": envelope.v,
        "id": envelope.id,
        "kind": envelope.kind,
        "sender": envelope.sender,
        "audience": envelope.audience,
        "issued_at": envelope.issued_at,
        "expires_at": envelope.expires_at,
        "capability": envelope.capability,
        "residency": envelope.residency,
        "data_classes": envelope.data_classes,
        "args": envelope.args,
        "grant": envelope.grant,
    });
    if let Err(e) = verify_json_domain(
        &envelope.sender,
        b"vkr.envelope/v0\0",
        &unsigned,
        &envelope.sig,
    ) {
        return audit_and_refuse(
            chain,
            format!("envelope signature verification failed: {e} (0015 S7)"),
        );
    }
    let now_s = parse_rfc3339_z(now).ok_or("invalid worker timestamp")?;
    let iat_s = parse_rfc3339_z(&envelope.issued_at).ok_or("invalid envelope issued_at")?;
    let exp_s = parse_rfc3339_z(&envelope.expires_at).ok_or("invalid envelope expires_at")?;
    if exp_s <= iat_s || now_s > exp_s {
        return audit_and_refuse(chain, "envelope is expired".into());
    }
    if envelope.residency.is_empty() || !envelope.residency.iter().all(|t| valid_residency_tag(t)) {
        return audit_and_refuse(
            chain,
            "envelope missing or invalid residency tags (0015 S10)".into(),
        );
    }
    let Some(descriptor) = registry.get(&envelope.capability) else {
        return audit_and_refuse(chain, format!("unknown capability {}", envelope.capability));
    };
    // S9: An edge without a Trusted UI channel MUST deny consequential steps.
    if descriptor.consequential {
        return audit_and_refuse(
            chain,
            "worker edge has no Trusted UI channel and must deny consequential steps (0015 S9)"
                .into(),
        );
    }

    let trusted = [owner_did];
    let mut token = match accept_presented(&envelope.grant, now, &trusted) {
        Ok(t) => t,
        Err(e) => {
            return audit_and_refuse(chain, format!("grant check failed: {e:?} (0015 S5/S7)"))
        }
    };
    let action = envelope
        .capability
        .strip_prefix("tag:vaikor.com,2026:capability:")
        .unwrap_or(&envelope.capability)
        .to_string();
    let evaluator = match CedarEvaluator::parse(cedar_policy) {
        Ok(ev) => ev,
        Err(e) => return audit_and_refuse(chain, format!("Cedar policy parse error: {e}")),
    };
    let class_refs: Vec<&str> = envelope.data_classes.iter().map(String::as_str).collect();
    let res_refs: Vec<&str> = envelope.residency.iter().map(String::as_str).collect();
    let auth_req = Request {
        holder: &envelope.sender,
        audience: &edge_did,
        action: &action,
        resource: Some(&envelope.capability),
        data_classes: &class_refs,
        residency: &res_refs,
    };
    if let Err(e) = authorise(&token, &auth_req, Some(now), &evaluator) {
        return audit_and_refuse(
            chain,
            format!("denied by worker grant or Cedar policy: {e:?} (0015 S7)"),
        );
    }
    if let Err(e) = spend_step(&mut token.link.budget, None, 1) {
        return audit_and_refuse(chain, format!("grant budget exhausted: {e:?}"));
    }

    // S8: Audit received message and effect BEFORE executing.
    chain.append(&AuditEvent {
        privacy_report: None,
        usage: None,
        reason: Some(format!(
            "swarm envelope {} from {}",
            envelope.id, envelope.sender
        )),
        step: envelope.id.clone(),
        capability: envelope.capability.clone(),
        effects: descriptor.effects.clone(),
        data_classes: envelope.data_classes.clone(),
        decision: "allow".into(),
        actor: envelope.sender.clone(),
        at: now.into(),
        approval: None,
    })?;

    let output = serde_json::json!({
        "executed_by": edge_did,
        "capability": envelope.capability,
        "residency": envelope.residency,
        "args": envelope.args,
    });
    let reply_unsigned = serde_json::json!({
        "envelope_id": envelope.id,
        "edge_did": edge_did,
        "status": "ok",
        "output": output,
    });
    let sig = sign_json_domain(edge_seed, b"vkr.reply/v0\0", &reply_unsigned)?;
    Ok(EnvelopeReply {
        envelope_id: envelope.id.clone(),
        edge_did,
        status: "ok".into(),
        output,
        error: None,
        sig,
    })
}

/// Mutual `did:key` handshake + single-request dispatch over a Unix domain socket (S6, S7, S8).
#[allow(clippy::too_many_arguments)]
pub fn serve_worker_once(
    socket_path: &Path,
    edge_seed: &[u8; 32],
    enrolled_edge1_did: &str,
    owner_did: &str,
    image_digest: &str,
    log_path: &Path,
    registry: &Registry,
    cedar_policy: &str,
    now: &str,
    local: bool,
) -> Result<(), String> {
    ensure_not_local(local)?;
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path).map_err(|e| e.to_string())?;
    let (mut stream, _) = listener.accept().map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let edge_pub = public_key(edge_seed);
    let edge_did = did_key(&edge_pub);

    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    let hello: serde_json::Value = serde_json::from_str(line.trim()).map_err(|e| e.to_string())?;
    let peer_did = hello["did"].as_str().ok_or("missing peer did")?;
    let c1 = hello["nonce"].as_str().ok_or("missing challenge nonce")?;
    if peer_did != enrolled_edge1_did {
        return Err(format!(
            "refused peer {peer_did}: not enrolled Edge 1 (0015 S6)"
        ));
    }
    let c2 =
        hex_encode(&Sha256::digest(format!("{edge_did}:{now}:{c1}").as_bytes()))[..32].to_string();
    let s2_payload = serde_json::json!({
        "edge_did": edge_did,
        "peer_did": peer_did,
        "c1": c1,
        "c2": c2,
    });
    let sig2 = sign_json_domain(edge_seed, b"vkr.handshake/v0\0", &s2_payload)?;
    writeln!(
        stream,
        "{}",
        serde_json::json!({"did": edge_did, "c2": c2, "sig": sig2})
    )
    .map_err(|e| e.to_string())?;

    line.clear();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    let fin: serde_json::Value = serde_json::from_str(line.trim()).map_err(|e| e.to_string())?;
    let sig1 = fin["sig"]
        .as_str()
        .ok_or("missing peer handshake signature")?;
    let s1_payload = serde_json::json!({
        "edge_did": peer_did,
        "peer_did": edge_did,
        "c1": c1,
        "c2": c2,
    });
    verify_json_domain(peer_did, b"vkr.handshake/v0\0", &s1_payload, sig1)?;

    // Handshake completed! Now read the command frame ("measure" or "envelope").
    line.clear();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    let frame: serde_json::Value = serde_json::from_str(line.trim()).map_err(|e| e.to_string())?;
    match frame["op"].as_str() {
        Some("measure") => {
            let m_nonce = frame["nonce"].as_str().ok_or("missing measure nonce")?;
            let report = produce_measurement(edge_seed, image_digest, log_path, m_nonce)?;
            writeln!(stream, "{}", serde_json::to_string(&report).unwrap())
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        Some("envelope") => {
            let env: SignedEnvelope =
                serde_json::from_value(frame["envelope"].clone()).map_err(|e| e.to_string())?;
            let mut chain = Chain::open(log_path, edge_seed)?;
            match handle_envelope_on_worker(
                edge_seed,
                enrolled_edge1_did,
                owner_did,
                &env,
                registry,
                cedar_policy,
                &mut chain,
                now,
                local,
            ) {
                Ok(reply) => {
                    writeln!(stream, "{}", serde_json::to_string(&reply).unwrap())
                        .map_err(|e| e.to_string())?;
                    Ok(())
                }
                Err(err) => {
                    let reply_unsigned = serde_json::json!({
                        "envelope_id": env.id,
                        "edge_did": edge_did,
                        "status": "refused",
                        "output": serde_json::Value::Null,
                        "error": err,
                    });
                    let sig = sign_json_domain(edge_seed, b"vkr.reply/v0\0", &reply_unsigned)?;
                    let reply = EnvelopeReply {
                        envelope_id: env.id,
                        edge_did,
                        status: "refused".into(),
                        output: serde_json::Value::Null,
                        error: Some(err.clone()),
                        sig,
                    };
                    writeln!(stream, "{}", serde_json::to_string(&reply).unwrap())
                        .map_err(|e| e.to_string())?;
                    Err(err)
                }
            }
        }
        other => Err(format!("unknown swarm frame op {other:?}")),
    }
}

fn connect_and_handshake(
    socket_path: &Path,
    edge1_seed: &[u8; 32],
    expected_edge_did: &str,
    nonce: &str,
) -> Result<(UnixStream, BufReader<UnixStream>), String> {
    let mut stream = UnixStream::connect(socket_path).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let edge1_pub = public_key(edge1_seed);
    let edge1_did = did_key(&edge1_pub);
    writeln!(
        stream,
        "{}",
        serde_json::json!({"did": edge1_did, "nonce": nonce})
    )
    .map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    if line.trim().is_empty() {
        return Err("peer closed connection during handshake (0015 S6)".into());
    }
    let resp: serde_json::Value = serde_json::from_str(line.trim()).map_err(|e| e.to_string())?;
    let worker_did = resp["did"].as_str().ok_or("missing worker did")?;
    let c2 = resp["c2"].as_str().ok_or("missing worker challenge")?;
    let sig2 = resp["sig"].as_str().ok_or("missing worker signature")?;
    if worker_did != expected_edge_did {
        return Err(format!(
            "handshake did mismatch: expected {expected_edge_did}, got {worker_did} (0015 S6)"
        ));
    }
    let s2_payload = serde_json::json!({
        "edge_did": worker_did,
        "peer_did": edge1_did,
        "c1": nonce,
        "c2": c2,
    });
    verify_json_domain(worker_did, b"vkr.handshake/v0\0", &s2_payload, sig2)?;

    let s1_payload = serde_json::json!({
        "edge_did": edge1_did,
        "peer_did": worker_did,
        "c1": nonce,
        "c2": c2,
    });
    let sig1 = sign_json_domain(edge1_seed, b"vkr.handshake/v0\0", &s1_payload)?;
    writeln!(stream, "{}", serde_json::json!({"sig": sig1})).map_err(|e| e.to_string())?;
    Ok((stream, reader))
}

/// Dispatch a signed capability envelope from Edge 1 to an enrolled worker over the mesh socket (S6, S7, S8).
#[allow(clippy::too_many_arguments)]
pub fn dispatch_envelope(
    state: &SwarmState,
    edge_id: &str,
    socket_path: &Path,
    edge1_seed: &[u8; 32],
    envelope: &SignedEnvelope,
    chain: &mut Chain,
    now: &str,
    local: bool,
) -> Result<EnvelopeReply, String> {
    ensure_not_local(local)?;
    let Some(edge) = state.edges.get(edge_id) else {
        return Err(format!("edge {edge_id} is not enrolled (0015 S6)"));
    };
    if edge.revoked {
        return Err(format!(
            "edge {edge_id} is revoked and cannot receive work (0015 S6/S11)"
        ));
    }
    // S8: Sending edge MUST audit the send before effect.
    chain.append(&AuditEvent {
        privacy_report: None,
        usage: None,
        reason: Some(format!(
            "swarm send envelope {} to {}",
            envelope.id, edge.did
        )),
        step: envelope.id.clone(),
        capability: envelope.capability.clone(),
        effects: Vec::new(),
        data_classes: envelope.data_classes.clone(),
        decision: "allow".into(),
        actor: "core".into(),
        at: now.into(),
        approval: None,
    })?;

    let nonce =
        hex_encode(&Sha256::digest(format!("{}:{now}", envelope.id).as_bytes()))[..32].to_string();
    let (mut stream, mut reader) =
        connect_and_handshake(socket_path, edge1_seed, &edge.did, &nonce)?;
    writeln!(
        stream,
        "{}",
        serde_json::json!({"op": "envelope", "envelope": envelope})
    )
    .map_err(|e| e.to_string())?;
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    let reply: EnvelopeReply = serde_json::from_str(line.trim()).map_err(|e| e.to_string())?;
    let reply_unsigned = if let Some(err) = &reply.error {
        serde_json::json!({
            "envelope_id": reply.envelope_id,
            "edge_did": reply.edge_did,
            "status": reply.status,
            "output": reply.output,
            "error": err,
        })
    } else {
        serde_json::json!({
            "envelope_id": reply.envelope_id,
            "edge_did": reply.edge_did,
            "status": reply.status,
            "output": reply.output,
        })
    };
    verify_json_domain(&edge.did, b"vkr.reply/v0\0", &reply_unsigned, &reply.sig)?;
    if reply.status != "ok" {
        return Err(reply
            .error
            .unwrap_or_else(|| "worker refused envelope".into()));
    }
    Ok(reply)
}

/// Technocratic Swarm Self-Healing: verify a worker's proposed plan against the static
/// verifier (0003) and Cedar IFC flow policy (0013 §4). If the worker hallucinates an
/// unknown capability, CEL macro, unapproved consequential step, or forbidden data flow,
/// immediately revoke (cull) the faulty worker in `SwarmState`, record `swarm_worker_culled`
/// in Edge 1's signed audit chain, and enroll a fresh replacement worker instance.
#[allow(clippy::too_many_arguments)]
pub fn verify_worker_proposal_or_cull_and_replace(
    state: &mut SwarmState,
    faulty_edge_id: &str,
    proposed_plan: &serde_json::Value,
    catalog_json: &serde_json::Value,
    flow_policy: &vaikor_verify::flow::CedarFlowPolicy,
    replacement_edge_id: &str,
    replacement_did: &str,
    capabilities: &[String],
    max_uses: u32,
    now: &str,
    exp: &str,
    owner_seed: &[u8; 32],
    approver: &impl ApprovalChannel,
    chain: &mut Chain,
    local: bool,
) -> Result<Option<EnrolledEdge>, String> {
    ensure_not_local(local)?;
    let Some(edge) = state.edges.get(faulty_edge_id) else {
        return Err(format!("edge {faulty_edge_id} is not enrolled"));
    };
    if edge.revoked {
        return Err(format!("edge {faulty_edge_id} is already revoked"));
    }

    // 1. Check structural plan validity & catalog references via vaikor-verify::stored::catalog_digest
    //    and Spec 0013 §4 Cedar IFC flows.
    let mut fault_reason: Option<String> = None;
    if vaikor_verify::stored::catalog_digest(proposed_plan, catalog_json).is_err() {
        fault_reason = Some("hallucinated plan structure or unknown capability".into());
    } else if let Err(flow_err) = vaikor_verify::flow::check_json_plan_flows(
        proposed_plan,
        catalog_json,
        &state.owner_did,
        flow_policy,
    ) {
        fault_reason = Some(format!(
            "technocratic IFC violation: {} on step {} ({} -> {})",
            flow_err.reason, flow_err.step, flow_err.class, flow_err.capability
        ));
    }

    let Some(reason) = fault_reason else {
        return Ok(None);
    };

    // 2. Fault/hallucination detected: cull (revoke) the faulty worker and audit the event.
    let culled_did = if let Some(e) = state.edges.get_mut(faulty_edge_id) {
        e.revoked = true;
        e.did.clone()
    } else {
        String::new()
    };
    let cull_msg = format!(
        "swarm_worker_culled: edge {faulty_edge_id} ({culled_did}) revoked due to {reason}; replacing with {replacement_edge_id}"
    );
    chain.append(&AuditEvent {
        privacy_report: None,
        usage: None,
        reason: Some(cull_msg),
        step: format!("swarm.cull.{faulty_edge_id}"),
        capability: "tag:vaikor.com,2026:capability:swarm.cull".into(),
        effects: Vec::new(),
        data_classes: Vec::new(),
        decision: "deny".into(),
        actor: "core".into(),
        at: now.into(),
        approval: None,
    })?;

    // 3. Enroll clean replacement worker with a fresh cryptographic identity (`did:key`).
    let digest = state.image_digest.clone();
    let replacement = enroll_edge(
        state,
        replacement_edge_id,
        replacement_did,
        &digest,
        capabilities,
        max_uses,
        now,
        exp,
        owner_seed,
        approver,
        chain,
        local,
    )?;
    Ok(Some(replacement))
}

/// QR-Code / `swiyu` (OpenID4VP / Passkey) Pairing Invite generated by Edge 1 (0016).
/// Supports `"local-direct"`, `"cloud-to-local-e2ee"`, and `"local-to-web-to-local-e2ee"` tunnel modes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QrPairingInvite {
    pub v: String,
    pub kind: String,
    pub edge1_did: String,
    pub image_digest: String,
    pub challenge: String,
    pub tunnel_mode: String,
    pub issued_at: String,
    pub expires_at: String,
    pub sig: String,
}

/// Verifiable Presentation returned by the Android / Desktop Companion App after scanning
/// the QR invite (compatible with `did:key`, Passkey, and `swiyu-admin-ch` OpenID4VP holder binding).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiablePairingPresentation {
    pub v: String,
    pub format: String, // "vkr-didkey-vp" | "swiyu-sd-jwt-vc" | "webauthn-passkey"
    pub device_id: String,
    pub device_did: String,
    pub audience: String,
    pub challenge: String,
    pub tunnel_mode: String,
    pub issuer_attestation: Option<String>,
    pub presented_at: String,
    pub sig: String,
}

const ALLOWED_TUNNEL_MODES: &[&str] = &[
    "local-direct",
    "cloud-to-local-e2ee",
    "local-to-web-to-local-e2ee",
];

const ALLOWED_VP_FORMATS: &[&str] = &["vkr-didkey-vp", "swiyu-sd-jwt-vc", "webauthn-passkey"];

/// Generate a signed QR-code pairing invite (`QrPairingInvite` + `vkr://pair/v0?...` URI).
pub fn create_qr_pairing_invite(
    edge1_seed: &[u8; 32],
    image_digest: &str,
    challenge: &str,
    tunnel_mode: &str,
    issued_at: &str,
    expires_at: &str,
) -> Result<(QrPairingInvite, String), String> {
    let edge1_pub = public_key(edge1_seed);
    let edge1_pub_hex = hex_encode(&edge1_pub);
    if [
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
    ]
    .contains(&edge1_pub_hex.as_str())
    {
        return Err("RFC 8032 test keys are forbidden for pairing invites".into());
    }
    if !valid_image_digest(image_digest) {
        return Err("invalid image_digest for QR pairing invite".into());
    }
    if challenge.len() < 16 {
        return Err("QR pairing challenge must be at least 16 characters".into());
    }
    if !ALLOWED_TUNNEL_MODES.contains(&tunnel_mode) {
        return Err(format!("unsupported tunnel_mode {tunnel_mode}"));
    }
    let iat = parse_rfc3339_z(issued_at).ok_or("invalid issued_at timestamp")?;
    let exp = parse_rfc3339_z(expires_at).ok_or("invalid expires_at timestamp")?;
    if exp <= iat || exp - iat > 300 {
        return Err("QR pairing invite lifetime must be between 1 and 300 seconds".into());
    }
    let edge1_did = did_key(&edge1_pub);
    let unsigned = serde_json::json!({
        "v": "0.1",
        "kind": "vkr.qr.pair",
        "edge1_did": edge1_did,
        "image_digest": image_digest,
        "challenge": challenge,
        "tunnel_mode": tunnel_mode,
        "issued_at": issued_at,
        "expires_at": expires_at,
    });
    let sig = sign_json_domain(edge1_seed, b"vkr.qr.pair/v0\0", &unsigned)?;
    let invite = QrPairingInvite {
        v: "0.1".into(),
        kind: "vkr.qr.pair".into(),
        edge1_did,
        image_digest: image_digest.into(),
        challenge: challenge.into(),
        tunnel_mode: tunnel_mode.into(),
        issued_at: issued_at.into(),
        expires_at: expires_at.into(),
        sig,
    };
    let encoded = hex_encode(&serde_json::to_vec(&invite).map_err(|e| e.to_string())?);
    Ok((invite, format!("vkr://pair/v0?invite={encoded}")))
}

/// Verify a `VerifiablePairingPresentation` (from QR / Passkey / `swiyu-admin-ch` wallet/companion)
/// and enroll the mobile/desktop companion into `SwarmState` with an attenuated capability grant.
#[allow(clippy::too_many_arguments)]
pub fn verify_qr_or_swiyu_pairing(
    state: &mut SwarmState,
    invite: &QrPairingInvite,
    presentation: &VerifiablePairingPresentation,
    capabilities: &[String],
    max_uses: u32,
    grant_expires_at: &str,
    owner_seed: &[u8; 32],
    approver: &impl ApprovalChannel,
    chain: &mut Chain,
    local: bool,
) -> Result<EnrolledEdge, String> {
    ensure_not_local(local)?;
    if invite.edge1_did != state.edge1_did || invite.image_digest != state.image_digest {
        return Err("QR invite does not match this Edge 1 instance".into());
    }
    let unsigned_invite = serde_json::json!({
        "v": invite.v,
        "kind": invite.kind,
        "edge1_did": invite.edge1_did,
        "image_digest": invite.image_digest,
        "challenge": invite.challenge,
        "tunnel_mode": invite.tunnel_mode,
        "issued_at": invite.issued_at,
        "expires_at": invite.expires_at,
    });
    verify_json_domain(
        &state.edge1_did,
        b"vkr.qr.pair/v0\0",
        &unsigned_invite,
        &invite.sig,
    )?;

    if presentation.v != "0.1" || !ALLOWED_VP_FORMATS.contains(&presentation.format.as_str()) {
        return Err(format!(
            "unsupported pairing presentation format {}",
            presentation.format
        ));
    }
    if presentation.audience != state.edge1_did {
        return Err("pairing presentation audience mismatch (phishing/relay protection)".into());
    }
    if presentation.challenge != invite.challenge {
        return Err("pairing presentation challenge mismatch (replay protection)".into());
    }
    if presentation.tunnel_mode != invite.tunnel_mode {
        return Err("pairing presentation tunnel_mode mismatch".into());
    }
    let now_s = parse_rfc3339_z(&presentation.presented_at).ok_or("invalid presented_at")?;
    let iat_s = parse_rfc3339_z(&invite.issued_at).ok_or("invalid invite issued_at")?;
    let exp_s = parse_rfc3339_z(&invite.expires_at).ok_or("invalid invite expires_at")?;
    if now_s < iat_s || now_s >= exp_s {
        return Err("QR pairing invite has expired".into());
    }
    let unsigned_vp = serde_json::json!({
        "v": presentation.v,
        "format": presentation.format,
        "device_id": presentation.device_id,
        "device_did": presentation.device_did,
        "audience": presentation.audience,
        "challenge": presentation.challenge,
        "tunnel_mode": presentation.tunnel_mode,
        "issuer_attestation": presentation.issuer_attestation,
        "presented_at": presentation.presented_at,
    });
    verify_json_domain(
        &presentation.device_did,
        b"vkr.vp.pair/v0\0",
        &unsigned_vp,
        &presentation.sig,
    )?;

    enroll_edge(
        state,
        &presentation.device_id,
        &presentation.device_did,
        &state.image_digest.clone(),
        capabilities,
        max_uses,
        &presentation.presented_at,
        grant_expires_at,
        owner_seed,
        approver,
        chain,
        local,
    )
}
