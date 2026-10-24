// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Native Sidged Adapter Contract (`SidgedAdapter`) & `LocalWorkspaceAdapter` (WP 4).
//! Experimental (feature `experimental`, ROADMAP v0.5): a v0.1 prototype with its own
//! authorization path, outside the one engine until v0.5 rebuilds it there.
//!
//! Unlike untrusted MCP annotations, every `SidgedAdapter`:
//! 1. Authenticates callers via mutual `did:key` Ed25519 signatures over canonical dCBOR (`0012`).
//! 2. Verifies an attenuated capability grant (`0002`) bound to the adapter's `did:key`.
//! 3. Emits every result as a signed `sidged_record::Record` with mandatory `class` and `residency`.

use std::io::{Read as _, Write as _};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sidged_core::valid_residency_tag;
use sidged_grant::{accept_presented, did_key, jwk_thumbprint, resolve_did_key, sign, verify};
use sidged_log::public_key;
use sidged_record::{
    artifact::{ArtifactPayload, CodeArtifact, CodeFileEntry},
    Record,
};

use crate::contained::Dir;

pub const CAP_WORKSPACE_READ: &str = "urn:sidged:capability:workspace.read";
pub const CAP_WORKSPACE_WRITE: &str = "urn:sidged:capability:workspace.write";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterRequestEnvelope {
    pub v: String,
    pub request_id: String,
    pub sender_did: String,
    pub adapter_did: String,
    pub capability: String,
    pub issued_at: String,
    pub residency: Vec<String>,
    pub data_classes: Vec<String>,
    pub args: Value,
    pub grant: Value,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterResponseEnvelope {
    pub v: String,
    pub request_id: String,
    pub adapter_did: String,
    pub status: String,
    pub data_classes: Vec<String>,
    pub residency: Vec<String>,
    pub record_dcbor: Vec<u8>,
    pub sig: String,
}

pub trait SidgedAdapter {
    fn adapter_did(&self) -> &str;
    fn supported_capabilities(&self) -> &[&'static str];
    fn invoke(
        &mut self,
        envelope_dcbor: &[u8],
        trusted_owner_keys: &[String],
    ) -> Result<Vec<u8>, String>;
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

fn sign_dcbor_domain(seed: &[u8; 32], domain: &[u8], payload: &Value) -> Result<String, String> {
    let dcbor = sidged_record::encode(payload).map_err(|e| e.to_string())?;
    let mut msg = Vec::with_capacity(domain.len() + dcbor.len());
    msg.extend_from_slice(domain);
    msg.extend_from_slice(&dcbor);
    Ok(hex_encode(&sign(seed, &msg)))
}

fn verify_dcbor_domain(
    signer_did: &str,
    domain: &[u8],
    payload: &Value,
    sig_hex: &str,
) -> Result<(), String> {
    let pubkey = resolve_did_key(signer_did)?;
    let sig = hex_decode64(sig_hex)?;
    let dcbor = sidged_record::encode(payload).map_err(|e| e.to_string())?;
    let mut msg = Vec::with_capacity(domain.len() + dcbor.len());
    msg.extend_from_slice(domain);
    msg.extend_from_slice(&dcbor);
    if !verify(&pubkey, &msg, &sig) {
        return Err(format!("invalid dCBOR adapter signature from {signer_did}"));
    }
    Ok(())
}

/// Build and sign a canonical dCBOR `AdapterRequestEnvelope`.
#[allow(clippy::too_many_arguments)]
pub fn create_adapter_request_dcbor(
    request_id: &str,
    sender_seed: &[u8; 32],
    adapter_did: &str,
    capability: &str,
    issued_at: &str,
    residency: Vec<String>,
    data_classes: Vec<String>,
    args: Value,
    grant: Value,
) -> Result<Vec<u8>, String> {
    if residency.is_empty() || !residency.iter().all(|t| valid_residency_tag(t)) {
        return Err("adapter request requires valid residency tags".into());
    }
    if data_classes.is_empty() {
        return Err("adapter request requires explicit data_classes".into());
    }
    let sender_did = did_key(&public_key(sender_seed));
    let unsigned = json!({
        "v": "0.1",
        "request_id": request_id,
        "sender_did": sender_did,
        "adapter_did": adapter_did,
        "capability": capability,
        "issued_at": issued_at,
        "residency": residency,
        "data_classes": data_classes,
        "args": args,
        "grant": grant,
    });
    let sig = sign_dcbor_domain(sender_seed, b"sdg.adapter.req/v0\0", &unsigned)?;
    let env = AdapterRequestEnvelope {
        v: "0.1".into(),
        request_id: request_id.into(),
        sender_did,
        adapter_did: adapter_did.into(),
        capability: capability.into(),
        issued_at: issued_at.into(),
        residency,
        data_classes,
        args,
        grant,
        sig,
    };
    let val = serde_json::to_value(&env).map_err(|e| e.to_string())?;
    sidged_record::encode(&val).map_err(|e| e.to_string())
}

/// Verify an `AdapterResponseEnvelope` encoded as canonical dCBOR and extract the signed `Record`.
pub fn verify_adapter_response_dcbor(
    response_dcbor: &[u8],
    expected_adapter_did: &str,
    trusted_core_keys: &[String],
) -> Result<(AdapterResponseEnvelope, Record), String> {
    let val = sidged_record::decode(response_dcbor).map_err(|e| e.to_string())?;
    let resp: AdapterResponseEnvelope = serde_json::from_value(val).map_err(|e| e.to_string())?;
    if resp.v != "0.1" || resp.adapter_did != expected_adapter_did {
        return Err("adapter response DID or version mismatch".into());
    }
    if resp.data_classes.is_empty()
        || resp.residency.is_empty()
        || !resp.residency.iter().all(|t| valid_residency_tag(t))
    {
        return Err("adapter response missing mandatory data_classes or residency".into());
    }
    let unsigned = json!({
        "v": resp.v,
        "request_id": resp.request_id,
        "adapter_did": resp.adapter_did,
        "status": resp.status,
        "data_classes": resp.data_classes,
        "residency": resp.residency,
        "record_dcbor": resp.record_dcbor,
    });
    verify_dcbor_domain(
        &resp.adapter_did,
        b"sdg.adapter.resp/v0\0",
        &unsigned,
        &resp.sig,
    )?;
    let rec_val = sidged_record::decode(&resp.record_dcbor).map_err(|e| e.to_string())?;
    let mut anchors = trusted_core_keys.to_vec();
    if !anchors.iter().any(|k| k == &resp.adapter_did) {
        anchors.push(resp.adapter_did.clone());
    }
    let record = Record::check(rec_val, &anchors).map_err(|e| e.to_string())?;
    Ok((resp, record))
}

/// Sandboxed Local Workspace Adapter (`LocalWorkspaceAdapter`) for reading and writing
/// project/code files as typed `documents.text` records with residency enforcement.
pub struct LocalWorkspaceAdapter {
    workspace_root: Dir,
    adapter_seed: [u8; 32],
    adapter_did: String,
    owner_did: String,
}

impl LocalWorkspaceAdapter {
    pub fn new(
        workspace_root: PathBuf,
        adapter_seed: [u8; 32],
        owner_did: String,
    ) -> Result<Self, String> {
        if !workspace_root.is_absolute() {
            return Err("workspace_root must be an absolute path".into());
        }
        // Opened once; every file operation resolves beneath this handle.
        let workspace_root = Dir::open_root(&workspace_root)?;
        let adapter_did = did_key(&public_key(&adapter_seed));
        Ok(Self {
            workspace_root,
            adapter_seed,
            adapter_did,
            owner_did,
        })
    }
}

impl SidgedAdapter for LocalWorkspaceAdapter {
    fn adapter_did(&self) -> &str {
        &self.adapter_did
    }

    fn supported_capabilities(&self) -> &[&'static str] {
        &[CAP_WORKSPACE_READ, CAP_WORKSPACE_WRITE]
    }

    fn invoke(
        &mut self,
        envelope_dcbor: &[u8],
        trusted_owner_keys: &[String],
    ) -> Result<Vec<u8>, String> {
        let val = sidged_record::decode(envelope_dcbor).map_err(|e| e.to_string())?;
        let req: AdapterRequestEnvelope = serde_json::from_value(val).map_err(|e| e.to_string())?;
        if req.v != "0.1" || req.adapter_did != self.adapter_did {
            return Err("adapter request version or adapter_did mismatch".into());
        }
        if !self
            .supported_capabilities()
            .contains(&req.capability.as_str())
        {
            return Err(format!("unsupported adapter capability {}", req.capability));
        }
        if req.data_classes.is_empty()
            || req.residency.is_empty()
            || !req.residency.iter().all(|t| valid_residency_tag(t))
        {
            return Err("adapter request missing mandatory data_classes or valid residency".into());
        }
        let unsigned_req = json!({
            "v": req.v,
            "request_id": req.request_id,
            "sender_did": req.sender_did,
            "adapter_did": req.adapter_did,
            "capability": req.capability,
            "issued_at": req.issued_at,
            "residency": req.residency,
            "data_classes": req.data_classes,
            "args": req.args,
            "grant": req.grant,
        });
        verify_dcbor_domain(
            &req.sender_did,
            b"sdg.adapter.req/v0\0",
            &unsigned_req,
            &req.sig,
        )?;

        // Verify capability grant bound to this adapter's did:key (`aud`) and sender's key (`cnf.jkt`).
        let sender_pub = resolve_did_key(&req.sender_did)?;
        let sender_jkt = jwk_thumbprint(&sender_pub);
        let trusted_refs: Vec<&str> = trusted_owner_keys.iter().map(String::as_str).collect();
        let token = accept_presented(&req.grant, &req.issued_at, &trusted_refs)
            .map_err(|e| format!("adapter grant check failed: {e:?}"))?;
        if token.link.aud != self.adapter_did || token.link.cnf.jkt != Some(sender_jkt) {
            return Err("adapter grant audience or sender cnf.jkt mismatch".into());
        }

        let rel_path = req.args["path"]
            .as_str()
            .ok_or("workspace adapter requires args.path string")?;

        let record = match req.capability.as_str() {
            CAP_WORKSPACE_READ => {
                let mut content = String::new();
                self.workspace_root
                    .open_read(rel_path)?
                    .read_to_string(&mut content)
                    .map_err(|e| format!("workspace.read {}: {}", rel_path, e.kind()))?;
                let payload = ArtifactPayload::Code(CodeArtifact {
                    files: vec![CodeFileEntry {
                        path: rel_path.into(),
                        diff: "read".into(),
                        content,
                    }],
                    test_summary: "workspace.read verified".into(),
                });
                sidged_record::artifact::sign_artifact_record(
                    &payload,
                    &self.owner_did,
                    CAP_WORKSPACE_READ,
                    &req.issued_at,
                    vec![],
                    None,
                    req.residency.clone(),
                    &self.adapter_seed,
                )
                .map_err(|e| e.to_string())?
            }
            CAP_WORKSPACE_WRITE => {
                let content = req.args["content"]
                    .as_str()
                    .ok_or("workspace.write requires args.content string")?;
                self.workspace_root
                    .open_write(rel_path, false)?
                    .write_all(content.as_bytes())
                    .map_err(|e| e.to_string())?;
                let payload = ArtifactPayload::Code(CodeArtifact {
                    files: vec![CodeFileEntry {
                        path: rel_path.into(),
                        diff: format!("+{} bytes", content.len()),
                        content: content.into(),
                    }],
                    test_summary: "workspace.write committed".into(),
                });
                sidged_record::artifact::sign_artifact_record(
                    &payload,
                    &self.owner_did,
                    CAP_WORKSPACE_WRITE,
                    &req.issued_at,
                    vec![],
                    None,
                    req.residency.clone(),
                    &self.adapter_seed,
                )
                .map_err(|e| e.to_string())?
            }
            _ => unreachable!(),
        };

        let record_dcbor = record.canonical_bytes().map_err(|e| e.to_string())?;
        let out_classes = vec!["documents.text".to_string()];
        let unsigned_resp = json!({
            "v": "0.1",
            "request_id": req.request_id,
            "adapter_did": self.adapter_did,
            "status": "ok",
            "data_classes": out_classes,
            "residency": req.residency,
            "record_dcbor": record_dcbor,
        });
        let sig = sign_dcbor_domain(&self.adapter_seed, b"sdg.adapter.resp/v0\0", &unsigned_resp)?;
        let resp = AdapterResponseEnvelope {
            v: "0.1".into(),
            request_id: req.request_id,
            adapter_did: self.adapter_did.clone(),
            status: "ok".into(),
            data_classes: out_classes,
            residency: req.residency,
            record_dcbor,
            sig,
        };
        let resp_val = serde_json::to_value(&resp).map_err(|e| e.to_string())?;
        sidged_record::encode(&resp_val).map_err(|e| e.to_string())
    }
}
