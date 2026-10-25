// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Integration tests for Spec 0015 Swarm mode (S1-S16).

use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use vaikor_capability::Registry;
use vaikor_cli::swarm::{
    check_drift, create_envelope, dispatch_envelope, enroll_edge, produce_measurement,
    serve_worker_once, SwarmState,
};
use vaikor_cli::{ApprovalChannel, ApprovalDecision, ApprovalRequest};
use vaikor_grant::did_key;
use vaikor_log::{public_key, verify_file, Chain};

struct TestApprover {
    allow: bool,
}

impl ApprovalChannel for TestApprover {
    fn decide(&self, _request: &ApprovalRequest, now: &str) -> ApprovalDecision {
        ApprovalDecision {
            granted: self.allow,
            actor: "vaikor-approver".into(),
            at: now.into(),
        }
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vaikor-swarm-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

const IMAGE_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn test_registry() -> Registry {
    let raw = serde_json::json!([
        {
            "id": "tag:vaikor.com,2026:capability:worker.fetch",
            "version": "0.1.0",
            "effects": ["read"],
            "data_classes": ["x-public.web"],
            "residency": {"tags": ["unrestricted"]},
            "consequential": false,
            "cost": {"class": "free"}
        },
        {
            "id": "tag:vaikor.com,2026:capability:guard.moderate",
            "version": "0.1.0",
            "effects": ["write"],
            "data_classes": ["communications.content"],
            "residency": {"tags": ["CH"]},
            "consequential": true,
            "cost": {"class": "free"}
        }
    ]);
    Registry::from_descriptors(&raw).unwrap()
}

#[test]
fn s1_s2_s4_s5_enrollment_requires_approval_and_unique_non_rfc_keys() {
    let dir = scratch("enroll");
    let owner_seed = [0x11u8; 32];
    let edge1_seed = [0x22u8; 32];
    let edge2_seed = [0x33u8; 32];
    let owner_did = did_key(&public_key(&owner_seed));
    let edge1_did = did_key(&public_key(&edge1_seed));
    let edge2_did = did_key(&public_key(&edge2_seed));

    let mut state = SwarmState {
        owner_did: owner_did.clone(),
        edge1_did: edge1_did.clone(),
        image_digest: IMAGE_DIGEST.into(),
        edges: Default::default(),
    };
    let mut chain = Chain::open(&dir.join("edge1.log"), &edge1_seed).unwrap();

    // S1: mismatched image digest is refused.
    let err = enroll_edge(
        &mut state,
        "edge2",
        &edge2_did,
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        &["tag:vaikor.com,2026:capability:worker.fetch".into()],
        5,
        "2026-10-19T12:00:00Z",
        "2026-10-19T12:30:00Z",
        &owner_seed,
        &TestApprover { allow: true },
        &mut chain,
        false,
    )
    .unwrap_err();
    assert!(err.contains("0015 S1"), "{err}");

    // S2: Edge 1's own did:key is refused for Edge 2.
    let err = enroll_edge(
        &mut state,
        "edge2",
        &edge1_did,
        IMAGE_DIGEST,
        &["tag:vaikor.com,2026:capability:worker.fetch".into()],
        5,
        "2026-10-19T12:00:00Z",
        "2026-10-19T12:30:00Z",
        &owner_seed,
        &TestApprover { allow: true },
        &mut chain,
        false,
    )
    .unwrap_err();
    assert!(err.contains("0015 S2"), "{err}");

    // S4: Denied approval refuses enrollment and records denial in audit log.
    let err = enroll_edge(
        &mut state,
        "edge2",
        &edge2_did,
        IMAGE_DIGEST,
        &["tag:vaikor.com,2026:capability:worker.fetch".into()],
        5,
        "2026-10-19T12:00:00Z",
        "2026-10-19T12:30:00Z",
        &owner_seed,
        &TestApprover { allow: false },
        &mut chain,
        false,
    )
    .unwrap_err();
    assert!(err.contains("0015 S4"), "{err}");
    assert!(!state.edges.contains_key("edge2"));

    // S4 + S5: Approved enrollment issues scoped grant bound to edge2's did:key.
    let enrolled = enroll_edge(
        &mut state,
        "edge2",
        &edge2_did,
        IMAGE_DIGEST,
        &["tag:vaikor.com,2026:capability:worker.fetch".into()],
        5,
        "2026-10-19T12:00:00Z",
        "2026-10-19T12:30:00Z",
        &owner_seed,
        &TestApprover { allow: true },
        &mut chain,
        false,
    )
    .unwrap();
    assert_eq!(enrolled.did, edge2_did);
    assert_eq!(enrolled.grant["aud"], edge2_did);
    assert_eq!(
        verify_file(&dir.join("edge1.log"), &public_key(&edge1_seed)).unwrap(),
        2
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn s6_s7_s8_s9_s10_mutual_handshake_signed_envelope_and_audit_chains() {
    let dir = scratch("dispatch");
    let owner_seed = [0x11u8; 32];
    let edge1_seed = [0x22u8; 32];
    let edge2_seed = [0x33u8; 32];
    let owner_did = did_key(&public_key(&owner_seed));
    let edge1_did = did_key(&public_key(&edge1_seed));
    let edge2_did = did_key(&public_key(&edge2_seed));

    let mut state = SwarmState {
        owner_did: owner_did.clone(),
        edge1_did: edge1_did.clone(),
        image_digest: IMAGE_DIGEST.into(),
        edges: Default::default(),
    };
    let edge1_log = dir.join("edge1.log");
    let edge2_log = dir.join("edge2.log");
    let sock = dir.join("edge2.sock");
    let mut chain1 = Chain::open(&edge1_log, &edge1_seed).unwrap();

    let enrolled = enroll_edge(
        &mut state,
        "edge2",
        &edge2_did,
        IMAGE_DIGEST,
        &[
            "tag:vaikor.com,2026:capability:worker.fetch".into(),
            "tag:vaikor.com,2026:capability:guard.moderate".into(),
        ],
        5,
        "2026-10-19T12:00:00Z",
        "2026-10-19T12:30:00Z",
        &owner_seed,
        &TestApprover { allow: true },
        &mut chain1,
        false,
    )
    .unwrap();

    let sock_worker = sock.clone();
    let edge1_did_w = edge1_did.clone();
    let owner_did_w = owner_did.clone();
    let edge2_log_w = edge2_log.clone();
    let worker = thread::spawn(move || {
        let reg = test_registry();
        let policy = r#"permit(principal, action == Action::"worker.fetch", resource == Resource::"tag:vaikor.com,2026:capability:worker.fetch");"#;
        serve_worker_once(
            &sock_worker,
            &edge2_seed,
            &edge1_did_w,
            &owner_did_w,
            IMAGE_DIGEST,
            &edge2_log_w,
            &reg,
            policy,
            "2026-10-19T12:05:00Z",
            false,
        )
    });

    while !sock.exists() {
        thread::sleep(Duration::from_millis(10));
    }

    let env = create_envelope(
        &edge1_seed,
        &edge2_did,
        "env-1",
        "tag:vaikor.com,2026:capability:worker.fetch",
        &["unrestricted".into()],
        &["x-public.web".into()],
        serde_json::json!({"url": "https://example.com"}),
        enrolled.grant.clone(),
        "2026-10-19T12:05:00Z",
        "2026-10-19T12:10:00Z",
    )
    .unwrap();

    let reply = dispatch_envelope(
        &state,
        "edge2",
        &sock,
        &edge1_seed,
        &env,
        &mut chain1,
        "2026-10-19T12:05:00Z",
        false,
    )
    .unwrap();
    worker.join().unwrap().unwrap();

    assert_eq!(reply.status, "ok");
    assert_eq!(reply.edge_did, edge2_did);
    assert_eq!(
        verify_file(&edge1_log, &public_key(&edge1_seed)).unwrap(),
        2
    );
    assert_eq!(
        verify_file(&edge2_log, &public_key(&edge2_seed)).unwrap(),
        1
    );

    // S9: Consequential capability delegated to Edge 2 is refused because Edge 2 has no Trusted UI channel.
    let _ = fs::remove_file(&sock);
    let sock_worker2 = sock.clone();
    let edge1_did_w2 = edge1_did.clone();
    let owner_did_w2 = owner_did.clone();
    let edge2_log_w2 = edge2_log.clone();
    let worker2 = thread::spawn(move || {
        let reg = test_registry();
        let policy = r#"permit(principal, action, resource);"#;
        serve_worker_once(
            &sock_worker2,
            &edge2_seed,
            &edge1_did_w2,
            &owner_did_w2,
            IMAGE_DIGEST,
            &edge2_log_w2,
            &reg,
            policy,
            "2026-10-19T12:06:00Z",
            false,
        )
    });
    while !sock.exists() {
        thread::sleep(Duration::from_millis(10));
    }
    let cons_env = create_envelope(
        &edge1_seed,
        &edge2_did,
        "env-consequential",
        "tag:vaikor.com,2026:capability:guard.moderate",
        &["CH".into()],
        &["communications.content".into()],
        serde_json::json!({"id": "c1"}),
        enrolled.grant.clone(),
        "2026-10-19T12:06:00Z",
        "2026-10-19T12:10:00Z",
    )
    .unwrap();
    let err = dispatch_envelope(
        &state,
        "edge2",
        &sock,
        &edge1_seed,
        &cons_env,
        &mut chain1,
        "2026-10-19T12:06:00Z",
        false,
    )
    .unwrap_err();
    let _ = worker2.join().unwrap();
    assert!(err.contains("0015 S9"), "{err}");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn s11_s14_drift_detection_revokes_edge_and_local_mode_disables_mesh() {
    let dir = scratch("drift");
    let owner_seed = [0x11u8; 32];
    let edge1_seed = [0x22u8; 32];
    let edge2_seed = [0x33u8; 32];
    let owner_did = did_key(&public_key(&owner_seed));
    let edge1_did = did_key(&public_key(&edge1_seed));
    let edge2_did = did_key(&public_key(&edge2_seed));

    let mut state = SwarmState {
        owner_did,
        edge1_did,
        image_digest: IMAGE_DIGEST.into(),
        edges: Default::default(),
    };
    let edge1_log = dir.join("edge1.log");
    let edge2_log = dir.join("edge2.log");
    let mut chain1 = Chain::open(&edge1_log, &edge1_seed).unwrap();
    let mut chain2 = Chain::open(&edge2_log, &edge2_seed).unwrap();
    chain2
        .append(&vaikor_core::AuditEvent {
            privacy_report: None,
            usage: None,
            reason: Some("init".into()),
            step: "init".into(),
            capability: "tag:vaikor.com,2026:capability:init".into(),
            effects: Vec::new(),
            data_classes: Vec::new(),
            decision: "allow".into(),
            actor: "core".into(),
            at: "2026-10-19T12:00:00Z".into(),
            approval: None,
        })
        .unwrap();

    enroll_edge(
        &mut state,
        "edge2",
        &edge2_did,
        IMAGE_DIGEST,
        &["tag:vaikor.com,2026:capability:worker.fetch".into()],
        5,
        "2026-10-19T12:00:00Z",
        "2026-10-19T12:30:00Z",
        &owner_seed,
        &TestApprover { allow: true },
        &mut chain1,
        false,
    )
    .unwrap();

    // Valid measurement passes.
    let rep = produce_measurement(&edge2_seed, IMAGE_DIGEST, &edge2_log, "nonce-1").unwrap();
    check_drift(
        &mut state,
        "edge2",
        Some(&rep),
        "nonce-1",
        "2026-10-19T12:01:00Z",
        &mut chain1,
    )
    .unwrap();
    assert!(!state.edges["edge2"].revoked);

    // Drifted image digest revokes the edge and appends revocation to Edge 1's audit log.
    let drifted = produce_measurement(
        &edge2_seed,
        "sha256:9999999999999999999999999999999999999999999999999999999999999999",
        &edge2_log,
        "nonce-2",
    )
    .unwrap();
    let err = check_drift(
        &mut state,
        "edge2",
        Some(&drifted),
        "nonce-2",
        "2026-10-19T12:02:00Z",
        &mut chain1,
    )
    .unwrap_err();
    assert!(err.contains("0015 S11"), "{err}");
    assert!(state.edges["edge2"].revoked);

    // S14: Local mode refuses mesh operations.
    let local_err = enroll_edge(
        &mut state,
        "edge3",
        &edge2_did,
        IMAGE_DIGEST,
        &["tag:vaikor.com,2026:capability:worker.fetch".into()],
        5,
        "2026-10-19T12:00:00Z",
        "2026-10-19T12:30:00Z",
        &owner_seed,
        &TestApprover { allow: true },
        &mut chain1,
        true,
    )
    .unwrap_err();
    assert!(local_err.contains("0015 S14"), "{local_err}");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn technocratic_swarm_culls_hallucinating_or_ifc_violating_worker_and_replaces_it() {
    use vaikor_cli::swarm::verify_worker_proposal_or_cull_and_replace;
    use vaikor_verify::flow::CedarFlowPolicy;

    let dir = scratch("cull");
    let owner_seed = [0x11u8; 32];
    let edge1_seed = [0x22u8; 32];
    let edge2_seed = [0x33u8; 32];
    let edge3_seed = [0x44u8; 32];
    let owner_did = did_key(&public_key(&owner_seed));
    let edge1_did = did_key(&public_key(&edge1_seed));
    let edge2_did = did_key(&public_key(&edge2_seed));
    let edge3_did = did_key(&public_key(&edge3_seed));

    let mut state = SwarmState {
        owner_did,
        edge1_did,
        image_digest: IMAGE_DIGEST.into(),
        edges: Default::default(),
    };
    let edge1_log = dir.join("edge1.log");
    let mut chain1 = Chain::open(&edge1_log, &edge1_seed).unwrap();

    enroll_edge(
        &mut state,
        "edge2",
        &edge2_did,
        IMAGE_DIGEST,
        &["tag:vaikor.com,2026:capability:worker.fetch".into()],
        5,
        "2026-10-19T12:00:00Z",
        "2026-10-19T12:30:00Z",
        &owner_seed,
        &TestApprover { allow: true },
        &mut chain1,
        false,
    )
    .unwrap();

    let catalog = serde_json::json!([
        {
            "id": "tag:vaikor.com,2026:capability:notes.read",
            "effects": ["read"],
            "data_classes": ["secrets.token"],
            "consequential": false,
            "cost": {"class": "free"}
        },
        {
            "id": "tag:vaikor.com,2026:capability:message.send",
            "effects": ["egress"],
            "data_classes": ["communications.content"],
            "consequential": true,
            "cost": {"class": "free"}
        }
    ]);
    let bad_plan = serde_json::json!({
        "v": "0.1",
        "goal": "Hallucinated exfiltration of secrets",
        "steps": [
            {
                "id": "r1",
                "kind": "call",
                "capability": "tag:vaikor.com,2026:capability:notes.read",
                "args": {}
            },
            {
                "id": "s1",
                "kind": "call",
                "capability": "tag:vaikor.com,2026:capability:message.send",
                "approval": true,
                "args": {
                    "to": {"lit": "contact:external"},
                    "body": {"ref": "r1"}
                }
            }
        ]
    });
    let flow_policy = CedarFlowPolicy::default_set();

    let replacement = verify_worker_proposal_or_cull_and_replace(
        &mut state,
        "edge2",
        &bad_plan,
        &catalog,
        &flow_policy,
        "edge3",
        &edge3_did,
        &["tag:vaikor.com,2026:capability:worker.fetch".into()],
        5,
        "2026-10-19T12:05:00Z",
        "2026-10-19T12:35:00Z",
        &owner_seed,
        &TestApprover { allow: true },
        &mut chain1,
        false,
    )
    .unwrap()
    .expect("faulty worker edge2 must be culled and replaced by edge3");

    assert!(state.edges["edge2"].revoked, "edge2 must be revoked");
    assert!(
        !state.edges["edge3"].revoked,
        "replacement edge3 must be active"
    );
    assert_eq!(replacement.did, edge3_did);
    assert_eq!(
        verify_file(&edge1_log, &public_key(&edge1_seed)).unwrap(),
        3
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn qr_and_swiyu_verifiable_presentation_pairing_with_e2ee_tunnel_modes() {
    use vaikor_cli::swarm::{
        create_qr_pairing_invite, verify_qr_or_swiyu_pairing, VerifiablePairingPresentation,
    };
    use vaikor_grant::{canonicalize, sign};

    let dir = scratch("qr-swiyu");
    let owner_seed = [0x11u8; 32];
    let edge1_seed = [0x22u8; 32];
    let phone_seed = [0x55u8; 32];
    let owner_did = did_key(&public_key(&owner_seed));
    let edge1_did = did_key(&public_key(&edge1_seed));
    let phone_did = did_key(&public_key(&phone_seed));

    let mut state = SwarmState {
        owner_did,
        edge1_did: edge1_did.clone(),
        image_digest: IMAGE_DIGEST.into(),
        edges: Default::default(),
    };
    let edge1_log = dir.join("edge1.log");
    let mut chain1 = Chain::open(&edge1_log, &edge1_seed).unwrap();

    let (invite, uri) = create_qr_pairing_invite(
        &edge1_seed,
        IMAGE_DIGEST,
        "nonce-swiyu-9876543210",
        "local-to-web-to-local-e2ee",
        "2026-10-19T12:00:00Z",
        "2026-10-19T12:04:00Z",
    )
    .unwrap();
    assert!(uri.starts_with("vkr://pair/v0?invite="));

    let unsigned_vp = serde_json::json!({
        "v": "0.1",
        "format": "swiyu-sd-jwt-vc",
        "device_id": "android-companion-1",
        "device_did": phone_did,
        "audience": edge1_did,
        "challenge": "nonce-swiyu-9876543210",
        "tunnel_mode": "local-to-web-to-local-e2ee",
        "issuer_attestation": "did:tdw:swiyu.admin.ch:issuer",
        "presented_at": "2026-10-19T12:01:00Z",
    });
    let mut msg = b"vkr.vp.pair/v0\0".to_vec();
    msg.extend_from_slice(canonicalize(&unsigned_vp).as_bytes());
    let sig: String = sign(&phone_seed, &msg)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let vp = VerifiablePairingPresentation {
        v: "0.1".into(),
        format: "swiyu-sd-jwt-vc".into(),
        device_id: "android-companion-1".into(),
        device_did: phone_did.clone(),
        audience: edge1_did,
        challenge: "nonce-swiyu-9876543210".into(),
        tunnel_mode: "local-to-web-to-local-e2ee".into(),
        issuer_attestation: Some("did:tdw:swiyu.admin.ch:issuer".into()),
        presented_at: "2026-10-19T12:01:00Z".into(),
        sig,
    };

    let enrolled = verify_qr_or_swiyu_pairing(
        &mut state,
        &invite,
        &vp,
        &["tag:vaikor.com,2026:capability:worker.fetch".into()],
        5,
        "2026-10-19T13:00:00Z",
        &owner_seed,
        &TestApprover { allow: true },
        &mut chain1,
        false,
    )
    .unwrap();
    assert_eq!(enrolled.did, phone_did);

    // Wrong challenge (replay attempt) must be refused.
    let mut replay_vp = vp.clone();
    replay_vp.challenge = "wrong-challenge-000000".into();
    assert!(verify_qr_or_swiyu_pairing(
        &mut state,
        &invite,
        &replay_vp,
        &["tag:vaikor.com,2026:capability:worker.fetch".into()],
        5,
        "2026-10-19T13:00:00Z",
        &owner_seed,
        &TestApprover { allow: true },
        &mut chain1,
        false,
    )
    .is_err());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn wp4_local_workspace_adapter_enforces_dcbor_didkey_handshake_and_refuses_traversal() {
    use vaikor_cli::adapter::{
        create_adapter_request_dcbor, verify_adapter_response_dcbor, LocalWorkspaceAdapter,
        VaikorAdapter, CAP_WORKSPACE_READ, CAP_WORKSPACE_WRITE,
    };
    use vaikor_grant::{attach_signature, jwk_thumbprint};

    let dir = scratch("wp4-adapter");
    let owner_seed = [0x11u8; 32];
    let edge1_seed = [0x22u8; 32];
    let adapter_seed = [0x66u8; 32];
    let owner_did = did_key(&public_key(&owner_seed));
    let edge1_pub = public_key(&edge1_seed);
    let edge1_did = did_key(&edge1_pub);
    let adapter_pub = public_key(&adapter_seed);
    let adapter_did = did_key(&adapter_pub);

    let mut adapter =
        LocalWorkspaceAdapter::new(dir.clone(), adapter_seed, owner_did.clone()).unwrap();

    // Issue an attenuated capability grant bound to adapter_did (aud) and edge1_did (holder).
    let unsigned_grant = serde_json::json!({
        "v": "0.1",
        "jti": "tag:vaikor.com,2026:grant:adapter:1",
        "iss": owner_did,
        "sub": edge1_did,
        "aud": adapter_did,
        "iat": "2026-10-20T01:00:00Z",
        "exp": "2026-10-20T01:30:00Z",
        "cnf": {
            "kid": edge1_did,
            "jkt": jwk_thumbprint(&edge1_pub)
        },
        "rights": [
            { "action": "workspace.read", "resource": CAP_WORKSPACE_READ, "constraints": { "max_uses": 10 } },
            { "action": "workspace.write", "resource": CAP_WORKSPACE_WRITE, "constraints": { "max_uses": 10 } }
        ],
        "budget": { "messages": 10 },
        "chain": []
    });
    let grant = attach_signature(&unsigned_grant, &owner_seed, &owner_did);

    // 1. Write a file via CAP_WORKSPACE_WRITE
    let write_req = create_adapter_request_dcbor(
        "req-write-1",
        &edge1_seed,
        &adapter_did,
        CAP_WORKSPACE_WRITE,
        "2026-10-20T01:00:00Z",
        vec!["CH".into()],
        vec!["documents.text".into()],
        serde_json::json!({ "path": "src/hello.rs", "content": "pub fn hi() {}\n" }),
        grant.clone(),
    )
    .unwrap();
    let write_resp_dcbor = adapter
        .invoke(&write_req, std::slice::from_ref(&owner_did))
        .unwrap();
    let (resp, rec) = verify_adapter_response_dcbor(
        &write_resp_dcbor,
        &adapter_did,
        std::slice::from_ref(&owner_did),
    )
    .unwrap();
    assert_eq!(resp.status, "ok");
    assert_eq!(rec.class(), "documents.text");

    // 2. Read the file back via CAP_WORKSPACE_READ
    let read_req = create_adapter_request_dcbor(
        "req-read-1",
        &edge1_seed,
        &adapter_did,
        CAP_WORKSPACE_READ,
        "2026-10-20T01:01:00Z",
        vec!["CH".into()],
        vec!["documents.text".into()],
        serde_json::json!({ "path": "src/hello.rs" }),
        grant.clone(),
    )
    .unwrap();
    let read_resp_dcbor = adapter
        .invoke(&read_req, std::slice::from_ref(&owner_did))
        .unwrap();
    let (_, read_rec) = verify_adapter_response_dcbor(
        &read_resp_dcbor,
        &adapter_did,
        std::slice::from_ref(&owner_did),
    )
    .unwrap();
    assert_eq!(
        read_rec.as_value()["content"]["files"][0]["content"],
        "pub fn hi() {}\n"
    );

    // 3. Path traversal ("../etc/passwd") MUST be refused.
    let traversal_req = create_adapter_request_dcbor(
        "req-trav-1",
        &edge1_seed,
        &adapter_did,
        CAP_WORKSPACE_READ,
        "2026-10-20T01:02:00Z",
        vec!["CH".into()],
        vec!["documents.text".into()],
        serde_json::json!({ "path": "../etc/passwd" }),
        grant,
    )
    .unwrap();
    assert!(adapter
        .invoke(&traversal_req, std::slice::from_ref(&owner_did))
        .is_err());

    let _ = fs::remove_dir_all(dir);
}
