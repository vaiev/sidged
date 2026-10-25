use serde_json::{json, Value};
use vaikor_grant::{did_key, jwk_thumbprint, sign, verify_token_chain};

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

fn sign_link(link: &Value, secret: &[u8; 32], issuer: &str) -> Value {
    let message = vaikor_grant::signing_input(link);
    let signature = sign(secret, message.as_bytes());
    let mut signed = link.clone();
    signed["sig"] = json!({
        "alg": "EdDSA",
        "kid": issuer,
        "canon": "jcs",
        "value": b64url(&signature)
    });
    signed
}

#[test]
fn a_two_link_chain_verifies_until_a_byte_changes() {
    let (owner_secret, owner, _owner_jkt) = party(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    );
    let (planner_secret, planner, planner_jkt) = party(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    );
    let (_child_secret, child, child_jkt) = party(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    );
    let parent = sign_link(
        &json!({
            "v": "0.1",
            "id": "tok-chain-root01",
            "iss": owner,
            "sub": planner,
            "aud": "did:example:ch-residency",
            "iat": "2026-10-14T12:00:00Z",
            "exp": "2026-10-14T13:00:00Z",
            "cnf": { "kid": planner, "jkt": planner_jkt },
            "rights": [{ "action": "app.comment.read", "resource": "tag:vaikor.com,2026:app:comments/*" }]
        }),
        &owner_secret,
        &owner,
    );
    let token = sign_link(
        &json!({
            "v": "0.1",
            "id": "tok-chain-delg01",
            "iss": planner,
            "sub": child,
            "aud": "did:example:ch-residency",
            "iat": "2026-10-14T12:05:00Z",
            "exp": "2026-10-14T12:35:00Z",
            "cnf": { "kid": child, "jkt": child_jkt },
            "rights": [{ "action": "app.comment.read", "resource": "tag:vaikor.com,2026:app:comments/public" }],
            "chain": [parent]
        }),
        &planner_secret,
        &planner,
    );
    assert!(
        verify_token_chain(&token).is_ok(),
        "{}",
        verify_token_chain(&token).unwrap_err()
    );
    let mut tampered = token.clone();
    tampered["rights"][0]["resource"] = json!("tag:vaikor.com,2026:app:comments/*");
    assert!(verify_token_chain(&tampered).is_err());
}

#[test]
fn shared_token_chain_vectors() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/test-vectors/signatures/token-chain.json");
    let file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for vector in file["vectors"].as_array().unwrap() {
        let ok = verify_token_chain(&vector["input"]["token"]).is_ok();
        let got = if ok { "accept" } else { "refuse" };
        assert_eq!(
            got,
            vector["expected"]["result"].as_str().unwrap(),
            "{}",
            vector["id"]
        );
    }
}

fn party(secret_hex: &str, public_hex: &str) -> ([u8; 32], String, String) {
    let secret = hex32(secret_hex);
    let public = hex32(public_hex);
    (secret, did_key(&public), jwk_thumbprint(&public))
}
