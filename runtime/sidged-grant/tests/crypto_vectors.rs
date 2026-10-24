use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use sidged_grant::{sign, signing_input, verify};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors")
}

fn keys() -> Value {
    serde_json::from_str(&fs::read_to_string(root().join("keys/rfc8032-test-keys.json")).unwrap())
        .unwrap()
}

fn key(name: &str) -> ([u8; 32], [u8; 32]) {
    let file = keys();
    let entry = file["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == name)
        .unwrap();
    let secret = hex(entry["secret_key_hex"].as_str().unwrap());
    let public = hex(entry["public_key_hex"].as_str().unwrap());
    (secret.try_into().unwrap(), public.try_into().unwrap())
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn vectors(name: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(root().join(name)).unwrap()).unwrap()
}

#[test]
fn rfc8032_sign_vectors() {
    for vector in vectors("signatures/ed25519.json")["vectors"]
        .as_array()
        .unwrap()
    {
        let (secret, _) = key(vector["input"]["key"].as_str().unwrap());
        let message = hex(vector["input"]["message_hex"].as_str().unwrap());
        let signature = sign(&secret, &message);
        assert_eq!(
            hex::encode(signature),
            vector["expected"]["value"].as_str().unwrap(),
            "{}",
            vector["id"]
        );
    }
}

#[test]
fn jcs_vectors() {
    for vector in vectors("signatures/jcs-signing-input.json")["vectors"]
        .as_array()
        .unwrap()
    {
        let got = signing_input(&vector["input"]["object"]);
        assert_eq!(
            got,
            vector["expected"]["value"].as_str().unwrap(),
            "{}",
            vector["id"]
        );
    }
}

#[test]
fn sign_vectors() {
    for vector in vectors("signatures/sign.json")["vectors"]
        .as_array()
        .unwrap()
    {
        let (secret, _) = key(vector["input"]["key"].as_str().unwrap());
        let message = signing_input(&vector["input"]["object"]);
        let signature = sign(&secret, message.as_bytes());
        assert_eq!(
            b64url(&signature),
            vector["expected"]["value"].as_str().unwrap(),
            "{}",
            vector["id"]
        );
    }
}

#[test]
fn verify_vectors() {
    for vector in vectors("signatures/verify.json")["vectors"]
        .as_array()
        .unwrap()
    {
        let object = &vector["input"]["object"];
        let message = signing_input(object);
        let (_, public) = key(vector["input"]["public_key"].as_str().unwrap());
        let signature = b64(object["sig"]["value"].as_str().unwrap());
        let ok = signature.len() == 64
            && verify(
                &public,
                message.as_bytes(),
                signature[..].try_into().unwrap(),
            );
        let expected = vector["expected"]["result"].as_str().unwrap();
        assert_eq!(
            if ok { "accept" } else { "refuse" },
            expected,
            "{}",
            vector["id"]
        );
    }
}

fn b64url(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let n = ((bytes[index] as u32) << 16)
            | ((bytes[index + 1] as u32) << 8)
            | bytes[index + 2] as u32;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        index += 3;
    }
    if index < bytes.len() {
        let mut n = (bytes[index] as u32) << 16;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        if index + 1 < bytes.len() {
            n |= (bytes[index + 1] as u32) << 8;
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        } else {
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
        }
    }
    out
}

fn b64(text: &str) -> Vec<u8> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for byte in text.bytes() {
        let value = TABLE.iter().position(|item| *item == byte).unwrap() as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    out
}

mod hex {
    pub fn encode(bytes: [u8; 64]) -> String {
        const HEX: &[u8] = b"0123456789abcdef";
        let mut out = String::new();
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0xf) as usize] as char);
        }
        out
    }
}
