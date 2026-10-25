use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use vaikor_grant::{bind_holder, did_key, jwk_thumbprint, resolve_did_key};

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/test-vectors/signatures/holder-key.json");
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn hex(text: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

#[test]
fn holder_key_vectors() {
    for vector in vectors()["vectors"].as_array().unwrap() {
        let id = vector["id"].as_str().unwrap();
        let input = &vector["input"];
        let expected = &vector["expected"];
        match vector["operation"].as_str().unwrap() {
            "did-key" => {
                if let Some(encoded) = input.get("public_key_hex").and_then(|item| item.as_str()) {
                    assert_eq!(
                        did_key(&hex(encoded)),
                        expected["value"].as_str().unwrap(),
                        "{id}"
                    );
                } else {
                    let public = resolve_did_key(input["did"].as_str().unwrap()).unwrap();
                    assert_eq!(
                        hex_encode(&public),
                        expected["value"].as_str().unwrap(),
                        "{id}"
                    );
                }
            }
            "jwk-thumbprint" => {
                let public = hex(input["public_key_hex"].as_str().unwrap());
                assert_eq!(
                    jwk_thumbprint(&public),
                    expected["value"].as_str().unwrap(),
                    "{id}"
                );
            }
            "holder-bind" => {
                let kid = input.get("kid").and_then(|item| item.as_str());
                let jkt = input.get("jkt").and_then(|item| item.as_str());
                let result = bind_holder(input["sub"].as_str().unwrap(), kid, jkt);
                let got = if result.is_ok() { "accept" } else { "refuse" };
                assert_eq!(got, expected["result"].as_str().unwrap(), "{id}");
            }
            other => panic!("unknown operation {other}"),
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::new();
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}
