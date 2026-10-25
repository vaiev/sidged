//! `did:key` for Ed25519 and the RFC 7638 thumbprint used as `cnf.jkt`.
//!
//! An Ed25519 `did:key` is `did:key:z` plus the base58btc encoding of the
//! multicodec prefix `0xed 0x01` and the 32-byte public key. The thumbprint
//! is SHA-256 over the JCS form of the required OKP JWK members.

use sha2::{Digest, Sha256};

use crate::jcs::canonicalize;

const ED25519_DID_KEY_CHARS: usize = 47;
const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub struct HolderKey {
    pub did: String,
    pub public: [u8; 32],
    pub jkt: String,
}

pub fn did_key(public: &[u8; 32]) -> String {
    let mut raw = Vec::with_capacity(34);
    raw.extend_from_slice(&[0xed, 0x01]);
    raw.extend_from_slice(public);
    format!("did:key:z{}", base58_encode(&raw))
}

pub fn resolve_did_key(did: &str) -> Result<[u8; 32], String> {
    let encoded = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| format!("not a did:key: {did}"))?;
    if encoded.contains('#') || encoded.is_empty() {
        return Err(format!("not a bare ed25519 did:key: {did}"));
    }
    // 34 bytes (multicodec 0xed 0x01 and the key) are 47 base58 characters. The decoder is
    // quadratic in its input, so anything longer is refused before decoding.
    if encoded.len() > ED25519_DID_KEY_CHARS {
        return Err("did:key is longer than an ed25519 did:key".to_string());
    }
    let raw = base58_decode(encoded)?;
    if raw.len() != 34 || raw[0] != 0xed || raw[1] != 0x01 {
        return Err(format!("did:key is not ed25519-pub: {did}"));
    }
    let mut public = [0u8; 32];
    public.copy_from_slice(&raw[2..]);
    Ok(public)
}

pub fn jwk_thumbprint(public: &[u8; 32]) -> String {
    let jwk = serde_json::json!({
        "crv": "Ed25519",
        "kty": "OKP",
        "x": b64url(public),
    });
    b64url(&Sha256::digest(canonicalize(&jwk).as_bytes()))
}

/// Resolve `cnf.kid` as a `did:key` and, when `cnf.jkt` is present, require
/// the RFC 7638 thumbprint. `kid` must equal `sub`: that is the holder it names.
pub fn bind_holder(sub: &str, kid: Option<&str>, jkt: Option<&str>) -> Result<HolderKey, String> {
    let Some(kid) = kid else {
        return Err("cnf.kid is required to resolve a did:key holder".into());
    };
    if kid != sub {
        return Err("cnf.kid does not name the holder".into());
    }
    let public = resolve_did_key(kid)?;
    let did = did_key(&public);
    if did != kid {
        return Err("cnf.kid is not the canonical did:key of the holder".into());
    }
    let thumbprint = jwk_thumbprint(&public);
    if let Some(jkt) = jkt {
        if jkt != thumbprint {
            return Err("cnf.jkt is not the thumbprint of the holder key".into());
        }
    }
    Ok(HolderKey {
        did,
        public,
        jkt: thumbprint,
    })
}

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

fn base58_encode(data: &[u8]) -> String {
    let zeros = data.iter().take_while(|byte| **byte == 0).count();
    let mut digits = vec![0u8];
    for byte in &data[zeros..] {
        let mut carry = u32::from(*byte);
        for digit in digits.iter_mut() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = "1".repeat(zeros);
    for digit in digits.iter().rev() {
        out.push(ALPHABET[*digit as usize] as char);
    }
    out
}

fn base58_decode(text: &str) -> Result<Vec<u8>, String> {
    let zeros = text.chars().take_while(|ch| *ch == '1').count();
    let mut bytes = vec![0u8];
    for ch in text.chars() {
        let value = ALPHABET
            .iter()
            .position(|item| *item as char == ch)
            .ok_or_else(|| format!("invalid base58 character {ch}"))? as u32;
        let mut carry = value;
        for byte in bytes.iter_mut() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    bytes.reverse();
    let mut out = vec![0u8; zeros];
    out.extend(bytes.into_iter().skip_while(|byte| *byte == 0));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8032_test_1_round_trips_and_binds() {
        let public = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let did = did_key(&public);
        assert_eq!(
            did,
            "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw"
        );
        assert_eq!(resolve_did_key(&did).unwrap(), public);
        let jkt = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
        assert_eq!(jwk_thumbprint(&public), jkt);
        let bound = bind_holder(&did, Some(&did), Some(jkt)).unwrap();
        assert_eq!(bound.public, public);
    }

    #[test]
    fn an_oversized_did_key_is_refused_before_decoding() {
        let started = std::time::Instant::now();
        let long = format!("did:key:z{}", "6Mk".repeat(100_000));
        assert!(resolve_did_key(&long).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        // One character more or less than the encoding of 34 bytes is still refused by length.
        let did = did_key(&hex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        ));
        assert!(resolve_did_key(&format!("{did}1")).is_err());
        assert!(resolve_did_key(&did[..did.len() - 1]).is_err());
    }

    fn hex(text: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }
}
