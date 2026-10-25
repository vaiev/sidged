//! Ed25519 as in RFC 8032. The 32-byte seed is the secret key in the test vectors.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let key = SigningKey::from_bytes(seed);
    key.sign(message).to_bytes()
}

pub fn verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}
