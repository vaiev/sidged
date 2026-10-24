//! Proof of possession by the presenter (0002 §6a R25).
//!
//! R8 binds a token to a holder key, but a token file alone is still a bearer token. The
//! engine therefore asks the presenter to sign, with the key the leaf `cnf` names, a message
//! that binds the exact token, the audience, the plan digest and a fresh Core nonce. A proof
//! cannot be replayed for another plan, nonce, node or token.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::crypto::{sign, verify};
use crate::didkey::bind_holder;
use crate::jcs::canonicalize;
use crate::token::GrantError;

/// Domain separation for presenter proofs.
pub const POP_CONTEXT: &str = "sdg.pop/v0";

/// The signed message: context, audience, plan digest, nonce and the SHA-256 of the leaf
/// token's JCS form (signature included), NUL-separated.
pub fn pop_message(token: &Value, audience: &str, plan_digest: &str, nonce: &str) -> Vec<u8> {
    let token_digest: String = Sha256::digest(canonicalize(token).as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    [POP_CONTEXT, audience, plan_digest, nonce, &token_digest]
        .join("\0")
        .into_bytes()
}

/// The presenter's proof, signed with the holder seed.
pub fn sign_pop(
    holder_seed: &[u8; 32],
    token: &Value,
    audience: &str,
    plan_digest: &str,
    nonce: &str,
) -> [u8; 64] {
    sign(
        holder_seed,
        &pop_message(token, audience, plan_digest, nonce),
    )
}

/// Check a presenter proof against the holder the leaf token names (`sub`, `cnf`). An empty
/// nonce or plan digest is refused: a proof must be fresh and bound to one plan.
pub fn verify_pop(
    token: &Value,
    audience: &str,
    plan_digest: &str,
    nonce: &str,
    signature: &[u8; 64],
) -> Result<(), GrantError> {
    if nonce.is_empty() || plan_digest.is_empty() {
        return Err(GrantError::Holder);
    }
    let sub = token["sub"].as_str().ok_or(GrantError::Malformed)?;
    let holder = bind_holder(
        sub,
        token["cnf"]["kid"].as_str(),
        token["cnf"]["jkt"].as_str(),
    )
    .map_err(|_| GrantError::Holder)?;
    if verify(
        &holder.public,
        &pop_message(token, audience, plan_digest, nonce),
        signature,
    ) {
        Ok(())
    } else {
        Err(GrantError::Holder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::didkey::did_key;
    use serde_json::json;

    const HOLDER: [u8; 32] = [44; 32];

    fn holder_did(seed: &[u8; 32]) -> String {
        did_key(
            &ed25519_dalek::SigningKey::from_bytes(seed)
                .verifying_key()
                .to_bytes(),
        )
    }

    fn token() -> Value {
        let did = holder_did(&HOLDER);
        json!({"v": "0.1", "sub": did, "cnf": {"kid": did}, "aud": "did:example:node",
               "sig": {"value": "x"}})
    }

    #[test]
    fn the_holder_proves_possession() {
        let proof = sign_pop(&HOLDER, &token(), "did:example:node", "plan-1", "n1");
        assert_eq!(
            verify_pop(&token(), "did:example:node", "plan-1", "n1", &proof),
            Ok(())
        );
    }

    #[test]
    fn a_proof_does_not_move_to_another_plan_nonce_node_or_token() {
        let proof = sign_pop(&HOLDER, &token(), "did:example:node", "plan-1", "n1");
        let check = |token: &Value, aud: &str, plan: &str, nonce: &str| {
            verify_pop(token, aud, plan, nonce, &proof)
        };
        assert_eq!(
            check(&token(), "did:example:node", "plan-2", "n1"),
            Err(GrantError::Holder)
        );
        assert_eq!(
            check(&token(), "did:example:node", "plan-1", "n2"),
            Err(GrantError::Holder)
        );
        assert_eq!(
            check(&token(), "did:example:other", "plan-1", "n1"),
            Err(GrantError::Holder)
        );
        let mut other = token();
        other["sig"]["value"] = json!("y");
        assert_eq!(
            check(&other, "did:example:node", "plan-1", "n1"),
            Err(GrantError::Holder)
        );
    }

    #[test]
    fn another_key_cannot_prove_for_the_holder() {
        let proof = sign_pop(&[45; 32], &token(), "did:example:node", "plan-1", "n1");
        assert_eq!(
            verify_pop(&token(), "did:example:node", "plan-1", "n1", &proof),
            Err(GrantError::Holder)
        );
    }

    #[test]
    fn an_empty_nonce_or_plan_is_refused() {
        let proof = sign_pop(&HOLDER, &token(), "did:example:node", "", "");
        assert_eq!(
            verify_pop(&token(), "did:example:node", "", "", &proof),
            Err(GrantError::Holder)
        );
    }
}
