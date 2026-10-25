//! Capability-token checks for Vaikor grants (VKR-L2).
//!
//! Provenance: the attenuation and resource rules follow the read-only
//! reference implementation at the repository named in NOTICE, module
//! `capability`. Signature verification is Ed25519 over an RFC 8785
//! signing input. The policy hook can be the Cedar engine. See
//! `docs/specs/0002-grant.md`.

mod cedar_eval;
mod chain;
mod crypto;
mod didkey;
mod jcs;
mod mandate;
mod pop;
mod present;
mod resource;
mod time;
mod token;

pub use cedar_eval::{AuthContext, CedarEvaluator};
pub use chain::{attach_signature, verify_token_chain};
pub use crypto::{sign, verify};
pub use didkey::{bind_holder, did_key, jwk_thumbprint, resolve_did_key, HolderKey};
pub use jcs::{canonicalize, signing_input};
pub use mandate::{
    sign_mandate, verify_mandate, within_mandate, Mandate, MANDATE_TYPE, MAX_MANDATE_SECONDS,
};
pub use pop::{pop_message, sign_pop, verify_pop, POP_CONTEXT};
pub use present::{accept_presented, run_grant_vectors, structural_token};
pub use resource::resource_covers;
pub use time::{add_rfc3339_z, format_rfc3339_z, parse_rfc3339_z};
pub use token::{
    authorise, check_chain, spend_step, spend_uses, Budget, Confirmation, Constraints, GrantError,
    Money, PolicyHook, Request, Right, Token, TokenLink,
};
pub use token::{DenyAll, PermitAll};
