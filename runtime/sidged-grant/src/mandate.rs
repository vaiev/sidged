//! Owner mandates (0002 §6a R23, R24).
//!
//! The owner signs a mandate once per period (at most 30 days): the rights and budget the
//! node's executor key may hand to its tasks. A mandate confers nothing by itself. Each task
//! gets an ordinary one-hour root token from the executor key (R3), and a node accepts that
//! token only when a valid mandate covers it. A compromised task holds its own plan's rights
//! for an hour; a compromised executor key is still capped by what the owner signed.

use serde_json::Value;

use crate::chain::attach_signature;
use crate::present::{budget_from, right_from};
use crate::time::parse_rfc3339_z;
use crate::token::{budget_narrows, right_narrows, Budget, GrantError, Right, Token};

/// The `type` member of a mandate document.
pub const MANDATE_TYPE: &str = "sdg.mandate/v0";
/// R23: a mandate lives at most 30 days.
pub const MAX_MANDATE_SECONDS: i64 = 30 * 24 * 3600;

/// A verified owner mandate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mandate {
    pub owner: String,
    pub executor: String,
    pub aud: String,
    pub iat: String,
    pub exp: String,
    pub rights: Vec<Right>,
    /// What the executor may spend in this period, across all tasks.
    pub budget: Budget,
}

/// Sign `body` (a mandate document without `sig`) with the owner key.
pub fn sign_mandate(body: &Value, owner_seed: &[u8; 32], owner_did: &str) -> Value {
    attach_signature(body, owner_seed, owner_did)
}

/// Verify a signed mandate: type, owner signature, the owner is the node's trusted owner,
/// lifetime at most 30 days, and `now` inside it.
pub fn verify_mandate(document: &Value, trusted_owner: &str, now: &str) -> Result<Mandate, String> {
    if document["type"] != MANDATE_TYPE {
        return Err("not a mandate".into());
    }
    let text = |key: &str| {
        document[key]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("mandate is missing {key}"))
    };
    let owner = text("owner")?;
    if owner != trusted_owner {
        return Err("mandate is not from the node's owner".into());
    }
    if document["sig"]["kid"].as_str() != Some(owner.as_str()) {
        return Err("mandate signature does not name the owner".into());
    }
    crate::chain::verify_signature(document).map_err(|e| format!("mandate {e}"))?;
    let iat = text("iat")?;
    let exp = text("exp")?;
    let (start, end, at) = match (
        parse_rfc3339_z(&iat),
        parse_rfc3339_z(&exp),
        parse_rfc3339_z(now),
    ) {
        (Some(start), Some(end), Some(at)) => (start, end, at),
        _ => return Err("mandate times are not RFC 3339".into()),
    };
    if end <= start || end - start > MAX_MANDATE_SECONDS {
        return Err("mandate lifetime is over 30 days".into());
    }
    if at < start || at >= end {
        return Err("mandate is not valid now".into());
    }
    let rights = document["rights"]
        .as_array()
        .filter(|rights| !rights.is_empty())
        .ok_or("mandate has no rights")?
        .iter()
        .map(right_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("mandate rights: {e}"))?;
    let budget = budget_from(&document["budget"]).map_err(|e| format!("mandate budget: {e}"))?;
    Ok(Mandate {
        owner,
        executor: text("executor")?,
        aud: text("aud")?,
        iat,
        exp,
        rights,
        budget,
    })
}

/// R24: `token` is a root token from the mandate's executor to itself, for the mandate's
/// audience, inside the mandate's lifetime, every right covered by a mandate right with
/// constraints at least as narrow, and its budget within `remaining` (what the period has left,
/// counted by the Core's ledger).
pub fn within_mandate(
    token: &Token,
    mandate: &Mandate,
    remaining: &Budget,
) -> Result<(), GrantError> {
    let link = &token.link;
    if !token.chain.is_empty() {
        return Err(GrantError::Chain);
    }
    if link.iss != mandate.executor {
        return Err(GrantError::UntrustedIssuer);
    }
    if link.sub != mandate.executor {
        return Err(GrantError::Holder);
    }
    if link.aud != mandate.aud {
        return Err(GrantError::Audience);
    }
    let end = parse_rfc3339_z(&mandate.exp).ok_or(GrantError::Malformed)?;
    let exp = parse_rfc3339_z(&link.exp).ok_or(GrantError::Malformed)?;
    if exp > end {
        return Err(GrantError::Lifetime);
    }
    for right in &link.rights {
        if !mandate
            .rights
            .iter()
            .any(|allowed| right_narrows(allowed, right))
        {
            return Err(GrantError::UncoveredRight);
        }
    }
    if !budget_narrows(&mandate.budget, &link.budget) || !budget_narrows(remaining, &link.budget) {
        return Err(GrantError::Budget);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::didkey::did_key;
    use crate::token::{Confirmation, Constraints, TokenLink};
    use serde_json::json;

    const OWNER_SEED: [u8; 32] = [11; 32];
    const NOW: &str = "2026-10-23T10:00:00Z";

    fn owner() -> String {
        did_key(
            &ed25519_dalek::SigningKey::from_bytes(&OWNER_SEED)
                .verifying_key()
                .to_bytes(),
        )
    }

    fn executor() -> String {
        did_key(
            &ed25519_dalek::SigningKey::from_bytes(&[22; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    fn body(exp: &str) -> Value {
        json!({
            "type": MANDATE_TYPE,
            "owner": owner(),
            "executor": executor(),
            "aud": "did:example:node",
            "iat": "2026-10-23T08:00:00Z",
            "exp": exp,
            "rights": [{
                "action": "write",
                "resource": "urn:sidged:capability:workspace.write",
                "constraints": {"max_uses": 50, "data_classes": ["documents.text"]}
            }],
            "budget": {"messages": 100}
        })
    }

    fn signed(exp: &str) -> Value {
        sign_mandate(&body(exp), &OWNER_SEED, &owner())
    }

    fn mandate() -> Mandate {
        verify_mandate(&signed("2026-11-20T08:00:00Z"), &owner(), NOW).unwrap()
    }

    fn task_token(right: Right) -> Token {
        Token {
            link: TokenLink {
                iss: executor(),
                sub: executor(),
                aud: "did:example:node".into(),
                iat: "2026-10-23T10:00:00Z".into(),
                nbf: None,
                exp: "2026-10-23T11:00:00Z".into(),
                cnf: Confirmation {
                    jkt: None,
                    kid: Some(executor()),
                },
                rights: vec![right],
                budget: Budget {
                    messages: Some(3),
                    ..Budget::default()
                },
            },
            chain: vec![],
        }
    }

    fn write_right(uses: Option<u64>, classes: Option<Vec<&str>>) -> Right {
        Right {
            action: "write".into(),
            resource: "urn:sidged:capability:workspace.write".into(),
            constraints: Constraints {
                max_uses: uses,
                max_amount: None,
                data_classes: classes.map(|c| c.into_iter().map(String::from).collect()),
            },
        }
    }

    fn remaining() -> Budget {
        Budget {
            messages: Some(100),
            ..Budget::default()
        }
    }

    #[test]
    fn a_signed_mandate_verifies() {
        let m = mandate();
        assert_eq!(m.owner, owner());
        assert_eq!(m.executor, executor());
        assert_eq!(m.rights.len(), 1);
        assert_eq!(m.budget.messages, Some(100));
    }

    #[test]
    fn a_mandate_from_another_owner_is_refused() {
        let other = did_key(
            &ed25519_dalek::SigningKey::from_bytes(&[33; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert!(verify_mandate(&signed("2026-11-20T08:00:00Z"), &other, NOW).is_err());
    }

    #[test]
    fn a_tampered_mandate_is_refused() {
        let mut doc = signed("2026-11-20T08:00:00Z");
        doc["rights"][0]["constraints"]["max_uses"] = json!(5000);
        assert!(verify_mandate(&doc, &owner(), NOW).is_err());
    }

    #[test]
    fn a_mandate_over_thirty_days_is_refused() {
        assert!(verify_mandate(&signed("2026-11-23T08:00:01Z"), &owner(), NOW).is_err());
    }

    #[test]
    fn an_expired_or_future_mandate_is_refused() {
        assert!(verify_mandate(&signed("2026-10-23T09:00:00Z"), &owner(), NOW).is_err());
        assert!(verify_mandate(
            &signed("2026-11-20T08:00:00Z"),
            &owner(),
            "2026-10-23T07:00:00Z"
        )
        .is_err());
    }

    #[test]
    fn a_mandate_without_the_type_is_refused() {
        let mut b = body("2026-11-20T08:00:00Z");
        b["type"] = json!("sdg.cap/v0");
        let doc = sign_mandate(&b, &OWNER_SEED, &owner());
        assert!(verify_mandate(&doc, &owner(), NOW).is_err());
    }

    #[test]
    fn a_narrower_task_token_is_within() {
        let token = task_token(write_right(Some(5), Some(vec!["documents.text"])));
        assert_eq!(within_mandate(&token, &mandate(), &remaining()), Ok(()));
    }

    #[test]
    fn a_wider_right_is_outside() {
        let uncapped = task_token(write_right(None, Some(vec!["documents.text"])));
        assert_eq!(
            within_mandate(&uncapped, &mandate(), &remaining()),
            Err(GrantError::UncoveredRight)
        );
        let other_class = task_token(write_right(Some(5), Some(vec!["health.records"])));
        assert_eq!(
            within_mandate(&other_class, &mandate(), &remaining()),
            Err(GrantError::UncoveredRight)
        );
        let mut send = write_right(Some(1), Some(vec!["documents.text"]));
        send.action = "send".into();
        assert_eq!(
            within_mandate(&task_token(send), &mandate(), &remaining()),
            Err(GrantError::UncoveredRight)
        );
    }

    #[test]
    fn a_token_from_another_issuer_or_for_another_node_is_outside() {
        let mut token = task_token(write_right(Some(5), Some(vec!["documents.text"])));
        token.link.iss = owner();
        assert_eq!(
            within_mandate(&token, &mandate(), &remaining()),
            Err(GrantError::UntrustedIssuer)
        );
        let mut token = task_token(write_right(Some(5), Some(vec!["documents.text"])));
        token.link.aud = "did:example:other".into();
        assert_eq!(
            within_mandate(&token, &mandate(), &remaining()),
            Err(GrantError::Audience)
        );
        let mut token = task_token(write_right(Some(5), Some(vec!["documents.text"])));
        token.link.sub = owner();
        assert_eq!(
            within_mandate(&token, &mandate(), &remaining()),
            Err(GrantError::Holder)
        );
    }

    #[test]
    fn a_delegated_token_is_outside() {
        let mut token = task_token(write_right(Some(5), Some(vec!["documents.text"])));
        token.chain.push(token.link.clone());
        assert_eq!(
            within_mandate(&token, &mandate(), &remaining()),
            Err(GrantError::Chain)
        );
    }

    #[test]
    fn a_token_past_the_mandate_or_over_the_period_budget_is_outside() {
        let mut token = task_token(write_right(Some(5), Some(vec!["documents.text"])));
        let mut short = mandate();
        short.exp = "2026-10-23T10:30:00Z".into();
        assert_eq!(
            within_mandate(&token, &short, &remaining()),
            Err(GrantError::Lifetime)
        );
        token.link.budget.messages = Some(101);
        assert_eq!(
            within_mandate(&token, &mandate(), &remaining()),
            Err(GrantError::Budget)
        );
        let mut nothing_left = remaining();
        nothing_left.messages = Some(2);
        let token = task_token(write_right(Some(5), Some(vec!["documents.text"])));
        assert_eq!(
            within_mandate(&token, &mandate(), &nothing_left),
            Err(GrantError::Budget)
        );
    }
}
