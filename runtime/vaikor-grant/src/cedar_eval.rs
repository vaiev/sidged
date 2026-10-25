//! Real Cedar evaluation for the grant hook.
//!
//! `cedar-policy` is the evaluator named by E6. The phase-7 note in IDEAS.md
//! put this integration here, beside signature checks, not in the structural
//! checker that shipped with VKR-L2.

use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityId, EntityTypeName, EntityUid, PolicySet,
    Request,
};

use crate::token::{PolicyHook, Token};

#[derive(Clone, Copy)]
pub struct AuthContext<'a> {
    pub audience: &'a str,
    pub data_classes: &'a [&'a str],
    pub residency: &'a [&'a str],
}

pub struct CedarEvaluator {
    policies: PolicySet,
}

impl CedarEvaluator {
    pub fn parse(policy: &str) -> Result<Self, String> {
        PolicySet::from_str(policy)
            .map(|policies| Self { policies })
            .map_err(|err| err.to_string())
    }

    pub fn permit(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        context: AuthContext,
    ) -> Result<bool, String> {
        let context = Context::from_json_value(
            serde_json::json!({
                "audience": context.audience,
                "data_classes": context.data_classes,
                "residency": context.residency,
            }),
            None,
        )
        .map_err(|err| err.to_string())?;
        let request = Request::new(
            uid("User", principal)?,
            uid("Action", action)?,
            uid("Resource", resource)?,
            context,
            None,
        )
        .map_err(|err| err.to_string())?;
        let response =
            Authorizer::new().is_authorized(&request, &self.policies, &Entities::empty());
        Ok(response.decision() == Decision::Allow)
    }
}

impl PolicyHook for CedarEvaluator {
    fn permit(&self, token: &Token, request: &crate::token::Request) -> bool {
        let Some(resource) = request.resource else {
            return false;
        };
        self.permit(
            &token.link.sub,
            request.action,
            resource,
            AuthContext {
                audience: request.audience,
                data_classes: request.data_classes,
                residency: request.residency,
            },
        )
        .unwrap_or(false)
    }
}

fn uid(kind: &str, id: &str) -> Result<EntityUid, String> {
    let type_name = EntityTypeName::from_str(kind).map_err(|err| err.to_string())?;
    Ok(EntityUid::from_type_name_and_id(
        type_name,
        EntityId::from_str(id).map_err(|err| err.to_string())?,
    ))
}

#[cfg(test)]
mod tests {
    use super::{AuthContext, CedarEvaluator};

    #[test]
    fn a_permit_allows_and_a_forbid_does_not() {
        let allow = CedarEvaluator::parse("permit(principal, action, resource);").unwrap();
        let empty = AuthContext {
            audience: "",
            data_classes: &[],
            residency: &[],
        };
        assert!(allow.permit("alice", "send", "msg", empty).unwrap());
        let deny = CedarEvaluator::parse("forbid(principal, action, resource);").unwrap();
        assert!(!deny.permit("alice", "send", "msg", empty).unwrap());
    }

    #[test]
    fn the_evaluator_is_the_grant_policy_hook() {
        use crate::token::{
            authorise, Budget, Confirmation, Constraints, GrantError, Request, Right, Token,
            TokenLink,
        };

        let token = Token {
            link: TokenLink {
                iss: "owner".into(),
                sub: "holder".into(),
                aud: "aud".into(),
                iat: "2026-10-09T08:00:00Z".into(),
                nbf: None,
                exp: "2026-10-09T09:00:00Z".into(),
                cnf: Confirmation {
                    jkt: Some("thumb".into()),
                    kid: None,
                },
                rights: vec![Right {
                    action: "send".into(),
                    resource: "msg".into(),
                    constraints: Constraints::default(),
                }],
                budget: Budget::default(),
            },
            chain: Vec::new(),
        };
        let request = Request {
            holder: "holder",
            audience: "aud",
            action: "send",
            resource: Some("msg"),
            data_classes: &["communications.content"],
            residency: &["CH"],
        };
        let allow = CedarEvaluator::parse("permit(principal, action, resource);").unwrap();
        assert_eq!(authorise(&token, &request, None, &allow), Ok(()));
        let deny = CedarEvaluator::parse("forbid(principal, action, resource);").unwrap();
        assert_eq!(
            authorise(&token, &request, None, &deny),
            Err(GrantError::Policy)
        );
    }

    #[test]
    fn context_carries_audience_classes_and_residency() {
        let policy = r#"
            permit(principal, action, resource)
            when {
                context.audience == "did:example:aud"
                && context.data_classes.contains("communications.content")
                && context.residency.contains("CH")
            };
        "#;
        let allow = CedarEvaluator::parse(policy).unwrap();
        let context = AuthContext {
            audience: "did:example:aud",
            data_classes: &["communications.content"],
            residency: &["CH"],
        };
        assert!(allow.permit("holder", "send", "msg", context).unwrap());
        let elsewhere = AuthContext {
            audience: "did:example:aud",
            data_classes: &["communications.content"],
            residency: &["EU"],
        };
        assert!(!allow.permit("holder", "send", "msg", elsewhere).unwrap());
    }
}
