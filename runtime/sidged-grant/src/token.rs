use crate::resource::resource_covers;
use crate::time::{decimal_le, parse_rfc3339_z};

const MAX_LIFETIME_SECONDS: i64 = 3600;
const MAX_CHAIN: usize = 16;
const CLOCK_SKEW_SECONDS: i64 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Money {
    pub amount: String,
    pub currency: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Constraints {
    pub max_uses: Option<u64>,
    pub max_amount: Option<Money>,
    pub data_classes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Right {
    pub action: String,
    pub resource: String,
    pub constraints: Constraints,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Budget {
    pub messages: Option<u64>,
    pub compute_units: Option<u64>,
    pub money: Option<Money>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Confirmation {
    pub jkt: Option<String>,
    pub kid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenLink {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: String,
    pub nbf: Option<String>,
    pub exp: String,
    pub cnf: Confirmation,
    pub rights: Vec<Right>,
    pub budget: Budget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub link: TokenLink,
    pub chain: Vec<TokenLink>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request<'a> {
    pub holder: &'a str,
    pub audience: &'a str,
    pub action: &'a str,
    pub resource: Option<&'a str>,
    pub data_classes: &'a [&'a str],
    pub residency: &'a [&'a str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantError {
    Malformed,
    Lifetime,
    NotYetValid,
    FutureIssued,
    Expired,
    Holder,
    Audience,
    UncoveredRight,
    Budget,
    Chain,
    MissingResource,
    Policy,
    Signature,
    UntrustedIssuer,
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            GrantError::Malformed => "malformed grant",
            GrantError::Lifetime => "grant lifetime",
            GrantError::NotYetValid => "grant not yet valid",
            GrantError::FutureIssued => "grant issued in the future",
            GrantError::Expired => "grant expired",
            GrantError::Holder => "grant holder",
            GrantError::Audience => "grant audience",
            GrantError::UncoveredRight => "grant widened or uncovered",
            GrantError::Budget => "grant budget",
            GrantError::Chain => "grant chain",
            GrantError::MissingResource => "grant resource",
            GrantError::Policy => "policy denied",
            GrantError::Signature => "grant signature",
            GrantError::UntrustedIssuer => "untrusted root issuer",
        };
        formatter.write_str(text)
    }
}

pub trait PolicyHook {
    fn permit(&self, token: &Token, request: &Request) -> bool;
}

pub struct PermitAll;

impl PolicyHook for PermitAll {
    fn permit(&self, _token: &Token, _request: &Request) -> bool {
        true
    }
}

pub struct DenyAll;

impl PolicyHook for DenyAll {
    fn permit(&self, _token: &Token, _request: &Request) -> bool {
        false
    }
}

/// Spend one step against the leaf budget. Messages and compute units, when
/// set, each drop by one. Money, when set, drops by `unit_cost * bound`.
/// A dimension that the token omitted stays unlimited. The budget is unchanged
/// when the step does not fit.
pub fn spend_step(
    budget: &mut Budget,
    unit_cost: Option<(&str, &str)>,
    bound: u32,
) -> Result<(), GrantError> {
    if matches!(budget.messages, Some(0)) || matches!(budget.compute_units, Some(0)) {
        return Err(GrantError::Budget);
    }
    let next_money = if let (Some(limit), Some((amount, currency))) = (&budget.money, unit_cost) {
        if limit.currency != currency {
            return Err(GrantError::Budget);
        }
        let total = crate::time::decimal_mul(amount, bound.max(1)).ok_or(GrantError::Budget)?;
        if !crate::time::decimal_le(&total, &limit.amount) {
            return Err(GrantError::Budget);
        }
        Some(Money {
            amount: crate::time::decimal_sub(&limit.amount, &total).ok_or(GrantError::Budget)?,
            currency: limit.currency.clone(),
        })
    } else {
        None
    };
    if let Some(left) = budget.messages.as_mut() {
        *left -= 1;
    }
    if let Some(left) = budget.compute_units.as_mut() {
        *left -= 1;
    }
    if let Some(money) = next_money {
        budget.money = Some(money);
    }
    Ok(())
}

/// 0002 R17 + R22: `right` covers `action` on `resource` and its data-class caveat holds
/// (every class the step touches is listed, when the right lists classes).
fn covers(right: &Right, action: &str, resource: &str, classes: &[&str]) -> bool {
    right.action == action
        && resource_covers(&right.resource, resource)
        && right
            .constraints
            .data_classes
            .as_ref()
            .is_none_or(|allowed| {
                classes
                    .iter()
                    .all(|class| allowed.iter().any(|a| a == class))
            })
}

/// 0002 R22: the step's cost times its bound fits `max_amount` (same currency).
fn amount_fits(right: &Right, unit_cost: Option<(&str, &str)>, bound: u32) -> bool {
    let (Some(cap), Some((amount, currency))) = (&right.constraints.max_amount, unit_cost) else {
        return true;
    };
    cap.currency == currency
        && crate::time::decimal_mul(amount, bound.max(1))
            .is_some_and(|total| crate::time::decimal_le(&total, &cap.amount))
}

/// Reserve the first right in leaf order whose every caveat holds for this step (0002 R21,
/// R22): it covers action and resource, its data classes include the step's, the step's cost
/// times `bound` fits `max_amount`, and `max_uses` has `bound` uses left (a zero bound costs
/// zero uses). Returns that right's index. The caller restores prior durable spends.
/// The rights are unchanged when no right fits.
pub fn spend_uses(
    rights: &mut [Right],
    action: &str,
    resource: &str,
    classes: &[&str],
    unit_cost: Option<(&str, &str)>,
    uses: u32,
) -> Result<usize, GrantError> {
    let needed = u64::from(uses);
    let Some(index) = rights.iter().position(|right| {
        covers(right, action, resource, classes)
            && amount_fits(right, unit_cost, uses)
            && right.constraints.max_uses.is_none_or(|left| left >= needed)
    }) else {
        return Err(
            if rights
                .iter()
                .any(|right| covers(right, action, resource, classes))
            {
                GrantError::Budget
            } else {
                GrantError::UncoveredRight
            },
        );
    };
    if let Some(left) = rights[index].constraints.max_uses.as_mut() {
        *left -= needed;
    }
    Ok(index)
}

pub fn check_chain(token: &Token, now: Option<&str>) -> Result<(), GrantError> {
    if token.chain.len() > MAX_CHAIN {
        return Err(GrantError::Chain);
    }
    let mut previous: Option<&TokenLink> = None;
    for link in token.chain.iter().chain(std::iter::once(&token.link)) {
        check_link(link, now)?;
        if let Some(parent) = previous {
            narrows(parent, link)?;
        }
        previous = Some(link);
    }
    Ok(())
}

pub fn authorise(
    token: &Token,
    request: &Request,
    now: Option<&str>,
    policy: &impl PolicyHook,
) -> Result<(), GrantError> {
    check_chain(token, now)?;
    if request.holder != token.link.sub {
        return Err(GrantError::Holder);
    }
    if request.audience != token.link.aud {
        return Err(GrantError::Audience);
    }
    let Some(resource) = request.resource else {
        return Err(GrantError::MissingResource);
    };
    if !token
        .link
        .rights
        .iter()
        .any(|right| covers(right, request.action, resource, request.data_classes))
    {
        return Err(GrantError::UncoveredRight);
    }
    if !policy.permit(token, request) {
        return Err(GrantError::Policy);
    }
    Ok(())
}

fn check_link(link: &TokenLink, now: Option<&str>) -> Result<(), GrantError> {
    if link.cnf.jkt.is_none() && link.cnf.kid.is_none() {
        return Err(GrantError::Holder);
    }
    let iat = parse_rfc3339_z(&link.iat).ok_or(GrantError::Malformed)?;
    let exp = parse_rfc3339_z(&link.exp).ok_or(GrantError::Malformed)?;
    if exp <= iat || exp - iat > MAX_LIFETIME_SECONDS {
        return Err(GrantError::Lifetime);
    }
    if let Some(nbf) = &link.nbf {
        let nbf = parse_rfc3339_z(nbf).ok_or(GrantError::Malformed)?;
        if nbf >= exp {
            return Err(GrantError::Lifetime);
        }
        if let Some(now) = now {
            let now = parse_rfc3339_z(now).ok_or(GrantError::Malformed)?;
            if nbf > now {
                return Err(GrantError::NotYetValid);
            }
        }
    }
    if let Some(now) = now {
        let now = parse_rfc3339_z(now).ok_or(GrantError::Malformed)?;
        if exp <= now {
            return Err(GrantError::Expired);
        }
        if iat > now + CLOCK_SKEW_SECONDS {
            return Err(GrantError::FutureIssued);
        }
    }
    Ok(())
}

fn narrows(parent: &TokenLink, child: &TokenLink) -> Result<(), GrantError> {
    if child.iss != parent.sub {
        return Err(GrantError::Holder);
    }
    if child.aud != parent.aud {
        return Err(GrantError::Audience);
    }
    let parent_exp = parse_rfc3339_z(&parent.exp).ok_or(GrantError::Malformed)?;
    let child_exp = parse_rfc3339_z(&child.exp).ok_or(GrantError::Malformed)?;
    if child_exp > parent_exp {
        return Err(GrantError::Lifetime);
    }
    for right in &child.rights {
        if !parent
            .rights
            .iter()
            .any(|parent_right| right_narrows(parent_right, right))
        {
            return Err(GrantError::UncoveredRight);
        }
    }
    if !budget_narrows(&parent.budget, &child.budget) {
        return Err(GrantError::Budget);
    }
    Ok(())
}

pub(crate) fn right_narrows(parent: &Right, child: &Right) -> bool {
    parent.action == child.action
        && resource_covers(&parent.resource, &child.resource)
        && constraints_narrow(&parent.constraints, &child.constraints)
}

fn constraints_narrow(parent: &Constraints, child: &Constraints) -> bool {
    if let Some(max_uses) = parent.max_uses {
        if child.max_uses.is_none_or(|value| value > max_uses) {
            return false;
        }
    }
    if let Some(parent_amount) = &parent.max_amount {
        match &child.max_amount {
            Some(child_amount) if money_le(child_amount, parent_amount) => {}
            _ => return false,
        }
    }
    if let Some(parent_classes) = &parent.data_classes {
        match &child.data_classes {
            Some(child_classes)
                if child_classes
                    .iter()
                    .all(|class| parent_classes.contains(class)) => {}
            _ => return false,
        }
    }
    true
}

pub(crate) fn budget_narrows(parent: &Budget, child: &Budget) -> bool {
    if let Some(limit) = parent.messages {
        if child.messages.is_none_or(|value| value > limit) {
            return false;
        }
    }
    if let Some(limit) = parent.compute_units {
        if child.compute_units.is_none_or(|value| value > limit) {
            return false;
        }
    }
    if let Some(parent_money) = &parent.money {
        match &child.money {
            Some(child_money) if money_le(child_money, parent_money) => {}
            _ => return false,
        }
    }
    true
}

fn money_le(child: &Money, parent: &Money) -> bool {
    child.currency == parent.currency && decimal_le(&child.amount, &parent.amount)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn money(amount: &str) -> Money {
        Money {
            amount: amount.to_string(),
            currency: "CHF".to_string(),
        }
    }

    fn link(iss: &str, sub: &str, exp: &str, resource: &str, uses: u64) -> TokenLink {
        TokenLink {
            iss: iss.to_string(),
            sub: sub.to_string(),
            aud: "did:example:aud".to_string(),
            iat: "2026-10-09T08:00:00Z".to_string(),
            nbf: None,
            exp: exp.to_string(),
            cnf: Confirmation {
                jkt: Some("thumb".to_string()),
                kid: None,
            },
            rights: vec![Right {
                action: "calendar.propose_meeting".to_string(),
                resource: resource.to_string(),
                constraints: Constraints {
                    max_uses: Some(uses),
                    max_amount: Some(money("20.00")),
                    data_classes: Some(vec!["calendar.availability".to_string()]),
                },
            }],
            budget: Budget {
                messages: Some(10),
                compute_units: None,
                money: Some(money("50")),
            },
        }
    }

    fn delegated() -> Token {
        let mut child = link(
            "did:example:holder",
            "did:example:child",
            "2026-10-09T08:30:00Z",
            "urn:x:alice/work",
            2,
        );
        child.budget.messages = Some(3);
        child.budget.money = Some(money("10"));
        child.rights[0].constraints.data_classes = Some(vec!["calendar.availability".to_string()]);
        child.rights[0].constraints.max_amount = Some(money("5"));
        Token {
            link: child,
            chain: vec![link(
                "did:example:owner",
                "did:example:holder",
                "2026-10-09T09:00:00Z",
                "urn:x:alice/*",
                5,
            )],
        }
    }

    #[test]
    fn zero_bound_and_alternative_covering_right() {
        let mut rights = vec![Right {
            action: "send".into(),
            resource: "urn:x".into(),
            constraints: Constraints {
                max_uses: Some(0),
                ..Constraints::default()
            },
        }];
        assert!(spend_uses(&mut rights, "send", "urn:x", &[], None, 0).is_ok());
        let mut uncapped = rights[0].clone();
        uncapped.constraints.max_uses = None;
        rights.push(uncapped);
        assert!(spend_uses(&mut rights, "send", "urn:x", &[], None, 1).is_ok());
    }

    #[test]
    fn a_narrower_delegation_is_accepted() {
        let token = delegated();
        let request = Request {
            holder: "did:example:child",
            audience: "did:example:aud",
            action: "calendar.propose_meeting",
            resource: Some("urn:x:alice/work"),
            data_classes: &[],
            residency: &[],
        };
        assert_eq!(
            authorise(&token, &request, Some("2026-10-09T08:10:00Z"), &PermitAll),
            Ok(())
        );
    }

    #[test]
    fn a_wider_resource_is_refused() {
        let mut token = delegated();
        token.link.rights[0].resource = "urn:x:*".to_string();
        assert_eq!(check_chain(&token, None), Err(GrantError::UncoveredRight));
    }

    #[test]
    fn dot_dot_is_outside_the_grant() {
        let token = delegated();
        let request = Request {
            holder: "did:example:child",
            audience: "did:example:aud",
            action: "calendar.propose_meeting",
            resource: Some("urn:x:alice/../bob"),
            data_classes: &[],
            residency: &[],
        };
        assert_eq!(
            authorise(&token, &request, None, &PermitAll),
            Err(GrantError::UncoveredRight)
        );
    }

    #[test]
    fn a_missing_resource_is_refused() {
        let token = delegated();
        let request = Request {
            holder: "did:example:child",
            audience: "did:example:aud",
            action: "calendar.propose_meeting",
            resource: None,
            data_classes: &[],
            residency: &[],
        };
        assert_eq!(
            authorise(&token, &request, None, &PermitAll),
            Err(GrantError::MissingResource)
        );
    }

    #[test]
    fn cedar_hook_can_refuse_a_valid_token() {
        let token = delegated();
        let request = Request {
            holder: "did:example:child",
            audience: "did:example:aud",
            action: "calendar.propose_meeting",
            resource: Some("urn:x:alice/work"),
            data_classes: &[],
            residency: &[],
        };
        assert_eq!(
            authorise(&token, &request, None, &DenyAll),
            Err(GrantError::Policy)
        );
    }

    #[test]
    fn a_lifetime_over_one_hour_is_refused() {
        let mut token = delegated();
        token.chain[0].exp = "2026-10-09T10:00:00Z".to_string();
        token.link.exp = "2026-10-09T08:30:00Z".to_string();
        assert_eq!(check_chain(&token, None), Err(GrantError::Lifetime));
    }

    #[test]
    fn a_step_spends_one_message_and_stops_at_zero() {
        let mut budget = Budget {
            messages: Some(1),
            compute_units: Some(2),
            money: Some(money("5.00")),
        };
        spend_step(&mut budget, Some(("1.25", "CHF")), 1).unwrap();
        assert_eq!(budget.messages, Some(0));
        assert_eq!(budget.compute_units, Some(1));
        assert_eq!(budget.money.as_ref().unwrap().amount, "3.75");
        let before = budget.clone();
        assert_eq!(spend_step(&mut budget, None, 1), Err(GrantError::Budget));
        assert_eq!(budget, before);
    }

    #[test]
    fn max_uses_drops_once_per_step_and_stops() {
        let mut rights = vec![Right {
            action: "send".into(),
            resource: "urn:sidged:capability:message.send".into(),
            constraints: Constraints {
                max_uses: Some(1),
                max_amount: None,
                data_classes: None,
            },
        }];
        spend_uses(
            &mut rights,
            "send",
            "urn:sidged:capability:message.send",
            &[],
            None,
            1,
        )
        .unwrap();
        assert_eq!(rights[0].constraints.max_uses, Some(0));
        assert_eq!(
            spend_uses(
                &mut rights,
                "send",
                "urn:sidged:capability:message.send",
                &[],
                None,
                1
            ),
            Err(GrantError::Budget)
        );
        assert_eq!(rights[0].constraints.max_uses, Some(0));
    }

    #[test]
    fn a_map_spends_its_bound_in_money() {
        let mut budget = Budget {
            messages: Some(4),
            compute_units: None,
            money: Some(money("2.00")),
        };
        assert_eq!(
            spend_step(&mut budget, Some(("1.50", "CHF")), 2),
            Err(GrantError::Budget)
        );
        assert_eq!(budget.money.as_ref().unwrap().amount, "2.00");
        assert_eq!(budget.messages, Some(4));
    }

    fn capped_right(classes: Option<&[&str]>, amount: Option<&str>) -> Right {
        Right {
            action: "send".into(),
            resource: "urn:x".into(),
            constraints: Constraints {
                max_uses: None,
                max_amount: amount.map(money),
                data_classes: classes.map(|c| c.iter().map(|s| s.to_string()).collect()),
            },
        }
    }

    fn send_request<'a>(token: &'a Token, classes: &'a [&'a str]) -> Request<'a> {
        Request {
            holder: &token.link.sub,
            audience: &token.link.aud,
            action: "send",
            resource: Some("urn:x"),
            data_classes: classes,
            residency: &[],
        }
    }

    fn single(right: Right) -> Token {
        let mut leaf = link(
            "did:example:owner",
            "did:example:holder",
            "2026-10-09T08:30:00Z",
            "urn:x",
            1,
        );
        leaf.rights = vec![right];
        leaf.budget = Budget::default();
        Token {
            link: leaf,
            chain: vec![],
        }
    }

    // 0002 R22: a data-class caveat holds at use, not only at delegation.
    #[test]
    fn a_data_class_outside_the_caveat_is_uncovered() {
        let token = single(capped_right(Some(&["contacts.basic"]), None));
        let outside = send_request(&token, &["health.records"]);
        assert_eq!(
            authorise(&token, &outside, None, &PermitAll),
            Err(GrantError::UncoveredRight)
        );
        let inside = send_request(&token, &["contacts.basic"]);
        assert_eq!(authorise(&token, &inside, None, &PermitAll), Ok(()));
    }

    // 0002 R22: max_amount caps cost times bound; another currency is refused.
    #[test]
    fn max_amount_caps_the_step_cost() {
        let mut rights = vec![capped_right(None, Some("3.00"))];
        assert_eq!(
            spend_uses(&mut rights, "send", "urn:x", &[], Some(("1.50", "CHF")), 2),
            Ok(0)
        );
        assert_eq!(
            spend_uses(&mut rights, "send", "urn:x", &[], Some(("1.50", "CHF")), 3),
            Err(GrantError::Budget)
        );
        assert_eq!(
            spend_uses(&mut rights, "send", "urn:x", &[], Some(("1.00", "EUR")), 1),
            Err(GrantError::Budget)
        );
    }

    // 0002 R22: the reserved right is one whose caveats hold for this step.
    #[test]
    fn the_reserved_right_satisfies_every_caveat() {
        let mut first = capped_right(Some(&["contacts.basic"]), None);
        first.constraints.max_uses = Some(5);
        let mut second = capped_right(Some(&["health.records"]), None);
        second.constraints.max_uses = Some(5);
        let mut rights = vec![first, second];
        assert_eq!(
            spend_uses(&mut rights, "send", "urn:x", &["health.records"], None, 1),
            Ok(1)
        );
        assert_eq!(rights[0].constraints.max_uses, Some(5));
        assert_eq!(rights[1].constraints.max_uses, Some(4));
        assert_eq!(
            spend_uses(&mut rights, "send", "urn:x", &["secrets.api"], None, 1),
            Err(GrantError::UncoveredRight)
        );
    }

    #[test]
    fn dropping_a_parent_budget_is_widening() {
        let mut token = delegated();
        token.link.budget.money = None;
        assert_eq!(check_chain(&token, None), Err(GrantError::Budget));
    }
}
