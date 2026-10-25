// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Grants on a single node (0002 §6a, ROADMAP 11f).
//!
//! At initialisation the owner key signs a mandate for the node's executor key (R23). For each
//! verified plan the executor issues a one-hour root token narrowed to the plan's capabilities
//! (R24) and proves possession of its key over the plan digest and a fresh nonce (R25). The
//! engine accepts the token only through [`accept_task_token`], which runs every check:
//! mandate signature and lifetime, token signature and lifetime, the executor as the only
//! trusted root, the token inside the mandate, and the presenter's proof.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use vaikor_capability::Registry;
use vaikor_core::AuditEvent;
use vaikor_grant::{
    accept_presented, authorise, did_key, format_rfc3339_z, jwk_thumbprint, parse_rfc3339_z,
    sign_mandate, verify_mandate, verify_pop, within_mandate, Budget, CedarEvaluator, GrantError,
    Mandate, Request, Token, MANDATE_TYPE, MAX_MANDATE_SECONDS,
};
use vaikor_verify::Step;

use crate::engine::{fresh_hex, Presenter};
use crate::{reserve_step, spend_event, LedgerAccount};

/// Messages a default mandate allows per period (one per executed step).
pub const DEFAULT_MANDATE_MESSAGES: u64 = 10_000;
/// R3: a task token lives at most one hour.
pub const TASK_TOKEN_SECONDS: i64 = 3600;

fn did_of(seed: &[u8; 32]) -> String {
    did_key(
        &ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes(),
    )
}

/// The action name the executors authorise a capability under: its last URN segment.
pub fn action_of(capability: &str) -> &str {
    capability.rsplit(':').next().unwrap_or(capability)
}

/// One right per capability descriptor in `capabilities` (the node's capability catalog).
pub fn default_mandate_rights(capabilities: &Value) -> Vec<Value> {
    capabilities
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|d| d["id"].as_str())
        .map(|id| json!({"action": action_of(id), "resource": id}))
        .collect()
}

/// R23: the owner signs a mandate for the executor key, valid for `seconds` (at most 30 days).
pub fn issue_mandate(
    owner_seed: &[u8; 32],
    executor_seed: &[u8; 32],
    audience: &str,
    rights: Vec<Value>,
    budget: Value,
    now: &str,
    seconds: i64,
) -> Result<Value, String> {
    if seconds <= 0 || seconds > MAX_MANDATE_SECONDS {
        return Err("a mandate lives between one second and 30 days".into());
    }
    if rights.is_empty() {
        return Err("a mandate needs at least one right".into());
    }
    let iat = parse_rfc3339_z(now).ok_or("now must be RFC 3339 UTC (Z)")?;
    let owner = did_of(owner_seed);
    let body = json!({
        "type": MANDATE_TYPE,
        "owner": owner,
        "executor": did_of(executor_seed),
        "aud": audience,
        "iat": now,
        "exp": format_rfc3339_z(iat + seconds),
        "rights": rights,
        "budget": budget,
    });
    Ok(sign_mandate(&body, owner_seed, &owner))
}

/// R24: the executor's root token for one plan: the mandate rights that cover the plan's
/// capabilities, each narrowed to that capability, at most `steps` uses where the mandate caps
/// uses, one message per step, one hour.
pub fn mint_task_token(
    executor_seed: &[u8; 32],
    mandate: &Mandate,
    capabilities: &[&str],
    steps: u64,
    remaining: &Budget,
    token_id: &str,
    now: &str,
) -> Result<Value, String> {
    let executor = did_of(executor_seed);
    if executor != mandate.executor {
        return Err("this key is not the mandate's executor".into());
    }
    let iat = parse_rfc3339_z(now).ok_or("now must be RFC 3339 UTC (Z)")?;
    let end = parse_rfc3339_z(&mandate.exp).ok_or("mandate exp")?;
    let exp = (iat + TASK_TOKEN_SECONDS).min(end);
    if exp <= iat {
        return Err("the mandate has expired".into());
    }
    let mut rights = Vec::new();
    for capability in capabilities {
        let action = action_of(capability);
        let right = mandate
            .rights
            .iter()
            .find(|r| r.action == action && vaikor_grant::resource_covers(&r.resource, capability))
            .ok_or_else(|| format!("the mandate does not allow {capability}"))?;
        let mut constraints = serde_json::Map::new();
        if let Some(uses) = right.constraints.max_uses {
            constraints.insert("max_uses".into(), json!(uses.min(steps)));
        }
        if let Some(amount) = &right.constraints.max_amount {
            constraints.insert(
                "max_amount".into(),
                json!({"amount": amount.amount, "currency": amount.currency}),
            );
        }
        if let Some(classes) = &right.constraints.data_classes {
            constraints.insert("data_classes".into(), json!(classes));
        }
        let mut entry = json!({"action": action, "resource": capability});
        if !constraints.is_empty() {
            entry["constraints"] = Value::Object(constraints);
        }
        if !rights.contains(&entry) {
            rights.push(entry);
        }
    }
    if rights.is_empty() {
        return Err("a plan without capability calls needs no token".into());
    }
    // R24: every dimension the mandate caps is capped in the token too: one message per step,
    // and compute and money up to what the period has left (each step's cost is reserved).
    let mut budget = serde_json::Map::new();
    if mandate.budget.messages.is_some() {
        budget.insert("messages".into(), json!(steps.max(1)));
    }
    if mandate.budget.compute_units.is_some() {
        budget.insert(
            "compute_units".into(),
            json!(remaining.compute_units.unwrap_or(0)),
        );
    }
    if let Some(cap) = &mandate.budget.money {
        let amount = remaining
            .money
            .as_ref()
            .map_or("0", |left| left.amount.as_str());
        budget.insert(
            "money".into(),
            json!({"amount": amount, "currency": cap.currency}),
        );
    }
    let public = ed25519_dalek::SigningKey::from_bytes(executor_seed)
        .verifying_key()
        .to_bytes();
    let document = json!({
        "v": "0.1",
        "id": token_id,
        "iss": executor,
        "sub": executor,
        "aud": mandate.aud,
        "iat": now,
        "exp": format_rfc3339_z(exp),
        "cnf": {"kid": executor, "jkt": jwk_thumbprint(&public)},
        "rights": rights,
        "budget": Value::Object(budget),
        "chain": [],
    });
    Ok(vaikor_grant::attach_signature(
        &document,
        executor_seed,
        &executor,
    ))
}

/// What the engine needs to accept a task token.
pub struct TaskGrant<'a> {
    pub mandate: &'a Value,
    pub owner: &'a str,
    pub audience: &'a str,
    /// What the mandate's period has left, from the Core's ledger.
    pub remaining: &'a Budget,
    pub plan_digest: &'a str,
    pub nonce: &'a str,
    pub now: &'a str,
}

/// Every check of 0002 §6a before a task token may authorise any step.
pub fn accept_task_token(
    token: &Value,
    proof: &str,
    grant: &TaskGrant,
) -> Result<(Mandate, Token), GrantError> {
    let mandate = verify_mandate(grant.mandate, grant.owner, grant.now)
        .map_err(|_| GrantError::UntrustedIssuer)?;
    if mandate.aud != grant.audience || token["aud"] != grant.audience {
        return Err(GrantError::Audience);
    }
    let parsed = accept_presented(token, grant.now, &[mandate.executor.as_str()])?;
    within_mandate(&parsed, &mandate, grant.remaining)?;
    let raw = URL_SAFE_NO_PAD
        .decode(proof)
        .map_err(|_| GrantError::Holder)?;
    let signature: [u8; 64] = raw.try_into().map_err(|_| GrantError::Holder)?;
    verify_pop(
        token,
        grant.audience,
        grant.plan_digest,
        grant.nonce,
        &signature,
    )?;
    Ok((mandate, parsed))
}

/// The Core's refusal to run a plan under the node's grant (0002 §6a), before any step.
pub fn grant_denial(reason: &str, now: &str) -> AuditEvent {
    AuditEvent {
        privacy_report: None,
        usage: None,
        reason: Some(reason.to_string()),
        step: "grant".into(),
        capability: GRANT_CAPABILITY.into(),
        effects: Vec::new(),
        data_classes: Vec::new(),
        decision: "deny".into(),
        actor: "core".into(),
        at: now.into(),
        approval: None,
    }
}

/// The audit `capability` of grant decisions that are not about one step.
pub const GRANT_CAPABILITY: &str = "tag:vaikor.com,2026:grant";

/// What the node needs to open the grant for one verified plan.
pub struct PlanGrantInputs<'a> {
    /// The owner mandate document; `None` when the workspace has none.
    pub mandate: Option<&'a Value>,
    /// The grant policy (Cedar, R18); `None` when the workspace has none.
    pub policy: Option<&'a str>,
    /// The node's owner `did:key`, the only trusted mandate signer.
    pub owner: &'a str,
    /// The node audience: its `did:key` as the workspace manifest names it.
    pub audience: &'a str,
    pub executor_seed: &'a [u8; 32],
    /// The plan as the verifier read it, and its 0013 digest.
    pub plan: &'a Value,
    pub plan_digest: &'a str,
    /// The node's capability catalog.
    pub capabilities: &'a Value,
    /// The verified audit chain: the Core's ledger.
    pub history: &'a [AuditEvent],
    /// Proves possession of the executor key over the plan digest and the Core's nonce.
    pub presenter: &'a dyn Presenter,
    pub now: &'a str,
}

/// The grant one plan runs under on this node (0002 §6a): a task token the executor minted
/// for the plan, accepted with every R23-R25 check, and its ledger account.
pub struct PlanGrant {
    token: Token,
    audience: String,
    policy: CedarEvaluator,
    registry: Registry,
    account: LedgerAccount,
    /// The time each step is authorised at: the clock, never the run's start (R17).
    clock: fn() -> String,
    /// The task token's id and the owner mandate's digest, recorded with every grant event.
    pub binding: String,
}

/// R24: what the mandate's period has left: its budget less every reservation of a token
/// the executor issued since the mandate's `iat`. A reservation whose key or time cannot be
/// read counts.
pub fn period_remaining(mandate: &Mandate, history: &[AuditEvent]) -> Result<Budget, String> {
    let since = parse_rfc3339_z(&mandate.iat).ok_or("mandate iat")?;
    let mut budget = mandate.budget.clone();
    crate::replay_reservations(
        history,
        |event, key| {
            let issuer = serde_json::from_str::<(String, String)>(key).ok();
            let at = parse_rfc3339_z(&event.at);
            issuer.is_none_or(|(iss, _)| iss == mandate.executor) && at.is_none_or(|at| at >= since)
        },
        None,
        &mut budget,
    )
    .map_err(|e| format!("grant denied: the mandate period is used up ({e})"))?;
    Ok(budget)
}

impl PlanGrant {
    /// Open the grant for one plan before its first step: load and verify the mandate,
    /// mint the task token for the plan's capabilities and step count, have the presenter prove
    /// possession over the plan digest and a nonce the Core draws now, and accept it with the
    /// period's remaining budget.
    /// The error is the refusal reason; no step may run without a `PlanGrant`.
    pub fn open(inputs: &PlanGrantInputs) -> Result<Self, String> {
        let mandate_doc = inputs
            .mandate
            .ok_or("no owner mandate; run `vaikor mandate renew`")?;
        let source = inputs.policy.ok_or(
            "no grant policy grant.cedar; run `vaikor mandate renew` to write the default",
        )?;
        let policy = CedarEvaluator::parse(source).map_err(|e| format!("grant.cedar: {e}"))?;
        let mandate = verify_mandate(mandate_doc, inputs.owner, inputs.now)
            .map_err(|e| format!("owner mandate: {e}"))?;
        let registry = Registry::from_descriptors(inputs.capabilities)?;
        let plan = vaikor_verify::stored::read_plan(inputs.plan)
            .map_err(|e| format!("plan: {}", e.detail))?;
        let mut capabilities: Vec<&str> = Vec::new();
        let mut steps = 0u64;
        for step in &plan.steps {
            let capability = match step {
                Step::Call { capability, .. } | Step::Map { capability, .. } => capability,
                Step::Expr { .. } => continue,
            };
            steps += 1;
            if !capabilities.contains(&capability.as_str()) {
                capabilities.push(capability);
            }
        }
        let remaining = period_remaining(&mandate, inputs.history)?;
        let token_id = format!("task-{}", fresh_hex(16)?);
        let nonce = fresh_hex(32)?;
        let document = mint_task_token(
            inputs.executor_seed,
            &mandate,
            &capabilities,
            steps,
            &remaining,
            &token_id,
            inputs.now,
        )?;
        let proof = URL_SAFE_NO_PAD.encode(inputs.presenter.prove(
            &document,
            document["aud"].as_str().unwrap_or_default(),
            inputs.plan_digest,
            &nonce,
        ));
        let (_, token) = accept_task_token(
            &document,
            &proof,
            &TaskGrant {
                mandate: mandate_doc,
                owner: inputs.owner,
                audience: inputs.audience,
                remaining: &remaining,
                plan_digest: inputs.plan_digest,
                nonce: &nonce,
                now: inputs.now,
            },
        )
        .map_err(|e| format!("grant denied: {e}"))?;
        let account = LedgerAccount::replayed(&token.link, &token_id, inputs.history)?;
        let digest = Sha256::digest(vaikor_grant::canonicalize(mandate_doc));
        let binding = format!(
            "task_token={token_id} mandate_sha256={}",
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        Ok(Self {
            token,
            audience: inputs.audience.to_string(),
            policy,
            registry,
            account,
            clock: vaikor_gateway::utc_stamp,
            binding,
        })
    }

    /// Another clock for [`Self::reserve`] (tests and deterministic replays).
    pub fn with_clock(mut self, clock: fn() -> String) -> Self {
        self.clock = clock;
        self
    }

    /// The Core's acceptance of the task token, appended before the first step.
    pub fn acceptance(&self, plan_digest: &str, now: &str) -> AuditEvent {
        AuditEvent {
            decision: "allow".into(),
            reason: Some(format!("{} plan_digest={plan_digest}", self.binding)),
            ..grant_denial("", now)
        }
    }

    /// R17-R22 for one call step, before its decision and at the clock's current time: the
    /// token covers the capability for the node audience, its data classes and residency
    /// under the grant policy, and a use and the step's budget are reserved. Returns the
    /// reservations to append before the effect; the error is the denial reason.
    pub fn reserve(&mut self, step: &str, capability: &str) -> Result<Vec<AuditEvent>, String> {
        self.reserve_bound(step, capability, 1)
    }

    /// [`Self::reserve`] for a step that calls its capability up to `bound` times.
    pub fn reserve_bound(
        &mut self,
        step: &str,
        capability: &str,
        bound: u32,
    ) -> Result<Vec<AuditEvent>, String> {
        let now = &(self.clock)();
        let denied = |err: String| format!("grant denied {step}: {err}; {}", self.binding);
        let record = self
            .registry
            .get(capability)
            .ok_or_else(|| denied(format!("no descriptor for {capability}")))?;
        let action = action_of(capability);
        let classes: Vec<&str> = record.data_classes.iter().map(String::as_str).collect();
        let residency: Vec<&str> = record.residency.iter().map(String::as_str).collect();
        let request = Request {
            holder: &self.token.link.sub,
            audience: &self.audience,
            action,
            resource: Some(capability),
            data_classes: &classes,
            residency: &residency,
        };
        authorise(&self.token, &request, Some(now), &self.policy)
            .map_err(|e| denied(e.to_string()))?;
        let cost = record
            .cost_amount
            .as_deref()
            .zip(record.cost_currency.as_deref());
        let selections = reserve_step(
            std::slice::from_mut(&mut self.account),
            action,
            capability,
            &classes,
            cost,
            bound,
        )
        .map_err(|e| denied(e.to_string()))?;
        Ok(selections
            .into_iter()
            .map(|(key, index)| spend_event(key, index, bound, cost, step, capability, now))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vaikor_grant::sign_pop;

    /// R25: the executor's proof over the plan digest and the Core's nonce (base64url).
    fn present_task_token(
        seed: &[u8; 32],
        token: &Value,
        plan_digest: &str,
        nonce: &str,
    ) -> String {
        let audience = token["aud"].as_str().unwrap_or_default();
        URL_SAFE_NO_PAD.encode(sign_pop(seed, token, audience, plan_digest, nonce))
    }

    const OWNER: [u8; 32] = [1; 32];
    const EXECUTOR: [u8; 32] = [2; 32];
    const NOW: &str = "2026-10-23T10:00:00Z";
    const AUD: &str = "did:example:node";
    const WRITE: &str = "tag:vaikor.com,2026:capability:workspace.write";
    const SEND: &str = "tag:vaikor.com,2026:capability:message.send";

    fn catalog() -> Value {
        json!([{"id": WRITE}, {"id": SEND}])
    }

    fn mandate_doc() -> Value {
        issue_mandate(
            &OWNER,
            &EXECUTOR,
            AUD,
            default_mandate_rights(&catalog()),
            json!({"messages": DEFAULT_MANDATE_MESSAGES}),
            NOW,
            MAX_MANDATE_SECONDS,
        )
        .unwrap()
    }

    fn remaining() -> Budget {
        Budget {
            messages: Some(DEFAULT_MANDATE_MESSAGES),
            ..Budget::default()
        }
    }

    fn grant<'a>(mandate: &'a Value, owner: &'a str, remaining: &'a Budget) -> TaskGrant<'a> {
        TaskGrant {
            mandate,
            owner,
            audience: AUD,
            remaining,
            plan_digest: "plan-1",
            nonce: "nonce-1",
            now: "2026-10-23T10:05:00Z",
        }
    }

    #[test]
    fn a_mandate_capping_compute_and_money_still_runs_its_plans() {
        const TIMER: &str = "tag:vaikor.com,2026:capability:timer.start";
        let catalog = crate::turnkey::default_catalog();
        let budget = json!({"messages": 10, "compute_units": 10,
                            "money": {"amount": "5.00", "currency": "CHF"}});
        let mandate = issue_mandate(
            &OWNER,
            &EXECUTOR,
            AUD,
            default_mandate_rights(&catalog),
            budget,
            NOW,
            MAX_MANDATE_SECONDS,
        )
        .unwrap();
        let plan = json!({"v": "0.1", "steps": [
            {"id": "t", "kind": "call", "capability": TIMER,
             "args": {"duration": {"lit": "5 minutes"}}}]});
        let policy = crate::turnkey::default_grant_policy(AUD);
        let owner = did_of(&OWNER);
        let mut grant = PlanGrant::open(&PlanGrantInputs {
            mandate: Some(&mandate),
            policy: Some(&policy),
            owner: &owner,
            audience: AUD,
            executor_seed: &EXECUTOR,
            plan: &plan,
            plan_digest: "plan-1",
            capabilities: &catalog,
            history: &[],
            presenter: &crate::engine::HolderKey::new(EXECUTOR),
            now: "2026-10-23T10:05:00Z",
        })
        .unwrap()
        .with_clock(|| "2026-10-23T10:06:00Z".into());
        assert!(grant.reserve("t", TIMER).is_ok());
    }

    #[test]
    fn every_step_is_authorised_at_its_own_time_not_the_run_start() {
        const TIMER: &str = "tag:vaikor.com,2026:capability:timer.start";
        let catalog = crate::turnkey::default_catalog();
        let mandate = issue_mandate(
            &OWNER,
            &EXECUTOR,
            AUD,
            default_mandate_rights(&catalog),
            json!({"messages": 10}),
            NOW,
            MAX_MANDATE_SECONDS,
        )
        .unwrap();
        let plan = json!({"v": "0.1", "steps": [
            {"id": "t", "kind": "call", "capability": TIMER,
             "args": {"duration": {"lit": "5 minutes"}}}]});
        let policy = crate::turnkey::default_grant_policy(AUD);
        let owner = did_of(&OWNER);
        let opened = |clock: fn() -> String| {
            PlanGrant::open(&PlanGrantInputs {
                mandate: Some(&mandate),
                policy: Some(&policy),
                owner: &owner,
                audience: AUD,
                executor_seed: &EXECUTOR,
                plan: &plan,
                plan_digest: "plan-1",
                capabilities: &catalog,
                history: &[],
                presenter: &crate::engine::HolderKey::new(EXECUTOR),
                now: "2026-10-23T10:05:00Z",
            })
            .unwrap()
            .with_clock(clock)
        };
        // The task token lives one hour from 10:05; a step that starts after that is denied
        // although the run began inside it.
        let mut late = opened(|| "2026-10-23T11:10:00Z".into());
        let err = late.reserve("t", TIMER).unwrap_err();
        assert!(err.starts_with("grant denied t:"), "{err}");
        let mut timely = opened(|| "2026-10-23T10:06:00Z".into());
        let spends = timely.reserve("t", TIMER).unwrap();
        assert!(spends.iter().all(|s| s.at == "2026-10-23T10:06:00Z"));
    }

    fn token_for(mandate: &Value, caps: &[&str]) -> Value {
        let m = verify_mandate(mandate, &did_of(&OWNER), NOW).unwrap();
        mint_task_token(&EXECUTOR, &m, caps, 2, &remaining(), "task-1", NOW).unwrap()
    }

    #[test]
    fn a_minted_and_presented_task_token_is_accepted() {
        let mandate = mandate_doc();
        let token = token_for(&mandate, &[WRITE]);
        let proof = present_task_token(&EXECUTOR, &token, "plan-1", "nonce-1");
        let owner = did_of(&OWNER);
        let left = remaining();
        let (_, parsed) =
            accept_task_token(&token, &proof, &grant(&mandate, &owner, &left)).unwrap();
        assert_eq!(parsed.link.rights.len(), 1);
        assert_eq!(parsed.link.rights[0].resource, WRITE);
        assert_eq!(parsed.link.budget.messages, Some(2));
    }

    #[test]
    fn a_proof_for_another_plan_or_nonce_is_refused() {
        let mandate = mandate_doc();
        let token = token_for(&mandate, &[WRITE]);
        let owner = did_of(&OWNER);
        let left = remaining();
        let other_plan = present_task_token(&EXECUTOR, &token, "plan-2", "nonce-1");
        assert_eq!(
            accept_task_token(&token, &other_plan, &grant(&mandate, &owner, &left)).err(),
            Some(GrantError::Holder)
        );
        let other_nonce = present_task_token(&EXECUTOR, &token, "plan-1", "nonce-2");
        assert_eq!(
            accept_task_token(&token, &other_nonce, &grant(&mandate, &owner, &left)).err(),
            Some(GrantError::Holder)
        );
    }

    #[test]
    fn a_mandate_from_another_owner_is_refused() {
        let mandate = mandate_doc();
        let token = token_for(&mandate, &[WRITE]);
        let proof = present_task_token(&EXECUTOR, &token, "plan-1", "nonce-1");
        let stranger = did_of(&[9; 32]);
        let left = remaining();
        assert_eq!(
            accept_task_token(&token, &proof, &grant(&mandate, &stranger, &left)).err(),
            Some(GrantError::UntrustedIssuer)
        );
    }

    #[test]
    fn a_token_from_another_key_is_refused_even_with_its_own_proof() {
        let mandate = mandate_doc();
        let m = verify_mandate(&mandate, &did_of(&OWNER), NOW).unwrap();
        // A key that is not the executor cannot mint under the mandate...
        assert!(mint_task_token(&[7; 32], &m, &[WRITE], 1, &remaining(), "t", NOW).is_err());
        // ...and a token it signs anyway is refused as untrusted.
        let mut forged = token_for(&mandate, &[WRITE]);
        let other = did_of(&[7; 32]);
        forged["iss"] = json!(other);
        forged["sub"] = json!(other);
        forged["cnf"] = json!({"kid": other});
        let forged = vaikor_grant::attach_signature(&forged, &[7; 32], &other);
        let proof = present_task_token(&[7; 32], &forged, "plan-1", "nonce-1");
        let owner = did_of(&OWNER);
        let left = remaining();
        assert_eq!(
            accept_task_token(&forged, &proof, &grant(&mandate, &owner, &left)).err(),
            Some(GrantError::UntrustedIssuer)
        );
    }

    #[test]
    fn the_mandate_bounds_what_can_be_minted_and_the_period_budget() {
        let mandate = issue_mandate(
            &OWNER,
            &EXECUTOR,
            AUD,
            vec![json!({"action": "workspace.write", "resource": WRITE})],
            json!({"messages": 5}),
            NOW,
            3600 * 24,
        )
        .unwrap();
        let m = verify_mandate(&mandate, &did_of(&OWNER), NOW).unwrap();
        assert!(mint_task_token(&EXECUTOR, &m, &[SEND], 1, &remaining(), "t", NOW).is_err());
        let token = mint_task_token(&EXECUTOR, &m, &[WRITE], 3, &remaining(), "t", NOW).unwrap();
        let proof = present_task_token(&EXECUTOR, &token, "plan-1", "nonce-1");
        let owner = did_of(&OWNER);
        let spent = Budget {
            messages: Some(2),
            ..Budget::default()
        };
        assert_eq!(
            accept_task_token(&token, &proof, &grant(&mandate, &owner, &spent)).err(),
            Some(GrantError::Budget)
        );
    }

    #[test]
    fn a_mandate_over_thirty_days_cannot_be_issued() {
        assert!(issue_mandate(
            &OWNER,
            &EXECUTOR,
            AUD,
            default_mandate_rights(&catalog()),
            json!({}),
            NOW,
            MAX_MANDATE_SECONDS + 1
        )
        .is_err());
    }

    #[test]
    fn a_task_token_never_outlives_its_mandate() {
        let mandate = issue_mandate(
            &OWNER,
            &EXECUTOR,
            AUD,
            default_mandate_rights(&catalog()),
            json!({}),
            NOW,
            600,
        )
        .unwrap();
        let m = verify_mandate(&mandate, &did_of(&OWNER), NOW).unwrap();
        let token = mint_task_token(&EXECUTOR, &m, &[WRITE], 1, &remaining(), "t", NOW).unwrap();
        assert_eq!(token["exp"], "2026-10-23T10:10:00Z");
    }
}
