//! 0007 R8: signed Core control state replayed under the audit lock.
//! This state is never a data Record and never enters a step read log.
use crate::{approval_audit, ApprovalChannel, ApprovalRequest};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sidged_core::AuditEvent;
use sidged_log::Chain;

const KIND: &str = "core.standing-approval";

fn digest(value: &Value) -> String {
    format!(
        "{:x}",
        Sha256::digest(sidged_grant::canonicalize(value).as_bytes())
    )
}
fn event(decision: &str, at: &str, record: Value) -> AuditEvent {
    AuditEvent {
        step: "planner".into(),
        capability: KIND.into(),
        effects: vec![],
        data_classes: vec![],
        decision: decision.into(),
        actor: "core".into(),
        at: at.into(),
        reason: None,
        privacy_report: Some(record.to_string()),
        usage: None,
        approval: None,
    }
}
fn timestamp(value: &str) -> Result<i64, String> {
    sidged_grant::parse_rfc3339_z(value).ok_or_else(|| "invalid standing expiry".into())
}
fn validate(scope: &Value, grant_expiry: &str, now: &str) -> Result<u64, String> {
    let expiry = timestamp(scope["expiry"].as_str().ok_or("missing standing expiry")?)?;
    let calls = scope["limit"]["calls"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or("invalid standing call limit")?;
    if scope["standing"] != true
        || scope["task_type"] != "planner"
        || scope["provider"].as_str().is_none_or(str::is_empty)
        || scope.as_object().map(|o| o.len()) != Some(5)
        || scope["limit"].as_object().map(|o| o.len()) != Some(1)
        || expiry <= timestamp(now)?
        || expiry > timestamp(grant_expiry)?
    {
        return Err("invalid or expired standing scope".into());
    }
    Ok(calls)
}

/// Drain authenticated revocations before any further planner call. If an
/// append fails the caller returns without connecting (revoked fail closed).
pub fn check_revocations(
    chain: &mut Chain,
    channel: &dyn ApprovalChannel,
    now: &str,
) -> Result<bool, String> {
    let mut revoked = channel.take_revocations();
    if channel.killed() {
        revoked.push("*".into());
    }
    let changed = !revoked.is_empty();
    for target in revoked {
        let mut audit = event("revoke", now, json!({"kind":KIND,"target":target}));
        audit.actor = "approval-channel".into();
        audit.approval = Some(approval_audit(channel));
        chain.append(&audit)?;
    }
    if channel.killed() {
        return Err("planner approval revoked by kill switch".into());
    }
    Ok(changed)
}

/// The proposed call-count scope is selected by the Core and displayed by the
/// existing R9 channel. Only an explicitly echoed scope becomes standing.
/// Over-limit answers approve one call; they never reset the stored counters.
#[allow(clippy::too_many_arguments)]
pub fn authorize_planner(
    chain: &mut Chain,
    channel: &dyn ApprovalChannel,
    mut request: ApprovalRequest,
    proposed: &Value,
    owner: &str,
    grant_expiry: &str,
    now: &str,
) -> Result<Option<Value>, String> {
    check_revocations(chain, channel, now)?;
    validate(proposed, grant_expiry, now)?;
    if !owner.starts_with("did:key:") {
        return Err("standing owner must be a key DID".into());
    }
    let mut state: Option<Value> = None;
    for entry in chain.read_events()? {
        if entry.capability != KIND {
            continue;
        }
        let record: Value = serde_json::from_str(
            entry
                .privacy_report
                .as_deref()
                .ok_or("missing standing control state")?,
        )
        .map_err(|_| "invalid standing control state")?;
        if record["kind"] != KIND {
            return Err("invalid standing control kind".into());
        }
        match entry.decision.as_str() {
            "store"
                if record["owner"] == owner
                    && record["scope"]["provider"] == proposed["provider"]
                    && record["scope"]["task_type"] == proposed["task_type"] =>
            {
                state = Some(record)
            }
            "revoke" => {
                if state.as_ref().is_some_and(|s| {
                    record["target"] == "*" || record["target"] == s["approval_digest"]
                }) {
                    state = None;
                }
            }
            "book" => {
                if let Some(s) = state
                    .as_mut()
                    .filter(|s| s["approval_digest"] == record["approval_digest"])
                {
                    let used = s["used"].as_u64().ok_or("invalid standing counter")?;
                    s["used"] = used
                        .checked_add(1)
                        .ok_or("standing counter overflow")?
                        .into();
                }
            }
            _ => {}
        }
    }
    let current = state.filter(|s| {
        s["scope_digest"].as_str() == Some(digest(&s["scope"]).as_str())
            && validate(&s["scope"], grant_expiry, now).is_ok()
    });
    if let Some(s) = &current {
        let used = s["used"].as_u64().ok_or("invalid standing counter")?;
        if used < validate(&s["scope"], grant_expiry, now)? {
            let binding =
                json!({"approval_digest":s["approval_digest"],"scope_digest":s["scope_digest"]});
            chain.append(&event(
                "book",
                now,
                json!({"kind":KIND,"approval_digest":s["approval_digest"],"scope_digest":s["scope_digest"]}),
            ))?;
            if check_revocations(chain, channel, now)? {
                return Err("planner standing approval revoked".into());
            }
            return Ok(Some(binding));
        }
    }
    // Do not widen an existing valid approval when the limit is exhausted.
    let scope = current.as_ref().map(|s| &s["scope"]).unwrap_or(proposed);
    request.scope = Some(scope.clone());
    request.scope_digest = Some(digest(scope));
    let decision = channel.decide(&request, now);
    for _ in 0..channel.take_stale_responses() {
        let mut stale = event("deny", now, Value::Null);
        stale.capability = request.capability.clone();
        stale.actor = "approval-channel".into();
        stale.reason = Some("stale approval response".into());
        stale.privacy_report = None;
        chain.append(&stale)?;
    }
    let mut audit = event(
        if decision.granted { "approve" } else { "deny" },
        &decision.at,
        json!({"scope":scope,"scope_digest":request.scope_digest,"args_digest":request.args_digest,"plan_digest":request.plan_digest}),
    );
    audit.capability = request.capability.clone();
    audit.actor = decision.actor;
    audit.approval = Some(approval_audit(channel));
    chain.append(&audit)?;
    let approval_digest = chain.head_digest().to_owned();
    if !decision.granted {
        return Err("planner owner approval denied".into());
    }
    if check_revocations(chain, channel, now)? {
        return Err("planner standing approval revoked".into());
    }
    if current.is_none() && channel.standing_scope_approved(&request) {
        let state = json!({"kind":KIND,"owner":owner,"scope":scope,"scope_digest":request.scope_digest,
            "approval_digest":approval_digest,"used":0});
        chain.append(&event("store", now, state))?;
        chain.append(&event(
            "book",
            now,
            json!({"kind":KIND,"approval_digest":approval_digest,"scope_digest":request.scope_digest}),
        ))?;
        return Ok(Some(
            json!({"approval_digest":approval_digest,"scope_digest":request.scope_digest}),
        ));
    }
    Ok(None)
}
