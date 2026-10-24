//! Owner-signed stored-plan validation (0013 R1–R7).
//!
//! Acceptance authenticates a reusable plan, never a grant or a per-run approval.
//! Each execution must call `check_for_run` again, retain the normal execution gates,
//! and persist the structured audit event for that run.
use crate::{Arg, Cap, FlowPolicy, Plan, Step, Summary};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, FixedOffset, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Malformed,
    UnsupportedVersion,
    BadSignature,
    Expired,
}
impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::UnsupportedVersion => "unsupported-version",
            Self::BadSignature => "bad-signature",
            Self::Expired => "expired",
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().ok_or(Error::Malformed)
}
fn encode(v: &Value) -> Result<Vec<u8>> {
    sidged_record::encode(v).map_err(|_| Error::Malformed)
}
/// SHA-256 over the entire plan tree, including any extension members.
pub fn plan_digest(plan: &Value) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(encode(plan)?)))
}
/// Preserve all members except the top-level signature.
pub fn signing_input(stored: &Value) -> Result<Vec<u8>> {
    sidged_record::signing_input(stored).map_err(|_| Error::Malformed)
}
/// A verification result, not execution authority. Approvals still name the steps
/// requiring Trusted UI; no grant or approval token is produced here.
#[derive(Debug)]
pub struct CheckedPlan {
    pub digest: String,
    pub summary: Summary,
}
/// Validate with the Core process clock and its provisioned owner DID. The policy
/// identifier and evaluator must come from the same current Core policy set.
pub fn check(
    stored: &Value,
    catalog: &Value,
    owner: &str,
    policy_digest: &str,
    policy: &impl FlowPolicy,
) -> Result<CheckedPlan> {
    check_at(
        stored,
        catalog,
        owner,
        policy_digest,
        policy,
        Utc::now().fixed_offset(),
    )
}
/// The outcome of authenticating a stored plan for one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Accept,
    Refuse,
}
/// Metadata presented by the caller is untrusted, especially on refusal. `owner`
/// is the Core-provisioned trust anchor; `plan_digest` is computed from the tree,
/// never copied from the presented digest. Missing or invalid metadata is `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub decision: Decision,
    pub reason: Option<&'static str>,
    pub plan_digest: Option<String>,
    pub owner: String,
    pub kid: Option<String>,
    pub catalog_digest: Option<String>,
    pub flow_policy: Option<String>,
}
/// Per-run entry point. Sends exactly one event to the Core's audit sink for
/// acceptance or refusal. Audit failure prevents execution; refusals retain their
/// original error even if the sink fails.
/// The executor must still obtain its grant and Trusted UI approval separately.
pub fn check_for_run(
    stored: &Value,
    catalog: &Value,
    owner: &str,
    policy_digest: &str,
    policy: &impl FlowPolicy,
    audit: impl FnOnce(&AuditEvent) -> std::io::Result<()>,
) -> Result<CheckedPlan> {
    let result = check(stored, catalog, owner, policy_digest, policy);
    let event = AuditEvent {
        decision: if result.is_ok() {
            Decision::Accept
        } else {
            Decision::Refuse
        },
        reason: result.as_ref().err().map(|error| error.code()),
        plan_digest: stored.get("plan").and_then(|plan| plan_digest(plan).ok()),
        owner: owner.to_owned(),
        kid: stored["sig"]["kid"].as_str().map(str::to_owned),
        catalog_digest: stored["catalog_digest"].as_str().map(str::to_owned),
        flow_policy: stored["flow_policy"].as_str().map(str::to_owned),
    };
    let audited = audit(&event);
    match result {
        Err(error) => Err(error),
        Ok(checked) => {
            audited.map_err(|_| Error::Malformed)?;
            Ok(checked)
        }
    }
}
fn instant(s: &str) -> Result<DateTime<FixedOffset>> {
    let t = DateTime::parse_from_rfc3339(s).map_err(|_| Error::Malformed)?;
    if t.offset().local_minus_utc() != 0 || t.timestamp_subsec_nanos() >= 1_000_000_000 {
        return Err(Error::Malformed);
    }
    Ok(t)
}
fn check_at(
    stored: &Value,
    catalog: &Value,
    owner: &str,
    policy_digest: &str,
    policy: &impl FlowPolicy,
    now: DateTime<FixedOffset>,
) -> Result<CheckedPlan> {
    let m = stored.as_object().ok_or(Error::Malformed)?;
    for k in [
        "v",
        "kind",
        "plan",
        "plan_digest",
        "catalog_digest",
        "owner",
        "issued",
        "expires",
        "flow_policy",
        "sig",
    ] {
        if !m.contains_key(k) {
            return Err(Error::Malformed);
        }
    }
    if text(stored, "v")? != "0.1" || text(stored, "kind")? != "sdg.plan.stored" {
        return Err(Error::UnsupportedVersion);
    }
    let digest = plan_digest(&stored["plan"])?;
    if text(stored, "plan_digest")? != digest {
        return Err(Error::Malformed);
    }
    let bytes = signing_input(stored)?;
    let s = &stored["sig"];
    let authenticated = (|| {
        if stored["owner"] != owner
            || s["kid"] != owner
            || s["signer"] != owner
            || s["alg"] != "EdDSA"
            || s["canon"] != "dcbor"
        {
            return None;
        }
        let public = sidged_grant::resolve_did_key(owner).ok()?;
        let signature: [u8; 64] = URL_SAFE_NO_PAD
            .decode(s["value"].as_str()?)
            .ok()?
            .try_into()
            .ok()?;
        sidged_grant::verify(&public, &bytes, &signature).then_some(())
    })();
    authenticated.ok_or(Error::BadSignature)?;
    let issued = instant(text(stored, "issued")?)?;
    let expires = instant(text(stored, "expires")?)?;
    if issued >= expires || expires - issued > chrono::Duration::days(365) || now < issued {
        return Err(Error::Malformed);
    }
    if now >= expires {
        return Err(Error::Expired);
    }
    let plan = parse_plan(&stored["plan"])?;
    if catalog_digest(&stored["plan"], catalog)? != text(stored, "catalog_digest")?
        || text(stored, "flow_policy")? != policy_digest
    {
        return Err(Error::Malformed);
    }
    let caps = parse_catalog(catalog)?;
    let summary = crate::verify(&plan, &caps, policy).map_err(|_| Error::Malformed)?;
    Ok(CheckedPlan { digest, summary })
}
/// Only referenced descriptors, sorted by id, contribute to the catalog digest.
pub fn catalog_digest(plan: &Value, catalog: &Value) -> Result<String> {
    let plan = parse_plan(plan)?;
    let ids: HashSet<&str> = plan
        .steps
        .iter()
        .filter_map(|s| match s {
            Step::Call { capability, .. } | Step::Map { capability, .. } => {
                Some(capability.as_str())
            }
            _ => None,
        })
        .collect();
    let mut found = HashMap::new();
    for cap in catalog.as_array().ok_or(Error::Malformed)? {
        let id = text(cap, "id")?;
        if ids.contains(id) && found.insert(id, cap.clone()).is_some() {
            return Err(Error::Malformed);
        }
    }
    if found.len() != ids.len() {
        return Err(Error::Malformed);
    }
    let mut entries: Vec<_> = found.into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    plan_digest(&Value::Array(entries.into_iter().map(|(_, v)| v).collect()))
}
/// Digest a Core-owned policy array of `{id, source}` entries. Source text is exact.
pub fn policy_digest(policies: &Value) -> Result<String> {
    let mut entries = policies.as_array().ok_or(Error::Malformed)?.clone();
    let mut ids = HashSet::new();
    for p in &entries {
        if p.as_object().ok_or(Error::Malformed)?.len() != 2 {
            return Err(Error::Malformed);
        }
        if !ids.insert(text(p, "id")?) {
            return Err(Error::Malformed);
        }
        text(p, "source")?;
    }
    entries.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    plan_digest(&Value::Array(entries))
}
/// Why a plan does not parse: the error code and a sentence naming the part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub error: Error,
    pub detail: String,
}
impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error, self.detail)
    }
}
impl std::error::Error for ParseError {}
fn malformed(detail: impl Into<String>) -> ParseError {
    ParseError {
        error: Error::Malformed,
        detail: detail.into(),
    }
}
fn member<'a>(v: &'a Value, k: &str, what: &str) -> std::result::Result<&'a str, ParseError> {
    v[k].as_str()
        .ok_or_else(|| malformed(format!("{what} has no string {k}")))
}
/// An output member name in a `ref` (0003 R4a); `plan.schema.json` has the same pattern.
fn is_field(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.len() <= 64
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
/// `{"ref": <id>}` or `{"ref": <id>, "field": <name>}`, nothing else.
fn reference(object: &serde_json::Map<String, Value>) -> Option<Arg> {
    let step = object.get("ref")?.as_str()?;
    let field = match object.get("field") {
        None if object.len() == 1 => None,
        Some(Value::String(name)) if object.len() == 2 && is_field(name) => Some(name.clone()),
        _ => return None,
    };
    Some(Arg::Ref {
        step: step.into(),
        field,
    })
}
fn arg(a: &Value) -> Option<Arg> {
    let object = a.as_object()?;
    if object.contains_key("ref") {
        return reference(object);
    }
    if object.len() != 1 {
        return None;
    }
    match object.iter().next()? {
        (k, v) if k == "lit" && !v.is_object() && !v.is_array() => Some(Arg::Lit(v.clone())),
        (k, v) if k == "item" && v == true => Some(Arg::Item),
        _ => None,
    }
}
fn args(v: &Value, id: &str) -> std::result::Result<Vec<(String, Arg)>, ParseError> {
    v.as_object()
        .ok_or_else(|| malformed(format!("step {id}: args is not an object")))?
        .iter()
        .map(|(name, a)| {
            let parsed = arg(a).ok_or_else(|| {
                malformed(format!(
                    "step {id}: argument {name} is not lit, ref, or item"
                ))
            })?;
            Ok((name.clone(), parsed))
        })
        .collect()
}
/// Parse an SDG-L3 v0.1 JSON plan into the verifier's form (structure only, no checks).
/// This is the only plan parser: the verifier and every executor read a plan through it
/// (ROADMAP 11f), so the plan that runs is the plan that was verified.
pub fn parse_plan(v: &Value) -> Result<Plan> {
    read_plan(v).map_err(|e| e.error)
}
/// Refuse every member of `v` outside `allowed`: the plan schema's
/// `additionalProperties: false` and `unevaluatedProperties: false` (0003 §1).
fn only(v: &Value, allowed: &[&str], what: &str) -> std::result::Result<(), ParseError> {
    let object = v
        .as_object()
        .ok_or_else(|| malformed(format!("{what} is not an object")))?;
    match object.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(malformed(format!(
            "{what} has a member {k} the plan schema does not allow"
        ))),
        None => Ok(()),
    }
}
/// [`parse_plan`] with a sentence that names what does not parse.
pub fn read_plan(v: &Value) -> std::result::Result<Plan, ParseError> {
    match v["v"].as_str() {
        Some("0.1") => {}
        Some(other) => {
            return Err(ParseError {
                error: Error::UnsupportedVersion,
                detail: format!("plan version {other} is not 0.1"),
            })
        }
        None => return Err(malformed("plan has no string v")),
    }
    only(v, &["v", "goal", "budget", "steps"], "the plan")?;
    if v.get("goal").is_some_and(|goal| !goal.is_string()) {
        return Err(malformed("plan goal is not a string"));
    }
    let budget = v
        .get("budget")
        .map(|b| {
            only(b, &["max"], "budget")?;
            only(&b["max"], &["amount", "currency"], "budget.max")?;
            Ok((
                member(&b["max"], "amount", "budget.max")?.into(),
                member(&b["max"], "currency", "budget.max")?.into(),
            ))
        })
        .transpose()?;
    let steps = v["steps"]
        .as_array()
        .ok_or_else(|| malformed("plan has no steps array"))?
        .iter()
        .map(|s| {
            let id: String = member(s, "id", "a step")?.into();
            let what = format!("step {id}");
            let approval = match s.get("approval") {
                None => false,
                Some(v) => v
                    .as_bool()
                    .ok_or_else(|| malformed(format!("{what}: approval is not a boolean")))?,
            };
            let kind = member(s, "kind", &what)?;
            only(
                s,
                match kind {
                    "expr" => &["id", "kind", "expr"][..],
                    "call" => &["id", "kind", "capability", "approval", "args"][..],
                    _ => &[
                        "id",
                        "kind",
                        "capability",
                        "approval",
                        "args",
                        "over",
                        "bound",
                    ][..],
                },
                &what,
            )?;
            Ok(match kind {
                "expr" => Step::Expr {
                    expr: member(s, "expr", &what)?.into(),
                    id,
                },
                "call" => Step::Call {
                    capability: member(s, "capability", &what)?.into(),
                    approval,
                    args: args(&s["args"], &id)?,
                    id,
                },
                "map" => Step::Map {
                    capability: member(s, "capability", &what)?.into(),
                    approval,
                    args: args(&s["args"], &id)?,
                    // A map's `over` is a whole earlier output; v0.1 has no `field` there.
                    over: match s["over"].as_object().and_then(reference) {
                        Some(Arg::Ref { step, field: None }) => step,
                        _ => {
                            return Err(malformed(format!(
                                "{what}: over is not a ref to an earlier output"
                            )))
                        }
                    },
                    bound: s["bound"]
                        .as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or_else(|| {
                            malformed(format!("{what}: bound is not an integer in range"))
                        })?,
                    id,
                },
                other => return Err(malformed(format!("{what}: unknown kind {other}"))),
            })
        })
        .collect::<std::result::Result<Vec<_>, ParseError>>()?;
    Ok(Plan { budget, steps })
}
fn strings(v: &Value) -> Result<Vec<String>> {
    v.as_array()
        .ok_or(Error::Malformed)?
        .iter()
        .map(|v| v.as_str().map(str::to_owned).ok_or(Error::Malformed))
        .collect()
}
/// Parse a JSON array of SDG-L1 descriptors into the verifier's capability table.
pub fn parse_catalog(v: &Value) -> Result<HashMap<String, Cap>> {
    let mut caps = HashMap::new();
    for c in v.as_array().ok_or(Error::Malformed)? {
        let cost = match text(&c["cost"], "class")? {
            "free" => None,
            "metered" => Some((
                text(&c["cost"]["max"], "amount")?.into(),
                text(&c["cost"]["max"], "currency")?.into(),
            )),
            _ => return Err(Error::Malformed),
        };
        let cap = Cap {
            effects: strings(&c["effects"])?,
            data_classes: strings(&c["data_classes"])?,
            consequential: c["consequential"].as_bool().ok_or(Error::Malformed)?,
            cost,
            outputs: c["output_schema"]["properties"]
                .as_object()
                .map(|properties| properties.keys().cloned().collect())
                .unwrap_or_default(),
        };
        if caps.insert(text(c, "id")?.into(), cap).is_some() {
            return Err(Error::Malformed);
        }
    }
    Ok(caps)
}
#[cfg(test)]
#[path = "../../../spec/test-vectors/plan/stored_plan_runner.rs"]
mod vectors;
