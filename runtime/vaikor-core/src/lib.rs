//! Core objects the hosted runtime passes between crates.
//!
//! No I/O and no third-party crates. Capability descriptors, grants, and
//! plans stay in their own crates. This module is the record they share.

/// One registered capability, reduced to the fields the verifier and the
/// gateway need. The full descriptor remains the JSON document in `spec/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRecord {
    pub id: String,
    pub effects: Vec<String>,
    pub data_classes: Vec<String>,
    pub consequential: bool,
    pub cost_amount: Option<String>,
    pub cost_currency: Option<String>,
    pub residency: Vec<String>,
}

impl CapabilityRecord {
    pub fn is_egress(&self) -> bool {
        self.effects.iter().any(|effect| effect == "egress")
    }

    pub fn is_consequential(&self) -> bool {
        self.consequential
    }
}

/// One line in the audit log. Values of arguments are not stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// Serialized privacy report for gateway report events; no payload values.
    pub privacy_report: Option<String>,
    /// Signed ledger reservation: issuer/token id, leaf right index, and bound.
    pub usage: Option<(String, usize, u64)>,
    pub reason: Option<String>,
    pub step: String,
    pub capability: String,
    pub effects: Vec<String>,
    pub data_classes: Vec<String>,
    pub decision: String,
    /// Who decided. `core` for a grant or residency decision. The Trusted UI
    /// channel names the person for approve and deny.
    pub actor: String,
    /// RFC 3339 time of the decision.
    pub at: String,
    /// 0004 R11: approval facts as schema fields. `None` is not serialized,
    /// so events without approval facts keep their old byte form.
    pub approval: Option<ApprovalAudit>,
}

/// 0004 R9/R9c/R11 approval audit fields. The three R11
/// fields `attestation`, `undetected` and `approval_binding` are always
/// written, with explicit values when nothing was attested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalAudit {
    /// The configured approver uid.
    pub approver_uid: Option<u32>,
    /// The SO_PEERCRED uid of a rejected peer (`None` when unknown).
    pub observed_uid: Option<u32>,
    /// `R9c` when the start checks ran, else [`ApprovalAudit::NONE`].
    pub attestation: String,
    /// What the R9c start checks do not detect (`[]` without R9c).
    pub undetected: Vec<String>,
    /// `operator-attested` only with `--operator-attest`, else
    /// [`ApprovalAudit::NONE`].
    pub approval_binding: String,
}

impl ApprovalAudit {
    /// The explicit "not attested" value of `attestation` and `approval_binding`.
    pub const NONE: &'static str = "none";

    /// All three R11 fields with their explicit non-attested values.
    pub fn not_attested() -> Self {
        Self {
            approver_uid: None,
            observed_uid: None,
            attestation: Self::NONE.into(),
            undetected: Vec::new(),
            approval_binding: Self::NONE.into(),
        }
    }
}

impl Default for ApprovalAudit {
    fn default() -> Self {
        Self::not_attested()
    }
}

/// What `Runtime::execute` did with one plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReport {
    pub capabilities: Vec<String>,
    pub approvals: Vec<String>,
    pub egress: Vec<String>,
    pub events: Vec<AuditEvent>,
    /// Privacy-report documents for egress steps, as JSON text.
    pub reports: Vec<String>,
    /// Core-observed step outcomes; unsupported capabilities are report-only.
    pub results: std::collections::BTreeMap<String, String>,
}

/// Derive residency from Core-observed inputs (0012 R10).
/// An undeclared input stays undeclared; unrestricted never erases a restriction.
pub fn derive_residency(inputs: &[Vec<String>]) -> Result<Vec<String>, String> {
    if inputs
        .iter()
        .any(|tags| tags.len() > 1 && tags.iter().any(|t| t == "unrestricted"))
    {
        return Err("malformed residency declaration".into());
    }
    if inputs.is_empty() || inputs.iter().any(Vec::is_empty) {
        return Ok(Vec::new());
    }
    let mut tags: std::collections::BTreeSet<String> = inputs.iter().flatten().cloned().collect();
    if tags.len() > 1 {
        tags.remove("unrestricted");
    }
    Ok(tags.into_iter().collect())
}

/// Labels for a derived Record. Inputs must come from the Core's read tracking.
pub fn derive_record_labels(
    inputs: &[(String, Vec<String>)],
) -> Result<(String, Vec<String>), String> {
    let class = inputs
        .iter()
        .map(|(class, _)| class)
        .find(|candidate| {
            inputs.iter().all(|(class, _)| {
                class == *candidate
                    || class
                        .strip_prefix(candidate.as_str())
                        .is_some_and(|suffix| suffix.starts_with('.'))
            })
        })
        .ok_or("data-class-forbidden")?;
    let tags = derive_residency(
        &inputs
            .iter()
            .map(|(_, tags)| tags.clone())
            .collect::<Vec<_>>(),
    )?;
    Ok((class.clone(), tags))
}

/// Registered residency tag syntax; owner mappings are resolved at egress.
pub fn valid_residency_tag(tag: &str) -> bool {
    matches!(tag, "CH" | "EU" | "CH-EU" | "unrestricted")
        || (tag.starts_with("x-")
            && tag.len() > 2
            && tag.len() <= 64
            && tag
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_and_consequential_are_visible_on_the_record() {
        let record = CapabilityRecord {
            id: "tag:vaikor.com,2026:capability:message.send".into(),
            effects: vec!["egress".into()],
            data_classes: vec!["communications.content".into()],
            consequential: true,
            cost_amount: None,
            cost_currency: None,
            residency: vec!["CH".into()],
        };
        assert!(record.is_egress());
        assert!(record.is_consequential());
    }
}
