// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Standardized Result Artifact Records and declarative `ResultSurface` generator
//! (WP 1 & WP 3: Resultat-Dock & Atomic `@vaiev/ui` Primitives).
//!
//! Supported artifact MIME types (`record["type"]`):
//! - `application/vnd.sidged.artifact.mail+json`
//! - `application/vnd.sidged.artifact.code+json`
//! - `application/vnd.sidged.artifact.solution+json`

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{Error, Record};

pub const MIME_ARTIFACT_MAIL: &str = "application/vnd.sidged.artifact.mail+json";
pub const MIME_ARTIFACT_CODE: &str = "application/vnd.sidged.artifact.code+json";
pub const MIME_ARTIFACT_SOLUTION: &str = "application/vnd.sidged.artifact.solution+json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailArtifact {
    pub to: Vec<String>,
    pub subject: String,
    pub body: String,
    #[serde(default)]
    pub attachments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodeFileEntry {
    pub path: String,
    pub diff: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodeArtifact {
    pub files: Vec<CodeFileEntry>,
    pub test_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolutionArtifact {
    pub title: String,
    pub summary: String,
    pub markdown_body: String,
    pub reusable_plan_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "artifact_kind", content = "payload")]
pub enum ArtifactPayload {
    Mail(MailArtifact),
    Code(CodeArtifact),
    Solution(SolutionArtifact),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StepTimelineItem {
    pub step_id: String,
    pub label: String,
    pub status: String,
    pub worker_id: Option<String>,
    pub requires_owner_gate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowBadgeSpec {
    pub mode: String,
    pub label: String,
    pub residency: Vec<String>,
}

impl ArtifactPayload {
    pub fn mime_type(&self) -> &'static str {
        match self {
            Self::Mail(_) => MIME_ARTIFACT_MAIL,
            Self::Code(_) => MIME_ARTIFACT_CODE,
            Self::Solution(_) => MIME_ARTIFACT_SOLUTION,
        }
    }

    pub fn default_data_class(&self) -> &'static str {
        match self {
            Self::Mail(_) => "communications.content",
            Self::Code(_) => "documents.text",
            Self::Solution(_) => "documents.text",
        }
    }

    pub fn consequential_capability(&self) -> &'static str {
        match self {
            Self::Mail(_) => "urn:sidged:capability:message.send",
            Self::Code(_) | Self::Solution(_) => "urn:sidged:capability:workspace.write",
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Mail(m) => {
                if m.to.is_empty() || m.subject.trim().is_empty() || m.body.trim().is_empty() {
                    return Err(Error::Malformed);
                }
            }
            Self::Code(c) => {
                if c.files.is_empty()
                    || c.files
                        .iter()
                        .any(|f| f.path.trim().is_empty() || f.path.contains(".."))
                {
                    return Err(Error::Malformed);
                }
            }
            Self::Solution(s) => {
                if s.title.trim().is_empty()
                    || s.summary.trim().is_empty()
                    || s.markdown_body.trim().is_empty()
                {
                    return Err(Error::Malformed);
                }
            }
        }
        Ok(())
    }

    pub fn to_content_value(&self) -> Result<Value, Error> {
        self.validate()?;
        match self {
            Self::Mail(m) => serde_json::to_value(m).map_err(|_| Error::Malformed),
            Self::Code(c) => serde_json::to_value(c).map_err(|_| Error::Malformed),
            Self::Solution(s) => serde_json::to_value(s).map_err(|_| Error::Malformed),
        }
    }

    pub fn from_record(record: &Record) -> Result<Self, Error> {
        let v = record.as_value();
        let mime = v["type"].as_str().ok_or(Error::Malformed)?;
        let content = &v["content"];
        let parsed = match mime {
            MIME_ARTIFACT_MAIL => {
                let m: MailArtifact =
                    serde_json::from_value(content.clone()).map_err(|_| Error::Malformed)?;
                Self::Mail(m)
            }
            MIME_ARTIFACT_CODE => {
                let c: CodeArtifact =
                    serde_json::from_value(content.clone()).map_err(|_| Error::Malformed)?;
                Self::Code(c)
            }
            MIME_ARTIFACT_SOLUTION => {
                let s: SolutionArtifact =
                    serde_json::from_value(content.clone()).map_err(|_| Error::Malformed)?;
                Self::Solution(s)
            }
            _ => return Err(Error::Malformed),
        };
        parsed.validate()?;
        Ok(parsed)
    }
}

/// Build and sign a canonical `sidged-record::Record` containing a typed `ArtifactPayload`.
#[allow(clippy::too_many_arguments)]
pub fn sign_artifact_record(
    payload: &ArtifactPayload,
    owner_did: &str,
    source_capability: &str,
    created_utc: &str,
    derived_from: Vec<String>,
    plan_digest: Option<String>,
    residency_tags: Vec<String>,
    signer_seed: &[u8; 32],
) -> Result<Record, Error> {
    let content = payload.to_content_value()?;
    let unsigned = json!({
        "v": "0.1",
        "type": payload.mime_type(),
        "class": payload.default_data_class(),
        "owner": owner_did,
        "provenance": {
            "source": source_capability,
            "created": created_utc,
            "derived_from": derived_from,
            "plan": plan_digest,
        },
        "residency": {
            "tags": residency_tags,
        },
        "retention": {
            "until": null,
            "on_expiry": "delete"
        },
        "content": content,
    });
    Record::sign(unsigned, signer_seed)
}

/// Generate a declarative A2UI `ResultSurface` composed of atomic `@vaiev/ui` primitives
/// (`IntentHeader`, `FlowBadge`, `ArtifactCard`, `StepTimeline`) from a signed artifact `Record`.
pub fn build_result_surface(
    record: &Record,
    intent_title: &str,
    active_workers: usize,
    flow_badge: &FlowBadgeSpec,
    timeline: &[StepTimelineItem],
) -> Result<Value, Error> {
    let payload = ArtifactPayload::from_record(record)?;
    let record_id = record.identifier()?;
    let record_digest = record.digest()?;
    let consequential_cap = payload.consequential_capability();

    let artifact_card = match &payload {
        ArtifactPayload::Mail(m) => json!({
            "primitive": "ArtifactCard",
            "artifact_type": MIME_ARTIFACT_MAIL,
            "record_id": record_id,
            "title": format!("Mail Draft: {}", m.subject),
            "subtitle": format!("To: {}", m.to.join(", ")),
            "body": m.body,
            "attachments": m.attachments,
            "consequential_action": {
                "capability": consequential_cap,
                "gate_hint": "Requires owner confirmation on control.sock (0004 R9)"
            }
        }),
        ArtifactPayload::Code(c) => json!({
            "primitive": "ArtifactCard",
            "artifact_type": MIME_ARTIFACT_CODE,
            "record_id": record_id,
            "title": format!("Code Artifact ({} file(s))", c.files.len()),
            "subtitle": c.test_summary,
            "files": c.files,
            "consequential_action": {
                "capability": consequential_cap,
                "gate_hint": "Requires owner confirmation to export via workspace.write"
            }
        }),
        ArtifactPayload::Solution(s) => json!({
            "primitive": "ArtifactCard",
            "artifact_type": MIME_ARTIFACT_SOLUTION,
            "record_id": record_id,
            "title": s.title,
            "subtitle": s.summary,
            "body": s.markdown_body,
            "reusable_plan_digest": s.reusable_plan_digest,
            "consequential_action": {
                "capability": consequential_cap,
                "gate_hint": "Requires owner confirmation to export via workspace.write"
            }
        }),
    };

    Ok(json!({
        "component": "ResultSurface",
        "props": {
            "record_id": record_id,
            "record_digest": record_digest,
            "primitives": [
                {
                    "primitive": "IntentHeader",
                    "title": intent_title,
                    "active_workers": active_workers,
                    "status": "completed"
                },
                {
                    "primitive": "FlowBadge",
                    "mode": flow_badge.mode,
                    "label": flow_badge.label,
                    "residency": flow_badge.residency
                },
                artifact_card,
                {
                    "primitive": "StepTimeline",
                    "steps": timeline
                }
            ]
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mail_code_and_solution_artifacts_roundtrip_and_build_result_surface() {
        let seed = [0x42u8; 32];
        let pubkey = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let owner_did = sidged_grant::did_key(&pubkey);

        let mail = ArtifactPayload::Mail(MailArtifact {
            to: vec!["team@vaiev.ch".into()],
            subject: "Architecture Update".into(),
            body: "All invariants verified.".into(),
            attachments: vec![],
        });
        let rec_mail = sign_artifact_record(
            &mail,
            &owner_did,
            "urn:sidged:capability:draft.mail",
            "2026-10-20T00:00:00Z",
            vec![],
            Some("sha256:1111".into()),
            vec!["CH".into()],
            &seed,
        )
        .unwrap();
        let checked = Record::check(
            rec_mail.as_value().clone(),
            std::slice::from_ref(&owner_did),
        )
        .unwrap();
        assert_eq!(ArtifactPayload::from_record(&checked).unwrap(), mail);

        let badge = FlowBadgeSpec {
            mode: "local".into(),
            label: "100% Local Processing".into(),
            residency: vec!["CH".into()],
        };
        let timeline = vec![StepTimelineItem {
            step_id: "s1".into(),
            label: "Draft email".into(),
            status: "completed".into(),
            worker_id: Some("worker-1".into()),
            requires_owner_gate: true,
        }];
        let surface =
            build_result_surface(&checked, "Write status email", 2, &badge, &timeline).unwrap();
        assert_eq!(surface["component"], "ResultSurface");
        assert_eq!(
            surface["props"]["primitives"][0]["primitive"],
            "IntentHeader"
        );
        assert_eq!(surface["props"]["primitives"][1]["primitive"], "FlowBadge");
        assert_eq!(
            surface["props"]["primitives"][2]["primitive"],
            "ArtifactCard"
        );
        assert_eq!(
            surface["props"]["primitives"][2]["consequential_action"]["capability"],
            "urn:sidged:capability:message.send"
        );
        assert_eq!(
            surface["props"]["primitives"][3]["primitive"],
            "StepTimeline"
        );
    }
}
