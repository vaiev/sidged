//! 0007 §5.3 Core-checked anonymization: checks A-D (R11), detector set
//! `sdg.pii/1` (R12), and the R13 audit record. Deterministic: no network,
//! no model. The record never holds the payload or matched text.
use std::sync::OnceLock;

use regex::Regex;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

pub const DETECTOR_VERSION: &str = "sdg.pii/1";
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 32 * 1024;
/// Default export threshold for every destination class (R11 A).
pub const DEFAULT_EXPORT_THRESHOLD: &[&str] = &["query", "documents.text"];

/// Built with [`Check::new`]; the fields are crate-private so the owner
/// export threshold (R11 A) cannot be set by a caller.
pub struct Check<'a> {
    pub(crate) provider: &'a str,
    /// `CH`, `EU` or `GLOBAL`.
    pub(crate) destination_class: &'a str,
    /// Input classes from the Core's record (never from the model/payload).
    pub(crate) read_classes: &'a [&'a str],
    /// Derived residency tags.
    pub(crate) tags: &'a [String],
    /// The exact bytes to be sent.
    pub(crate) payload: &'a [u8],
    pub(crate) max_payload_bytes: Option<usize>,
    /// Configured detector version; `None` = `sdg.pii/1`.
    pub(crate) detector_version: Option<&'a str>,
    /// Owner export threshold for this destination class (R11 A);
    /// `None` = [`DEFAULT_EXPORT_THRESHOLD`].
    pub(crate) export_threshold: Option<&'a [&'a str]>,
}

impl<'a> Check<'a> {
    /// The per-call inputs of a 0007 §5.3 check. Size limit, detector
    /// version and export threshold take the owner-policy defaults.
    pub fn new(
        provider: &'a str,
        destination_class: &'a str,
        read_classes: &'a [&'a str],
        tags: &'a [String],
        payload: &'a [u8],
    ) -> Self {
        Self {
            provider,
            destination_class,
            read_classes,
            tags,
            payload,
            max_payload_bytes: None,
            detector_version: None,
            export_threshold: None,
        }
    }
    /// Owner-configured `max_payload_bytes` (R11 C); `None` = default.
    // Owner-policy override (R11 C); no production caller yet, exercised by unit tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn with_max_payload_bytes(mut self, max: Option<usize>) -> Self {
        self.max_payload_bytes = max;
        self
    }
    /// Configured detector version (R12a); `None` = [`DETECTOR_VERSION`].
    pub fn with_detector_version(mut self, version: Option<&'a str>) -> Self {
        self.detector_version = version;
        self
    }
}

pub struct Outcome {
    /// `None` = permit; otherwise the R11 reason code.
    pub refusal: Option<String>,
    /// The R13 audit record (permit or refuse).
    pub record: serde_json::Value,
}

fn covered(class: &str, allowed: &str) -> bool {
    class == allowed
        || class
            .strip_prefix(allowed)
            .is_some_and(|rest| rest.starts_with('.'))
}

fn detectors() -> &'static [(&'static str, Regex)] {
    static SET: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    SET.get_or_init(|| {
        let r = |p: &str| Regex::new(&format!("(?i){p}")).expect("sdg.pii/1 pattern");
        vec![
            ("email", r(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}")),
            ("phone", r(r"\+?\d[\d ().-]{7,}\d")),
            ("iban", r(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b")),
            ("ch-ahv", r(r"\b756[.\s]?\d{4}[.\s]?\d{4}[.\s]?\d{2}\b")),
            // A whole digit run (spaces/dashes allowed), checked as one run
            // below: 13-19 digits + Luhn. Whole-run is the normative reading
            // of 0007 R12 for sdg.pii/1 (lead ruling); windowing inside a
            // longer run would be sdg.pii/2 (R12a), deferred.
            ("card", r(r"\d(?:[ -]?\d){12,}")),
            ("ipv4", r(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
            (
                "secret",
                r(r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{16,}|\bgh[pousr]_[A-Za-z0-9]{20,}|\bAKIA[0-9A-Z]{16}\b|\bxox[abpr]-[A-Za-z0-9-]{10,}"),
            ),
        ]
    })
}

fn luhn(digits: &[u32]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 {
                    x - 9
                } else {
                    x
                }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

/// Detector ids that match the NFKC-normalized text (R11 D, R12).
pub fn detect(text: &str) -> Vec<&'static str> {
    let text: String = text.nfkc().collect();
    let mut hits = Vec::new();
    for (id, re) in detectors() {
        let hit = match *id {
            "phone" => re
                .find_iter(&text)
                .any(|m| m.as_str().chars().filter(char::is_ascii_digit).count() >= 9),
            // sdg.pii/1 exactly (R12 table, R12a): a whole digit run of 13
            // to 19 digits that passes Luhn. A longer run is not a /1 card;
            // windowing inside it is a later sdg.pii/2.
            "card" => re.find_iter(&text).any(|m| {
                let d: Vec<u32> = m.as_str().chars().filter_map(|c| c.to_digit(10)).collect();
                (13..=19).contains(&d.len()) && luhn(&d)
            }),
            _ => re.is_match(&text),
        };
        if hit {
            hits.push(*id);
        }
    }
    hits
}

pub fn egress_check(c: &Check) -> Outcome {
    let mut classes: Vec<&str> = c.read_classes.to_vec();
    classes.sort_unstable();
    classes.dedup();
    let version = c.detector_version.unwrap_or(DETECTOR_VERSION);
    let mut record = serde_json::json!({
        "check": "0007-5.3",
        "payload_sha256": format!("{:x}", Sha256::digest(c.payload)),
        "payload_bytes": c.payload.len(),
        "detector_version": version,
        "input_classes": classes,
        "residency_tags": c.tags,
        "destination_class": c.destination_class,
        "provider": c.provider,
    });
    let refuse = |mut record: serde_json::Value, reason: &str, failed: &str| {
        record["result"] = "refuse".into();
        record["reason"] = reason.into();
        record["failed_check"] = failed.into();
        Outcome {
            refusal: Some(reason.into()),
            record,
        }
    };
    if version != DETECTOR_VERSION {
        return refuse(record, "policy-denied", "R12a");
    }
    // A: classes from the Core record; none, or any above the owner's
    // configured threshold (default only `query`, `documents.text`).
    let threshold = c.export_threshold.unwrap_or(DEFAULT_EXPORT_THRESHOLD);
    if classes.is_empty()
        || classes
            .iter()
            .any(|class| !threshold.iter().any(|allowed| covered(class, allowed)))
    {
        return refuse(record, "data-class-forbidden", "A");
    }
    // B: residency (0001 R8), fail closed on missing tags.
    if c.tags.is_empty()
        || crate::residency_destination(
            c.tags,
            c.destination_class,
            &std::collections::HashMap::new(),
        )
        .is_err()
    {
        return refuse(record, "residency-unsupported", "B");
    }
    // C: size.
    if c.payload.len() > c.max_payload_bytes.unwrap_or(DEFAULT_MAX_PAYLOAD_BYTES) {
        return refuse(record, "policy-denied", "C");
    }
    // D: detectors on the UTF-8 payload after NFKC.
    let Ok(text) = std::str::from_utf8(c.payload) else {
        return refuse(record, "data-class-forbidden", "D");
    };
    let hits = detect(text);
    record["matched_detectors"] = serde_json::json!(hits);
    if !hits.is_empty() {
        return refuse(record, "data-class-forbidden", "D");
    }
    record["result"] = "permit".into();
    Outcome {
        refusal: None,
        record,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Vec<Value> {
        let d: Value = serde_json::from_str(include_str!(
            "../../../spec/test-vectors/egress/anonymization.json"
        ))
        .unwrap();
        d["vectors"].as_array().unwrap().clone()
    }

    #[test]
    fn normative_vectors_a_to_d() {
        let mut ran = 0;
        for v in vectors() {
            let i = &v["input"];
            let exp = &v["expected"];
            let reason = exp["reason"].as_str();
            if matches!(reason, Some("approval-required" | "budget-exceeded"))
                || i["route"] == "local"
            {
                continue;
            }
            let classes: Vec<&str> = i["read_classes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| c.as_str().unwrap())
                .collect();
            let tags: Vec<String> = i["tags"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| c.as_str().unwrap().to_string())
                .collect();
            let payload = i["payload"].as_str().unwrap();
            let check = Check::new(
                i["provider"].as_str().unwrap(),
                i["destination"].as_str().unwrap(),
                &classes,
                &tags,
                payload.as_bytes(),
            )
            .with_max_payload_bytes(i["max_payload_bytes"].as_u64().map(|n| n as usize))
            .with_detector_version(i["detector_version"].as_str());
            let out = egress_check(&check);
            match reason {
                None => assert!(out.refusal.is_none(), "{}: {:?}", v["id"], out.refusal),
                Some(r) => assert_eq!(out.refusal.as_deref(), Some(r), "{}", v["id"]),
            }
            ran += 1;
        }
        assert!(ran >= 20, "ran {ran}");
    }

    #[test]
    fn check_c_uses_the_configured_size_limit() {
        let tags = vec!["unrestricted".to_string()];
        let q: &[&str] = &["query"];
        let base = || {
            Check::new(
                "https://generativelanguage.googleapis.com/",
                "GLOBAL",
                q,
                &tags,
                b"a short public question",
            )
        };
        assert_eq!(
            egress_check(&base().with_max_payload_bytes(Some(4)))
                .refusal
                .as_deref(),
            Some("policy-denied")
        );
        assert_eq!(
            egress_check(&base().with_max_payload_bytes(None)).refusal,
            None
        );
    }

    // Check A uses the configured export threshold. The
    // threshold is owner policy, settable only inside the crate (pub(crate)).
    #[test]
    fn check_a_uses_the_configured_threshold() {
        let tags = vec!["unrestricted".to_string()];
        let run = |classes: &[&str], threshold: Option<&[&str]>| {
            let mut c = Check::new(
                "https://generativelanguage.googleapis.com/",
                "GLOBAL",
                classes,
                &tags,
                b"a short public question",
            );
            c.export_threshold = threshold;
            egress_check(&c).refusal
        };
        assert_eq!(run(&["query"], None), None);
        assert_eq!(
            run(&["query"], Some(&["documents.text"])).as_deref(),
            Some("data-class-forbidden")
        );
        assert_eq!(run(&["weather.public"], Some(&["weather"])), None);
        assert_eq!(
            run(&["query"], Some(&[])).as_deref(),
            Some("data-class-forbidden")
        );
    }
}
