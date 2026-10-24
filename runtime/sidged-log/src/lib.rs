//! Append-only audit log. Events record decisions, not argument values.
//! `Chain` is the on-disk form: each line names the previous line's hash
//! and carries an Ed25519 signature.

mod chain;
pub mod oslock;

use sidged_core::AuditEvent;

pub use chain::{public_key, read_events, verify_file, Chain};

/// Resolve the audit chain independently of the working directory.
pub fn log_path(configured: Option<&str>, key_present: bool) -> Result<Option<String>, String> {
    if !key_present {
        return if configured.is_some() {
            Err("--log-key is required to write the audit log".into())
        } else {
            Ok(None)
        };
    }
    let path = match configured {
        Some(path) => std::path::PathBuf::from(path),
        None => {
            let base = std::env::var_os("XDG_STATE_HOME")
                .filter(|v| !v.is_empty())
                .map(std::path::PathBuf::from)
                .or_else(|| {
                    std::env::var_os("HOME")
                        .map(|home| std::path::PathBuf::from(home).join(".local/state"))
                })
                .ok_or("audit log requires XDG_STATE_HOME or HOME")?;
            if !base.is_absolute() {
                return Err("audit state directory must be absolute".into());
            }
            base.join("sidged/audit.log")
        }
    };
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    Ok(Some(
        path.to_str().ok_or("audit path is not UTF-8")?.to_string(),
    ))
}

#[cfg(test)]
mod path_tests {
    use super::log_path;

    #[test]
    fn a_log_key_without_a_path_uses_the_default_file() {
        assert_eq!(log_path(None, false).unwrap(), None);
        assert!(log_path(None, true)
            .unwrap()
            .unwrap()
            .ends_with("/sidged/audit.log"));
        assert!(log_path(Some("audit.log"), true)
            .unwrap()
            .unwrap()
            .ends_with("/audit.log"));
        assert!(log_path(Some("audit.log"), false).is_err());
    }
}

#[derive(Debug, Default, Clone)]
pub struct Log {
    events: Vec<AuditEvent>,
}

impl Log {
    pub fn append(&mut self, event: AuditEvent) {
        self.events.push(event);
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    pub fn to_json_lines(&self) -> String {
        let mut out = String::new();
        for event in &self.events {
            out.push('{');
            write_field(&mut out, "step", &event.step);
            out.push(',');
            write_field(&mut out, "capability", &event.capability);
            out.push(',');
            write_field(&mut out, "decision", &event.decision);
            out.push(',');
            write_field(&mut out, "actor", &event.actor);
            out.push(',');
            write_field(&mut out, "at", &event.at);
            if let Some(report) = &event.privacy_report {
                out.push(',');
                write_field(&mut out, "privacy_report", report);
            }
            out.push_str("}\n");
        }
        out
    }
}

fn write_field(out: &mut String, name: &str, value: &str) {
    out.push('"');
    out.push_str(name);
    out.push_str("\":");
    write_string(out, value);
}

fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_stay_in_order() {
        let mut log = Log::default();
        log.append(AuditEvent {
            privacy_report: None,
            usage: None,
            reason: None,
            step: "send".into(),
            capability: "urn:sidged:capability:message.send".into(),
            effects: vec!["egress".into()],
            data_classes: vec!["communications.content".into()],
            decision: "allow".into(),
            actor: "core".into(),
            at: "2026-10-15T00:00:00Z".into(),
            approval: None,
        });
        assert_eq!(log.events().len(), 1);
        assert!(log.to_json_lines().contains("\"actor\":\"core\""));
        assert!(log
            .to_json_lines()
            .contains("\"at\":\"2026-10-15T00:00:00Z\""));
        assert!(log.to_json_lines().contains("\"decision\":\"allow\""));
    }

    #[test]
    fn quotes_in_ids_are_escaped() {
        let mut log = Log::default();
        log.append(AuditEvent {
            privacy_report: None,
            usage: None,
            reason: None,
            step: "a\"b".into(),
            capability: "urn:sidged:capability:x".into(),
            effects: Vec::new(),
            data_classes: Vec::new(),
            decision: "allow".into(),
            actor: "core".into(),
            at: "2026-10-15T00:00:00Z".into(),
            approval: None,
        });
        assert!(log.to_json_lines().contains(r#""step":"a\"b""#));
    }
}
