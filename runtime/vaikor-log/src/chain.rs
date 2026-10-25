//! Append-only audit file. Each line is tied to the previous line by SHA-256
//! and signed with Ed25519.

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use vaikor_core::AuditEvent;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub struct Chain {
    path: std::path::PathBuf,
    seed: [u8; 32],
    prev: String,
    // Hold an exclusive OS lock through replay and all appends.
    file: fs::File,
}

impl Chain {
    pub fn open(path: &Path, seed: &[u8; 32]) -> Result<Self, String> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let mut lock = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)
            .map_err(|err| err.to_string())?;
        crate::oslock::try_lock_exclusive(&lock)
            .map_err(|err| format!("audit log is locked: {err}"))?;
        let mut text = String::new();
        lock.read_to_string(&mut text)
            .map_err(|err| err.to_string())?;
        verify_text(&text, &public_key(seed))?;
        let prev = text
            .lines()
            .rev()
            .find(|line| !line.is_empty())
            .map(|line| sha256_hex(line.as_bytes()))
            .unwrap_or_else(|| GENESIS.to_string());
        Ok(Self {
            path: path.to_path_buf(),
            seed: *seed,
            prev,
            file: lock,
        })
    }

    pub fn append(&mut self, event: &AuditEvent) -> Result<(), String> {
        let payload = payload_json(event);
        let message = format!("{}.{}", self.prev, payload);
        let sig = hex(&sign(&self.seed, message.as_bytes()));
        let line = format!("{} {} {}\n", self.prev, sig, payload);
        self.file
            .write_all(line.as_bytes())
            .map_err(|err| err.to_string())?;
        self.file.sync_all().map_err(|err| err.to_string())?;
        self.prev = sha256_hex(line.trim_end_matches('\n').as_bytes());
        Ok(())
    }

    /// Replay the same inode protected by this chain's lock.
    pub fn read_events(&mut self) -> Result<Vec<AuditEvent>, String> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|err| err.to_string())?;
        let mut text = String::new();
        self.file
            .read_to_string(&mut text)
            .map_err(|err| err.to_string())?;
        verify_text(&text, &public_key(&self.seed))?;
        text.lines()
            .filter(|line| !line.is_empty())
            .map(|line| parse_payload(line.splitn(3, ' ').nth(2).ok_or("audit line")?))
            .collect()
    }

    /// Digest of the last durably appended signed audit entry.
    pub fn head_digest(&self) -> &str {
        &self.prev
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Chain {
    /// Release the flock explicitly before the fd closes. The lock belongs to the
    /// open file description; a child forked by another thread holds a copy of
    /// the fd until its exec (O_CLOEXEC), so relying on close() alone keeps the
    /// lock alive for that window and a reopen fails with "audit log is locked".
    fn drop(&mut self) {
        let _ = crate::oslock::unlock(&self.file);
    }
}

pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

pub fn verify_file(path: &Path, public: &[u8; 32]) -> Result<usize, String> {
    let text = fs::read_to_string(path).map_err(|err| err.to_string())?;
    verify_text(&text, public)
}

fn verify_text(text: &str, public: &[u8; 32]) -> Result<usize, String> {
    let mut prev = GENESIS.to_string();
    let mut count = 0usize;
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(3, ' ');
        let got_prev = parts.next().ok_or("audit line")?;
        let sig = parts.next().ok_or("audit line")?;
        let payload = parts.next().ok_or("audit line")?;
        if got_prev != prev {
            return Err(format!("audit line {} breaks the hash chain", index + 1));
        }
        let message = format!("{got_prev}.{payload}");
        let raw = unhex(sig)?;
        if raw.len() != 64 {
            return Err("audit signature length".into());
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&raw);
        if !verify(public, message.as_bytes(), &signature) {
            return Err(format!("audit line {} signature", index + 1));
        }
        let _ = parse_payload(payload)?;
        prev = sha256_hex(line.as_bytes());
        count += 1;
    }
    Ok(count)
}

pub fn read_events(path: &Path, public: &[u8; 32]) -> Result<Vec<AuditEvent>, String> {
    verify_file(path, public)?;
    let text = fs::read_to_string(path).map_err(|err| err.to_string())?;
    let mut events = Vec::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let payload = line.splitn(3, ' ').nth(2).ok_or("audit line")?;
        events.push(parse_payload(payload)?);
    }
    Ok(events)
}

fn payload_json(event: &AuditEvent) -> String {
    let mut value = serde_json::json!({"step":event.step,"capability":event.capability,
        "effects":event.effects,"data_classes":event.data_classes,
        "decision":event.decision,"actor":event.actor,"at":event.at,
        "usage":event.usage,"reason":event.reason,"privacy_report":event.privacy_report});
    if let Some(approval) = &event.approval {
        let mut fields = serde_json::Map::new();
        if let Some(uid) = approval.approver_uid {
            fields.insert("approver_uid".into(), uid.into());
        }
        if let Some(uid) = approval.observed_uid {
            fields.insert("observed_uid".into(), uid.into());
        }
        // 0004 R11: all three fields, always.
        fields.insert("attestation".into(), approval.attestation.clone().into());
        fields.insert("undetected".into(), approval.undetected.clone().into());
        fields.insert(
            "approval_binding".into(),
            approval.approval_binding.clone().into(),
        );
        value["approval"] = fields.into();
    }
    value.to_string()
}

fn parse_payload(payload: &str) -> Result<AuditEvent, String> {
    let value: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
    let string = |key: &str| {
        value[key]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("audit {key}"))
    };
    Ok(AuditEvent {
        privacy_report: serde_json::from_value(value["privacy_report"].clone())
            .map_err(|e| e.to_string())?,
        step: string("step")?,
        capability: string("capability")?,
        effects: serde_json::from_value(value["effects"].clone()).map_err(|e| e.to_string())?,
        data_classes: serde_json::from_value(value["data_classes"].clone())
            .map_err(|e| e.to_string())?,
        decision: string("decision")?,
        actor: string("actor")?,
        at: string("at")?,
        usage: serde_json::from_value(value["usage"].clone()).map_err(|e| e.to_string())?,
        reason: serde_json::from_value(value["reason"].clone()).map_err(|e| e.to_string())?,
        approval: match value.get("approval") {
            None => None,
            Some(fields) => Some(parse_approval(fields)?),
        },
    })
}

fn parse_approval(fields: &serde_json::Value) -> Result<vaikor_core::ApprovalAudit, String> {
    let fields = fields.as_object().ok_or("audit approval")?;
    let uid = |key: &str| -> Result<Option<u32>, String> {
        fields
            .get(key)
            .map(|v| {
                v.as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| format!("audit approval {key}"))
            })
            .transpose()
    };
    let text = |key: &str| -> Result<String, String> {
        fields
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("audit approval {key}"))
    };
    Ok(vaikor_core::ApprovalAudit {
        approver_uid: uid("approver_uid")?,
        observed_uid: uid("observed_uid")?,
        attestation: text("attestation")?,
        undetected: serde_json::from_value(
            fields
                .get("undetected")
                .cloned()
                .ok_or("audit approval undetected")?,
        )
        .map_err(|e| e.to_string())?,
        approval_binding: text("approval_binding")?,
    })
}

fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(message).to_bytes()
}

fn verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes).as_slice())
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0xf) as usize] as char);
    }
    out
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 {
        return Err("odd hex".into());
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let hi = hex_value(bytes[index])?;
        let lo = hex_value(bytes[index + 1])?;
        out.push((hi << 4) | lo);
        index += 2;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("bad hex".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_reports_and_control_characters_round_trip() {
        let mut item = event("egress");
        item.step = "a\nb\rc\t\u{0001}".into();
        item.privacy_report = Some("{\n  \"nested\": {\"text\": \"line\\nnext\"}\n}".into());
        let parsed = parse_payload(&payload_json(&item)).unwrap();
        assert_eq!(parsed.step, item.step);
        assert_eq!(parsed.privacy_report, item.privacy_report);
    }

    // 0004 R11: approval facts are schema fields. Every approval
    // object carries all three R11 fields, explicit values included
    // ("none", []); events without an approval object are unchanged.
    #[test]
    fn approval_fields_round_trip_and_always_carry_the_three_r11_fields() {
        let plain = event("allow");
        let text = payload_json(&plain);
        assert!(!text.contains("\"approval\""), "{text}");
        assert_eq!(parse_payload(&text).unwrap(), plain);

        let mut item = event("approve");
        item.approval = Some(vaikor_core::ApprovalAudit {
            approver_uid: Some(4242),
            observed_uid: None,
            attestation: "R9c".into(),
            undetected: vec!["su-password".into(), "keys".into()],
            approval_binding: "operator-attested".into(),
        });
        let text = payload_json(&item);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["approval"]["approver_uid"], 4242);
        assert_eq!(value["approval"]["attestation"], "R9c");
        assert_eq!(
            value["approval"]["undetected"],
            serde_json::json!(["su-password", "keys"])
        );
        assert_eq!(value["approval"]["approval_binding"], "operator-attested");
        assert!(value["approval"].get("observed_uid").is_none(), "{text}");
        assert_eq!(parse_payload(&text).unwrap(), item);

        // Explicit non-attested values are still written.
        item.approval = Some(vaikor_core::ApprovalAudit::not_attested());
        let text = payload_json(&item);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["approval"]["attestation"], "none", "{text}");
        assert_eq!(
            value["approval"]["undetected"],
            serde_json::json!([]),
            "{text}"
        );
        assert_eq!(value["approval"]["approval_binding"], "none", "{text}");
        assert_eq!(parse_payload(&text).unwrap(), item);

        // An approval object missing any R11 field is refused on read.
        for key in ["attestation", "undetected", "approval_binding"] {
            let mut broken = value.clone();
            broken["approval"].as_object_mut().unwrap().remove(key);
            assert!(parse_payload(&broken.to_string()).is_err(), "{key}");
        }
    }

    fn event(decision: &str) -> AuditEvent {
        AuditEvent {
            privacy_report: None,
            usage: None,
            reason: None,
            step: "send".into(),
            capability: "tag:vaikor.com,2026:capability:message.send".into(),
            effects: vec!["egress".into()],
            data_classes: vec!["communications.content".into()],
            decision: decision.into(),
            actor: "ada".into(),
            at: "2026-10-15T00:00:00Z".into(),
            approval: None,
        }
    }

    fn seed() -> [u8; 32] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../spec/test-vectors/keys/rfc8032-test-keys.json");
        let text = fs::read_to_string(path).unwrap();
        let secret = text
            .split("\"secret_key_hex\": \"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let bytes = unhex(secret).unwrap();
        bytes.try_into().unwrap()
    }

    #[test]
    fn replay_keeps_the_locked_inode_when_the_path_is_replaced() {
        let path =
            std::env::temp_dir().join(format!("vaikor-path-swap-{}.log", std::process::id()));
        let moved = path.with_extension("original");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&moved);
        let mut chain = Chain::open(&path, &[42; 32]).unwrap();
        chain.append(&event("spend")).unwrap();
        fs::rename(&path, &moved).unwrap();
        fs::write(&path, "").unwrap();
        let events = chain.read_events().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].decision, "spend");
        chain.append(&event("allow")).unwrap();
        assert_eq!(verify_file(&moved, &public_key(&[42; 32])).unwrap(), 2);
        assert!(fs::read_to_string(&path).unwrap().is_empty());
        drop(chain);
        fs::remove_file(path).unwrap();
        fs::remove_file(moved).unwrap();
    }

    /// Regression: a child forked by another thread holds a copy of the audit fd
    /// between fork and exec (O_CLOEXEC only closes it at exec). flock belongs to
    /// the open file description, so without an explicit unlock on drop the lock
    /// outlives the Chain and a reopen fails with "audit log is locked".
    #[cfg(unix)]
    #[test]
    fn lock_is_released_on_drop_while_a_forked_child_holds_the_fd() {
        use std::os::unix::process::CommandExt;
        let path =
            std::env::temp_dir().join(format!("vaikor-fork-unlock-{}.log", std::process::id()));
        let _ = fs::remove_file(&path);
        let chain = Chain::open(&path, &[42; 32]).unwrap();
        let spawner = std::thread::spawn(|| {
            let mut command = std::process::Command::new("/bin/true");
            // SAFETY: only async-signal-safe work (a sleep) between fork and exec;
            // it widens the window in which the child holds the inherited fd.
            unsafe {
                command.pre_exec(|| {
                    std::thread::sleep(std::time::Duration::from_millis(1500));
                    Ok(())
                });
            }
            command.status().unwrap()
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        drop(chain);
        let reopened = Chain::open(&path, &[42; 32]);
        assert!(reopened.is_ok(), "{:?}", reopened.err());
        drop(reopened);
        assert!(spawner.join().unwrap().success());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn simultaneous_writers_are_refused() {
        let path = std::env::temp_dir().join(format!("vaikor-lock-{}.log", std::process::id()));
        let first = Chain::open(&path, &[42; 32]).unwrap();
        assert!(Chain::open(&path, &[42; 32]).is_err());
        drop(first);
        drop(Chain::open(&path, &[42; 32]).unwrap());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn the_file_survives_reopen_and_a_flipped_byte_fails() {
        let dir = std::env::temp_dir().join("vaikor-log-chain");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log");
        let key = seed();
        let public = public_key(&key);
        {
            let mut chain = Chain::open(&path, &key).unwrap();
            chain.append(&event("deny")).unwrap();
            chain.append(&event("approve")).unwrap();
        }
        let again = Chain::open(&path, &key).unwrap();
        let events = read_events(again.path(), &public).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].decision, "deny");
        assert_eq!(events[1].actor, "ada");
        assert!(
            Chain::open(&path, &key).is_err(),
            "concurrent writer must be refused"
        );
        drop(again);
        {
            let mut chain = Chain::open(&path, &key).unwrap();
            chain.append(&event("approve")).unwrap();
        }
        assert_eq!(verify_file(&path, &public).unwrap(), 3);
        let mut text = fs::read_to_string(&path).unwrap();
        let byte = text.as_bytes()[80];
        let flipped = if byte == b'a' { b'b' } else { b'a' };
        text.replace_range(80..81, std::str::from_utf8(&[flipped]).unwrap());
        fs::write(&path, &text).unwrap();
        assert!(verify_file(&path, &public).is_err());
        assert!(path.exists());
    }
}
