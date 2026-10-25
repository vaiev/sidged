//! VKR-L0 0012 canonical dCBOR and signed Records. File storage is available in `store`.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use unicode_normalization::is_nfc;
pub use vaikor_core::derive_record_labels;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Malformed,
    UnsupportedVersion,
    BadSignature,
    ResidencyUnknownTag,
    DataClassForbidden,
}
impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::UnsupportedVersion => "unsupported-version",
            Self::BadSignature => "bad-signature",
            Self::ResidencyUnknownTag => "residency-unknown-tag",
            Self::DataClassForbidden => "data-class-forbidden",
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
fn arg(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=255 => out.extend([m | 24, n as u8]),
        256..=65535 => {
            out.push(m | 25);
            out.extend((n as u16).to_be_bytes())
        }
        65536..=4294967295 => {
            out.push(m | 26);
            out.extend((n as u32).to_be_bytes())
        }
        _ => {
            out.push(m | 27);
            out.extend(n.to_be_bytes())
        }
    }
}
/// Encode the JSON tree using the 0012 profile. Nesting is limited to 128 levels.
pub fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    enc(value, &mut out, 0)?;
    Ok(out)
}
fn enc(v: &Value, o: &mut Vec<u8>, depth: usize) -> Result<()> {
    if depth > 128 {
        return Err(Error::Malformed);
    }
    match v {
        Value::Null => o.push(246),
        Value::Bool(b) => o.push(if *b { 245 } else { 244 }),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                arg(o, 0, u)
            } else if let Some(i) = n.as_i64() {
                arg(o, 1, (-1i128 - i as i128) as u64)
            } else {
                return Err(Error::Malformed);
            }
        }
        Value::String(s) => {
            if !is_nfc(s) {
                return Err(Error::Malformed);
            }
            arg(o, 3, s.len() as u64);
            o.extend(s.as_bytes())
        }
        Value::Array(a) => {
            arg(o, 4, a.len() as u64);
            for v in a {
                enc(v, o, depth + 1)?
            }
        }
        Value::Object(m) => {
            let mut entries = Vec::new();
            for (k, v) in m {
                entries.push((encode(&Value::String(k.clone()))?, v));
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            arg(o, 5, entries.len() as u64);
            for (k, v) in entries {
                o.extend(k);
                enc(v, o, depth + 1)?
            }
        }
    }
    Ok(())
}
/// Decode and re-encode to reject every non-canonical representation.
pub fn decode(bytes: &[u8]) -> Result<Value> {
    let mut d = Decoder { b: bytes, p: 0 };
    let v = d.value(0)?;
    if d.p != bytes.len() || encode(&v)? != bytes {
        return Err(Error::Malformed);
    }
    Ok(v)
}
struct Decoder<'a> {
    b: &'a [u8],
    p: usize,
}
impl Decoder<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self.p.checked_add(n).ok_or(Error::Malformed)?;
        let b = self.b.get(self.p..end).ok_or(Error::Malformed)?;
        self.p = end;
        Ok(b)
    }
    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth > 128 {
            return Err(Error::Malformed);
        }
        let h = self.take(1)?[0];
        let major = h >> 5;
        let a = h & 31;
        if major == 7 {
            return match h {
                244 => Ok(Value::Bool(false)),
                245 => Ok(Value::Bool(true)),
                246 => Ok(Value::Null),
                _ => Err(Error::Malformed),
            };
        }
        let n =
            match a {
                0..=23 => a as u64,
                24 => self.take(1)?[0] as u64,
                25 => u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| Error::Malformed)?)
                    as u64,
                26 => u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| Error::Malformed)?)
                    as u64,
                27 => u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| Error::Malformed)?),
                _ => return Err(Error::Malformed),
            };
        match major {
            0 => Ok(Value::from(n)),
            1 => {
                if n > i64::MAX as u64 {
                    return Err(Error::Malformed);
                }
                Ok(Value::from(-1 - (n as i64)))
            }
            3 => {
                let len = usize::try_from(n).map_err(|_| Error::Malformed)?;
                let s = std::str::from_utf8(self.take(len)?).map_err(|_| Error::Malformed)?;
                Ok(Value::String(s.to_owned()))
            }
            4 | 5 => {
                if n > self.b.len().saturating_sub(self.p) as u64 {
                    return Err(Error::Malformed);
                }
                if major == 4 {
                    let mut a = Vec::new();
                    for _ in 0..n {
                        a.push(self.value(depth + 1)?)
                    }
                    Ok(Value::Array(a))
                } else {
                    let mut m = Map::new();
                    for _ in 0..n {
                        let Value::String(k) = self.value(depth + 1)? else {
                            return Err(Error::Malformed);
                        };
                        let v = self.value(depth + 1)?;
                        if m.insert(k, v).is_some() {
                            return Err(Error::Malformed);
                        }
                    }
                    Ok(Value::Object(m))
                }
            }
            _ => Err(Error::Malformed),
        }
    }
}
pub fn signing_input(record: &Value) -> Result<Vec<u8>> {
    let mut m = record.as_object().ok_or(Error::Malformed)?.clone();
    m.remove("sig");
    encode(&Value::Object(m))
}
pub fn digest(record: &Value) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(signing_input(record)?)))
}
pub fn class_resource(class: &str) -> Result<String> {
    validate_class(class)?;
    Ok(format!(
        "tag:vaikor.com,2026:record:{}",
        class.replace('.', "/")
    ))
}
fn validate_class(c: &str) -> Result<()> {
    let root = c.split('.').next().unwrap_or("");
    let registered = include_str!("../../../spec/registries/data-classes.md")
        .lines()
        .filter_map(|line| {
            line.strip_prefix("| `")?
                .split_once('`')
                .map(|(root, _)| root)
        })
        .any(|registered| registered == root);
    if !c.split('.').all(|s| {
        !s.is_empty()
            && s.as_bytes()[0].is_ascii_alphanumeric()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    }) || !(registered || root.starts_with("x-"))
    {
        return Err(Error::Malformed);
    }
    Ok(())
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v.get(k).and_then(Value::as_str).ok_or(Error::Malformed)
}
fn timestamp(s: &str) -> Result<i64> {
    let instant = vaikor_grant::parse_rfc3339_z(s).ok_or(Error::Malformed)?;
    // The grant parser also accepts offsets and leap seconds. Records require
    // the exact UTC spelling and a valid calendar date, without normalisation.
    if vaikor_grant::format_rfc3339_z(instant) != s {
        return Err(Error::Malformed);
    }
    Ok(instant)
}
/// Structurally valid record, preserving every signed member including extensions.
#[derive(Debug, Clone)]
pub struct Record {
    value: Value,
}
impl Record {
    pub fn parse(value: Value) -> Result<Self> {
        encode(&value)?;
        let m = value.as_object().ok_or(Error::Malformed)?;
        for k in [
            "v",
            "type",
            "class",
            "owner",
            "provenance",
            "residency",
            "retention",
            "content",
            "sig",
        ] {
            if !m.contains_key(k) {
                return Err(Error::Malformed);
            }
        }
        if text(&value, "v")? != "0.1" {
            return Err(Error::UnsupportedVersion);
        }
        text(&value, "type")?;
        validate_class(text(&value, "class")?)?;
        vaikor_grant::resolve_did_key(text(&value, "owner")?).map_err(|_| Error::Malformed)?;
        let p = &value["provenance"];
        let source = text(p, "source")?;
        if !(source.starts_with("tag:vaikor.com,2026:capability:")
            || source.starts_with("tag:vaikor.com,2026:import:")
            || vaikor_grant::resolve_did_key(source).is_ok())
        {
            return Err(Error::Malformed);
        }
        timestamp(text(p, "created")?)?;
        let ds = p["derived_from"].as_array().ok_or(Error::Malformed)?;
        for d in ds {
            if !d.is_string() {
                return Err(Error::Malformed);
            }
        }
        if !p.get("plan").is_some_and(|v| v.is_null() || v.is_string()) {
            return Err(Error::Malformed);
        }
        let tags = value["residency"]["tags"]
            .as_array()
            .ok_or(Error::Malformed)?;
        for t in tags {
            if !vaikor_core::valid_residency_tag(t.as_str().ok_or(Error::Malformed)?) {
                return Err(Error::ResidencyUnknownTag);
            }
        }
        if tags.len() > 1 && tags.iter().any(|t| t == "unrestricted") {
            return Err(Error::Malformed);
        }
        let r = &value["retention"];
        match r.get("until") {
            Some(Value::Null) => {}
            Some(Value::String(s)) => {
                timestamp(s)?;
            }
            _ => return Err(Error::Malformed),
        }
        if !["delete", "tombstone"].contains(&text(r, "on_expiry")?) {
            return Err(Error::Malformed);
        }
        if !value["sig"].is_object() {
            return Err(Error::Malformed);
        }
        Ok(Self { value })
    }
    /// Verify against configured Core did:key anchors, never anchors supplied by the record.
    pub fn check(value: Value, trusted_core_keys: &[String]) -> Result<Self> {
        let record = Self::parse(value)?;
        let s = &record.value["sig"];
        let check = || -> Option<()> {
            let signer = s["signer"].as_str()?;
            if s["alg"] != "EdDSA"
                || s["canon"] != "dcbor"
                || s["kid"] != signer
                || !trusted_core_keys.iter().any(|k| k == signer)
            {
                return None;
            }
            let public = vaikor_grant::resolve_did_key(signer).ok()?;
            let signature: [u8; 64] = URL_SAFE_NO_PAD
                .decode(s["value"].as_str()?)
                .ok()?
                .try_into()
                .ok()?;
            vaikor_grant::verify(&public, &signing_input(&record.value).ok()?, &signature)
                .then_some(())
        };
        check().ok_or(Error::BadSignature)?;
        Ok(record)
    }
    /// Sign with a Core seed. Trust remains the verifier's configuration.
    pub fn sign(mut value: Value, seed: &[u8; 32]) -> Result<Self> {
        let public = ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes();
        let signer = vaikor_grant::did_key(&public);
        let signature = vaikor_grant::sign(seed, &signing_input(&value)?);
        value.as_object_mut().ok_or(Error::Malformed)?.insert(
            "sig".into(),
            serde_json::json!({
                "alg": "EdDSA", "canon": "dcbor", "kid": signer, "signer": signer,
                "value": URL_SAFE_NO_PAD.encode(signature)
            }),
        );
        Self::parse(value)
    }
    /// Canonical bytes including the signature, for exchange or future storage.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        encode(&self.value)
    }
    pub fn identifier(&self) -> Result<String> {
        Ok(format!("tag:vaikor.com,2026:record:{}", self.digest()?))
    }
    pub fn as_value(&self) -> &Value {
        &self.value
    }
    pub fn class(&self) -> &str {
        self.value["class"].as_str().unwrap()
    }
    pub fn digest(&self) -> Result<String> {
        digest(&self.value)
    }
    pub fn resource(&self) -> Result<String> {
        class_resource(self.class())
    }
    /// Production expiry uses the Core process clock. Caller clocks are not public API.
    ///
    /// ```compile_fail
    /// fn caller_clock(record: &vaikor_record::Record) {
    ///     record.expired_at("2000-01-01T00:00:00Z").unwrap();
    /// }
    /// ```
    pub fn expired(&self) -> Result<bool> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Malformed)?;
        self.expired_at(&vaikor_grant::format_rfc3339_z(
            now.as_secs().try_into().map_err(|_| Error::Malformed)?,
        ))
    }
    /// Private comparison helper; production callers must use `expired`.
    fn expired_at(&self, now: &str) -> Result<bool> {
        let now = timestamp(now)?;
        match self.value["retention"]["until"].as_str() {
            None => Ok(false),
            Some(until) => Ok(now >= timestamp(until)?),
        }
    }
}

pub mod artifact;
// The file-backed store (fs locks, audit chain) is host-only; wasm32 keeps the in-memory
// record, dCBOR and artifact checks (vaikor.com verifier playground).
#[cfg(not(target_arch = "wasm32"))]
pub mod store;

#[cfg(test)]
#[path = "vectors_tests.rs"]
mod vectors_tests;
