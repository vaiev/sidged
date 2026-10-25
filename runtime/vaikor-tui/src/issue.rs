//! Issuer helper for Demo 1: one `egress.send` right for exactly the Gemini
//! chat-completions URL (`CLOUD_URL`), a messages budget, holder-bound
//! (`cnf`), signed by the issuer key. Lifetime is capped at one hour (0002 R3).
//! The audience (`aud`) is the Core's configured audience (`--audience` /
//! `VAIKOR_AUDIENCE`); the Core matches the grant's `aud` against it.
use crate::{CLOUD_URL, EGRESS_ACTION};

/// 55 minutes: below the 0002 R3 one-hour maximum.
pub const DEFAULT_LIFETIME_SECS: i64 = 3300;
const MAX_LIFETIME_SECS: i64 = 3600;

pub struct GrantOptions {
    /// Holder `did:key` (becomes `sub` and `cnf`).
    pub holder: String,
    pub audience: String,
    /// RFC 3339 UTC issue time (`iat`).
    pub now: String,
    pub lifetime_secs: i64,
    /// `budget.messages`: one per call (0002 R20).
    pub messages: u64,
}

pub fn issue_cloud_grant(seed: &[u8; 32], o: &GrantOptions) -> Result<serde_json::Value, String> {
    if o.lifetime_secs <= 0 || o.lifetime_secs > MAX_LIFETIME_SECS {
        return Err("lifetime must be 1..=3600 s (0002 R3)".into());
    }
    if o.messages == 0 {
        return Err("messages budget must be at least 1".into());
    }
    if o.audience.is_empty() {
        return Err("audience must not be empty".into());
    }
    let iat = vaikor_grant::parse_rfc3339_z(&o.now).ok_or("now must be RFC 3339 UTC (Z)")?;
    let exp = vaikor_grant::format_rfc3339_z(iat + o.lifetime_secs);
    let holder = vaikor_grant::resolve_did_key(&o.holder).map_err(|e| format!("holder: {e}"))?;
    let jkt = vaikor_grant::jwk_thumbprint(&holder);
    let issuer = vaikor_grant::did_key(&vaikor_log::public_key(seed));
    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;
    let id: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let document = serde_json::json!({
        "v": "0.1",
        "id": format!("tok-demo1-{id}"),
        "iss": issuer,
        "sub": o.holder,
        "aud": o.audience,
        "iat": o.now,
        "exp": exp,
        "cnf": { "kid": o.holder, "jkt": jkt },
        "rights": [{ "action": EGRESS_ACTION, "resource": CLOUD_URL }],
        "budget": { "messages": o.messages },
        "chain": []
    });
    Ok(vaikor_grant::attach_signature(&document, seed, &issuer))
}

/// `--minutes <n>` as seconds: checked multiplication, then 1..=60 min
/// (0002 R3). Overflow is an error, never a wrapped value.
pub fn minutes_to_secs(text: &str) -> Result<i64, String> {
    let n: i64 = text.trim().parse().map_err(|_| "--minutes: invalid")?;
    let secs = n.checked_mul(60).ok_or("--minutes: overflow")?;
    if !(1..=MAX_LIFETIME_SECS).contains(&secs) {
        return Err("--minutes must be 1..=60 (0002 R3)".into());
    }
    Ok(secs)
}

/// The issuer seed, zeroized on drop.
pub fn parse_seed_hex(text: &str) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    let t = text.trim();
    if t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("issuer key must be 32 bytes hex".into());
    }
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    for (i, b) in seed.iter_mut().enumerate() {
        *b = u8::from_str_radix(&t[2 * i..2 * i + 2], 16).map_err(|_| "hex")?;
    }
    Ok(seed)
}
