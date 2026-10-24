// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! WebAuthn enrollment (0004 R9w Enrollment, WP 16).
//!
//! A platform bridge relays the WebAuthn Level 3 JSON form of a registration
//! (`registrationResponseJSON` on Android); the Core checks it against a single-use
//! challenge and stores the one enrolled credential with its counter. Attestation
//! conveyance is `none`: trust comes from the registration being made through Trusted UI
//! with user verification, so an attestation object is not an input.
//!
//! A challenge is consumed by [`register`], so it cannot be used twice:
//!
//! ```compile_fail
//! use sidged_cli::webauthn_enroll::{register, EnrollmentChallenge, RegistrationResponse};
//! fn twice(challenge: EnrollmentChallenge, response: &RegistrationResponse) {
//!     let _ = register(challenge, response);
//!     let _ = register(challenge, response); // use of moved value
//! }
//! ```

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::webauthn::{
    b64, Enrollment, ED25519_SPKI_PREFIX, FLAG_USER_PRESENT, FLAG_USER_VERIFIED,
};

const FLAG_ATTESTED: u8 = 0x40;
const FLAG_EXTENSIONS: u8 = 0x80;
/// DER prefix of a P-256 SubjectPublicKeyInfo; the uncompressed point follows.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const COSE_ES256: i64 = -7;
const COSE_EDDSA: i64 = -8;
/// Longest credential id WebAuthn allows.
const MAX_CREDENTIAL_ID: usize = 1023;

/// Why a registration was refused. Never carries key bytes or the challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollError {
    /// The challenge could not be issued (randomness, empty relying party or origins).
    Challenge(&'static str),
    /// A binary field is not unpadded base64url.
    Encoding(&'static str),
    /// `clientDataJSON`: JSON, type, challenge, origin or crossOrigin.
    ClientData(&'static str),
    /// `authenticatorData` is too short or truncated.
    AuthenticatorData(&'static str),
    /// `authenticatorData` is for another relying party.
    RelyingParty,
    /// User present, user verified, attested credential data or extension data flag.
    Flags(&'static str),
    /// Credential id length or mismatch with `id`.
    CredentialId(&'static str),
    /// The COSE_Key is not the canonical encoding of an accepted key.
    CoseKey(&'static str),
    /// Unsupported algorithm, or `publicKeyAlgorithm` differs from the COSE_Key.
    Algorithm(&'static str),
    /// `publicKey` does not encode the COSE_Key, or the key is not a valid point.
    PublicKey(&'static str),
}

impl std::fmt::Display for EnrollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Challenge(what) => write!(f, "enrollment challenge: {what}"),
            Self::Encoding(what) => write!(f, "{what} is not unpadded base64url"),
            Self::ClientData(what) => write!(f, "clientDataJSON: {what}"),
            Self::AuthenticatorData(what) => write!(f, "authenticatorData: {what}"),
            Self::RelyingParty => write!(f, "authenticatorData is for another relying party"),
            Self::Flags(what) => write!(f, "authenticatorData flags: {what}"),
            Self::CredentialId(what) => write!(f, "credential id: {what}"),
            Self::CoseKey(what) => write!(f, "credential public key (COSE_Key): {what}"),
            Self::Algorithm(what) => write!(f, "algorithm: {what}"),
            Self::PublicKey(what) => write!(f, "publicKey: {what}"),
        }
    }
}

impl std::error::Error for EnrollError {}

/// A fresh single-use registration challenge and the relying party and origins it was
/// issued for. Not `Clone`: [`register`] takes it by value.
pub struct EnrollmentChallenge {
    bytes: [u8; 32],
    rp_id: String,
    origins: Vec<String>,
}

impl std::fmt::Debug for EnrollmentChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentChallenge")
            .field("rp_id", &self.rp_id)
            .field("origins", &self.origins)
            .finish_non_exhaustive()
    }
}

impl EnrollmentChallenge {
    /// 32 fresh random bytes for `rp_id`, accepting `origins`.
    pub fn new(rp_id: &str, origins: &[String]) -> Result<Self, EnrollError> {
        if rp_id.is_empty() {
            return Err(EnrollError::Challenge("no relying-party id"));
        }
        if origins.is_empty() {
            return Err(EnrollError::Challenge("no accepted origin"));
        }
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| EnrollError::Challenge("no randomness"))?;
        Ok(Self {
            bytes,
            rp_id: rp_id.into(),
            origins: origins.to_vec(),
        })
    }

    /// The bytes the bridge passes to the authenticator as the challenge.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub fn origins(&self) -> &[String] {
        &self.origins
    }

    #[cfg(test)]
    fn fixed(bytes: [u8; 32], rp_id: &str, origins: &[&str]) -> Self {
        Self {
            bytes,
            rp_id: rp_id.into(),
            origins: origins.iter().map(|o| o.to_string()).collect(),
        }
    }
}

/// The WebAuthn Level 3 JSON form of a registration. Other members (`rawId`, `type`,
/// `transports`, `attestationObject`, `clientExtensionResults`, ...) are not inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub id: String,
    pub response: AttestationResponse,
}

/// The `response` member of a registration; binary fields are unpadded base64url.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    /// SubjectPublicKeyInfo DER.
    #[serde(rename = "publicKey")]
    pub public_key: String,
    /// COSE algorithm identifier.
    #[serde(rename = "publicKeyAlgorithm")]
    pub public_key_algorithm: i64,
}

/// Check a registration against its challenge (consumed, success or failure).
pub fn register(
    challenge: EnrollmentChallenge,
    response: &RegistrationResponse,
) -> Result<Enrollment, EnrollError> {
    let EnrollmentChallenge {
        bytes,
        rp_id,
        origins,
    } = challenge;
    let r = &response.response;
    let field =
        |text: &str, what: &'static str| b64(text, what).map_err(|_| EnrollError::Encoding(what));

    let client_data = field(&r.client_data_json, "clientDataJSON")?;
    let client: Value =
        serde_json::from_slice(&client_data).map_err(|_| EnrollError::ClientData("not JSON"))?;
    if client["type"] != "webauthn.create" {
        return Err(EnrollError::ClientData("type is not webauthn.create"));
    }
    if client["challenge"] != URL_SAFE_NO_PAD.encode(bytes) {
        return Err(EnrollError::ClientData("challenge is not the issued one"));
    }
    let origin = client["origin"].as_str().unwrap_or("");
    if !origins.iter().any(|o| o == origin) {
        return Err(EnrollError::ClientData("origin is not accepted"));
    }
    if client
        .get("crossOrigin")
        .is_some_and(|c| c != &Value::Bool(false))
    {
        return Err(EnrollError::ClientData("cross-origin registration"));
    }

    let auth = field(&r.authenticator_data, "authenticatorData")?;
    if auth.len() < 37 {
        return Err(EnrollError::AuthenticatorData("too short"));
    }
    if auth[..32] != Sha256::digest(rp_id.as_bytes())[..] {
        return Err(EnrollError::RelyingParty);
    }
    let flags = auth[32];
    if flags & FLAG_USER_PRESENT == 0 {
        return Err(EnrollError::Flags("user not present"));
    }
    if flags & FLAG_USER_VERIFIED == 0 {
        return Err(EnrollError::Flags("user not verified"));
    }
    if flags & FLAG_ATTESTED == 0 {
        return Err(EnrollError::Flags("no attested credential data"));
    }
    if flags & FLAG_EXTENSIONS != 0 {
        return Err(EnrollError::Flags("extension data was not requested"));
    }
    let sign_count = u32::from_be_bytes([auth[33], auth[34], auth[35], auth[36]]);
    // Attested credential data: AAGUID (16, ignored), length (2), credential id, COSE_Key.
    let attested = &auth[37..];
    if attested.len() < 18 {
        return Err(EnrollError::AuthenticatorData(
            "attested credential data is truncated",
        ));
    }
    let id_len = usize::from(u16::from_be_bytes([attested[16], attested[17]]));
    if id_len == 0 || id_len > MAX_CREDENTIAL_ID {
        return Err(EnrollError::CredentialId("length is not 1 to 1023 bytes"));
    }
    let rest = &attested[18..];
    let credential = rest
        .get(..id_len)
        .ok_or(EnrollError::CredentialId("longer than authenticatorData"))?;
    let id = field(&response.id, "id")?;
    if URL_SAFE_NO_PAD.encode(&id) != response.id {
        return Err(EnrollError::Encoding("id"));
    }
    if credential != id.as_slice() {
        return Err(EnrollError::CredentialId("differs from id"));
    }
    // The COSE_Key must end exactly at the end of authenticatorData.
    let key = CoseKey::decode(&rest[id_len..])?;

    if ![COSE_ES256, COSE_EDDSA].contains(&r.public_key_algorithm) {
        return Err(EnrollError::Algorithm(
            "publicKeyAlgorithm is not ES256 or EdDSA",
        ));
    }
    if r.public_key_algorithm != key.alg() {
        return Err(EnrollError::Algorithm(
            "publicKeyAlgorithm differs from the credential key",
        ));
    }
    let spki = field(&r.public_key, "publicKey")?;
    if spki != key.spki() {
        return Err(EnrollError::PublicKey("does not encode the credential key"));
    }
    // The same parsing `webauthn::verify` will do, so an enrolled key always loads.
    let alg = match key {
        CoseKey::Es256 { .. } => {
            p256::ecdsa::VerifyingKey::from_public_key_der(&spki)
                .map_err(|_| EnrollError::PublicKey("not a P-256 point"))?;
            "ES256"
        }
        CoseKey::EdDsa { x } => {
            ed25519_dalek::VerifyingKey::from_bytes(&x)
                .map_err(|_| EnrollError::PublicKey("not an Ed25519 point"))?;
            "EdDSA"
        }
    };
    Ok(Enrollment {
        credential_id: response.id.clone(),
        alg: alg.into(),
        public_key: URL_SAFE_NO_PAD.encode(&spki),
        rp_id,
        origins,
        sign_count,
    })
}

/// An accepted credential public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoseKey {
    Es256 { x: [u8; 32], y: [u8; 32] },
    EdDsa { x: [u8; 32] },
}

impl CoseKey {
    /// Strict CTAP2 canonical decoding of the two accepted key shapes:
    /// ES256 `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`, EdDSA `{1: 1, 3: -8, -1: 6, -2: x}`.
    fn decode(data: &[u8]) -> Result<Self, EnrollError> {
        let mut cbor = Cbor { data, pos: 0 };
        let (major, count) = cbor.head()?;
        if major != 5 {
            return Err(EnrollError::CoseKey("not a map"));
        }
        if !(4..=5).contains(&count) {
            return Err(EnrollError::CoseKey("wrong number of members"));
        }
        let (mut kty, mut alg, mut crv, mut x, mut y) = (None, None, None, None, None);
        let mut previous: Option<&[u8]> = None;
        for _ in 0..count {
            let start = cbor.pos;
            let key = cbor.int()?;
            let encoded = &data[start..cbor.pos];
            // CTAP2 canonical order: major type, then length, then bytes. Equal = duplicate.
            let rank = |e: &[u8]| (e[0] >> 5, e.len(), e.to_vec());
            if previous.is_some_and(|p| rank(p) >= rank(encoded)) {
                return Err(EnrollError::CoseKey(
                    "keys are duplicated or not in canonical order",
                ));
            }
            previous = Some(encoded);
            match key {
                1 => kty = Some(cbor.int()?),
                3 => alg = Some(cbor.int()?),
                -1 => crv = Some(cbor.int()?),
                -2 => x = Some(cbor.bytes32()?),
                -3 => y = Some(cbor.bytes32()?),
                _ => return Err(EnrollError::CoseKey("unexpected member")),
            }
        }
        if cbor.pos != data.len() {
            return Err(EnrollError::CoseKey("trailing bytes after the key"));
        }
        match (kty, alg, crv, x, y) {
            (Some(2), Some(COSE_ES256), Some(1), Some(x), Some(y)) => Ok(Self::Es256 { x, y }),
            (Some(1), Some(COSE_EDDSA), Some(6), Some(x), None) => Ok(Self::EdDsa { x }),
            (_, Some(alg), ..) if alg != COSE_ES256 && alg != COSE_EDDSA => Err(
                EnrollError::Algorithm("credential key is not ES256 or EdDSA"),
            ),
            _ => Err(EnrollError::CoseKey(
                "key type, algorithm, curve and members do not match",
            )),
        }
    }

    fn alg(&self) -> i64 {
        match self {
            Self::Es256 { .. } => COSE_ES256,
            Self::EdDsa { .. } => COSE_EDDSA,
        }
    }

    /// The SubjectPublicKeyInfo DER of this key.
    fn spki(&self) -> Vec<u8> {
        match self {
            Self::Es256 { x, y } => [&P256_SPKI_PREFIX[..], &[0x04], x, y].concat(),
            Self::EdDsa { x } => [&ED25519_SPKI_PREFIX[..], x].concat(),
        }
    }
}

/// A minimal CBOR reader: definite lengths, shortest argument encoding, bounds checked.
struct Cbor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cbor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], EnrollError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.data.len())
            .ok_or(EnrollError::CoseKey("truncated"))?;
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    /// Major type and argument of the next item.
    fn head(&mut self) -> Result<(u8, u64), EnrollError> {
        let initial = self.take(1)?[0];
        let (major, info) = (initial >> 5, initial & 0x1f);
        let (argument, minimum) = match info {
            0..=23 => (u64::from(info), 0),
            24 => (u64::from(self.take(1)?[0]), 24),
            25 => {
                let b = self.take(2)?;
                (u64::from(u16::from_be_bytes([b[0], b[1]])), 0x100)
            }
            26 => {
                let b = self.take(4)?;
                (
                    u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
                    0x1_0000,
                )
            }
            27 => {
                let b = self.take(8)?;
                let mut be = [0u8; 8];
                be.copy_from_slice(b);
                (u64::from_be_bytes(be), 0x1_0000_0000)
            }
            31 => return Err(EnrollError::CoseKey("indefinite length")),
            _ => return Err(EnrollError::CoseKey("reserved additional information")),
        };
        if argument < minimum {
            return Err(EnrollError::CoseKey("not the shortest encoding"));
        }
        Ok((major, argument))
    }

    fn int(&mut self) -> Result<i64, EnrollError> {
        let (major, argument) = self.head()?;
        let value =
            i64::try_from(argument).map_err(|_| EnrollError::CoseKey("integer out of range"))?;
        match major {
            0 => Ok(value),
            1 => Ok(-1 - value),
            _ => Err(EnrollError::CoseKey("expected an integer")),
        }
    }

    fn bytes32(&mut self) -> Result<[u8; 32], EnrollError> {
        let (major, length) = self.head()?;
        if major != 2 {
            return Err(EnrollError::CoseKey("expected a byte string"));
        }
        if length != 32 {
            return Err(EnrollError::CoseKey("coordinate is not 32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(self.take(32)?);
        Ok(out)
    }
}

/// The one enrolled credential in a JSON file, mode 0600, replaced atomically. Writers
/// hold an exclusive lock on `<path>.lock`, so a check and its write are one step.
pub struct EnrollmentStore;

impl EnrollmentStore {
    /// The stored enrollment; `None` only when the file does not exist.
    pub fn load(path: &Path) -> Result<Option<Enrollment>, String> {
        let shown = path.display();
        let mut file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(format!("{shown}: {}", err.kind())),
        };
        let meta = file
            .metadata()
            .map_err(|err| format!("{shown}: {}", err.kind()))?;
        if !meta.is_file() {
            return Err(format!("{shown} is not a regular file"));
        }
        // Any permission bit outside 0600 (group, other, execute, setuid, sticky) is looser.
        if meta.mode() & 0o7777 & !0o600 != 0 {
            return Err(format!(
                "{shown} has mode {:o}; it must be 0600",
                meta.mode() & 0o7777
            ));
        }
        let mut text = Vec::new();
        file.read_to_end(&mut text)
            .map_err(|err| format!("{shown}: {}", err.kind()))?;
        serde_json::from_slice(&text)
            .map(Some)
            .map_err(|_| format!("{shown} is not an enrollment"))
    }

    /// Store the first enrollment; refused when one exists.
    pub fn enroll(path: &Path, enrollment: &Enrollment) -> Result<(), String> {
        let _lock = PathLock::take(path)?;
        if std::fs::symlink_metadata(path).is_ok() {
            return Err(format!(
                "{} exists; a credential is already enrolled",
                path.display()
            ));
        }
        write_atomic(path, enrollment, false)
    }

    /// Raise the stored counter of `credential_id` to `count` after an approval.
    pub fn store_counter(path: &Path, credential_id: &str, count: u32) -> Result<(), String> {
        // Without the lock two updates (6 and 7 over 5) could both pass and 6 land last.
        let _lock = PathLock::take(path)?;
        let mut enrollment = Self::load(path)?
            .ok_or_else(|| format!("{}: no credential is enrolled", path.display()))?;
        if enrollment.credential_id != credential_id {
            return Err("credential is not the enrolled one".into());
        }
        if (count != 0 || enrollment.sign_count != 0) && count <= enrollment.sign_count {
            return Err("signature counter did not increase".into());
        }
        enrollment.sign_count = count;
        write_atomic(path, &enrollment, true)
    }
}

/// An exclusive flock(2) on `<path>.lock`, held until drop. The lock file stays in place:
/// removing it would let a waiter lock a file that a newcomer no longer sees.
struct PathLock(#[allow(dead_code)] std::fs::File);

impl PathLock {
    fn take(path: &Path) -> Result<Self, String> {
        use std::os::unix::io::AsRawFd;
        let mut name = path.as_os_str().to_owned();
        name.push(".lock");
        let lock = Path::new(&name);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(lock)
            .map_err(|err| format!("{}: {}", lock.display(), err.kind()))?;
        // SAFETY: flock only reads the fd, which `file` keeps open for the call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!("{}: {}", lock.display(), err.kind()));
        }
        Ok(Self(file))
    }
}

/// Write a temp file (0600) in the same directory, fsync it, then move it into place:
/// `rename` when replacing, a hard link (fails if `path` exists) when creating.
fn write_atomic(path: &Path, enrollment: &Enrollment, replace: bool) -> Result<(), String> {
    let shown = path.display();
    let name = path
        .file_name()
        .ok_or_else(|| format!("{shown} has no file name"))?;
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let bytes = serde_json::to_vec(enrollment).map_err(|e| e.to_string())?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(
        ".{}.tmp-{}-{nonce}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)
            .map_err(|err| format!("{}: {}", tmp.display(), err.kind()))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|err| format!("{}: {}", tmp.display(), err.kind()))?;
        if replace {
            std::fs::rename(&tmp, path).map_err(|err| format!("{shown}: {}", err.kind()))?;
        } else {
            std::fs::hard_link(&tmp, path).map_err(|err| match err.kind() {
                std::io::ErrorKind::AlreadyExists => {
                    format!("{shown} exists; a credential is already enrolled")
                }
                kind => format!("{shown}: {kind}"),
            })?;
            std::fs::remove_file(&tmp)
                .map_err(|err| format!("{}: {}", tmp.display(), err.kind()))?;
        }
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|err| format!("directory {}: {}", dir.display(), err.kind()))
    })();
    let _ = std::fs::remove_file(&tmp);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn::{self, Assertion, ED25519_SPKI_PREFIX};
    use crate::ApprovalRequest;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    const RP: &str = "sidged.local";
    const ORIGIN: &str = "https://sidged.local";
    const CHALLENGE: [u8; 32] = [0x42; 32];
    const P256_SPKI_HEADER: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

    fn hex_bytes(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// A test authenticator that makes real registrations and assertions.
    enum Key {
        Es(p256::ecdsa::SigningKey),
        Ed(ed25519_dalek::SigningKey),
    }

    impl Key {
        fn es256() -> Self {
            Self::Es(p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap())
        }

        fn ed25519() -> Self {
            Self::Ed(ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]))
        }

        fn alg(&self) -> i64 {
            match self {
                Self::Es(_) => -7,
                Self::Ed(_) => -8,
            }
        }

        fn name(&self) -> &'static str {
            match self {
                Self::Es(_) => "ES256",
                Self::Ed(_) => "EdDSA",
            }
        }

        /// The uncompressed point without 0x04 (x ‖ y), or the Ed25519 key.
        fn raw(&self) -> Vec<u8> {
            match self {
                Self::Es(k) => k.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec(),
                Self::Ed(k) => k.verifying_key().as_bytes().to_vec(),
            }
        }

        /// CTAP2 canonical COSE_Key.
        fn cose(&self) -> Vec<u8> {
            let raw = self.raw();
            match self {
                Self::Es(_) => {
                    let mut c = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
                    c.extend_from_slice(&raw[..32]);
                    c.extend_from_slice(&[0x22, 0x58, 0x20]);
                    c.extend_from_slice(&raw[32..]);
                    c
                }
                Self::Ed(_) => {
                    let mut c = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
                    c.extend_from_slice(&raw);
                    c
                }
            }
        }

        fn spki(&self) -> Vec<u8> {
            match self {
                Self::Es(k) => {
                    let mut spki = hex_bytes(P256_SPKI_HEADER);
                    spki.extend_from_slice(k.verifying_key().to_encoded_point(false).as_bytes());
                    spki
                }
                Self::Ed(k) => {
                    let mut spki = ED25519_SPKI_PREFIX.to_vec();
                    spki.extend_from_slice(k.verifying_key().as_bytes());
                    spki
                }
            }
        }

        fn sign(&self, data: &[u8]) -> Vec<u8> {
            match self {
                Self::Es(k) => {
                    use p256::ecdsa::signature::Signer;
                    let signature: p256::ecdsa::Signature = k.sign(data);
                    signature.to_der().as_bytes().to_vec()
                }
                Self::Ed(k) => {
                    use ed25519_dalek::Signer;
                    k.sign(data).to_bytes().to_vec()
                }
            }
        }

        /// An assertion for `request` with counter `count` (webauthn::verify input).
        fn assert(&self, credential_id: &str, request: &ApprovalRequest, count: u32) -> Assertion {
            let client = json!({
                "type": "webauthn.get",
                "challenge": URL_SAFE_NO_PAD.encode(webauthn::challenge(request)),
                "origin": ORIGIN,
            })
            .to_string();
            let mut auth = Sha256::digest(RP.as_bytes()).to_vec();
            auth.push(0x05);
            auth.extend_from_slice(&count.to_be_bytes());
            let mut signed = auth.clone();
            signed.extend_from_slice(&Sha256::digest(client.as_bytes()));
            Assertion {
                credential_id: credential_id.into(),
                client_data_json: URL_SAFE_NO_PAD.encode(client.as_bytes()),
                authenticator_data: URL_SAFE_NO_PAD.encode(&auth),
                signature: URL_SAFE_NO_PAD.encode(self.sign(&signed)),
            }
        }
    }

    /// Every part of a registration, so a test can change exactly one.
    struct Registration {
        client: Value,
        rp: String,
        flags: u8,
        count: u32,
        cred_len: u16,
        cred: Vec<u8>,
        cose: Vec<u8>,
        trailing: Vec<u8>,
        id: String,
        spki: Vec<u8>,
        alg: i64,
    }

    impl Registration {
        fn new(key: &Key, challenge: &[u8; 32]) -> Self {
            let cred = b"credential-0001".to_vec();
            Self {
                client: json!({
                    "type": "webauthn.create",
                    "challenge": URL_SAFE_NO_PAD.encode(challenge),
                    "origin": ORIGIN,
                    "crossOrigin": false,
                }),
                rp: RP.into(),
                flags: 0x45,
                count: 3,
                cred_len: cred.len() as u16,
                id: URL_SAFE_NO_PAD.encode(&cred),
                cred,
                cose: key.cose(),
                trailing: Vec::new(),
                spki: key.spki(),
                alg: key.alg(),
            }
        }

        fn auth_data(&self) -> Vec<u8> {
            let mut auth = Sha256::digest(self.rp.as_bytes()).to_vec();
            auth.push(self.flags);
            auth.extend_from_slice(&self.count.to_be_bytes());
            auth.extend_from_slice(&[0xaa; 16]); // AAGUID
            auth.extend_from_slice(&self.cred_len.to_be_bytes());
            auth.extend_from_slice(&self.cred);
            auth.extend_from_slice(&self.cose);
            auth.extend_from_slice(&self.trailing);
            auth
        }

        fn response(&self) -> RegistrationResponse {
            self.with_auth_data(&self.auth_data())
        }

        fn with_auth_data(&self, auth: &[u8]) -> RegistrationResponse {
            RegistrationResponse {
                id: self.id.clone(),
                response: AttestationResponse {
                    client_data_json: URL_SAFE_NO_PAD.encode(self.client.to_string()),
                    authenticator_data: URL_SAFE_NO_PAD.encode(auth),
                    public_key: URL_SAFE_NO_PAD.encode(&self.spki),
                    public_key_algorithm: self.alg,
                },
            }
        }
    }

    fn challenge() -> EnrollmentChallenge {
        EnrollmentChallenge::fixed(CHALLENGE, RP, &[ORIGIN])
    }

    fn try_register(
        key: &Key,
        change: impl FnOnce(&mut Registration),
    ) -> Result<Enrollment, EnrollError> {
        let mut registration = Registration::new(key, &CHALLENGE);
        change(&mut registration);
        register(challenge(), &registration.response())
    }

    fn request() -> ApprovalRequest {
        let mut request = ApprovalRequest::new(
            "plan-digest",
            "t1_send",
            "urn:sidged:capability:message.send",
            &json!({"to": "Marco"}),
        )
        .unwrap();
        request.nonce = "00".repeat(32);
        request
    }

    #[test]
    fn a_valid_registration_enrolls_and_its_enrollment_verifies_an_assertion() {
        for key in [Key::es256(), Key::ed25519()] {
            let challenge = EnrollmentChallenge::new(RP, &[ORIGIN.to_string()]).unwrap();
            let registration = Registration::new(&key, challenge.bytes());
            let enrollment = register(challenge, &registration.response()).unwrap();
            assert_eq!(
                enrollment,
                Enrollment {
                    credential_id: registration.id.clone(),
                    alg: key.name().into(),
                    public_key: URL_SAFE_NO_PAD.encode(key.spki()),
                    rp_id: RP.into(),
                    origins: vec![ORIGIN.into()],
                    sign_count: 3,
                },
                "{}",
                key.name()
            );
            let request = request();
            let assertion = key.assert(&enrollment.credential_id, &request, 4);
            assert_eq!(
                webauthn::verify(&enrollment, &request, &assertion),
                Ok(4),
                "{}",
                key.name()
            );
        }
    }

    #[test]
    fn the_level3_json_of_a_platform_parses_with_its_other_members() {
        let key = Key::es256();
        let registration = Registration::new(&key, &CHALLENGE);
        let r = registration.response();
        let text = json!({
            "id": r.id,
            "rawId": r.id,
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": r.response.client_data_json,
                "authenticatorData": r.response.authenticator_data,
                "publicKey": r.response.public_key,
                "publicKeyAlgorithm": -7,
                "transports": ["internal", "hybrid"],
                "attestationObject": "o2NmbXRkbm9uZQ",
            },
        })
        .to_string();
        let parsed: RegistrationResponse = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, r);
        assert!(register(challenge(), &parsed).is_ok());
    }

    #[test]
    fn fresh_challenges_differ_and_a_response_does_not_register_under_another() {
        let origins = [ORIGIN.to_string()];
        let first = EnrollmentChallenge::new(RP, &origins).unwrap();
        let second = EnrollmentChallenge::new(RP, &origins).unwrap();
        assert_ne!(first.bytes(), second.bytes());
        assert_eq!((first.rp_id(), first.origins()), (RP, &origins[..]));
        let key = Key::es256();
        let response = Registration::new(&key, first.bytes()).response();
        // `first` is consumed by this call; a second `register(first, ..)` does not compile
        // (module doc test). A new challenge does not accept the old response.
        assert!(register(first, &response).is_ok());
        assert!(matches!(
            register(second, &response),
            Err(EnrollError::ClientData(_))
        ));
        assert!(EnrollmentChallenge::new("", &origins).is_err());
        assert!(EnrollmentChallenge::new(RP, &[]).is_err());
    }

    #[test]
    fn every_client_data_failure_is_refused() {
        let key = Key::es256();
        let cases: [(&str, Value); 8] = [
            (
                "wrong type",
                json!({"type": "webauthn.get", "challenge": URL_SAFE_NO_PAD.encode(CHALLENGE), "origin": ORIGIN}),
            ),
            (
                "no type",
                json!({"challenge": URL_SAFE_NO_PAD.encode(CHALLENGE), "origin": ORIGIN}),
            ),
            (
                "wrong challenge",
                json!({"type": "webauthn.create", "challenge": URL_SAFE_NO_PAD.encode([0x43; 32]), "origin": ORIGIN}),
            ),
            (
                "padded challenge",
                json!({"type": "webauthn.create", "challenge": format!("{}=", URL_SAFE_NO_PAD.encode(CHALLENGE)), "origin": ORIGIN}),
            ),
            (
                "wrong origin",
                json!({"type": "webauthn.create", "challenge": URL_SAFE_NO_PAD.encode(CHALLENGE), "origin": "https://evil.example"}),
            ),
            (
                "no origin",
                json!({"type": "webauthn.create", "challenge": URL_SAFE_NO_PAD.encode(CHALLENGE)}),
            ),
            (
                "crossOrigin true",
                json!({"type": "webauthn.create", "challenge": URL_SAFE_NO_PAD.encode(CHALLENGE), "origin": ORIGIN, "crossOrigin": true}),
            ),
            (
                "crossOrigin not a boolean",
                json!({"type": "webauthn.create", "challenge": URL_SAFE_NO_PAD.encode(CHALLENGE), "origin": ORIGIN, "crossOrigin": "false"}),
            ),
        ];
        for (what, client) in cases {
            let result = try_register(&key, |r| r.client = client);
            assert!(
                matches!(result, Err(EnrollError::ClientData(_))),
                "{what}: {result:?}"
            );
        }
        // crossOrigin absent is accepted.
        assert!(try_register(&key, |r| {
            r.client.as_object_mut().unwrap().remove("crossOrigin");
        })
        .is_ok());
        let mut registration = Registration::new(&key, &CHALLENGE);
        let mut response = registration.response();
        response.response.client_data_json = URL_SAFE_NO_PAD.encode(b"{not json");
        assert!(matches!(
            register(challenge(), &response),
            Err(EnrollError::ClientData(_))
        ));
        registration.client = json!("webauthn.create");
        assert!(matches!(
            register(challenge(), &registration.response()),
            Err(EnrollError::ClientData(_))
        ));
    }

    #[test]
    fn every_authenticator_data_failure_is_refused() {
        for key in [Key::es256(), Key::ed25519()] {
            let refused =
                |what: &str, change: &dyn Fn(&mut Registration), want: fn(&EnrollError) -> bool| {
                    let result = try_register(&key, |r| change(r));
                    assert!(
                        result.as_ref().is_err_and(want),
                        "{} {what}: {result:?}",
                        key.name()
                    );
                };
            refused("rp hash", &|r| r.rp = "evil.example".into(), |e| {
                *e == EnrollError::RelyingParty
            });
            refused("no user present", &|r| r.flags = 0x44, |e| {
                matches!(e, EnrollError::Flags(_))
            });
            refused("no user verified", &|r| r.flags = 0x41, |e| {
                matches!(e, EnrollError::Flags(_))
            });
            refused("no attested data", &|r| r.flags = 0x05, |e| {
                matches!(e, EnrollError::Flags(_))
            });
            refused("extension data", &|r| r.flags = 0xc5, |e| {
                matches!(e, EnrollError::Flags(_))
            });
            refused(
                "credential id length 0",
                &|r| {
                    r.cred_len = 0;
                },
                |e| matches!(e, EnrollError::CredentialId(_)),
            );
            refused(
                "credential id 1024 bytes",
                &|r| {
                    r.cred = vec![1; 1024];
                    r.cred_len = 1024;
                    r.id = URL_SAFE_NO_PAD.encode(&r.cred);
                },
                |e| matches!(e, EnrollError::CredentialId(_)),
            );
            refused(
                "credential id mismatch",
                &|r| {
                    r.id = URL_SAFE_NO_PAD.encode(b"credential-0002");
                },
                |e| matches!(e, EnrollError::CredentialId(_)),
            );
            refused(
                "credential id longer than authenticatorData",
                &|r| {
                    r.cred_len = 1023;
                },
                |e| {
                    matches!(
                        e,
                        EnrollError::CredentialId(_) | EnrollError::AuthenticatorData(_)
                    )
                },
            );
            refused("padded id", &|r| r.id.push('='), |e| {
                matches!(e, EnrollError::Encoding(_))
            });
            refused("id not base64url", &|r| r.id = "cred+1/".into(), |e| {
                matches!(e, EnrollError::Encoding(_))
            });
            refused("trailing bytes", &|r| r.trailing = vec![0], |e| {
                matches!(e, EnrollError::CoseKey(_))
            });
        }
        // A 1023-byte credential id is the longest accepted.
        assert!(try_register(&Key::es256(), |r| {
            r.cred = vec![1; 1023];
            r.cred_len = 1023;
            r.id = URL_SAFE_NO_PAD.encode(&r.cred);
        })
        .is_ok());
        // Shorter than the 37 fixed bytes, and fixed bytes without attested credential data.
        let key = Key::es256();
        let registration = Registration::new(&key, &CHALLENGE);
        for len in [0, 36, 37, 54] {
            let auth = registration.auth_data();
            let result = register(challenge(), &registration.with_auth_data(&auth[..len]));
            assert!(
                matches!(result, Err(EnrollError::AuthenticatorData(_))),
                "authenticatorData of {len} bytes: {result:?}"
            );
        }
    }

    #[test]
    fn every_cose_key_deviation_is_refused() {
        let es = Key::es256();
        let ed = Key::ed25519();
        let (x, y) = {
            let raw = es.raw();
            (raw[..32].to_vec(), raw[32..].to_vec())
        };
        let bstr = |b: &[u8]| [vec![0x58, b.len() as u8], b.to_vec()].concat();
        // ES256 members in canonical order, each as (key bytes, value bytes).
        let members = |kty: &[u8], alg: &[u8], crv: &[u8]| -> Vec<(Vec<u8>, Vec<u8>)> {
            vec![
                (vec![0x01], kty.to_vec()),
                (vec![0x03], alg.to_vec()),
                (vec![0x20], crv.to_vec()),
                (vec![0x21], bstr(&x)),
                (vec![0x22], bstr(&y)),
            ]
        };
        let map = |head: u8, members: &[(Vec<u8>, Vec<u8>)]| -> Vec<u8> {
            let mut c = vec![head];
            for (k, v) in members {
                c.extend_from_slice(k);
                c.extend_from_slice(v);
            }
            c
        };
        let good = members(&[0x02], &[0x26], &[0x01]);
        assert_eq!(map(0xa5, &good), es.cose());
        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            ("not a map", map(0x85, &good)),
            ("indefinite map", [map(0xbf, &good), vec![0xff]].concat()),
            (
                "non-minimal map length",
                [vec![0xb8, 0x05], map(0xa5, &good)[1..].to_vec()].concat(),
            ),
            ("too few members", map(0xa4, &good[..4])),
            ("member count beyond the data", map(0xa6, &good)),
        ];
        let mut extra = good.clone();
        extra.push((vec![0x23], bstr(&x)));
        cases.push(("extra member -4", map(0xa6, &extra)));
        let mut unknown = good.clone();
        unknown[4].0 = vec![0x23];
        cases.push(("unknown key -4 instead of -3", map(0xa5, &unknown)));
        let mut duplicate = good.clone();
        duplicate[4].0 = vec![0x21];
        cases.push(("duplicate key -2", map(0xa5, &duplicate)));
        let mut order = good.clone();
        order.swap(3, 4);
        cases.push(("-3 before -2", map(0xa5, &order)));
        let mut order = good.clone();
        order.swap(0, 1);
        cases.push(("3 before 1", map(0xa5, &order)));
        let mut wide = good.clone();
        wide[0].0 = vec![0x18, 0x01];
        cases.push(("non-minimal key 1", map(0xa5, &wide)));
        cases.push((
            "non-minimal kty value",
            map(0xa5, &members(&[0x18, 0x02], &[0x26], &[0x01])),
        ));
        cases.push((
            "kty as byte string",
            map(0xa5, &members(&[0x41, 0x02], &[0x26], &[0x01])),
        ));
        cases.push((
            "kty OKP for ES256",
            map(0xa5, &members(&[0x01], &[0x26], &[0x01])),
        ));
        cases.push(("crv P-384", map(0xa5, &members(&[0x02], &[0x26], &[0x02]))));
        cases.push((
            "reserved additional info",
            map(0xa5, &members(&[0x1c], &[0x26], &[0x01])),
        ));
        cases.push((
            "indefinite integer",
            map(0xa5, &members(&[0x1f], &[0x26], &[0x01])),
        ));
        let mut short_x = good.clone();
        short_x[3].1 = bstr(&x[..31]);
        cases.push(("x of 31 bytes", map(0xa5, &short_x)));
        let mut long_y = good.clone();
        long_y[4].1 = bstr(&[y.clone(), vec![0]].concat());
        cases.push(("y of 33 bytes", map(0xa5, &long_y)));
        let mut text_x = good.clone();
        text_x[3].1 = [vec![0x78, 0x20], x.clone()].concat();
        cases.push(("x as text string", map(0xa5, &text_x)));
        let mut wide_x = good.clone();
        wide_x[3].1 = [vec![0x59, 0x00, 0x20], x.clone()].concat();
        cases.push(("non-minimal x length", map(0xa5, &wide_x)));
        let mut huge_x = good.clone();
        huge_x[3].1 = vec![0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        cases.push(("x length 2^64-1", map(0xa5, &huge_x)));
        let mut huge_int = good.clone();
        huge_int[0].1 = vec![0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        cases.push(("kty below i64::MIN", map(0xa5, &huge_int)));
        cases.push(("truncated", es.cose()[..es.cose().len() - 1].to_vec()));
        cases.push(("empty", Vec::new()));
        for (what, cose) in cases {
            let result = try_register(&es, |r| r.cose = cose);
            assert!(
                matches!(result, Err(EnrollError::CoseKey(_))),
                "{what}: {result:?}"
            );
        }
        // EdDSA deviations.
        let ed_cose = ed.cose();
        let mut with_y = ed_cose.clone();
        with_y[0] = 0xa5;
        with_y.extend_from_slice(&bstr(&[0; 32]));
        let mut x25519 = ed_cose.clone();
        x25519[6] = 0x04;
        let mut kty_ec2 = ed_cose.clone();
        kty_ec2[2] = 0x02;
        let mut short = ed_cose.clone();
        short[9] = 0x1f;
        short.pop();
        for (what, cose) in [
            ("EdDSA with y", with_y),
            ("EdDSA on X25519", x25519),
            ("EdDSA with kty EC2", kty_ec2),
            ("EdDSA x of 31 bytes", short),
        ] {
            let result = try_register(&ed, |r| r.cose = cose);
            assert!(
                matches!(result, Err(EnrollError::CoseKey(_))),
                "{what}: {result:?}"
            );
        }
    }

    #[test]
    fn every_algorithm_and_public_key_failure_is_refused() {
        let es = Key::es256();
        let ed = Key::ed25519();
        let algorithm = |e: &EnrollError| matches!(e, EnrollError::Algorithm(_));
        let public_key = |e: &EnrollError| matches!(e, EnrollError::PublicKey(_));
        type Expected = fn(&EnrollError) -> bool;
        let cases: Vec<(&str, Result<Enrollment, EnrollError>, Expected)> = vec![
            (
                "publicKeyAlgorithm EdDSA for an ES256 key",
                try_register(&es, |r| r.alg = -8),
                algorithm,
            ),
            (
                "publicKeyAlgorithm ES256 for an EdDSA key",
                try_register(&ed, |r| r.alg = -7),
                algorithm,
            ),
            ("RS256", try_register(&es, |r| r.alg = -257), algorithm),
            (
                "COSE alg RS256",
                try_register(&es, |r| {
                    r.cose[4] = 0x39;
                    r.cose.splice(5..5, [0x01, 0x00]);
                    r.alg = -257;
                }),
                algorithm,
            ),
            (
                "COSE alg ES384 in an EC2 key",
                try_register(&es, |r| {
                    r.cose[4] = 0x38;
                    r.cose.insert(5, 0x22);
                    r.alg = -35;
                }),
                algorithm,
            ),
            (
                "SPKI of another key",
                try_register(&es, |r| {
                    r.spki =
                        Key::Es(p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap()).spki()
                }),
                public_key,
            ),
            (
                "SPKI of another Ed25519 key",
                try_register(&ed, |r| {
                    r.spki = Key::Ed(ed25519_dalek::SigningKey::from_bytes(&[4u8; 32])).spki()
                }),
                public_key,
            ),
            (
                "Ed25519 SPKI for an ES256 key",
                try_register(&es, |r| r.spki = ed.spki()),
                public_key,
            ),
            (
                "compressed P-256 SPKI",
                try_register(&es, |r| {
                    let Key::Es(k) = &es else { unreachable!() };
                    let mut spki =
                        hex_bytes("3039301306072a8648ce3d020106082a8648ce3d030107032200");
                    spki.extend_from_slice(k.verifying_key().to_encoded_point(true).as_bytes());
                    r.spki = spki;
                }),
                public_key,
            ),
            (
                "SPKI with a trailing byte",
                try_register(&ed, |r| r.spki.push(0)),
                public_key,
            ),
            (
                "x and y not on the curve",
                try_register(&es, |r| {
                    let point = [vec![0x04], vec![1; 64]].concat();
                    r.cose[10..42].copy_from_slice(&point[1..33]);
                    r.cose[45..77].copy_from_slice(&point[33..]);
                    r.spki = [hex_bytes(P256_SPKI_HEADER), point].concat();
                }),
                public_key,
            ),
        ];
        for (what, result, want) in cases {
            assert!(result.as_ref().is_err_and(want), "{what}: {result:?}");
        }
        let mut response = Registration::new(&es, &CHALLENGE).response();
        response.response.public_key = "not base64url!".into();
        assert!(matches!(
            register(challenge(), &response),
            Err(EnrollError::Encoding(_))
        ));
    }

    #[test]
    fn error_text_never_shows_the_challenge_or_key_bytes() {
        let key = Key::es256();
        let secrets = [
            URL_SAFE_NO_PAD.encode(CHALLENGE),
            URL_SAFE_NO_PAD.encode(key.spki()),
            URL_SAFE_NO_PAD.encode(&key.raw()[..32]),
        ];
        let errors = [
            try_register(&key, |r| r.client["type"] = json!("webauthn.get")),
            try_register(&key, |r| {
                r.client["challenge"] = json!(URL_SAFE_NO_PAD.encode([1; 32]))
            }),
            try_register(&key, |r| r.spki = Key::ed25519().spki()),
            try_register(&key, |r| r.cose.pop().map(|_| ()).unwrap()),
        ];
        for error in errors {
            let text = format!(
                "{} {:?}",
                error.as_ref().unwrap_err(),
                error.as_ref().unwrap_err()
            );
            assert!(secrets.iter().all(|s| !text.contains(s.as_str())), "{text}");
        }
        let debug = format!("{:?}", challenge());
        assert!(!debug.contains("66, 66"), "{debug}");
    }

    #[test]
    fn truncated_and_bit_flipped_authenticator_data_never_panics_or_enrolls_another_key() {
        for key in [Key::es256(), Key::ed25519()] {
            let registration = Registration::new(&key, &CHALLENGE);
            let auth = registration.auth_data();
            let expected = register(challenge(), &registration.response()).unwrap();
            for len in 0..auth.len() {
                let result = register(challenge(), &registration.with_auth_data(&auth[..len]));
                assert!(result.is_err(), "{} prefix {len}", key.name());
            }
            for byte in 0..auth.len() {
                for bit in 0..8 {
                    let mut flipped = auth.clone();
                    flipped[byte] ^= 1 << bit;
                    let result = register(challenge(), &registration.with_auth_data(&flipped));
                    // Only members the Core does not check may change: the RFU and backup
                    // flags, the counter and the AAGUID. The enrolled key never changes.
                    let unchecked =
                        (byte == 32 && [1, 3, 4, 5].contains(&bit)) || (33..53).contains(&byte);
                    match result {
                        Ok(enrollment) => {
                            assert!(unchecked, "{} byte {byte} bit {bit} enrolled", key.name());
                            assert_eq!(
                                (
                                    enrollment.credential_id,
                                    enrollment.public_key,
                                    enrollment.alg
                                ),
                                (
                                    expected.credential_id.clone(),
                                    expected.public_key.clone(),
                                    expected.alg.clone()
                                )
                            );
                        }
                        Err(_) => {
                            assert!(!unchecked, "{} byte {byte} bit {bit} refused", key.name())
                        }
                    }
                }
            }
            // Bit flips of the SubjectPublicKeyInfo never enroll.
            let spki = key.spki();
            for byte in 0..spki.len() {
                for bit in 0..8 {
                    let mut flipped = registration.response();
                    let mut bytes = spki.clone();
                    bytes[byte] ^= 1 << bit;
                    flipped.response.public_key = URL_SAFE_NO_PAD.encode(&bytes);
                    assert!(
                        register(challenge(), &flipped).is_err(),
                        "{} spki byte {byte} bit {bit}",
                        key.name()
                    );
                }
            }
        }
    }

    // --- EnrollmentStore ---

    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    fn store_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sidged-enroll-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn enrollment(count: u32) -> Enrollment {
        Enrollment {
            credential_id: "Y3JlZC0x".into(),
            alg: "ES256".into(),
            public_key: URL_SAFE_NO_PAD.encode(Key::es256().spki()),
            rp_id: RP.into(),
            origins: vec![ORIGIN.into()],
            sign_count: count,
        }
    }

    #[test]
    fn the_store_writes_one_0600_file_atomically_and_loads_it() {
        let dir = store_dir();
        let path = dir.join("enrollment.json");
        assert_eq!(EnrollmentStore::load(&path), Ok(None));
        EnrollmentStore::enroll(&path, &enrollment(3)).unwrap();
        assert_eq!(names(&dir), ["enrollment.json", "enrollment.json.lock"]);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(EnrollmentStore::load(&path), Ok(Some(enrollment(3))));
        EnrollmentStore::store_counter(&path, "Y3JlZC0x", 9).unwrap();
        assert_eq!(names(&dir), ["enrollment.json", "enrollment.json.lock"]);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(EnrollmentStore::load(&path), Ok(Some(enrollment(9))));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn enrolling_over_an_existing_credential_is_refused() {
        let dir = store_dir();
        let path = dir.join("enrollment.json");
        EnrollmentStore::enroll(&path, &enrollment(3)).unwrap();
        let mut other = enrollment(0);
        other.credential_id = "Y3JlZC0y".into();
        assert!(EnrollmentStore::enroll(&path, &other).is_err());
        assert_eq!(EnrollmentStore::load(&path), Ok(Some(enrollment(3))));
        assert_eq!(names(&dir), ["enrollment.json", "enrollment.json.lock"]);
        // Any existing entry blocks enrollment, even one that is not a valid enrollment.
        let junk = dir.join("junk.json");
        std::fs::write(&junk, "x").unwrap();
        assert!(EnrollmentStore::enroll(&junk, &enrollment(0)).is_err());
        assert_eq!(std::fs::read_to_string(&junk).unwrap(), "x");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_counter_update_waits_for_the_lock() {
        let dir = store_dir();
        let path = dir.join("enrollment.json");
        EnrollmentStore::enroll(&path, &enrollment(5)).unwrap();
        let held = PathLock::take(&path).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let target = path.clone();
        let update = std::thread::spawn(move || {
            tx.send(EnrollmentStore::store_counter(&target, "Y3JlZC0x", 7))
                .unwrap()
        });
        let wait = std::time::Duration::from_millis(200);
        assert!(
            rx.recv_timeout(wait).is_err(),
            "ran while the lock was held"
        );
        drop(held);
        let done = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        assert_eq!(done, Ok(()));
        update.join().unwrap();
        assert_eq!(EnrollmentStore::load(&path), Ok(Some(enrollment(7))));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn concurrent_counter_updates_never_roll_back() {
        let dir = store_dir();
        let path = dir.join("enrollment.json");
        EnrollmentStore::enroll(&path, &enrollment(0)).unwrap();
        let updates: Vec<_> = (1..=32u32)
            .rev()
            .map(|count| {
                let target = path.clone();
                std::thread::spawn(move || {
                    EnrollmentStore::store_counter(&target, "Y3JlZC0x", count)
                })
            })
            .collect();
        for update in updates {
            let _ = update.join().unwrap();
        }
        // Serialised, the highest count always lands and nothing lower replaces it.
        assert_eq!(EnrollmentStore::load(&path), Ok(Some(enrollment(32))));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_counter_only_rises_for_the_stored_credential() {
        let dir = store_dir();
        let path = dir.join("enrollment.json");
        assert!(
            EnrollmentStore::store_counter(&path, "Y3JlZC0x", 1).is_err(),
            "nothing enrolled"
        );
        EnrollmentStore::enroll(&path, &enrollment(5)).unwrap();
        assert!(
            EnrollmentStore::store_counter(&path, "Y3JlZC0x", 5).is_err(),
            "equal"
        );
        assert!(
            EnrollmentStore::store_counter(&path, "Y3JlZC0x", 4).is_err(),
            "rollback"
        );
        assert!(
            EnrollmentStore::store_counter(&path, "Y3JlZC0x", 0).is_err(),
            "to zero"
        );
        assert!(
            EnrollmentStore::store_counter(&path, "Y3JlZC0y", 6).is_err(),
            "other credential"
        );
        assert_eq!(EnrollmentStore::load(&path), Ok(Some(enrollment(5))));
        let zero = dir.join("zero.json");
        EnrollmentStore::enroll(&zero, &enrollment(0)).unwrap();
        EnrollmentStore::store_counter(&zero, "Y3JlZC0x", 0).unwrap();
        assert_eq!(EnrollmentStore::load(&zero), Ok(Some(enrollment(0))));
        EnrollmentStore::store_counter(&zero, "Y3JlZC0x", 1).unwrap();
        assert_eq!(EnrollmentStore::load(&zero), Ok(Some(enrollment(1))));
        assert_eq!(
            names(&dir),
            [
                "enrollment.json",
                "enrollment.json.lock",
                "zero.json",
                "zero.json.lock"
            ]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_loose_mode_an_unknown_field_or_junk_is_an_error_not_none() {
        let dir = store_dir();
        let path = dir.join("enrollment.json");
        EnrollmentStore::enroll(&path, &enrollment(3)).unwrap();
        for mode in [0o644, 0o640, 0o604, 0o660, 0o700] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(EnrollmentStore::load(&path).is_err(), "mode {mode:o}");
            assert!(
                EnrollmentStore::store_counter(&path, "Y3JlZC0x", 4).is_err(),
                "mode {mode:o}"
            );
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            EnrollmentStore::load(&path),
            Ok(Some(enrollment(3))),
            "0400 is not looser"
        );
        let write = |name: &str, text: &str| {
            let p = dir.join(name);
            std::fs::write(&p, text).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            p
        };
        let mut extra = serde_json::to_value(enrollment(3)).unwrap();
        extra["replaced_by"] = json!("Y3JlZC0y");
        assert!(EnrollmentStore::load(&write("extra.json", &extra.to_string())).is_err());
        assert!(EnrollmentStore::load(&write("junk.json", "{")).is_err());
        assert!(EnrollmentStore::load(&write("empty.json", "")).is_err());
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(EnrollmentStore::load(&link).is_err(), "symlink");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
