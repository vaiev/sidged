//! Non-interactive tool: print the Core audit-log public key. Verification is
//! `sidged log verify <file> --public <hex>` (0005 R7).
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use zeroize::Zeroizing;

const MAX_SEED_FILE: usize = 130;

/// Read an owner-only seed file without following symlinks. Errors contain no key data.
pub fn log_public_key(path: &Path) -> Result<[u8; 32], String> {
    let error = |why: String| format!("log key file {}: {why}", path.display());
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            error(if e.raw_os_error() == Some(libc::ELOOP) {
                "symlink refused".into()
            } else {
                e.kind().to_string()
            })
        })?;
    let meta = file.metadata().map_err(|e| error(e.kind().to_string()))?;
    if !meta.is_file() {
        return Err(error("not a regular file".into()));
    }
    // Same rule as the API key file: exactly 0600, owned by the reading uid.
    // SAFETY: geteuid has no preconditions.
    sidged_gateway::check_key_file_meta(meta.mode(), meta.uid(), unsafe { libc::geteuid() })
        .map_err(error)?;
    if meta.len() > MAX_SEED_FILE as u64 {
        return Err(error(format!("too large (max {MAX_SEED_FILE} bytes)")));
    }
    let mut bytes = Zeroizing::new([0u8; MAX_SEED_FILE]);
    let mut filled = 0;
    while filled < MAX_SEED_FILE {
        match file.read(&mut bytes[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(error(e.kind().to_string())),
        }
    }
    if filled == MAX_SEED_FILE {
        let mut probe = Zeroizing::new([0u8; 1]);
        loop {
            match file.read(&mut probe[..]) {
                Ok(0) => break,
                Ok(_) => return Err(error(format!("too large (max {MAX_SEED_FILE} bytes)"))),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(error(e.kind().to_string())),
            }
        }
    }
    while filled > 0 && matches!(bytes[filled - 1], b' ' | b'\t' | b'\n' | b'\r') {
        filled -= 1;
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    decode_hex(&bytes[..filled], &mut seed).map_err(|_| error("must be 32 bytes hex".into()))?;
    Ok(sidged_log::public_key(&seed))
}

fn decode_hex(text: &[u8], out: &mut [u8; 32]) -> Result<(), String> {
    if text.len() != 64 {
        return Err("must be 32 bytes hex".into());
    }
    let nibble = |b| match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("must be 32 bytes hex".to_string()),
    };
    for (slot, pair) in out.iter_mut().zip(text.chunks_exact(2)) {
        *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Short SHA-256 fingerprint of the public bytes.
pub fn fingerprint(public: &[u8; 32]) -> String {
    format!("sha256:{}", &hex(&Sha256::digest(public))[..16])
}

/// Dispatch the public-key command without terminal or build-SHA requirements.
pub fn log_pubkey_command(args: &[String]) -> Result<(), String> {
    let [flag, path] = args else {
        return Err("usage: sidged-tui log-pubkey --log-key <PATH>".into());
    };
    if flag != "--log-key" {
        return Err("usage: sidged-tui log-pubkey --log-key <PATH>".into());
    }
    let public = log_public_key(Path::new(path))?;
    println!(
        "log-public-key {}\nfingerprint {}",
        hex(&public),
        fingerprint(&public)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_unbounded_read_in_seed_reader() {
        let source = include_str!("logkey.rs");
        assert!(!source.contains(concat!("read_to", "_string")));
        assert!(source.contains("[u8; MAX_SEED_FILE]") || source.contains("[0u8; MAX_SEED_FILE]"));
    }
}
