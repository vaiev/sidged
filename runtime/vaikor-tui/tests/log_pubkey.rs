use sha2::{Digest, Sha256};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "vaikor-tui-logkey-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn key(&self, text: &str, mode: u32) -> PathBuf {
        let p = self.0.join("key");
        fs::write(&p, text).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        p
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vaikor-tui"))
        .args(args)
        .output()
        .unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn no_secret(out: &Output, secret: &str) {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    for needle in [
        secret.to_string(),
        secret.to_uppercase(),
        secret.chars().take(16).collect(),
    ] {
        // Needles shorter than 16 chars could match the temp path (pid digits).
        if needle.len() >= 16 {
            assert!(!text.contains(&needle));
        }
    }
}
#[test]
fn public_key_and_fingerprint() {
    let temp = Temp::new();
    let secret = "07".repeat(32);
    let key = temp.key(&format!("{secret}\n \t"), 0o600);
    let out = run(&["log-pubkey", "--log-key", key.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    let public = vaikor_log::public_key(&[7; 32]);
    let digest = hex(&Sha256::digest(public));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!(
            "log-public-key {}\nfingerprint sha256:{}\n",
            hex(&public),
            &digest[..16]
        )
    );
    assert!(out.stderr.is_empty());
    no_secret(&out, &secret);
}
#[test]
fn refuses_unsafe_or_invalid_keys_without_disclosure() {
    let temp = Temp::new();
    let secret = "07".repeat(32);
    let key = temp.key(&secret, 0o644);
    for mode in [0o644, 0o640, 0o400, 0o700] {
        fs::set_permissions(&key, fs::Permissions::from_mode(mode)).unwrap();
        let out = run(&["log-pubkey", "--log-key", key.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("mode"));
        no_secret(&out, &secret);
    }
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let link = temp.0.join("link");
    symlink(&key, &link).unwrap();
    for path in [link, temp.0.join("missing"), temp.0.clone()] {
        let out = run(&["log-pubkey", "--log-key", path.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
        assert!(!out.stderr.is_empty());
        no_secret(&out, &secret);
    }
    for bad in [
        "not-a-secret-hex-key".to_string(),
        "07".into(),
        "é".repeat(32),
        "g".repeat(64),
    ] {
        fs::write(&key, &bad).unwrap();
        let out = run(&["log-pubkey", "--log-key", key.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
        no_secret(&out, &bad);
    }
    for args in [vec!["log-pubkey"], vec!["log-pubkey", "--log-key"]] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
        assert!(!out.stderr.is_empty());
    }
}
#[test]
fn printed_public_key_verifies_a_chain_signed_with_the_seed() {
    // The demo hands this key to `vaikor log verify --public` (0005 R7).
    let temp = Temp::new();
    let path = temp.0.join("audit.log");
    {
        let mut chain = vaikor_log::Chain::open(&path, &[7; 32]).unwrap();
        for i in 0..3 {
            chain
                .append(&vaikor_core::AuditEvent {
                    privacy_report: None,
                    usage: None,
                    reason: None,
                    step: format!("step-{i}"),
                    capability: "test".into(),
                    effects: vec![],
                    data_classes: vec![],
                    decision: "allow".into(),
                    actor: "core".into(),
                    at: "2026-10-17T00:00:00Z".into(),
                    approval: None,
                })
                .unwrap();
        }
    }
    let key = temp.key(&"07".repeat(32), 0o600);
    let out = run(&["log-pubkey", "--log-key", key.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8(out.stdout).unwrap();
    let printed = stdout
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("log-public-key "))
        .unwrap();
    let public: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&printed[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    let public: [u8; 32] = public.try_into().unwrap();
    assert_eq!(vaikor_log::verify_file(&path, &public), Ok(3));
    assert!(vaikor_log::verify_file(&path, &vaikor_log::public_key(&[8; 32])).is_err());
}

#[test]
fn seed_file_over_130_bytes_is_refused() {
    let temp = Temp::new();
    let secret = "07".repeat(32);
    for padding in [" ".repeat(67), "\n".repeat(4032)] {
        let key = temp.key(&format!("{secret}{padding}"), 0o600);
        let out = run(&["log-pubkey", "--log-key", key.to_str().unwrap()]);
        no_secret(&out, &secret);
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("too large"));
    }
}

#[test]
fn seed_file_of_exactly_130_bytes_is_accepted() {
    let temp = Temp::new();
    let secret = "07".repeat(32);
    let key = temp.key(&format!("{secret}{}", " \n".repeat(33)), 0o600);
    let out = run(&["log-pubkey", "--log-key", key.to_str().unwrap()]);
    no_secret(&out, &secret);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).lines().next().unwrap(),
        format!("log-public-key {}", hex(&vaikor_log::public_key(&[7; 32])))
    );
    assert!(out.stderr.is_empty());
}
