use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture {
    dir: PathBuf,
    log: PathBuf,
    sidged: PathBuf,
    public: String,
}
impl Fixture {
    fn new() -> Self {
        let sidged = Path::new(env!("CARGO_BIN_EXE_sidged-tui")).with_file_name("sidged");
        assert!(
            sidged.exists(),
            "build the workspace first: cargo test --workspace"
        );
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sidged-log-verify-e2e-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let log = dir.join("audit.log");
        let mut fixture = Self {
            dir,
            log,
            sidged,
            public: String::new(),
        };
        {
            let mut chain = sidged_log::Chain::open(&fixture.log, &[7; 32]).unwrap();
            for i in 0..3 {
                chain
                    .append(&sidged_core::AuditEvent {
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
        fixture.public = fixture.printed_key("seed", "07");
        fixture
    }
    fn printed_key(&self, name: &str, byte: &str) -> String {
        let seed = self.dir.join(name);
        fs::write(&seed, byte.repeat(32)).unwrap();
        fs::set_permissions(&seed, fs::Permissions::from_mode(0o600)).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_sidged-tui"))
            .args(["log-pubkey", "--log-key"])
            .arg(seed)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0));
        assert!(out.stderr.is_empty());
        let stdout = String::from_utf8(out.stdout).unwrap();
        stdout
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("log-public-key "))
            .expect("missing public key line")
            .to_owned()
    }
    fn verify(&self, log: &Path, public: &str) -> Output {
        Command::new(&self.sidged)
            .args(["log", "verify"])
            .arg(log)
            .args(["--public", public])
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
#[test]
fn printed_key_verifies_with_sidged_log_verify() {
    let fixture = Fixture::new();
    let out = fixture.verify(&fixture.log, &fixture.public);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(out.stdout, b"audit-entries 3\n");
}
#[test]
fn wrong_key_fails_sidged_log_verify() {
    let fixture = Fixture::new();
    let wrong = fixture.printed_key("wrong-seed", "08");
    let out = fixture.verify(&fixture.log, &wrong);
    assert_eq!(out.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("audit-entries"));
}
#[test]
fn tampered_log_fails_sidged_log_verify() {
    let fixture = Fixture::new();
    let tampered = fixture.dir.join("tampered.log");
    fs::copy(&fixture.log, &tampered).unwrap();
    let text = fs::read_to_string(&tampered).unwrap();
    assert!(text
        .split_inclusive('\n')
        .nth(1)
        .unwrap()
        .contains("step-1"));
    fs::write(&tampered, text.replacen("step-1", "step-X", 1)).unwrap();
    let out = fixture.verify(&tampered, &fixture.public);
    assert_eq!(out.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("audit-entries"));
}
#[test]
fn malformed_public_key_is_usage_error() {
    let fixture = Fixture::new();
    let out = fixture.verify(&fixture.log, &fixture.public[..63]);
    assert_eq!(out.status.code(), Some(2));
}
