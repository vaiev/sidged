//! 0007 §5 and R10a in the real binary: `sidged guard` does not open
//! `SIDGED_API_KEY_FILE` at startup. A refused run (local latch, audit log,
//! destination) never reads it. No live calls.
use std::path::{Path, PathBuf};
use std::process::Command;

const KEY: &str = "cli-TEST-send-time-key-9a21f3";

fn scratch(name: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("sidged-key-order-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    base
}

/// A key file the gateway would refuse (mode 0644): reading it names
/// "API key file" in the error.
fn bad_key(base: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = base.join("planner.key");
    std::fs::write(&path, format!("{KEY}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    path
}

fn guard(base: &Path, log: &Path, extra: &[&str], base_url: &str) -> (bool, String) {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../demo/ch-residency");
    let dir = base.join("scenario");
    std::fs::create_dir_all(&dir).unwrap();
    for name in [
        "config.json",
        "tools.json",
        "policy.cedar",
        "grant.json",
        "stub-plan.json",
    ] {
        std::fs::copy(source.join(name), dir.join(name)).unwrap();
    }
    let mut config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    // Keep the profile valid so this fixture reaches the destination check.
    config["provider_profile"] = "P0".into();
    std::fs::write(dir.join("config.json"), config.to_string()).unwrap();
    let log_key = base.join("log.key");
    std::fs::write(&log_key, "33".repeat(32)).unwrap();
    let keys = base.join("keys");
    let keygen = Command::new(env!("CARGO_BIN_EXE_sidged"))
        .arg("keygen")
        .arg(&keys)
        .output()
        .unwrap();
    assert!(keygen.status.success());
    let out = Command::new(env!("CARGO_BIN_EXE_sidged"))
        .arg("guard")
        .arg(dir)
        .arg("--keys")
        .arg(&keys)
        .arg("--log")
        .arg(log)
        .arg("--log-key")
        .arg(&log_key)
        .args(extra)
        .env_remove("SIDGED_API_KEY")
        .env_remove("SIDGED_LOCAL")
        .env("SIDGED_PROVIDER", "openai")
        .env("SIDGED_BASE_URL", base_url)
        .env("SIDGED_API_KEY_FILE", bad_key(base))
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!text.contains(KEY), "{text}");
    (out.status.success(), text)
}

#[test]
fn a_destination_denial_does_not_open_the_key_file() {
    let base = scratch("destination");
    let (ok, text) = guard(&base, &base.join("audit.log"), &[], "https://api.x.ai/v1");
    assert!(!ok);
    assert!(
        text.contains("destination does not match provider"),
        "{text}"
    );
    assert!(!text.contains("API key file"), "{text}");
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn an_unwritable_audit_log_does_not_open_the_key_file() {
    let base = scratch("audit");
    let (ok, text) = guard(
        &base,
        Path::new("/proc/sidged-unwritable-audit"),
        &[],
        "https://api.infomaniak.com/",
    );
    assert!(!ok);
    assert!(!text.contains("API key file"), "{text}");
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn local_mode_does_not_open_the_key_file() {
    let base = scratch("local");
    let (ok, text) = guard(
        &base,
        &base.join("audit.log"),
        &["--local"],
        "https://api.infomaniak.com/",
    );
    assert!(!ok);
    assert!(!text.contains("API key file"), "{text}");
    std::fs::remove_dir_all(base).unwrap();
}
