//! xAI planner key handling in the real binary: file only, never in the
//! environment, never in stdout/stderr or the signed audit log. No live calls.
use std::path::Path;
use std::process::Command;

const KEY: &str = "xai-TEST-guard-key-4b1d2e";

fn guard(env: &[(&str, &str)], log: &Path, log_key: &Path) -> std::process::Output {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../demo/ch-residency");
    let mut command = Command::new(env!("CARGO_BIN_EXE_vaikor"));
    command
        .arg("guard")
        .arg(dir)
        .arg("--log")
        .arg(log)
        .arg("--log-key")
        .arg(log_key);
    command
        .env_remove("VAIKOR_API_KEY")
        .env_remove("VAIKOR_API_KEY_FILE")
        .env_remove("VAIKOR_LOCAL");
    for (k, v) in env {
        command.env(k, v);
    }
    command.output().unwrap()
}

#[test]
fn xai_key_from_env_is_refused_and_file_key_never_leaks() {
    let base = std::env::temp_dir().join(format!("vaikor-xai-guard-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let log_key = base.join("log.key");
    std::fs::write(&log_key, "22".repeat(32)).unwrap();
    let key_file = base.join("xai.key");
    write600(&key_file, format!("{KEY}\n"));
    let key_path = key_file.to_str().unwrap();
    let xai = [
        ("VAIKOR_PROVIDER", "openai"),
        ("VAIKOR_BASE_URL", "https://api.x.ai/v1"),
    ];

    // env key for xAI: refused at startup, no audit log written
    let log = base.join("env.log");
    let out = guard(&[xai[0], xai[1], ("VAIKOR_API_KEY", KEY)], &log, &log_key);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("VAIKOR_API_KEY_FILE"), "{stderr}");
    assert!(!stderr.contains(KEY) && !String::from_utf8_lossy(&out.stdout).contains(KEY));
    assert!(!log.exists());

    // A percent-encoded host is still xAI
    let out = guard(
        &[
            xai[0],
            ("VAIKOR_BASE_URL", "https://%61pi.x.ai/v1"),
            ("VAIKOR_API_KEY", KEY),
        ],
        &log,
        &log_key,
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // both set: refused
    let out = guard(
        &[
            xai[0],
            xai[1],
            ("VAIKOR_API_KEY", KEY),
            ("VAIKOR_API_KEY_FILE", key_path),
        ],
        &log,
        &log_key,
    );
    assert_eq!(out.status.code(), Some(2));

    // missing file: not opened at startup (0007 R10a: read at send time); the
    // run is refused before the send (here: no grant keys), so the file is
    // never read at all
    let out = guard(
        &[
            xai[0],
            xai[1],
            ("VAIKOR_API_KEY_FILE", base.join("absent").to_str().unwrap()),
        ],
        &log,
        &log_key,
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("API key file"), "{stderr}");

    // file key accepted at startup; the run fails before transport (no live
    // call). Whatever happens, the key appears in no output or audit entry.
    let log = base.join("file.log");
    let out = guard(
        &[xai[0], xai[1], ("VAIKOR_API_KEY_FILE", key_path)],
        &log,
        &log_key,
    );
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "no live xAI call in tests: {all}");
    assert!(!all.contains(KEY), "{all}");
    if let Ok(audit) = std::fs::read(&log) {
        assert!(
            !String::from_utf8_lossy(&audit).contains(KEY),
            "key in audit log"
        );
    }
    std::fs::remove_dir_all(base).unwrap();
}

fn write600(path: &std::path::Path, contents: impl AsRef<[u8]>) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
