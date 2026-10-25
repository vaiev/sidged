#[test]
fn a_log_target_without_a_key_refuses_before_planning() {
    let demo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../demo/ch-residency");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vaikor"))
        .arg("guard")
        .arg(demo)
        .args(["--log", "unused-audit.log"])
        .env("VAIKOR_PROVIDER", "openai")
        .env("VAIKOR_BASE_URL", "https://api.openai.com")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--log-key is required"));
}
