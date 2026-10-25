//! `vaikor mandate renew` in the real binary: an owner action, so without an interactive
//! terminal it refuses and the node's mandate stays as it was (0002 R23).
use std::process::{Command, Stdio};

#[test]
fn mandate_renew_refuses_without_a_terminal_and_changes_nothing() {
    let dir = std::env::temp_dir().join(format!("vaikor-mandate-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    vaikor_cli::turnkey::bootstrap_workspace(&dir).unwrap();
    let path = dir.join(vaikor_cli::turnkey::MANDATE_FILE);
    let before = std::fs::read(&path).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_vaikor"))
        .args(["mandate", "renew", "--workspace"])
        .arg(&dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("interactive terminal"), "{stderr}");
    assert_eq!(std::fs::read(&path).unwrap(), before);

    let out = Command::new(env!("CARGO_BIN_EXE_vaikor"))
        .args(["mandate", "widen"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage: vaikor mandate renew"));
    std::fs::remove_dir_all(dir).unwrap();
}
