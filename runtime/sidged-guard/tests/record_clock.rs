use std::process::Command;

// Record storage never accepts a CLI clock override.
// The plan runner's --now must not become a path to Record retention checks.
#[test]
fn cli_cannot_read_records_with_a_caller_clock() {
    let output = Command::new(env!("CARGO_BIN_EXE_sidged"))
        .args(["record", "read", "digest", "--now", "2000-01-01T00:00:00Z"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr).unwrap().contains("usage:"));
}
