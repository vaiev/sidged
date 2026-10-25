//! Turnkey WP e: the app openers open the local shell file, accept only
//! `http://` + loopback IP literal + port, and refuse everything else with
//! exit 2 (`scripts/tests/open_app_check.sh`).
use std::path::Path;
use std::process::Command;

#[test]
fn openers_accept_only_the_shell_file_or_a_loopback_literal() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new("bash")
        .arg(root.join("scripts/tests/open_app_check.sh"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn openers_pass_style_and_profile_safety_checks() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut failures = Vec::new();
    match Command::new("shellcheck")
        .args(["-S", "style"])
        .arg(root.join("scripts/open-vaikor-app.sh"))
        .arg(root.join("scripts/tests/open_app_check.sh"))
        .output()
    {
        Ok(out) => {
            if !out.status.success() {
                failures.push(format!(
                    "shellcheck: {}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            println!("shellcheck not on PATH; style check skipped");
        }
        Err(err) => panic!("cannot run shellcheck: {err}"),
    }
    for script in ["scripts/open-vaikor-app.sh", "scripts/open-vaikor-app.ps1"] {
        let source = std::fs::read_to_string(root.join(script)).unwrap();
        if !source.contains("launcher forked and the temporary profile was removed") {
            failures.push(format!("{script}: missing launcher warning"));
        }
        if source.contains("/tmp/") {
            failures.push(format!("{script}: literal temporary profile path"));
        }
        if script.ends_with(".ps1") {
            if source.contains("$'") || source.contains("$\"") || !source.contains(r"\z") {
                failures.push(format!("{script}: regexes must use absolute end anchors"));
            }
            if source.contains("\"vaikor-app-profile\"") {
                failures.push(format!("{script}: fixed profile directory"));
            }
        } else if !source.contains("mktemp -d") {
            failures.push(format!("{script}: profile must use mktemp -d"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
