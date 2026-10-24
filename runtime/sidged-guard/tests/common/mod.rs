// Shared by several integration tests; not every test binary uses every helper.
#![allow(dead_code)]

pub fn report_only_scenario(root: &std::path::Path) -> std::path::PathBuf {
    let dir = root.join("scenario");
    std::fs::create_dir_all(&dir).unwrap();
    for name in [
        "config.json",
        "tools.json",
        "policy.cedar",
        "grant.json",
        "stub-plan.json",
    ] {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../demo/public-weather")
            .join(name);
        let text = std::fs::read_to_string(source)
            .unwrap()
            .replace("weather.lookup", "weather.proposal");
        std::fs::write(dir.join(name), text).unwrap();
    }
    dir
}

/// An approved guard run, in-process. 0004 R9 forbids any approval path in
/// the `sidged` binary that lacks a separate approver uid, so tests inject
/// `FixedApproval` through the library instead (nothing reachable by a
/// feature flag or CLI mode).
pub fn approved_guard(
    dir: &std::path::Path,
    keys: &std::path::Path,
    log: &std::path::Path,
    key: &std::path::Path,
) -> Result<sidged_guard::GuardReport, String> {
    let seed = seed(key);
    let approval = sidged_cli::FixedApproval {
        granted: true,
        actor: "test-approver".into(),
    };
    sidged_guard::run_from_env_with_keys(
        dir,
        "stub",
        None,
        None,
        None,
        &approval,
        Some(sidged_guard::LogTarget {
            path: log,
            seed: &seed,
        }),
        Some(keys),
    )
}

use std::{path::Path, process::Command};
pub fn keys(dir: &Path) {
    let out = Command::new(env!("CARGO_BIN_EXE_sidged"))
        .arg("keygen")
        .arg(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
pub fn seed(path: &Path) -> [u8; 32] {
    let text = std::fs::read_to_string(path).unwrap();
    let mut seed = [0; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap();
    }
    seed
}
