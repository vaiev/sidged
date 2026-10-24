// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! `sidged swarm measure` exists only in a build with the feature `experimental`
//! (ROADMAP v0.5, 11g); the default build refuses it.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sidged-swarm-cli-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn measure(dir: &std::path::Path) -> Output {
    let key = dir.join("edge.key");
    fs::write(&key, "42".repeat(32)).unwrap();
    Command::new(env!("CARGO_BIN_EXE_sidged"))
        .args(["swarm", "measure", "--log-key"])
        .arg(&key)
        .arg("--log")
        .arg(dir.join("audit.log"))
        .args([
            "--image-digest",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--nonce",
            "challenge-1",
        ])
        .output()
        .unwrap()
}

#[cfg(not(feature = "experimental"))]
#[test]
fn the_default_build_refuses_swarm_measure() {
    let dir = scratch("default");
    let out = measure(&dir);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("experimental"), "{err}");
    let _ = fs::remove_dir_all(dir);
}

#[cfg(feature = "experimental")]
#[test]
fn the_experimental_build_signs_a_measurement() {
    let dir = scratch("experimental");
    let out = measure(&dir);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["nonce"], "challenge-1");
    assert!(report["edge_did"].as_str().unwrap().starts_with("did:key:"));
    assert!(!report["sig"].as_str().unwrap().is_empty());
    let _ = fs::remove_dir_all(dir);
}
