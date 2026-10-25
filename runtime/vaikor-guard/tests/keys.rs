mod common;
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn generated_keys_are_private_fresh_and_never_printed() {
    let root = std::env::temp_dir().join(format!("vaikor-keygen-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for name in ["one", "two"] {
        let dir = root.join(name);
        fs::create_dir_all(&root).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_vaikor"))
            .arg("keygen")
            .arg(&dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for role in ["issuer", "holder"] {
            let path = dir.join(format!("{role}.key"));
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let secret = fs::read_to_string(path).unwrap();
            assert_eq!(secret.trim().len(), 64);
            assert!(!String::from_utf8_lossy(&out.stdout).contains(secret.trim()));
            assert!(!String::from_utf8_lossy(&out.stderr).contains(secret.trim()));
        }
        let before = fs::read(dir.join("issuer.key")).unwrap();
        assert!(!Command::new(env!("CARGO_BIN_EXE_vaikor"))
            .arg("keygen")
            .arg(&dir)
            .output()
            .unwrap()
            .status
            .success());
        assert_eq!(before, fs::read(dir.join("issuer.key")).unwrap());
    }
    assert_ne!(
        fs::read(root.join("one/issuer.key")).unwrap(),
        fs::read(root.join("two/issuer.key")).unwrap()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn guard_refuses_rfc_demo_keys() {
    let root = std::env::temp_dir().join(format!("vaikor-rfc-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    for entry in fs::read_dir("../../demo/public-weather").unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            fs::copy(entry.path(), root.join(entry.file_name())).unwrap();
        }
    }
    let path = root.join("grant.json");
    let mut grant: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    grant["issuer_key"] = "rfc8032-test-1".into();
    grant["holder_key"] = "rfc8032-test-2".into();
    fs::write(&path, grant.to_string()).unwrap();
    fs::write(root.join("log.key"), "11".repeat(32)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_vaikor"))
        .arg("guard")
        .arg(&root)
        .arg("--log")
        .arg(root.join("audit"))
        .arg("--log-key")
        .arg(root.join("log.key"))
        .env("VAIKOR_PROVIDER", "stub")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("RFC 8032 test keys"));
    // The same keys must be rejected when supplied as files under generated-key names.
    common::keys(&root.join("keys"));
    grant["issuer_key"] = "keys/issuer.key".into();
    grant["holder_key"] = "keys/holder.key".into();
    fs::write(&path, grant.to_string()).unwrap();
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../spec/test-vectors/keys/rfc8032-test-keys.json"
    ))
    .unwrap();
    // Fixture keys plus RFC 8032 section 7.1 TEST 1024 and TEST SHA(abc), copied from the RFC.
    let mut secrets: Vec<String> = vectors["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["secret_key_hex"].as_str().unwrap().to_string())
        .collect();
    secrets.push("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5".into());
    secrets.push("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42".into());
    for secret in &secrets {
        fs::write(root.join("keys/issuer.key"), secret).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_vaikor"))
            .arg("guard")
            .arg(&root)
            .arg("--keys")
            .arg(root.join("keys"))
            .arg("--log")
            .arg(root.join("audit"))
            .arg("--log-key")
            .arg(root.join("log.key"))
            .env("VAIKOR_PROVIDER", "stub")
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("RFC 8032 test keys"));
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn run_trusts_generated_issuer_and_refuses_a_different_key_directory() {
    use serde_json::json;
    let root = std::env::temp_dir().join(format!("vaikor-run-keys-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    common::keys(&root.join("keys"));
    common::keys(&root.join("other"));
    let seed = common::seed(&root.join("keys/issuer.key"));
    let issuer = vaikor_grant::did_key(&vaikor_log::public_key(&seed));
    let holder = vaikor_grant::did_key(&vaikor_log::public_key(&common::seed(
        &root.join("keys/holder.key"),
    )));
    let cap = "tag:vaikor.com,2026:capability:calendar.free_slots";
    let token = vaikor_grant::attach_signature(
        &json!({
            "v":"0.1", "id":"generated-cli", "iss":issuer, "sub":holder,
            "aud":"did:example:hosted", "iat":"2026-10-14T12:00:00Z", "exp":"2026-10-14T12:30:00Z",
            "cnf":{"kid":holder}, "chain":[], "rights":[{"action":"calendar.free_slots","resource":cap}]
        }),
        &seed,
        &issuer,
    );
    fs::write(root.join("grant.json"), token.to_string()).unwrap();
    fs::write(
        root.join("plan.json"),
        json!({"v":"0.1","steps":[{"id":"one","kind":"call","capability":cap,"args":{}}]})
            .to_string(),
    )
    .unwrap();
    fs::write(root.join("catalog.json"), json!([{"id":cap,"effects":["read"],"data_classes":[],"consequential":false,"cost":{"class":"free"}}]).to_string()).unwrap();
    fs::write(
        root.join("policy.cedar"),
        "permit(principal, action, resource);",
    )
    .unwrap();
    for (dir, success) in [("keys", true), ("other", false)] {
        let out = Command::new(env!("CARGO_BIN_EXE_vaikor"))
            .current_dir(&root)
            .args([
                "run",
                "plan.json",
                "catalog.json",
                "--policy",
                "policy.cedar",
                "--grant",
                "grant.json",
                "--keys",
                dir,
                "--audience",
                "did:example:hosted",
                "--now",
                "2026-10-14T12:10:00Z",
                "--dry-run",
            ])
            .output()
            .unwrap();
        assert_eq!(
            out.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    fs::remove_dir_all(root).unwrap();
}

fn scenario_copy(tag: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("vaikor-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    for entry in fs::read_dir("../../demo/ch-residency").unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            fs::copy(entry.path(), root.join(entry.file_name())).unwrap();
        }
    }
    fs::write(root.join("log.key"), "22".repeat(32)).unwrap();
    root
}

fn guard_without_keys(root: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_vaikor"))
        .arg("guard")
        .arg(root)
        .arg("--log")
        .arg(root.join("audit"))
        .arg("--log-key")
        .arg(root.join("log.key"))
        .env("VAIKOR_PROVIDER", "stub")
        .output()
        .unwrap()
}

#[test]
fn guard_refuses_key_references_outside_scenario_keys() {
    let root = scenario_copy("keyref");
    let outside = std::env::temp_dir().join(format!("vaikor-outside-{}", std::process::id()));
    let _ = fs::remove_dir_all(&outside);
    common::keys(&outside);
    common::keys(&root.join("keys"));
    let path = root.join("grant.json");
    let mut grant: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let absolute = outside.join("issuer.key").display().to_string();
    let dotdot = format!(
        "../{}/holder.key",
        outside.file_name().unwrap().to_string_lossy()
    );
    for (issuer, holder) in [
        (absolute.as_str(), "keys/holder.key"),
        ("keys/issuer.key", dotdot.as_str()),
        ("keys/../keys/issuer.key", "keys/holder.key"),
    ] {
        grant["issuer_key"] = issuer.into();
        grant["holder_key"] = holder.into();
        fs::write(&path, grant.to_string()).unwrap();
        let out = guard_without_keys(&root);
        assert!(!out.status.success());
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("grant key reference must be"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // Fixed names, but the files are symlinks pointing outside the scenario.
    grant["issuer_key"] = "keys/issuer.key".into();
    grant["holder_key"] = "keys/holder.key".into();
    fs::write(&path, grant.to_string()).unwrap();
    fs::remove_dir_all(root.join("keys")).unwrap();
    fs::create_dir(root.join("keys")).unwrap();
    std::os::unix::fs::symlink(outside.join("issuer.key"), root.join("keys/issuer.key")).unwrap();
    std::os::unix::fs::symlink(outside.join("holder.key"), root.join("keys/holder.key")).unwrap();
    let out = guard_without_keys(&root);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("symlink"));
    // A symlinked keys directory is refused too.
    fs::remove_dir_all(root.join("keys")).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("keys")).unwrap();
    let out = guard_without_keys(&root);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("symlink"));
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(outside).unwrap();
}
