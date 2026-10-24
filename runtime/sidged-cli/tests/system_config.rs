//! System config store (turnkey WP b1): non-secret settings and credential
//! references only (0007 R2, R10, R10a; 0004 R9, R9c). Saved atomically, 0600,
//! owned by the Core uid; loaded only from a private regular file.
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use sidged_cli::system_config::{self, Interface, ProviderId, SystemConfig};

const KEY: &str = "Zq9TESTsystemConfigKey0042";

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sidged-sysconf-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn vectors() -> serde_json::Value {
    let mut file: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/system-config-vectors.json")).unwrap();
    // Exercise the real detector without storing a key-shaped literal on disk.
    for vector in file["vectors"].as_array_mut().unwrap() {
        if vector["id"] == "secret-in-unknown-field" {
            assert_eq!(vector["config"]["note"], "NOT-A-KEY-SYNTHETIC-ACCESS-ID");
            vector["config"]["note"] = ["AK", "IA", "ABCDEFGHIJKLMNOP"].concat().into();
        }
    }
    file
}

#[test]
fn vectors_accept_and_refuse_with_the_named_reason() {
    let file = vectors();
    let core = file["core_uid"].as_u64().unwrap() as u32;
    for vector in file["vectors"].as_array().unwrap() {
        let id = vector["id"].as_str().unwrap();
        let result = system_config::parse(&vector["config"], core);
        match vector["expected"].as_str().unwrap() {
            "accept" => {
                let config = result.unwrap_or_else(|e| panic!("{id}: {e}"));
                // Round trip: what is saved parses back to the same config.
                let again = system_config::parse(&system_config::to_value(&config), core)
                    .unwrap_or_else(|e| panic!("{id} round trip: {e}"));
                assert_eq!(config, again, "{id}");
            }
            "refuse" => {
                let error = result.err().unwrap_or_else(|| panic!("{id}: accepted"));
                let reason = vector["reason"].as_str().unwrap();
                assert!(error.contains(reason), "{id}: {error:?} lacks {reason:?}");
            }
            other => panic!("{id}: bad expectation {other}"),
        }
    }
}

#[test]
fn parsed_fields_hold_references_only() {
    let file = vectors();
    let gemini = file["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "gemini-with-project-and-file-reference")
        .unwrap();
    let config = system_config::parse(&gemini["config"], 990).unwrap();
    let provider = config.provider.as_ref().unwrap();
    assert_eq!(provider.id, ProviderId::Gemini);
    assert_eq!(provider.id.as_str(), "gemini");
    assert_eq!(provider.project.as_deref(), Some("billing-project"));
    assert_eq!(
        provider.credential.as_deref(),
        Some(Path::new("/var/lib/sidged/credentials/gemini.key"))
    );
    assert_eq!(config.interface, Interface::StaticShell);
    let approval = config.approval.as_ref().unwrap();
    assert_eq!(
        (approval.approver, approval.non_approvers.clone()),
        (1001, vec![1002, 1003])
    );
}

fn sample() -> SystemConfig {
    system_config::parse(
        &serde_json::json!({"v": "0.1", "mode": "personal", "local": false, "interface": "tui",
            "provider": {"id": "xai", "credential": {"file": "/nonexistent/xai.key"}}}),
        euid(),
    )
    .unwrap()
}

#[test]
fn save_writes_a_private_file_atomically_and_load_reads_it_back() {
    let dir = scratch("save");
    let path = dir.join("config.json");
    system_config::save(&path, &sample()).unwrap();
    let meta = std::fs::symlink_metadata(&path).unwrap();
    assert!(meta.is_file());
    assert_eq!(meta.mode() & 0o7777, 0o600);
    assert_eq!(meta.uid(), euid());
    assert_eq!(system_config::load(&path, euid()).unwrap(), sample());
    // Saving again replaces the file (new inode) and leaves no temp file.
    let before = meta.ino();
    system_config::save(&path, &sample()).unwrap();
    assert_ne!(std::fs::metadata(&path).unwrap().ino(), before);
    let names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["config.json"]);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn save_refuses_a_symlink_target_and_a_shared_directory() {
    let dir = scratch("save-refuse");
    let victim = dir.join("victim");
    std::fs::write(&victim, "untouched").unwrap();
    let link = dir.join("config.json");
    std::os::unix::fs::symlink(&victim, &link).unwrap();
    assert!(system_config::save(&link, &sample())
        .unwrap_err()
        .contains("symlink"));
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
    let shared = dir.join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
    let error = system_config::save(&shared.join("config.json"), &sample()).unwrap_err();
    assert!(error.contains("directory"), "{error}");
    assert!(!shared.join("config.json").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn load_refuses_symlinks_shared_modes_foreign_types_and_oversize() {
    let dir = scratch("load-refuse");
    let path = dir.join("config.json");
    system_config::save(&path, &sample()).unwrap();
    for mode in [0o640, 0o604, 0o660] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let error = system_config::load(&path, euid()).unwrap_err();
        assert!(error.contains("mode"), "{mode:o}: {error}");
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.join("link.json");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(system_config::load(&link, euid())
        .unwrap_err()
        .contains("symlink"));
    assert!(system_config::load(&dir, euid()).is_err());
    let fifo = dir.join("fifo");
    let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(system_config::load(&fifo, euid())
        .unwrap_err()
        .contains("regular"));
    let big = dir.join("big.json");
    std::fs::write(&big, " ".repeat(70 * 1024)).unwrap();
    std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(system_config::load(&big, euid())
        .unwrap_err()
        .contains("large"));
    let foreign = system_config::load(&path, euid().wrapping_add(1)).unwrap_err();
    assert!(foreign.contains("owner"), "{foreign}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn load_refuses_key_material_in_the_file() {
    let dir = scratch("load-secret");
    let path = dir.join("config.json");
    std::fs::write(
        &path,
        r#"{"v":"0.1","mode":"personal","local":false,"interface":"tui","provider":{"id":"gemini","project":"ghp_abcdefghijklmnopqrstuvwxyz"}}"#,
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let error = system_config::load(&path, euid()).unwrap_err();
    assert!(error.contains("key material"), "{error}");
    assert!(
        !error.contains("ghp_"),
        "the matched text is never echoed: {error}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn debug_and_saved_json_never_contain_key_bytes() {
    let dir = scratch("debug");
    let key = dir.join("xai.key");
    std::fs::write(&key, KEY).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = system_config::parse(
        &serde_json::json!({"v": "0.1", "mode": "personal", "local": false, "interface": "tui",
            "provider": {"id": "xai", "credential": {"file": key}}}),
        euid(),
    )
    .unwrap();
    assert!(!format!("{config:?}").contains(KEY));
    let path = dir.join("config.json");
    system_config::save(&path, &config).unwrap();
    assert!(!std::fs::read_to_string(&path).unwrap().contains(KEY));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_store_and_the_wizard_open_no_listener() {
    for (name, source) in [
        ("system_config.rs", include_str!("../src/system_config.rs")),
        ("init.rs", include_str!("../src/init.rs")),
    ] {
        for needle in [
            "TcpListener",
            "UnixListener",
            "UdpSocket",
            "bind(",
            "listen(",
        ] {
            assert!(!source.contains(needle), "{name} contains {needle}");
        }
    }
}

#[test]
fn fixture_contains_no_access_key_shaped_literal() {
    let prefix = ["AK", "IA"].concat();
    assert!(!include_str!("fixtures/system-config-vectors.json").contains(&prefix));
}
