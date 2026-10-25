//! `vaikor init` in the real binary: refuses a non-TTY, runs on a real PTY
//! with the key prompt in echo-off mode, and `vaikor guard --system-config`
//! applies the written config (local latch, credential reference, approval
//! uids). No live calls, no listener.
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const KEY: &str = "Zq9TESTptyWizardKey3141";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vaikor-init-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[test]
fn init_refuses_without_a_terminal() {
    let dir = scratch("notty");
    let path = dir.join("config.json");
    let out = Command::new(env!("CARGO_BIN_EXE_vaikor"))
        .args(["init", "--config"])
        .arg(&path)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("terminal"), "{stderr}");
    assert!(!path.exists());
    std::fs::remove_dir_all(dir).unwrap();
}

/// A child process on a fresh PTY; the test reads what it prints and types
/// answers only after the expected prompt has appeared.
struct Pty {
    master: File,
    child: std::process::Child,
    seen: String,
}

impl Pty {
    /// The `Command` (and with it every parent copy of the slave fd) is
    /// dropped here, so the master reads EOF/EIO once the child exits.
    fn spawn(args: &[&std::ffi::OsStr]) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vaikor"));
        command.args(args);
        // SAFETY: plain libc PTY setup; every return value is checked.
        unsafe {
            let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
            assert!(master >= 0);
            assert_eq!(libc::grantpt(master), 0);
            assert_eq!(libc::unlockpt(master), 0);
            let mut name = [0 as libc::c_char; 128];
            assert_eq!(libc::ptsname_r(master, name.as_mut_ptr(), name.len()), 0);
            let slave = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
            assert!(slave >= 0);
            let slave = OwnedFd::from_raw_fd(slave);
            command
                .stdin(Stdio::from(slave.try_clone().unwrap()))
                .stdout(Stdio::from(slave.try_clone().unwrap()))
                .stderr(Stdio::from(slave))
                .pre_exec(|| {
                    if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            let child = command.spawn().unwrap();
            Self {
                master: File::from_raw_fd(master),
                child,
                seen: String::new(),
            }
        }
    }

    /// Read until `needle` appears after the current position (10 s limit).
    fn expect(&mut self, needle: &str) {
        let start = self.seen.len();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.seen[start..].contains(needle) {
            assert!(
                Instant::now() < deadline,
                "timeout waiting for {needle:?}: {}",
                self.seen
            );
            if self.read_some() == Read::Closed {
                panic!("child closed the terminal before {needle:?}: {}", self.seen);
            }
        }
    }

    fn read_some(&mut self) -> Read {
        let mut poll = libc::pollfd {
            fd: self.master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        let ready = unsafe { libc::poll(&mut poll, 1, 200) };
        if ready <= 0 {
            return Read::Idle;
        }
        let mut buf = [0u8; 4096];
        match std::io::Read::read(&mut self.master, &mut buf) {
            Ok(0) | Err(_) => Read::Closed, // EIO once the child side is closed
            Ok(n) => {
                self.seen.push_str(&String::from_utf8_lossy(&buf[..n]));
                Read::Data
            }
        }
    }

    fn send(&mut self, line: &str) {
        self.master.write_all(line.as_bytes()).unwrap();
        self.master.write_all(b"\n").unwrap();
    }

    /// Drain output until the terminal closes (10 s limit), then reap.
    fn finish(mut self) -> (Option<i32>, String) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.read_some() != Read::Closed {
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                panic!("child did not finish: {}", self.seen);
            }
        }
        let status = self.child.wait().unwrap();
        (status.code(), self.seen)
    }
}

#[derive(PartialEq, Eq)]
enum Read {
    Data,
    Idle,
    Closed,
}

#[test]
fn init_on_a_pty_hides_the_key_and_writes_a_private_config() {
    let dir = scratch("pty");
    let path = dir.join("config.json");
    let state = dir.join("state");
    let mut pty = Pty::spawn(&[
        "init".as_ref(),
        "--config".as_ref(),
        path.as_os_str(),
        "--state-dir".as_ref(),
        state.as_os_str(),
    ]);
    pty.expect("Local mode");
    pty.send("n");
    pty.expect("Provider");
    pty.send("xai");
    pty.expect("API key source");
    pty.send("e");
    // The prompt is printed only after echo is off, so the typed key is
    // never echoed back by the terminal.
    pty.expect("input hidden");
    pty.send(KEY);
    pty.expect("Approver uid");
    pty.send("");
    pty.expect("Interface");
    pty.send("");
    let (code, seen) = pty.finish();
    assert_eq!(code, Some(0), "{seen}");
    assert!(!seen.contains(KEY) && !seen.contains(&KEY[..4]), "{seen}");
    assert!(seen.contains("configured"), "{seen}");
    let saved = std::fs::read_to_string(&path).unwrap();
    assert!(!saved.contains(KEY));
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o600);
    assert!(!dir.join("credentials").exists());
    assert_eq!(
        std::fs::metadata(state.join("credentials"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(state.join("credentials/xai.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let key = std::fs::read_to_string(state.join("credentials/xai.key")).unwrap();
    assert_eq!(key.trim(), KEY);
    std::fs::remove_dir_all(dir).unwrap();
}

fn write_config(dir: &Path, config: serde_json::Value) -> PathBuf {
    let path = dir.join("config.json");
    std::fs::write(&path, config.to_string()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn guard(dir: &Path, config: &Path, extra: &[&str], env: &[(&str, &str)]) -> (Option<i32>, String) {
    let scenario = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../demo/ch-residency");
    let log_key = dir.join("log.key");
    std::fs::write(&log_key, "44".repeat(32)).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_vaikor"));
    command
        .arg("guard")
        .arg(scenario)
        .arg("--system-config")
        .arg(config)
        .arg("--log")
        .arg(dir.join("audit.log"))
        .arg("--log-key")
        .arg(&log_key)
        .args(extra)
        .env_remove("VAIKOR_API_KEY")
        .env_remove("VAIKOR_API_KEY_FILE")
        .env_remove("VAIKOR_BASE_URL")
        .env_remove("VAIKOR_LOCAL");
    for (k, v) in env {
        command.env(k, v);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("guard blocked before refusal");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let out = child.wait_with_output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code(), text)
}

#[test]
fn guard_takes_the_local_latch_from_the_system_config() {
    let dir = scratch("guard-local");
    let config = write_config(
        &dir,
        serde_json::json!({"v": "0.1", "mode": "personal", "local": true, "interface": "tui"}),
    );
    let (code, text) = guard(
        &dir,
        &config,
        &[
            "--approve",
            "unix:/nonexistent/vaikor/s",
            "--approve-uid",
            "41001",
        ],
        &[],
    );
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("local mode"), "{text}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn guard_uses_the_provider_base_url_and_credential_reference_without_leaking_the_key() {
    let dir = scratch("guard-xai");
    let key = dir.join("xai.key");
    std::fs::write(&key, format!("{KEY}\n")).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = write_config(
        &dir,
        serde_json::json!({"v": "0.1", "mode": "personal", "local": false, "interface": "tui",
            "provider": {"id": "xai", "credential": {"file": key}}}),
    );
    let (code, text) = guard(&dir, &config, &[], &[("VAIKOR_PROVIDER", "openai")]);
    // The xAI base URL comes from the provider id; the ch-residency scenario
    // is registered for Infomaniak, so the run is refused before transport.
    assert_ne!(code, Some(0), "{text}");
    assert!(!text.contains("VAIKOR_BASE_URL is required"), "{text}");
    assert!(!text.contains(KEY), "{text}");
    if let Ok(audit) = std::fs::read(dir.join("audit.log")) {
        assert!(!String::from_utf8_lossy(&audit).contains(KEY));
    }
    // A base URL for another provider than the configured one is refused.
    let (code, text) = guard(
        &dir,
        &config,
        &[],
        &[
            ("VAIKOR_PROVIDER", "openai"),
            ("VAIKOR_BASE_URL", "https://api.infomaniak.com/"),
        ],
    );
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("does not match the system config provider"),
        "{text}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn guard_refuses_a_shared_or_invalid_system_config() {
    let dir = scratch("guard-bad");
    let config = write_config(
        &dir,
        serde_json::json!({"v": "0.1", "mode": "personal", "local": false, "interface": "tui"}),
    );
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (code, text) = guard(&dir, &config, &[], &[]);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("mode"), "{text}");
    let config = write_config(&dir, serde_json::json!({"v": "0.1", "mode": "swarm"}));
    let (code, text) = guard(&dir, &config, &[], &[]);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("swarm"), "{text}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn guard_does_not_open_system_config_credential_before_refusal() {
    let dir = scratch("fifo");
    let key = dir.join("credential.fifo");
    assert!(Command::new("mkfifo").arg(&key).status().unwrap().success());
    let config = write_config(
        &dir,
        serde_json::json!({"v": "0.1", "mode": "personal", "local": false, "interface": "tui",
            "provider": {"id": "xai", "credential": {"file": key}}}),
    );
    let (code, text) = guard(&dir, &config, &[], &[("VAIKOR_PROVIDER", "openai")]);
    assert_ne!(code, Some(0), "{text}");
    assert!(!text.contains("VAIKOR_BASE_URL is required"), "{text}");
    assert!(!text.contains("key file"), "{text}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn guard_refuses_conflicting_cli_and_system_approver_uids() {
    let dir = scratch("approver-conflict");
    let config = write_config(
        &dir,
        serde_json::json!({"v": "0.1", "mode": "personal", "local": false, "interface": "tui",
            "approval": {"approve_uid": 41001, "non_approver_uids": [41002]}}),
    );
    for extra in [
        vec!["--approve-uid", "41003"],
        vec![
            "--approve",
            "unix:/nonexistent/vaikor/s",
            "--approve-uid",
            "41003",
        ],
    ] {
        let (code, text) = guard(&dir, &config, &extra, &[]);
        assert_eq!(code, Some(2), "{text}");
        assert!(
            text.contains("--approve-uid conflicts with system config"),
            "{text}"
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn guard_matching_cli_and_system_approver_uids_reach_channel_validation() {
    let dir = scratch("approver-matches");
    let config = write_config(
        &dir,
        serde_json::json!({"v": "0.1", "mode": "personal", "local": false, "interface": "tui",
            "approval": {"approve_uid": 41001, "non_approver_uids": [41002]}}),
    );
    let (code, text) = guard(&dir, &config, &["--approve-uid", "41001"], &[]);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("require --approve unix:<path>"), "{text}");
    assert!(!text.contains("conflicts with system config"), "{text}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn guard_names_the_selected_approver_source_once() {
    for (configured, cli, source) in [
        (true, false, "system config"),
        (false, true, "cli"),
        (true, true, "cli"),
    ] {
        let dir = scratch(&format!("source-{configured}-{cli}"));
        let mut value =
            serde_json::json!({"v":"0.1", "mode":"personal", "local":false, "interface":"tui"});
        if configured {
            value["approval"] =
                serde_json::json!({"approve_uid":41001,"non_approver_uids":[41002]});
        }
        let config = write_config(&dir, value);
        let mut args = vec!["--approve", "unix:/nonexistent/vaikor/s"];
        if cli {
            args.extend(["--approve-uid", "41001"]);
        }
        let (_, text) = guard(&dir, &config, &args, &[]);
        let notices: Vec<_> = text
            .lines()
            .filter(|line| line.starts_with("approval: approver uid from "))
            .collect();
        assert_eq!(
            notices,
            vec![format!("approval: approver uid from {source}")],
            "{text}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn init_refuses_a_relative_state_directory() {
    let out = Command::new(env!("CARGO_BIN_EXE_vaikor"))
        .args(["init", "--state-dir", "relative"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("state directory must be absolute"));
}

#[test]
fn guard_names_a_configured_approver_without_cli_approval_flags() {
    let dir = scratch("config-source-only");
    let config = write_config(
        &dir,
        serde_json::json!({"v":"0.1","mode":"personal","local":false,"interface":"tui","approval":{"approve_uid":41001,"non_approver_uids":[41002]}}),
    );
    let (_, text) = guard(&dir, &config, &[], &[]);
    assert_eq!(
        text.matches("approval: approver uid from system config")
            .count(),
        1,
        "{text}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}
