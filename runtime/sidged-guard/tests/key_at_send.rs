//! 0007 §5 and R10a: guard reads the planner credential only at send time, in
//! the gateway, after the local latch, the audit log lock, the destination
//! check, grant verification with reservation and approval. A refusal at any
//! earlier step never opens the key file. No live calls.
mod common;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

use sidged_gateway::KeySource;

const KEY: &str = "guard-TEST-send-time-key-0b7e44";

struct Fixture {
    root: PathBuf,
    dir: PathBuf,
    keys: PathBuf,
    log: PathBuf,
}

impl Fixture {
    /// Public-weather scenario pointed at a loopback planner endpoint.
    fn new(name: &str, endpoint: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("sidged-key-send-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = common::report_only_scenario(&root);
        let mut config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap())
                .unwrap();
        config["provider_id"] = endpoint.into();
        config["provider_region"] = "GLOBAL".into();
        config["provider_profile"] = "P0".into();
        config["record_result"] = false.into();
        std::fs::write(dir.join("config.json"), config.to_string()).unwrap();
        let keys = root.join("keys");
        common::keys(&keys);
        let log = root.join("audit.log");
        Self {
            root,
            dir,
            keys,
            log,
        }
    }

    fn key_file(&self, mode: u32) -> KeySource {
        use std::os::unix::fs::PermissionsExt;
        let path = self.root.join(format!("planner-{mode:o}.key"));
        std::fs::write(&path, format!("{KEY}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        KeySource::File(path)
    }

    fn run(
        &self,
        endpoint: &str,
        credential: KeySource,
        approval: &dyn sidged_cli::ApprovalChannel,
        log: &Path,
    ) -> Result<sidged_guard::GuardReport, String> {
        sidged_guard::run_from_env_with_credential(
            &self.dir,
            "openai",
            Some(endpoint),
            None,
            Some(credential),
            approval,
            Some(sidged_guard::LogTarget {
                path: log,
                seed: &[71; 32],
            }),
            Some(&self.keys),
        )
    }

    fn decisions(&self) -> Vec<String> {
        sidged_log::read_events(&self.log, &sidged_log::public_key(&[71; 32]))
            .unwrap_or_default()
            .into_iter()
            .map(|e| e.decision)
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn granted() -> sidged_cli::FixedApproval {
    sidged_cli::FixedApproval {
        granted: true,
        actor: "test-approver".into(),
    }
}

fn idle_listener() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    (listener, url)
}

// HTTP may split the headers and body across reads. Consume the complete
// request before replying so closing the fixture cannot reset the connection.
fn read_request(stream: &mut std::net::TcpStream) -> String {
    use std::io::{BufRead, BufReader};
    let mut reader = BufReader::new(stream);
    let mut head = String::new();
    let mut length = None;
    loop {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = Some(value.trim().parse::<usize>().unwrap());
            }
        }
        head.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    let mut body = vec![0; length.expect("request length")];
    reader.read_exact(&mut body).unwrap();
    assert!(serde_json::from_slice::<serde_json::Value>(&body).is_ok());
    head
}

#[test]
fn a_cedar_denial_never_reads_the_key() {
    let (listener, url) = idle_listener();
    let fx = Fixture::new("cedar", &url);
    std::fs::write(
        fx.dir.join("policy.cedar"),
        "forbid(principal, action, resource);",
    )
    .unwrap();
    let error = fx
        .run(&url, fx.key_file(0o644), &granted(), &fx.log)
        .unwrap_err();
    assert!(!error.contains("API key file"), "{error}");
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    assert!(fx.decisions().contains(&"deny".to_string()));
}

/// 0004 R9: a refused approval channel denies planner egress (the approval
/// gate guard enforces today); the key is never read.
#[test]
fn a_refused_approval_channel_never_reads_the_key() {
    let (listener, url) = idle_listener();
    let fx = Fixture::new("approval", &url);
    let socket = fx.root.join("no-approver/s");
    let mode = format!("unix:{}", socket.display());
    let refused = sidged_cli::open_channel(&sidged_cli::ChannelConfig {
        mode: Some(&mode),
        timeout: std::time::Duration::from_millis(10),
        approver: None,
        agents: &[1000],
        local: false,
        operator_attest: false,
    });
    assert!(refused.refusal().is_some());
    let error = fx
        .run(&url, fx.key_file(0o644), refused.as_ref(), &fx.log)
        .unwrap_err();
    assert!(error.contains("approval channel refused"), "{error}");
    assert!(!error.contains("API key file"), "{error}");
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}

#[test]
fn a_destination_denial_never_reads_the_key() {
    let (listener, url) = idle_listener();
    let fx = Fixture::new("destination", &url);
    let error = fx
        .run(
            "https://api.x.ai/v1",
            fx.key_file(0o644),
            &granted(),
            &fx.log,
        )
        .unwrap_err();
    assert!(
        error.contains("destination does not match provider"),
        "{error}"
    );
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    assert!(!fx.decisions().contains(&"spend".to_string()));
}

#[test]
fn an_unusable_audit_log_never_reads_the_key() {
    let (listener, url) = idle_listener();
    let fx = Fixture::new("audit", &url);
    for log in [
        Path::new("/dev/null"),
        Path::new("/proc/sidged-unwritable-audit"),
    ] {
        let error = fx
            .run(&url, fx.key_file(0o644), &granted(), log)
            .unwrap_err();
        assert!(
            !error.contains("API key file"),
            "{}: {error}",
            log.display()
        );
    }
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}

#[test]
fn an_unreadable_key_refuses_after_reservation_and_intent_without_connecting() {
    let (listener, url) = idle_listener();
    let fx = Fixture::new("unreadable", &url);
    let error = fx
        .run(&url, fx.key_file(0o644), &granted(), &fx.log)
        .unwrap_err();
    assert!(error.contains("API key file"), "{error}");
    assert!(!error.contains(KEY));
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    // Read happened after the durable reservation and the signed intent;
    // nothing left, so there is no privacy report.
    assert_eq!(
        fx.decisions(),
        ["spend", "reserve", "approve", "permit", "attempt", "deny"]
    );
    let events = sidged_log::read_events(&fx.log, &sidged_log::public_key(&[71; 32])).unwrap();
    let denied = events.last().unwrap();
    assert_eq!(denied.reason.as_deref(), Some("credential-unavailable"));
    let entry = format!("{denied:?}");
    assert!(!entry.contains(KEY));
    assert!(!entry.contains(fx.root.to_str().unwrap()));
}

#[test]
fn a_valid_key_is_read_at_send_and_never_reaches_the_audit_log() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let fx = Fixture::new("valid", &url);
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let head = read_request(&mut stream);
        let _ = stream.write_all(
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        head
    });
    let error = fx
        .run(&url, fx.key_file(0o600), &granted(), &fx.log)
        .unwrap_err();
    let head = server.join().unwrap().to_ascii_lowercase();
    assert!(error.contains("500"), "{error}");
    assert!(
        head.contains(&format!(
            "authorization: bearer {}",
            KEY.to_ascii_lowercase()
        )),
        "{head}"
    );
    let audit = std::fs::read(&fx.log).unwrap();
    assert!(!String::from_utf8_lossy(&audit).contains(KEY));
    assert_eq!(
        fx.decisions(),
        [
            "spend",
            "reserve",
            "approve",
            "permit",
            "attempt",
            "privacy-report",
            "deny"
        ]
    );
}

#[test]
fn denied_owner_approval_blocks_planner_before_key_read_and_egress() {
    let (listener, url) = idle_listener();
    let fx = Fixture::new("owner-deny", &url);
    let fifo = fx.root.join("credential");
    let path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: path is NUL terminated and valid for the call.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let denied = sidged_cli::FixedApproval {
        granted: false,
        actor: "test-approver".into(),
    };
    let error = fx
        .run(&url, KeySource::File(fifo), &denied, &fx.log)
        .unwrap_err();
    assert!(!error.contains("API key file"), "{error}");
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    let events = sidged_log::read_events(&fx.log, &sidged_log::public_key(&[71; 32])).unwrap();
    let denial = events
        .iter()
        .find(|e| e.step == "planner" && e.decision == "deny")
        .unwrap();
    assert_eq!(denial.actor, "test-approver");
    assert!(denial.approval.is_some(), "R11 fields required");
    assert!(!events.iter().any(|e| e.decision == "attempt"));
}

#[test]
fn one_approval_never_funds_hidden_planner_retries() {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };
    let (listener, url) = idle_listener();
    let fx = Fixture::new("retry", &url);
    let done = Arc::new(AtomicBool::new(false));
    let count = Arc::new(AtomicUsize::new(0));
    let (stop, calls) = (done.clone(), count.clone());
    let server = std::thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let _ = read_request(&mut stream);
                    calls.fetch_add(1, Ordering::SeqCst);
                    let _ = stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::yield_now(),
                Err(e) => panic!("{e}"),
            }
        }
    });
    let result = fx.run(&url, fx.key_file(0o600), &granted(), &fx.log);
    done.store(true, Ordering::SeqCst);
    server.join().unwrap();
    assert!(result.is_err());
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "each transport needs its own booked call"
    );
}

#[test]
fn pending_revocations_are_persisted_on_planner_failure() {
    struct Revoking(std::cell::Cell<bool>);
    impl sidged_cli::ApprovalChannel for Revoking {
        fn decide(
            &self,
            r: &sidged_cli::ApprovalRequest,
            now: &str,
        ) -> sidged_cli::ApprovalDecision {
            sidged_cli::ApprovalChannel::decide(&granted(), r, now)
        }
        fn shutdown(&self) {
            self.0.set(true);
        }
        fn take_revocations(&self) -> Vec<String> {
            if self.0.replace(false) {
                vec!["*".into()]
            } else {
                vec![]
            }
        }
    }
    let (_listener, url) = idle_listener();
    let fx = Fixture::new("revoke-on-failure", &url);
    assert!(fx
        .run(
            &url,
            fx.key_file(0o644),
            &Revoking(std::cell::Cell::new(false)),
            &fx.log
        )
        .is_err());
    let events = sidged_log::read_events(&fx.log, &sidged_log::public_key(&[71; 32])).unwrap();
    assert!(events
        .iter()
        .any(|e| e.capability == "core.standing-approval" && e.decision == "revoke"));
}

#[test]
fn granted_planner_still_checks_payload_before_reading_credential() {
    let (listener, url) = idle_listener();
    let fx = Fixture::new("approved-payload", &url);
    let mut config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(fx.dir.join("config.json")).unwrap())
            .unwrap();
    config["task"] = format!("task {}", "1".repeat(9)).into();
    std::fs::write(fx.dir.join("config.json"), config.to_string()).unwrap();
    let error = fx
        .run(&url, fx.key_file(0o644), &granted(), &fx.log)
        .unwrap_err();
    assert_eq!(error, "data-class-forbidden");
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    let events = sidged_log::read_events(&fx.log, &sidged_log::public_key(&[71; 32])).unwrap();
    assert!(events.iter().any(|e| e.decision == "deny"
        && e.privacy_report
            .as_deref()
            .is_some_and(|r| r.contains("payload_sha256"))));
}

#[test]
fn an_environment_credential_failure_keeps_its_existing_audit_reason() {
    let (listener, url) = idle_listener();
    let fx = Fixture::new("environment-error-kind", &url);
    // An empty environment variable name cannot resolve, without changing
    // process-global environment state shared with the other tests.
    let error = fx
        .run(&url, KeySource::Env(String::new()), &granted(), &fx.log)
        .unwrap_err();
    assert_eq!(error, " is not set");
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    let events = sidged_log::read_events(&fx.log, &sidged_log::public_key(&[71; 32])).unwrap();
    assert_eq!(
        events.last().unwrap().reason.as_deref(),
        Some("planner-failed")
    );
}
