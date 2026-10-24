mod common;
use std::{
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

#[test]
fn audit_failures_never_reach_the_http_planner() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done = stop.clone();
    let server = std::thread::spawn(move || {
        while !done.load(Ordering::SeqCst) {
            if let Ok((mut stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                    .unwrap();
                let mut buf = [0; 8192];
                let _ = stream.read(&mut buf);
                count.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    });
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../demo/ch-residency");
    let path = std::env::temp_dir().join(format!("sidged-planner-audit-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let approval = sidged_cli::FixedApproval {
        granted: true,
        actor: "test".into(),
    };
    let run =
        |log| sidged_guard::run_from_env(&dir, "openai", Some(&url), None, None, &approval, log);
    let error = run(None).unwrap_err();
    assert!(error.contains("audit log"), "{error}");
    let missing = requests.load(Ordering::SeqCst);
    let locked = sidged_log::Chain::open(&path, &[17; 32]).unwrap();
    assert!(run(Some(sidged_guard::LogTarget {
        path: &path,
        seed: &[17; 32]
    }))
    .is_err());
    let busy = requests.load(Ordering::SeqCst);
    // Exercise the binary entry point against the same recording server.
    let key_path = path.with_extension("key");
    std::fs::write(&key_path, "11".repeat(32)).unwrap();
    let cli = |key: bool, log: &Path| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_sidged"));
        command
            .arg("guard")
            .arg(&dir)
            .env("SIDGED_PROVIDER", "openai")
            .env("SIDGED_BASE_URL", &url)
            .env("SIDGED_API_KEY", "")
            .arg("--log")
            .arg(log);
        if key {
            command.arg("--log-key").arg(&key_path);
        }
        command.output().unwrap()
    };
    assert!(!cli(false, &path).status.success());
    assert!(!cli(true, &path).status.success());
    assert!(!cli(true, Path::new("/proc/sidged-unwritable-audit"))
        .status
        .success());
    drop(locked);
    // /proc cannot create files, even when the test runs as root.
    assert!(run(Some(sidged_guard::LogTarget {
        path: Path::new("/proc/sidged-unwritable-audit"),
        seed: &[17; 32]
    }))
    .is_err());
    // This target can open and accept bytes, but cannot durably sync them.
    // The attempt must fail before contacting the planner as well.
    assert!(run(Some(sidged_guard::LogTarget {
        path: Path::new("/dev/null"),
        seed: &[17; 32],
    }))
    .is_err());
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    let unwritable = requests.load(Ordering::SeqCst);
    std::fs::remove_file(path).unwrap();
    std::fs::remove_file(key_path).unwrap();
    assert_eq!((missing, busy, unwritable), (0, 0, 0));
}

// 0004 R9: a Refused approval channel is not "no channel". Planner
// egress that requires approval fails closed, audited, before any request.
#[test]
fn refused_channel_blocks_planner_egress() {
    let fixture = std::env::temp_dir().join(format!("sidged-refused-fx-{}", std::process::id()));
    let dir = common::report_only_scenario(&fixture);
    let path = std::env::temp_dir().join(format!("sidged-refused-planner-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let socket = std::env::temp_dir().join(format!("sidged-refused-{}/s", std::process::id()));
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
    let seed = [23; 32];
    let keys = path.with_extension("keys");
    common::keys(&keys);
    let error = sidged_guard::run_from_env_with_keys(
        &dir,
        "stub",
        None,
        None,
        None,
        refused.as_ref(),
        Some(sidged_guard::LogTarget {
            path: &path,
            seed: &seed,
        }),
        Some(&keys),
    )
    .unwrap_err();
    assert!(error.contains("approval channel refused"), "{error}");
    let events = sidged_log::read_events(&path, &sidged_log::public_key(&seed)).unwrap();
    assert!(
        events.iter().any(|e| e.decision == "deny"
            && e.reason
                .as_deref()
                .unwrap_or("")
                .contains("approval channel refused")),
        "{events:?}"
    );
    // The planner step itself must be denied: no reservation, no planner egress.
    assert!(
        !events
            .iter()
            .any(|e| e.step == "planner" && e.decision != "deny"),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e.step == "planner" && e.decision == "deny"),
        "{events:?}"
    );
    std::fs::remove_file(path).unwrap();
}

// 0004 R9: SO_PEERCRED rejections that happen while the planner runs are
// audited even when planning then fails (no executor drain is ever reached).
#[test]
fn rejected_peers_are_audited_when_the_planner_fails() {
    struct Rejecting(std::sync::Mutex<Vec<u32>>, std::sync::atomic::AtomicBool);
    impl sidged_cli::ApprovalChannel for Rejecting {
        fn decide(
            &self,
            _: &sidged_cli::ApprovalRequest,
            now: &str,
        ) -> sidged_cli::ApprovalDecision {
            sidged_cli::ApprovalDecision {
                granted: false,
                actor: "x".into(),
                at: now.into(),
            }
        }
        fn take_rejected_peers(&self) -> Vec<u32> {
            std::mem::take(&mut *self.0.lock().unwrap())
        }
        fn approver_uid(&self) -> Option<u32> {
            Some(4242)
        }
        fn shutdown(&self) {
            self.1.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    // The planner endpoint is dead, so planning fails after the attempt entry.
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", dead.local_addr().unwrap());
    drop(dead);
    let fixture = std::env::temp_dir().join(format!("sidged-m7-fx-{}", std::process::id()));
    let dir = common::report_only_scenario(&fixture);
    let path = std::env::temp_dir().join(format!("sidged-m7-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let keys = path.with_extension("keys");
    common::keys(&keys);
    let channel = Rejecting(std::sync::Mutex::new(vec![31337]), Default::default());
    let seed = [29; 32];
    let result = sidged_guard::run_from_env_with_keys(
        &dir,
        "openai",
        Some(&url),
        None,
        None,
        &channel,
        Some(sidged_guard::LogTarget {
            path: &path,
            seed: &seed,
        }),
        Some(&keys),
    );
    assert!(result.is_err());
    assert!(
        channel.1.load(std::sync::atomic::Ordering::SeqCst),
        "listener shut down"
    );
    let events = sidged_log::read_events(&path, &sidged_log::public_key(&seed)).unwrap();
    assert!(
        events
            .iter()
            .any(|e| e.reason.as_deref().is_some_and(
                |r| r.contains("observed uid 31337") && r.contains("approver uid 4242")
            )),
        "{events:?}"
    );
    std::fs::remove_file(&path).unwrap();
    let _ = std::fs::remove_dir_all(keys);
    std::fs::remove_dir_all(fixture).unwrap();
}

#[test]
fn planner_error_text_does_not_classify_a_credential_failure() {
    struct FailedPlanner;
    impl sidged_model::Planner for FailedPlanner {
        fn plan(&self, _: &str) -> Result<String, String> {
            Err("planner response mentions API key".into())
        }
    }
    let root = std::env::temp_dir().join(format!("sidged-error-kind-{}", std::process::id()));
    let dir = common::report_only_scenario(&root);
    common::keys(&dir.join("keys"));
    let path = root.join("audit.log");
    let seed = [39; 32];
    let error = sidged_guard::run_dir(
        &dir,
        &FailedPlanner,
        &sidged_cli::NonInteractive,
        Some(sidged_guard::LogTarget {
            path: &path,
            seed: &seed,
        }),
    )
    .unwrap_err();
    assert_eq!(error, "planner response mentions API key");
    let events = sidged_log::read_events(&path, &sidged_log::public_key(&seed)).unwrap();
    assert_eq!(
        events.last().unwrap().reason.as_deref(),
        Some("planner-failed")
    );
    std::fs::remove_dir_all(root).unwrap();
}
