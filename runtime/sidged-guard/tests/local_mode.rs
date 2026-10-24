mod common;
use std::process::Command;

// Isolate process environment so parallel tests never race on SIDGED_LOCAL.
#[test]
fn env_local_cannot_be_bypassed() {
    if std::env::var_os("SIDGED_LOCAL_TEST_CHILD").is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "env_local_cannot_be_bypassed", "--nocapture"])
            .env("SIDGED_LOCAL_TEST_CHILD", "1")
            .env("SIDGED_LOCAL", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let parsed = sidged_cli::parse_run_args(
        [
            "run",
            "plan",
            "catalog",
            "--policy",
            "policy",
            "--grant",
            "grant",
            "--trusted-issuer",
            "issuer",
        ]
        .map(str::to_string),
    )
    .unwrap();
    assert!(parsed.local, "sidged run must honor SIDGED_LOCAL");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let error = sidged_gateway::send(&sidged_gateway::SendRequest {
        provider_project: None,
        url: &url,
        provider_id: "test",
        profile: "P0",
        residency: &[],
        region: "CH",
        data_classes: &[],
        fields: &[],
        body: b"{}",
        authorization: None,
        call_at: "2026-10-15T00:00:00Z",
        step: "planner",
        local: false,
    })
    .unwrap_err();
    assert!(error.message.contains("local mode"), "{}", error.message);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn guard_env_local_refuses_hosted_planner() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let key = std::env::temp_dir().join(format!(
        "guard-key-{}-{}",
        std::process::id(),
        listener.local_addr().unwrap().port()
    ));
    let log = key.with_extension("log");
    let keys = key.with_extension("keys");
    common::keys(&keys);
    std::fs::copy(keys.join("issuer.key"), &key).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sidged"))
        .args(["guard", "../../demo/ch-residency"])
        .arg("--keys")
        .arg(&keys)
        .env("SIDGED_PROVIDER", "openai")
        .args([
            "--log",
            log.to_str().unwrap(),
            "--log-key",
            key.to_str().unwrap(),
        ])
        .env(
            "SIDGED_BASE_URL",
            format!("http://{}", listener.local_addr().unwrap()),
        )
        .env("SIDGED_LOCAL", "1")
        .output()
        .unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "0007 R2: no socket"
    );
    std::fs::remove_dir_all(keys).unwrap();
    let _ = std::fs::remove_file(key);
    let _ = std::fs::remove_file(log);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("local mode"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn guard_config_local_refuses_hosted_planner() {
    let dir = std::env::temp_dir().join(format!("sidged-local-config-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for entry in std::fs::read_dir("../../demo/ch-residency").unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), dir.join(entry.file_name())).unwrap();
        }
    }
    common::keys(&dir.join("keys"));
    let path = dir.join("config.json");
    let mut config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    config["local"] = true.into();
    std::fs::write(&path, config.to_string()).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let key = std::env::temp_dir().join(format!(
        "guard-key-{}-{}",
        std::process::id(),
        listener.local_addr().unwrap().port()
    ));
    let log = key.with_extension("log");
    let keys = key.with_extension("keys");
    common::keys(&keys);
    std::fs::copy(keys.join("issuer.key"), &key).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sidged"))
        .arg("guard")
        .arg(&dir)
        .arg("--keys")
        .arg(&keys)
        .env("SIDGED_PROVIDER", "openai")
        .args([
            "--log",
            log.to_str().unwrap(),
            "--log-key",
            key.to_str().unwrap(),
        ])
        .env(
            "SIDGED_BASE_URL",
            format!("http://{}", listener.local_addr().unwrap()),
        )
        .env_remove("SIDGED_LOCAL")
        .output()
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "0007 R2: no socket"
    );
    std::fs::remove_dir_all(keys).unwrap();
    let _ = std::fs::remove_file(key);
    let _ = std::fs::remove_file(log);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("local mode"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// 0007 R2: library callers must latch config before a default online planner runs.
#[test]
fn library_local_and_malformed_settings() {
    if std::env::var_os("LIB_LOCAL_CHILD").is_none() {
        for mode in ["local", "bad-config", "bad-env"] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "library_local_and_malformed_settings"])
                .env("LIB_LOCAL_CHILD", mode)
                .env_remove("SIDGED_LOCAL")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return;
    }
    let mode = std::env::var("LIB_LOCAL_CHILD").unwrap();
    let dir = std::env::temp_dir().join(format!("guard-library-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for entry in std::fs::read_dir("../../demo/ch-residency").unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), dir.join(entry.file_name())).unwrap();
        }
    }
    common::keys(&dir.join("keys"));
    let path = dir.join("config.json");
    let mut config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let values = if mode == "bad-config" {
        vec![
            serde_json::json!("true"),
            serde_json::json!(1),
            serde_json::Value::Null,
        ]
    } else {
        vec![serde_json::json!(mode == "local")]
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let planner = sidged_model::OpenAiPlanner::new(
        format!("http://{}", listener.local_addr().unwrap()),
        "test",
        None,
        vec![],
        "",
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let log = dir.join("audit.log");
    let seed = common::seed(&dir.join("keys/issuer.key"));
    for value in values {
        config["local"] = value;
        std::fs::write(&path, config.to_string()).unwrap();
        let envs = if mode == "bad-env" {
            vec!["true", "yes", "1 ", "", "2"]
        } else {
            vec!["0"]
        };
        for env in envs {
            std::env::set_var("SIDGED_LOCAL", env);
            let error = sidged_guard::run_dir(
                &dir,
                &planner,
                &sidged_cli::NonInteractive,
                Some(sidged_guard::LogTarget {
                    path: &log,
                    seed: &seed,
                }),
            )
            .unwrap_err();
            let expected = match mode.as_str() {
                "bad-config" => "config.local",
                "bad-env" => "SIDGED_LOCAL",
                _ => "local mode",
            };
            assert!(error.contains(expected), "{error}");
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }
    if mode == "local" {
        assert!(sidged_gateway::is_local());
        assert!(
            sidged_gateway::resolve_local(false).unwrap(),
            "one-way latch"
        );
        let events = sidged_log::read_events(&log, &sidged_log::public_key(&seed)).unwrap();
        assert_eq!(events[0].step, "planner");
        assert_eq!(
            events
                .iter()
                .map(|event| event.decision.as_str())
                .collect::<Vec<_>>(),
            ["deny"]
        );
        assert!(events.iter().all(|event| event.usage.is_none()));
        assert_eq!(events.last().unwrap().step, "planner");
        assert_eq!(events.last().unwrap().decision, "deny");
    }
    std::fs::remove_dir_all(dir).unwrap();
}

// 0004 R9 (leads decision): SIDGED_LOCAL=1 plus any approval channel refuses
// to start, fails closed, and creates no socket. With strace available the
// real binary is also checked for zero AF_UNIX/AF_INET socket() and bind().
#[test]
fn local_mode_with_approval_channel_refuses_to_start() {
    let base = std::env::temp_dir().join(format!("sidged-local-approve-{}", std::process::id()));
    let socket = base.join("approval").join("control.sock");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let scenario = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../demo/ch-residency");
    let unix = format!("unix:{}", socket.display());
    let commands: Vec<Vec<String>> = vec![
        vec![
            "guard".into(),
            scenario.display().to_string(),
            "--approve-timeout".into(),
            "5".into(),
        ],
        vec![
            "guard".into(),
            scenario.display().to_string(),
            "--approve-timeout=5".into(),
        ],
        vec![
            "guard".into(),
            scenario.display().to_string(),
            "--approve".into(),
            unix.clone(),
            "--approve-uid".into(),
            "4242".into(),
        ],
        vec![
            "guard".into(),
            scenario.display().to_string(),
            "--approve".into(),
            "tty".into(),
        ],
        vec![
            "run".into(),
            "p.json".into(),
            "c.json".into(),
            "--approve".into(),
            unix.clone(),
            "--approve-uid".into(),
            "4242".into(),
        ],
    ];
    let strace = Command::new("strace").arg("-V").output().is_ok();
    for args in commands {
        let trace = base.join("trace.txt");
        let mut command = if strace {
            let mut c = Command::new("strace");
            c.args(["-f", "-qq", "-e", "trace=socket,bind", "-o"])
                .arg(&trace)
                .arg(env!("CARGO_BIN_EXE_sidged"));
            c
        } else {
            Command::new(env!("CARGO_BIN_EXE_sidged"))
        };
        let output = command
            .args(&args)
            .env("SIDGED_LOCAL", "1")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "{args:?} must not start: {stderr}"
        );
        assert!(
            stderr.contains("local mode") && stderr.contains("no approval channel"),
            "{stderr}"
        );
        assert!(
            !socket.exists() && !socket.parent().unwrap().exists(),
            "no socket may be created"
        );
        if strace {
            let calls = std::fs::read_to_string(&trace).unwrap_or_default();
            assert!(
                !calls
                    .lines()
                    .any(|l| l.contains("socket(") || l.contains("bind(")),
                "{args:?}: unexpected socket/bind calls:\n{calls}"
            );
        } else {
            assert!(
                std::env::var_os("SIDGED_REQUIRE_STRACE").is_none(),
                "strace required"
            );
            eprintln!("strace not available; checked exit code and socket path only");
        }
    }
    std::fs::remove_dir_all(base).unwrap();
}

// config.json "local": true is resolved before any approval channel, so
// the real binary refuses to start and makes zero socket()/bind() calls.
#[test]
fn config_local_with_approval_flag_refuses_before_any_socket() {
    let root = std::env::temp_dir().join(format!("sidged-cfg-local-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let dir = common::report_only_scenario(&root);
    let config = dir.join("config.json");
    let mut value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&config).unwrap()).unwrap();
    value["local"] = true.into();
    std::fs::write(&config, value.to_string()).unwrap();
    let socket = root.join("approval").join("control.sock");
    let trace = root.join("trace.txt");
    let strace = Command::new("strace").arg("-V").output().is_ok();
    let mut command = if strace {
        let mut c = Command::new("strace");
        c.args(["-f", "-qq", "-e", "trace=socket,bind,listen,connect", "-o"])
            .arg(&trace)
            .arg(env!("CARGO_BIN_EXE_sidged"));
        c
    } else {
        assert!(
            std::env::var_os("SIDGED_REQUIRE_STRACE").is_none(),
            "strace required"
        );
        Command::new(env!("CARGO_BIN_EXE_sidged"))
    };
    let output = command
        .arg("guard")
        .arg(&dir)
        .args([
            "--approve",
            &format!("unix:{}", socket.display()),
            "--approve-uid",
            "4242",
            "--agent-uid",
            "1000",
        ])
        .env_remove("SIDGED_LOCAL")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("no approval channel"), "{stderr}");
    assert!(!socket.exists());
    if strace {
        let calls = std::fs::read_to_string(&trace).unwrap_or_default();
        assert!(
            !calls
                .lines()
                .any(|l| ["socket(", "bind(", "listen(", "connect("]
                    .iter()
                    .any(|c| l.contains(c))),
            "{calls}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn usage_names_the_spec_socket_path_and_non_approver_uids() {
    let out = Command::new(env!("CARGO_BIN_EXE_sidged")).output().unwrap();
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("/run/sidged/approval/control.sock"), "{text}");
    assert!(text.contains("--non-approver-uid"), "{text}");
    assert!(text.contains("not sticky"), "{text}");
}

// 0004 R9d: a local-mode run makes zero bind/listen and exactly one
// outbound connect, to the configured AF_UNIX model socket. The model output
// is an untrusted plan that still goes through verify, grant, Cedar and
// approval (consequential steps are denied: local mode has no approval).
#[test]
fn local_mode_connects_once_to_the_configured_model_socket_and_never_binds() {
    use std::io::{Read, Write};
    let root = std::env::temp_dir().join(format!("sidged-n9-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let dir = common::report_only_scenario(&root);
    let socket = root.join("model.sock");
    let config_path = dir.join("config.json");
    let mut config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    config["local"] = true.into();
    config["model"] = serde_json::json!({
        "endpoint": format!("unix:{}", socket.display()),
        "uid": unsafe { libc::geteuid() },
    });
    std::fs::write(&config_path, config.to_string()).unwrap();
    let plan = std::fs::read_to_string(dir.join("stub-plan.json")).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut conn = loop {
            match listener.accept() {
                Ok((conn, _)) => break conn,
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(20))
                }
                Err(_) => return 0,
            }
        };
        conn.set_nonblocking(false).unwrap();
        conn.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 8192];
        while let Ok(n) = conn.read(&mut buf) {
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buf[..n]);
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                let text = String::from_utf8_lossy(&request).to_string();
                let length = text
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                let head = text.find("\r\n\r\n").unwrap() + 4;
                if request.len() >= head + length {
                    break;
                }
            }
        }
        let body = serde_json::json!({"choices":[{"message":{"content": plan}}]}).to_string();
        let _ = write!(
            conn,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        request.len()
    });
    let trace = root.join("trace.txt");
    let key = root.join("log.key");
    std::fs::write(&key, "42".repeat(32)).unwrap();
    let strace = Command::new("strace").arg("-V").output().is_ok();
    let mut command = if strace {
        let mut c = Command::new("strace");
        c.args([
            "-f",
            "-qq",
            "-yy",
            "-e",
            "trace=socket,bind,listen,connect",
            "-o",
        ])
        .arg(&trace)
        .arg(env!("CARGO_BIN_EXE_sidged"));
        c
    } else {
        assert!(
            std::env::var_os("SIDGED_REQUIRE_STRACE").is_none(),
            "strace required (0004 R9d)"
        );
        Command::new(env!("CARGO_BIN_EXE_sidged"))
    };
    let keys = root.join("keys");
    common::keys(&keys);
    let output = command
        .arg("guard")
        .arg(&dir)
        .arg("--keys")
        .arg(&keys)
        .args(["--log"])
        .arg(root.join("audit.log"))
        .args(["--log-key"])
        .arg(&key)
        .env_remove("SIDGED_LOCAL")
        .env("SIDGED_PROVIDER", "local")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        server.join().unwrap() > 0,
        "the model was asked once: {stderr}"
    );
    if strace {
        let calls = std::fs::read_to_string(&trace).unwrap_or_default();
        assert!(
            !calls
                .lines()
                .any(|l| l.contains("bind(") || l.contains("listen(")),
            "{calls}"
        );
        let connects: Vec<&str> = calls.lines().filter(|l| l.contains("connect(")).collect();
        assert_eq!(connects.len(), 1, "{calls}");
        // Why the address is usually not decoded: harden_process() sets
        // PR_SET_DUMPABLE=0 at startup (0004 R9c), which also stops a same-uid
        // tracer from reading the tracee's memory, so strace prints the
        // sockaddr pointer instead of sun_path (even with -yy). Then the
        // AF_UNIX addrlen must equal the configured path exactly
        // (sizeof sa_family + path + NUL).
        let path = socket.display().to_string();
        let expected_len = format!(", {}) ", 2 + path.len() + 1);
        assert!(
            connects[0].contains(&path) || connects[0].contains(&expected_len),
            "{calls}"
        );
        // D3: exactly one socket(), of family AF_UNIX, and exactly one connect.
        let sockets: Vec<&str> = calls.lines().filter(|l| l.contains("socket(")).collect();
        assert_eq!(sockets.len(), 1, "{calls}");
        assert!(sockets[0].contains("socket(AF_UNIX,"), "{calls}");
    }
    std::fs::remove_dir_all(root).unwrap();
}

// D4: the real binary is single-threaded when it opens the approval channel
// (umask is process-wide). Test binaries always run >1 thread, so this is
// checked in a spawned `sidged`: a debug build would panic on the
// debug_assert before reaching the later refusal it prints here.
#[test]
fn real_binary_has_one_thread_when_opening_the_approval_channel() {
    let root = std::env::temp_dir().join(format!("sidged-d4-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let dir = common::report_only_scenario(&root);
    let output = Command::new(env!("CARGO_BIN_EXE_sidged"))
        .arg("guard")
        .arg(&dir)
        .args(["--approve", "unix:/nonexistent-sidged-d4/control.sock"])
        .args(["--approve-uid", "4242", "--non-approver-uid", "4243"])
        .env_remove("SIDGED_LOCAL")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    // A hard check in debug and release builds alike (no debug_assert).
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(!stderr.contains("threads at approval bind"), "{stderr}");
    assert!(stderr.contains("approval channel refused"), "{stderr}");
    std::fs::remove_dir_all(root).unwrap();
}

// The 127.0.0.1 fallback is used only when configured explicitly, and
// its start is audited with a risk note (no peer uid check over TCP).
#[test]
fn loopback_fallback_is_audited_at_start_with_a_risk_note() {
    use std::io::{Read, Write};
    let root = std::env::temp_dir().join(format!("sidged-m18-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let dir = common::report_only_scenario(&root);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config_path = dir.join("config.json");
    let mut config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    config["local"] = true.into();
    config["model"] = serde_json::json!({ "endpoint": format!("tcp:127.0.0.1:{port}") });
    std::fs::write(&config_path, config.to_string()).unwrap();
    let plan = std::fs::read_to_string(dir.join("stub-plan.json")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut conn = loop {
            match listener.accept() {
                Ok((conn, _)) => break conn,
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(20))
                }
                Err(_) => return,
            }
        };
        conn.set_nonblocking(false).unwrap();
        conn.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; 65536];
        let _ = conn.read(&mut buf);
        let body = serde_json::json!({"choices":[{"message":{"content": plan}}]}).to_string();
        let _ = write!(
            conn,
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
    });
    let keys = root.join("keys");
    common::keys(&keys);
    let key = root.join("log.key");
    std::fs::write(&key, "42".repeat(32)).unwrap();
    let log = root.join("audit.log");
    let output = Command::new(env!("CARGO_BIN_EXE_sidged"))
        .arg("guard")
        .arg(&dir)
        .arg("--keys")
        .arg(&keys)
        .arg("--log")
        .arg(&log)
        .arg("--log-key")
        .arg(&key)
        .env_remove("SIDGED_LOCAL")
        .env("SIDGED_PROVIDER", "local")
        .output()
        .unwrap();
    server.join().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let events = sidged_log::read_events(&log, &sidged_log::public_key(&[0x42; 32])).unwrap();
    let note = format!("local model loopback fallback 127.0.0.1:{port}");
    let starts = events
        .iter()
        .filter(|e| {
            e.reason
                .as_deref()
                .is_some_and(|r| r.starts_with(&note) && r.contains("no peer uid check"))
        })
        .count();
    assert_eq!(starts, 1, "{stderr} {events:?}");
    let help = Command::new(env!("CARGO_BIN_EXE_sidged")).output().unwrap();
    let help = String::from_utf8_lossy(&help.stderr);
    assert!(
        help.contains("model.endpoint")
            && help.contains("tcp:127.0.0.1:<port>")
            && !help.contains("local_model")
            && help.contains("no peer uid check"),
        "{help}"
    );
    std::fs::remove_dir_all(root).unwrap();
}
