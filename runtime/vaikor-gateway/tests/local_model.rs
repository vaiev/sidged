// 0004 R9d: in local mode the Core makes at most ONE outbound
// connect, to the statically configured model endpoint. Default is AF_UNIX
// with an SO_PEERCRED check against the configured model uid; 127.0.0.1:<port>
// is only a fallback. Local mode latches per process, so these tests live in
// their own test binary.
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use vaikor_gateway::local_model::{model_endpoint, LocalModel, ModelEndpoint};

fn me() -> u32 {
    unsafe { libc::geteuid() }
}

fn serve_once(listener: UnixListener, body: &'static str) -> std::thread::JoinHandle<usize> {
    std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        conn.set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();
        let mut buf = [0u8; 4096];
        let n = conn.read(&mut buf).unwrap_or(0);
        if n > 0 {
            let _ = write!(
                conn,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
        n
    })
}

fn socket_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("vaikor-model-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn endpoint_config_is_static_and_unix_by_default() {
    // The ratified key is model.endpoint (0004 R9, 0005 R8): unix:<path>
    // with a model uid by default, an explicit tcp loopback address otherwise.
    let ep = |v: serde_json::Value| model_endpoint(&serde_json::json!({ "model": v }));
    assert_eq!(
        ep(serde_json::json!({"endpoint": "unix:/run/vaikor/model.sock", "uid": 4000})).unwrap(),
        Some(ModelEndpoint::Unix {
            path: "/run/vaikor/model.sock".into(),
            uid: 4000
        })
    );
    assert_eq!(
        ep(serde_json::json!({"name": "apertus", "endpoint": "tcp:127.0.0.1:8080"})).unwrap(),
        Some(ModelEndpoint::Loopback { port: 8080 })
    );
    // the served weights may be named by hash (0011 R8)
    assert_eq!(
        ep(
            serde_json::json!({"endpoint": "unix:/run/vaikor/model.sock", "uid": 4000,
                              "digest": {"alg": "sha-256", "value": "ab".repeat(32)}})
        )
        .unwrap(),
        Some(ModelEndpoint::Unix {
            path: "/run/vaikor/model.sock".into(),
            uid: 4000
        })
    );
    // the linguist's output form (0017 L3a): full or compact, read by vaikor-cli
    for output in ["full", "compact"] {
        assert_eq!(
            ep(serde_json::json!({"endpoint": "tcp:127.0.0.1:8080", "output": output})).unwrap(),
            Some(ModelEndpoint::Loopback { port: 8080 })
        );
    }
    assert_eq!(model_endpoint(&serde_json::json!({})).unwrap(), None);
    // a plain model name has no endpoint
    assert_eq!(
        model_endpoint(&serde_json::json!({"model": "apertus"})).unwrap(),
        None
    );
    assert_eq!(ep(serde_json::json!({"name": "apertus"})).unwrap(), None);
    for bad in [
        serde_json::json!({"endpoint": "unix:/run/vaikor/model.sock"}),
        serde_json::json!({"endpoint": "unix:relative.sock", "uid": 4000}),
        serde_json::json!({"endpoint": "tcp:127.0.0.1:0"}),
        serde_json::json!({"endpoint": "tcp:10.0.0.1:8080"}),
        serde_json::json!({"endpoint": "tcp:localhost:8080"}),
        serde_json::json!({"endpoint": "tcp:127.0.0.1:8080", "uid": 1}),
        serde_json::json!({"endpoint": "http://127.0.0.1:8080"}),
        serde_json::json!({"endpoint": "/run/vaikor/model.sock", "uid": 1}),
        serde_json::json!({"endpoint": "unix:/a", "uid": 1, "port": 2}),
        serde_json::json!({"endpoint": "unix:/a", "uid": 1, "output": "v0.2"}),
        serde_json::json!({"endpoint": "unix:/a", "uid": 1, "output": true}),
        serde_json::json!({"endpoint": "unix:/a", "uid": 1, "digest": "abc"}),
        serde_json::json!({"endpoint": "unix:/a", "uid": 1, "digest": {"alg": "md5", "value": "0".repeat(64)}}),
        serde_json::json!({"endpoint": "unix:/a", "uid": 1, "digest": {"alg": "sha-256", "value": "A".repeat(64)}}),
        serde_json::json!({"endpoint": "unix:/a", "uid": 1, "digest": {"alg": "sha-256", "value": "0".repeat(63)}}),
    ] {
        assert!(ep(bad.clone()).is_err(), "{bad}");
    }
    // Only the canonical decimal port is accepted
    for port in [
        "+8080",
        "08080",
        "0",
        "00",
        "-1",
        " 8080",
        "8080 ",
        "8_080",
        "65536",
        "",
        "0x1f90",
        "８０８０",
    ] {
        let bad = serde_json::json!({"endpoint": format!("tcp:127.0.0.1:{port}")});
        assert!(ep(bad).is_err(), "port {port:?} must be refused");
    }
    for port in [1u32, 80, 8080, 65535] {
        let good = serde_json::json!({"endpoint": format!("tcp:127.0.0.1:{port}")});
        assert_eq!(
            ep(good).unwrap(),
            Some(ModelEndpoint::Loopback { port: port as u16 })
        );
    }
    // the pre-ratification key is refused, not silently ignored
    let old = model_endpoint(&serde_json::json!({"local_model": {"loopback_port": 8080}}));
    assert!(old.unwrap_err().contains("model.endpoint"));
}

#[test]
fn model_socket_with_the_wrong_peer_uid_is_refused_before_any_byte() {
    vaikor_gateway::enable_local();
    let dir = socket_dir("peer");
    let path = dir.join("model.sock");
    let server = serve_once(UnixListener::bind(&path).unwrap(), "{}");
    let model = LocalModel::new(ModelEndpoint::Unix {
        path: path.clone(),
        uid: me() + 1,
    });
    let err = model.complete("{}").unwrap_err();
    assert!(err.contains("peer uid"), "{err}");
    assert_eq!(
        server.join().unwrap(),
        0,
        "no request bytes reach a wrong peer"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn one_connect_only_to_the_configured_socket() {
    vaikor_gateway::enable_local();
    let dir = socket_dir("once");
    let path = dir.join("model.sock");
    let body = r#"{"choices":[{"message":{"content":"plan"}}]}"#;
    let server = serve_once(UnixListener::bind(&path).unwrap(), body);
    let model = LocalModel::new(ModelEndpoint::Unix {
        path: path.clone(),
        uid: me(),
    });
    assert_eq!(model.complete(r#"{"messages":[]}"#).unwrap(), body);
    assert!(server.join().unwrap() > 0);
    let again = model.complete("{}").unwrap_err();
    assert!(again.contains("at most one"), "{again}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn loopback_fallback_carries_a_risk_note_unix_does_not() {
    let note = ModelEndpoint::Loopback { port: 8080 }.risk_note().unwrap();
    assert!(
        note.starts_with("local model loopback fallback 127.0.0.1:8080"),
        "{note}"
    );
    assert!(note.contains("no peer uid check"), "{note}");
    let unix = ModelEndpoint::Unix {
        path: "/run/vaikor/model.sock".into(),
        uid: 4000,
    };
    assert_eq!(unix.risk_note(), None);
}
