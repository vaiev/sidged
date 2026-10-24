// 0004 R9d (owner decision 2026-10-20): outside local mode the AF_UNIX model endpoint
// with the SO_PEERCRED check may be used (it is not egress); the TCP loopback fallback
// may not. This binary never enables local mode, so it lives apart from local_model.rs.
use sidged_gateway::local_model::{LocalModel, ModelEndpoint};
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;

fn me() -> u32 {
    unsafe { libc::geteuid() }
}

fn socket_dir(tag: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("sidged-model-normal-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
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

#[test]
fn unix_endpoint_with_peer_check_works_outside_local_mode() {
    assert!(!sidged_gateway::is_local());
    let dir = socket_dir("unix");
    let path = dir.join("model.sock");
    let body = r#"{"choices":[{"message":{"content":"proposal"}}]}"#;
    let server = serve_once(UnixListener::bind(&path).unwrap(), body);
    let model = LocalModel::new(ModelEndpoint::Unix {
        path: path.clone(),
        uid: me(),
    });
    assert_eq!(model.complete(r#"{"messages":[]}"#).unwrap(), body);
    assert!(server.join().unwrap() > 0);
    assert!(model.complete("{}").unwrap_err().contains("at most one"));
    assert!(
        !sidged_gateway::is_local(),
        "using the model did not latch local mode"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn wrong_peer_uid_is_still_refused_outside_local_mode() {
    let dir = socket_dir("peer");
    let path = dir.join("model.sock");
    let server = serve_once(UnixListener::bind(&path).unwrap(), "{}");
    let model = LocalModel::new(ModelEndpoint::Unix {
        path: path.clone(),
        uid: me() + 1,
    });
    assert!(model.complete("{}").unwrap_err().contains("peer uid"));
    assert_eq!(
        server.join().unwrap(),
        0,
        "no request bytes reach a wrong peer"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn loopback_endpoint_is_refused_outside_local_mode_before_any_connect() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let err = LocalModel::new(ModelEndpoint::Loopback { port })
        .complete("{}")
        .unwrap_err();
    assert!(err.contains("only used in local mode"), "{err}");
    assert!(listener.accept().is_err(), "no connect was made");
}
