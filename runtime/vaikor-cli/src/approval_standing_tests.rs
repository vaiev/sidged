use super::*;
use std::sync::atomic::AtomicUsize;
static NEXT: AtomicUsize = AtomicUsize::new(0);
fn peer(_: &UnixStream) -> Result<u32, String> {
    Ok(4242)
}
fn fixture() -> (std::path::PathBuf, SocketApproval) {
    // Short path under the temp dir: a deep target dir exceeds SUN_LEN for
    // the unix socket on CI runners.
    let dir = std::env::temp_dir().join(format!(
        "vkr-st-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    // Other R9 tests temporarily change the process-wide umask.
    let umask = UMASK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::fs::create_dir_all(&dir).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.join("control.sock");
    let listener = UnixListener::bind(&path).unwrap();
    drop(umask);
    let hub = SocketApproval::serve(
        listener,
        format!("unix:{}", path.display()),
        Duration::from_millis(200),
        4242,
        peer,
        None,
    );
    (dir, hub)
}
#[test]
fn standing_binding_vectors_over_authenticated_socket() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../spec/test-vectors/approval/standing-binding.json"
    ))
    .unwrap();
    for vector in vectors["vectors"].as_array().unwrap() {
        let (dir, hub) = fixture();
        let v = &vector["input"]["request"];
        let text = |key: &str| v[key].as_str().unwrap().to_string();
        let r = ApprovalRequest {
            step: text("step"),
            capability: text("capability"),
            args_digest: text("args_digest"),
            nonce: text("nonce"),
            plan_digest: text("plan_digest"),
            sent_url_sha256: None,
            scope: v.get("scope").cloned(),
            scope_digest: v["scope_digest"].as_str().map(str::to_string),
        };
        *hub.pending.lock().unwrap() = Some(r.clone());
        let mut stream = UnixStream::connect(dir.join("control.sock")).unwrap();
        writeln!(stream, "request").unwrap();
        let mut snapshot = String::new();
        stream.read_to_string(&mut snapshot).unwrap();
        let snapshot: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
        assert_eq!(snapshot["scope"], v["scope"]);
        assert_eq!(snapshot["scope_digest"], v["scope_digest"]);
        post_approval(hub.addr(), vector["input"]["line"].as_str().unwrap()).unwrap();
        let decision = hub.decide(&r, "now");
        assert_eq!(
            decision.granted,
            vector["expected"]["value"]["approved"].as_bool().unwrap(),
            "{}",
            vector["id"]
        );
        assert_eq!(
            hub.standing_scope_approved(&r),
            vector["expected"]["value"]["standing"].as_bool().unwrap(),
            "{}",
            vector["id"]
        );
        hub.shutdown();
        drop(hub);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
#[test]
fn owner_revocation_uses_existing_authenticated_socket() {
    let (dir, hub) = fixture();
    post_approval(hub.addr(), "revoke *").unwrap();
    assert_eq!(hub.take_revocations(), vec!["*"]);
    assert!(hub.take_revocations().is_empty());
    post_approval(hub.addr(), "kill").unwrap();
    assert!(hub.killed());
    hub.shutdown();
    drop(hub);
    std::fs::remove_dir_all(dir).unwrap();
}
