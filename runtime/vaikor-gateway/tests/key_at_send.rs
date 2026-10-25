//! 0007 R10a: the credential is read by the gateway at send time, after the
//! local latch, the profile, provider and destination checks, and never before.
//! A refused call never opens the key file. The key lives in `Zeroizing`.
//! No live calls: the success path uses a loopback mock endpoint.
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::thread;

use vaikor_gateway::{send_with_credential, KeySource, SendRequest};

const KEY: &str = "gw-TEST-send-time-key-51c0d9";
const BODY: &[u8] = br#"{"model":"demo","messages":[{"role":"user","content":"hi"}]}"#;

fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("vaikor-key-at-send-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_mode(path: &Path, contents: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A key file that fails the `ApiKey::from_file` checks (mode 0644). If the
/// gateway reads it, the error names "API key file"; a refusal that happens
/// before the read never mentions it.
fn unreadable_key(dir: &Path) -> KeySource {
    let path = dir.join("bad.key");
    write_mode(&path, KEY, 0o644);
    KeySource::File(path)
}

fn req<'a>(url: &'a str, profile: &'a str, tags: &'a [String]) -> SendRequest<'a> {
    SendRequest {
        url,
        provider_id: url,
        provider_project: None,
        profile,
        residency: tags,
        region: "",
        data_classes: &["communications.content"],
        fields: &["messages"],
        body: BODY,
        authorization: None,
        call_at: "2026-10-18T09:00:00Z",
        step: "planner-1",
        local: false,
    }
}

fn unrestricted() -> Vec<String> {
    vec!["unrestricted".into()]
}

#[test]
fn a_destination_denial_never_reads_the_key() {
    let dir = scratch("destination");
    let key = unreadable_key(&dir);
    let tags = unrestricted();
    for url in [
        "https://unknown.example/v1/chat/completions",
        "http://192.0.2.1/v1/chat/completions",
    ] {
        let error = send_with_credential(&req(url, "P0", &tags), Some(&key)).unwrap_err();
        assert!(
            !error.message.contains("API key file"),
            "{url}: {}",
            error.message
        );
        assert!(error.report.is_none());
    }
    // CH data never reaches a loopback (unknown residency) destination.
    let ch = vec!["CH".to_string()];
    let error = send_with_credential(
        &req("http://127.0.0.1:9/v1/chat/completions", "P0", &ch),
        Some(&key),
    )
    .unwrap_err();
    assert!(error.message.contains("residency"), "{}", error.message);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn an_unknown_profile_never_reads_the_key() {
    let dir = scratch("profile");
    let key = unreadable_key(&dir);
    let tags = unrestricted();
    let error = send_with_credential(
        &req("http://127.0.0.1:9/v1/chat/completions", "P9", &tags),
        Some(&key),
    )
    .unwrap_err();
    assert!(error.message.contains("P0-P3"), "{}", error.message);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn xai_refuses_an_environment_key_before_reading_it() {
    let tags = unrestricted();
    let mut request = req("https://api.x.ai/v1/chat/completions", "P0", &tags);
    request.provider_id = "https://api.x.ai";
    let error =
        send_with_credential(&request, Some(&KeySource::Env("VAIKOR_API_KEY".into()))).unwrap_err();
    assert!(
        error.message.contains("VAIKOR_API_KEY_FILE"),
        "{}",
        error.message
    );
    assert!(error.report.is_none());
}

#[test]
fn an_authorization_header_and_a_credential_together_are_refused() {
    let tags = unrestricted();
    let mut request = req("http://127.0.0.1:9/v1/chat/completions", "P0", &tags);
    request.authorization = Some("Bearer other");
    let error = send_with_credential(&request, Some(&KeySource::fixed(KEY))).unwrap_err();
    assert!(error.message.contains("credential"), "{}", error.message);
    assert!(error.report.is_none());
}

#[test]
fn an_unreadable_key_refuses_after_the_checks_and_before_connect() {
    let dir = scratch("unreadable");
    let key = unreadable_key(&dir);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let tags = unrestricted();
    let error = send_with_credential(&req(&url, "P0", &tags), Some(&key)).unwrap_err();
    assert!(error.message.contains("API key file"), "{}", error.message);
    assert!(!error.message.contains(KEY));
    assert!(error.report.is_none(), "nothing left the runtime");
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_file_key_is_read_at_send_and_reaches_only_the_header() {
    let dir = scratch("file");
    let path = dir.join("ok.key");
    write_mode(&path, &format!("{KEY}\n"), 0o600);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        use std::io::{BufRead, BufReader};
        let mut reader = BufReader::new(&mut stream);
        let mut head = String::new();
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            head.push_str(&line);
            if line == "\r\n" {
                break;
            }
        }
        // Drain the complete request before closing, avoiding TCP resets when
        // headers and body arrive in separate reads.
        let mut payload = vec![0; BODY.len()];
        reader.read_exact(&mut payload).unwrap();
        assert_eq!(payload, BODY);
        drop(reader);
        let body = r#"{"choices":[{"message":{"content":"ok"}}]}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        head
    });
    let tags = unrestricted();
    let key = KeySource::File(path);
    let sent = send_with_credential(&req(&url, "P0", &tags), Some(&key)).unwrap();
    let head = server.join().unwrap().to_ascii_lowercase();
    assert!(
        head.contains(&format!(
            "authorization: bearer {}",
            KEY.to_ascii_lowercase()
        )),
        "{head}"
    );
    assert_eq!(sent.status, 200);
    assert!(!sent.report.to_string().contains(KEY));
    assert!(!format!("{sent:?}").contains(KEY));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_bearer_is_zeroizing_and_sources_are_redacted() {
    let source = KeySource::fixed(KEY);
    let bearer: zeroize::Zeroizing<String> = source.bearer().unwrap();
    assert_eq!(bearer.as_str(), format!("Bearer {KEY}"));
    for shown in [
        format!("{source:?}"),
        format!("{:?}", KeySource::Env("VAIKOR_API_KEY".into())),
    ] {
        assert!(!shown.contains(KEY), "{shown}");
    }
    assert!(format!("{source:?}").contains("redacted"));
}
