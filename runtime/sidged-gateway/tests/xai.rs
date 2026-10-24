//! xAI send path (0007 xAI registry entry, residency.md): GLOBAL destination,
//! profile P0, unrestricted payloads only, key from a file, never logged.
//! No live calls: refusals happen before transport; the success path uses a
//! loopback mock endpoint.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use sidged_gateway::{send, validate_destination, ApiKey, SendRequest};

const ENDPOINT: &str = "https://api.x.ai/v1/chat/completions";
const PROVIDER: &str = "https://api.x.ai";
const KEY: &str = "xai-TEST-not-a-real-key-7f3a9c";

fn unrestricted() -> Vec<String> {
    vec!["unrestricted".into()]
}

fn req<'a>(
    url: &'a str,
    provider: &'a str,
    profile: &'a str,
    tags: &'a [String],
    body: &'a [u8],
    auth: Option<&'a str>,
) -> SendRequest<'a> {
    SendRequest {
        url,
        provider_id: provider,
        provider_project: None,
        profile,
        residency: tags,
        region: "",
        data_classes: &["communications.content"],
        fields: &["messages"],
        body,
        authorization: auth,
        call_at: "2026-10-16T09:00:00Z",
        step: "planner-1",
        local: false,
    }
}

const BODY: &[u8] = br#"{"model":"grok-4","messages":[{"role":"user","content":"hi"}]}"#;

#[test]
fn xai_is_a_registered_global_destination_for_unrestricted_payloads_only() {
    for region in ["", "GLOBAL"] {
        assert!(
            validate_destination(ENDPOINT, PROVIDER, region, &unrestricted()).is_ok(),
            "{region}"
        );
    }
    for tag in ["CH", "EU", "CH-EU"] {
        assert!(
            validate_destination(ENDPOINT, PROVIDER, "", &[tag.into()]).is_err(),
            "{tag}"
        );
        assert!(
            validate_destination(ENDPOINT, PROVIDER, tag, &unrestricted()).is_err(),
            "region {tag}"
        );
    }
    assert!(
        validate_destination(ENDPOINT, PROVIDER, "", &[]).is_err(),
        "missing residency"
    );
    assert!(validate_destination(ENDPOINT, PROVIDER, "", &["x-unknown".into()]).is_err());
    // origin binding: lookalike hosts and other ports are unknown destinations
    for url in [
        "https://api.x.ai.evil.example/v1/chat/completions",
        "https://api.x.ai:8443/v1/chat/completions",
        "http://api.x.ai/v1/chat/completions",
    ] {
        assert!(
            validate_destination(url, url, "", &unrestricted()).is_err(),
            "{url}"
        );
    }
}

#[test]
fn xai_refuses_before_transport_on_profile_endpoint_residency_or_body() {
    let tags = unrestricted();
    let ch = vec!["CH".to_string()];
    let cases: Vec<(SendRequest, &str)> = vec![
        (req(ENDPOINT, PROVIDER, "P1", &tags, BODY, None), "P0"),
        (req(ENDPOINT, PROVIDER, "P9", &tags, BODY, None), "P0-P3"),
        (req(ENDPOINT, PROVIDER, "", &tags, BODY, None), "P0-P3"),
        (
            req(
                "https://api.x.ai/v1/responses",
                PROVIDER,
                "P0",
                &tags,
                BODY,
                None,
            ),
            "endpoint",
        ),
        (
            req(
                "https://api.x.ai/v1/chat/completions?stream=true",
                PROVIDER,
                "P0",
                &tags,
                BODY,
                None,
            ),
            "endpoint",
        ),
        (req(ENDPOINT, PROVIDER, "P0", &ch, BODY, None), "residency"),
        (req(ENDPOINT, PROVIDER, "P0", &[], BODY, None), "residency"),
        (req(ENDPOINT, PROVIDER, "P0", &tags, b"[1]", None), "body"),
        (
            req(ENDPOINT, PROVIDER, "P0", &tags, b"not json", None),
            "body",
        ),
    ];
    for (request, expect) in cases {
        let error = send(&request).unwrap_err();
        assert!(
            error.message.contains(expect),
            "{expect}: {}",
            error.message
        );
        assert!(
            error.report.is_none(),
            "refused before a report/transport: {}",
            error.message
        );
    }
}

#[test]
fn xai_detection_uses_the_url_parser() {
    for url in [
        "https://api.x.ai/v1",
        "https://%61pi.x.ai/v1",
        "HTTPS://API.X.AI./v1",
        "https://user@api.x.ai:443/v1",
    ] {
        assert!(sidged_gateway::is_xai(url), "{url}");
    }
    for url in [
        "https://api.x.ai.evil.example/v1",
        "https://x.ai/v1",
        "not a url",
    ] {
        assert!(!sidged_gateway::is_xai(url), "{url}");
    }
}

#[test]
fn api_key_comes_from_a_file_and_is_redacted() {
    let dir = std::env::temp_dir().join(format!("sidged-xai-key-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("xai.key");
    write600(&path, format!("{KEY}\n"));
    let key = ApiKey::from_file(&path).unwrap();
    assert_eq!(*key.bearer(), format!("Bearer {KEY}"));
    for shown in [format!("{key:?}"), format!("{key}")] {
        assert!(
            !shown.contains(KEY) && shown.contains("redacted"),
            "{shown}"
        );
    }
    write600(&path, "  \n");
    assert!(ApiKey::from_file(&path).unwrap_err().contains("empty"));
    write600(&path, "two\nlines\n");
    assert!(ApiKey::from_file(&path).is_err());
    // A BOM or any non-printable-ASCII byte is refused before
    // transport (ureq would echo an invalid header value in its error).
    for bad in ["\u{feff}xai-key", "xai-k\u{e9}y", "xai\x07key"] {
        write600(&path, bad);
        let err = ApiKey::from_file(&path).unwrap_err();
        assert!(
            err.contains("printable ASCII") && !err.contains(bad),
            "{err}"
        );
    }
    let missing = ApiKey::from_file(&dir.join("absent")).unwrap_err();
    assert!(!missing.contains(KEY));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn mock_endpoint_gets_the_key_header_but_report_and_errors_never_contain_it() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).unwrap();
        let head = String::from_utf8_lossy(&buf[..n]).to_string();
        let body = r#"{"choices":[{"message":{"content":"ok"}}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        head
    });
    let url = format!("http://127.0.0.1:{port}/v1/chat/completions");
    let bearer = format!("Bearer {KEY}");
    let tags = unrestricted();
    let sent = send(&req(&url, &url, "P0", &tags, BODY, Some(&bearer))).unwrap();
    let head = server.join().unwrap();
    assert!(
        head.to_ascii_lowercase().contains(&format!(
            "authorization: bearer {}",
            KEY.to_ascii_lowercase()
        )),
        "{head}"
    );
    assert_eq!(sent.status, 200);
    assert!(
        sent.report["id"].as_str().unwrap().starts_with("pr-"),
        "one privacy report per call"
    );
    assert!(!sent.report.to_string().contains(KEY));
    assert!(!format!("{sent:?}").contains(KEY));
    // transport failure after the report: message and report are key-free
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_url = format!(
        "http://127.0.0.1:{}/v1/chat/completions",
        dead.local_addr().unwrap().port()
    );
    drop(dead);
    let error = send(&req(&dead_url, &dead_url, "P0", &tags, BODY, Some(&bearer))).unwrap_err();
    assert!(error.report.is_some(), "failed calls still report");
    assert!(!format!("{error:?}").contains(KEY));
}

fn write600(path: &std::path::Path, contents: impl AsRef<[u8]>) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
