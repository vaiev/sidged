use sidged_gateway::validate_destination;

const ENDPOINT: &str = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions";
const PROVIDER: &str = "https://generativelanguage.googleapis.com/";

#[test]
fn gemini_accepts_public_data_with_global_or_unspecified_region() {
    for region in ["GLOBAL", ""] {
        assert!(validate_destination(ENDPOINT, PROVIDER, region, &["unrestricted".into()]).is_ok());
    }
}

#[test]
fn gemini_never_claims_ch_or_eu_residency() {
    for region in ["CH", "EU", "CH-EU"] {
        assert!(validate_destination(ENDPOINT, PROVIDER, region, &[]).is_err());
        assert!(validate_destination(ENDPOINT, PROVIDER, "GLOBAL", &[region.into()]).is_err());
    }
}

#[test]
fn gemini_provider_must_match_destination_even_for_public_data() {
    for (url, provider) in [
        (ENDPOINT, "https://api.infomaniak.com/"),
        ("https://api.infomaniak.com/v1/chat/completions", PROVIDER),
        (
            "https://generativelanguage.googleapis.com.evil.example/v1",
            PROVIDER,
        ),
    ] {
        assert!(
            validate_destination(url, provider, "", &["unrestricted".into()])
                .unwrap_err()
                .contains("does not match")
        );
    }
}

#[test]
fn empty_residency_is_denied_for_every_destination() {
    for endpoint in [
        ENDPOINT,
        "https://api.infomaniak.com/v1",
        "http://127.0.0.1:9/v1",
    ] {
        assert!(
            validate_destination(endpoint, endpoint, "", &[]).is_err(),
            "{endpoint}"
        );
    }
}

#[test]
fn unrestricted_cannot_mix_with_restrictions_and_owner_mapping_is_explicit() {
    for tag in ["CH", "EU", "CH-EU"] {
        assert!(validate_destination(
            ENDPOINT,
            PROVIDER,
            "GLOBAL",
            &["unrestricted".into(), tag.into()]
        )
        .is_err());
    }
    let owner = std::collections::HashMap::from([("x-global".into(), vec!["GLOBAL".into()])]);
    assert!(sidged_gateway::provider_allows(&["x-global".into()], "GLOBAL", &owner).unwrap());
}

#[test]
fn gemini_policy_refuses_before_any_mock_request() {
    use sidged_gateway::{send, SendRequest};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mock = format!("http://{}", listener.local_addr().unwrap());
    let vectors = [
        (
            "/v1beta/openai/chat/completions",
            "{}",
            None,
            "P0",
            "billing project",
        ),
        (
            "/v1beta/openai/chat/completions",
            "{}",
            Some("  "),
            "P0",
            "billing project",
        ),
        (
            "/v1beta/openai/chat/completions",
            "{}",
            Some("billing"),
            "P1",
            "P0",
        ),
        (
            "/v1beta/openai/chat/completions",
            r#"{"tools":[{"google_search":{}}]}"#,
            Some("billing"),
            "P0",
            "unsupported",
        ),
        (
            "/v1beta/openai/chat/completions",
            r#"{"tools":[{"googleSearchRetrieval":{}}]}"#,
            Some("billing"),
            "P0",
            "unsupported",
        ),
        (
            "/v1beta/openai/chat/completions",
            r#"{"tools":[{"googleSearch":{}}]}"#,
            Some("billing"),
            "P0",
            "unsupported",
        ),
        (
            "/v1beta/openai/chat/completions",
            r#"{"tools":[{"retrieval":{}}]}"#,
            Some("billing"),
            "P0",
            "unsupported",
        ),
        (
            "/v1beta/openai/chat/completions",
            r#"{"extra_body":{"google":{"cached_content":"abc"}}}"#,
            Some("billing"),
            "P0",
            "unsupported",
        ),
        (
            "/v1beta/openai/chat/completions",
            r#"{"contents":[{"parts":[{"fileData":{}}]}]}"#,
            Some("billing"),
            "P0",
            "unsupported",
        ),
        (
            "/v1beta/openai/chat/completions",
            r#"{"contents":[{"parts":[{"fileUri":"abc"}]}]}"#,
            Some("billing"),
            "P0",
            "unsupported",
        ),
        (
            "/v1beta/openai/chat/completions",
            r#"{"session_resumption":{}}"#,
            Some("billing"),
            "P0",
            "unsupported",
        ),
        (
            "/v1beta/openai/chat/completions",
            r#"{"grounding":{}}"#,
            Some("billing"),
            "P0",
            "unsupported",
        ),
        (
            "/v1beta/openai/chat/completions",
            r#"{"cachedContent":"abc"}"#,
            Some("billing"),
            "P0",
            "unsupported",
        ),
        (
            "/v1beta/openai/chat/completions",
            r#"{"cached_content":"abc"}"#,
            Some("billing"),
            "P0",
            "unsupported",
        ),
        (
            "/v1beta/openai/chat/completions",
            r#"{"parts":[{"file_data":{}}]}"#,
            Some("billing"),
            "P0",
            "unsupported",
        ),
        (
            "/v1beta/openai/chat/completions",
            r#"{"fileUri":"abc"}"#,
            Some("billing"),
            "P0",
            "unsupported",
        ),
        (
            "/v1beta/openai/chat/completions",
            r#"{"files":[]}"#,
            Some("billing"),
            "P0",
            "unsupported",
        ),
        (
            "/v1beta/openai/chat/completions",
            r#"{"sessionResumption":{}}"#,
            Some("billing"),
            "P0",
            "unsupported",
        ),
        (
            "/upload/v1beta/files",
            "{}",
            Some("billing"),
            "P0",
            "unsupported",
        ),
        (
            "/v1beta/files/123",
            "{}",
            Some("billing"),
            "P0",
            "unsupported",
        ),
        ("/live", "{}", Some("billing"), "P0", "unsupported"),
        (
            "/bidiGenerateContent",
            "{}",
            Some("billing"),
            "P0",
            "unsupported",
        ),
        (
            "/v1beta/openai/chat/completions?cachedContent=abc",
            "{}",
            Some("billing"),
            "P0",
            "unsupported",
        ),
    ];
    for (path, body, project, profile, reason) in vectors {
        let url = format!("{mock}{path}");
        let err = send(&SendRequest {
            url: &url,
            provider_id: PROVIDER,
            profile,
            provider_project: project,
            residency: &["unrestricted".into()],
            region: "GLOBAL",
            data_classes: &["communications.content"],
            fields: &["messages"],
            body: body.as_bytes(),
            authorization: None,
            call_at: "2026-10-15T00:00:00Z",
            step: "test",
            local: false,
        })
        .unwrap_err();
        assert!(err.message.contains(reason), "{path} {body}: {err:?}");
        assert!(err.report.is_none());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
