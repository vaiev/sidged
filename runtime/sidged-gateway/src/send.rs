//! The only HTTP path out of the runtime.
//!
//! Local mode, an unknown provider profile, and a residency mismatch refuse
//! before a socket is opened. The privacy report is built before the bytes leave.

use std::io::Read;
use std::time::Duration;

use super::{call_id, known_profile, report, residency_destination, Egress};

pub struct SendRequest<'a> {
    pub url: &'a str,
    pub provider_id: &'a str,
    pub provider_project: Option<&'a str>,
    pub profile: &'a str,
    pub residency: &'a [String],
    pub region: &'a str,
    pub data_classes: &'a [&'a str],
    pub fields: &'a [&'a str],
    pub body: &'a [u8],
    pub authorization: Option<&'a str>,
    pub call_at: &'a str,
    pub step: &'a str,
    pub local: bool,
}

#[derive(Debug)]
pub struct SendResponse {
    pub status: u16,
    pub body: String,
    pub report: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressErrorKind {
    /// File or fixed-value credential failures use credential-unavailable.
    Credential,
    /// Preserve the guard's existing planner-failed reason for env sources.
    EnvironmentCredential,
    Other,
}

#[derive(Debug)]
pub struct EgressError {
    pub kind: EgressErrorKind,
    pub message: String,
    pub report: Option<serde_json::Value>,
}

pub fn send(request: &SendRequest) -> Result<SendResponse, EgressError> {
    send_method(request, false, None)
}

/// GET reports bind the complete URL bytes, including the verified query.
pub fn send_get(request: &SendRequest) -> Result<SendResponse, EgressError> {
    send_method(request, true, None)
}

/// POST with a credential reference (0007 R10a): the gateway reads the key at
/// send time, after the local latch, profile, provider and destination checks
/// and after the privacy report is built, so a refused call never opens it.
pub fn send_with_credential(
    request: &SendRequest,
    credential: Option<&KeySource>,
) -> Result<SendResponse, EgressError> {
    send_method(request, false, credential)
}

/// The send-time destination checks without credential access or transport.
/// Guard uses this before grant reservation and owner approval (0007 §5).
pub fn preflight(request: &SendRequest, credential: Option<&KeySource>) -> Result<(), EgressError> {
    super::resolve_local(request.local).map_err(refused)?;
    if super::is_local() {
        return Err(refused("local mode refuses egress"));
    }
    if credential.is_some() && request.authorization.is_some() {
        return Err(refused(
            "set an authorization header or a credential reference, not both",
        ));
    }
    if !known_profile(request.profile) {
        return Err(refused("provider profile is not P0-P3"));
    }
    validate_gemini(request).map_err(refused)?;
    validate_xai(request).map_err(refused)?;
    if matches!(credential, Some(KeySource::Env(_)))
        && (is_xai(request.url) || is_xai(request.provider_id))
    {
        return Err(refused(
            "xAI needs its API key from a file (SIDGED_API_KEY_FILE); an environment key is refused",
        ));
    }
    let destination =
        url::Url::parse(request.url).map_err(|_| refused("invalid destination URL"))?;
    // Only IP literals qualify: localhost DNS resolution is not trusted.
    let loopback = destination.host_str().is_some_and(|host| {
        host.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    });
    if !matches!(destination.scheme(), "http" | "https")
        || (destination.scheme() == "http" && !loopback)
    {
        return Err(refused("HTTPS is required for a non-loopback destination"));
    }
    validate_destination(
        request.url,
        request.provider_id,
        request.region,
        request.residency,
    )
    .map_err(refused)?;
    Ok(())
}

fn send_method(
    request: &SendRequest,
    get: bool,
    credential: Option<&KeySource>,
) -> Result<SendResponse, EgressError> {
    preflight(request, credential)?;
    let payload = if get {
        request.url.as_bytes()
    } else {
        request.body
    };
    let id = call_id(request.provider_id, request.call_at, request.step, payload);
    let tags: Vec<&str> = request.residency.iter().map(String::as_str).collect();
    let mut document = report(&Egress {
        id: &id,
        call_at: request.call_at,
        provider_id: request.provider_id,
        profile: request.profile,
        data_classes: request.data_classes,
        fields: request.fields,
        payload,
        residency: &tags,
    });
    document["payload_binding"] = if get { "request-url" } else { "request-body" }.into();
    // 0007 R10a: the key is read here, after every check and the report, and
    // held in `Zeroizing` until the request is built. A read failure means
    // nothing left the runtime, so there is no report.
    let bearer = credential
        .map(KeySource::bearer)
        .transpose()
        .map_err(|message| EgressError {
            kind: if matches!(credential, Some(KeySource::Env(_))) {
                EgressErrorKind::EnvironmentCredential
            } else {
                EgressErrorKind::Credential
            },
            message,
            report: None,
        })?;
    let authorization = bearer
        .as_ref()
        .map(|b| b.as_str())
        .or(request.authorization);
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .redirects(0)
        .build();
    let mut http = agent.request(if get { "GET" } else { "POST" }, request.url);
    if !get {
        http = http.set("Content-Type", "application/json");
    }
    if let Some(authorization) = authorization {
        if !authorization.is_empty() {
            http = http.set("Authorization", authorization);
        }
    }
    drop(bearer);
    let sent = if get {
        http.call()
    } else {
        http.send_bytes(request.body)
    };
    let response = match sent {
        Ok(response) | Err(ureq::Error::Status(_, response)) => response,
        Err(err) => {
            return Err(EgressError {
                kind: EgressErrorKind::Other,
                message: err.to_string(),
                report: Some(document),
            })
        }
    };
    if (300..400).contains(&response.status()) {
        return Err(EgressError {
            kind: EgressErrorKind::Other,
            message: "destination redirect refused".into(),
            report: Some(document),
        });
    }
    let status = response.status();
    let body = read_body(response.into_reader()).map_err(|message| EgressError {
        kind: EgressErrorKind::Other,
        message,
        report: Some(document.clone()),
    })?;
    Ok(SendResponse {
        status,
        body,
        report: document,
    })
}

fn refused(message: impl Into<String>) -> EgressError {
    EgressError {
        kind: EgressErrorKind::Other,
        message: message.into(),
        report: None,
    }
}

impl From<String> for EgressError {
    fn from(message: String) -> Self {
        refused(message)
    }
}
impl From<&str> for EgressError {
    fn from(message: &str) -> Self {
        refused(message)
    }
}

pub fn utc_stamp() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    let days = seconds.div_euclid(86_400);
    let tod = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = tod / 3_600;
    let minute = (tod % 3_600) / 60;
    let second = tod % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days: i64) -> (i32, i32, i32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let year_of_era = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_prime = (5 * doy + 2) / 153;
    let day = (doy - (153 * month_prime + 2) / 5 + 1) as i32;
    let month = if month_prime < 10 {
        month_prime as i32 + 3
    } else {
        month_prime as i32 - 9
    };
    let year = if month <= 2 {
        year_of_era + 1
    } else {
        year_of_era
    };
    (year as i32, month, day)
}

const MAX_RESPONSE_BYTES: u64 = 1_048_576;

fn read_body(reader: impl Read) -> Result<String, String> {
    let mut body = String::new();
    reader
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_string(&mut body)
        .map_err(|err| err.to_string())?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("provider response exceeds size limit".into());
    }
    Ok(body)
}

/// Only this registry supplies residency; a caller's region is a consistency check.
/// Unknown remote destinations are refused. Literal loopback requires an explicit unrestricted declaration.
pub fn validate_destination(
    url: &str,
    provider: &str,
    region: &str,
    tags: &[String],
) -> Result<(), String> {
    let destination = url::Url::parse(url).map_err(|_| "invalid destination URL")?;
    let provider = url::Url::parse(provider).map_err(|_| "invalid destination provider")?;
    if destination.origin() != provider.origin()
        || !destination.username().is_empty()
        || destination.password().is_some()
        || !matches!(destination.scheme(), "http" | "https")
    {
        return Err("destination does not match provider".into());
    }
    let registered = match (
        destination.scheme(),
        destination.host_str(),
        destination.port_or_known_default(),
    ) {
        ("https", Some("api.infomaniak.com"), Some(443)) => Some("CH"),
        // No reviewed geographic processing guarantee: unrestricted payloads only.
        ("https", Some("api.open-meteo.com"), Some(443)) => Some("GLOBAL"),
        // Developer API uses a global pool; this supplies no CH/EU guarantee.
        ("https", Some("generativelanguage.googleapis.com"), Some(443)) => Some("GLOBAL"),
        // xAI (0007 amendment): GLOBAL, no residency guarantee; unrestricted only.
        ("https", Some("api.x.ai"), Some(443)) => Some("GLOBAL"),
        _ => None,
    };
    let loopback = destination.host_str().is_some_and(|host| {
        host.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    });
    if registered.is_none() && !loopback {
        return Err("destination residency is unknown".into());
    }
    if let Some(actual) = registered {
        if !region.is_empty() && region != actual {
            return Err(format!(
                "destination residency is {actual}, not allowed in {region}"
            ));
        }
    }
    if tags.is_empty() {
        return Err("residency declaration is missing or empty for destination".into());
    }
    // Loopback supplies no geographic guarantee, just like GLOBAL.
    let actual = registered.unwrap_or("GLOBAL");
    residency_destination(tags, actual, &std::collections::HashMap::new())
        .map_err(|reason| format!("residency: {reason}"))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    use super::{send, SendRequest};

    fn request<'a>(
        url: &'a str,
        residency: &'a [String],
        local: bool,
        profile: &'a str,
        region: &'a str,
        step: &'a str,
    ) -> SendRequest<'a> {
        SendRequest {
            url,
            provider_id: url,
            provider_project: None,
            profile,
            residency,
            region,
            data_classes: &["communications.content"],
            fields: &["prompt"],
            body: b"{\"model\":\"demo\"}",
            authorization: None,
            call_at: "2026-10-15T01:02:03Z",
            step,
            local,
        }
    }

    #[test]
    fn reviewed_gemini_request_passes_policy_without_treating_prompt_text_as_parameters() {
        let tags = vec!["unrestricted".into()];
        let mut req = request(
            "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            &tags,
            false,
            "P0",
            "GLOBAL",
            "planner",
        );
        req.provider_project = Some("test-billing");
        req.body =
            br#"{"messages":[{"role":"user","content":"Explain cachedContent and fileUri"}]}"#;
        assert!(super::validate_gemini(&req).is_ok());
        assert!(
            super::validate_destination(req.url, req.provider_id, req.region, req.residency)
                .is_ok()
        );
    }

    #[test]
    fn function_schema_property_names_pass_gemini_policy() {
        let tags = vec!["unrestricted".into()];
        for name in ["files", "live", "grounding"] {
            let body = serde_json::json!({"tools": [{
                "type": "function", "function": {
                    "name": "lookup", "parameters": {
                        "type": "object", "properties": {name: {"type": "string"}}
                    }
                }
            }]})
            .to_string();
            let mut req = request(
                "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
                &tags,
                false,
                "P0",
                "GLOBAL",
                "planner",
            );
            req.provider_project = Some("test-billing");
            req.body = body.as_bytes();
            assert!(super::validate_gemini(&req).is_ok(), "{name}");
            assert!(super::validate_destination(
                req.url,
                req.provider_id,
                req.region,
                req.residency
            )
            .is_ok());
        }
    }

    #[test]
    fn unknown_remote_destination_is_refused_even_without_residency_tags() {
        assert!(super::validate_destination(
            "https://unknown.example/v1",
            "https://unknown.example",
            "",
            &[]
        )
        .is_err());
    }

    #[test]
    fn registered_residency_does_not_require_a_claimed_region() {
        assert!(super::validate_destination(
            "https://api.infomaniak.com",
            "https://api.infomaniak.com",
            "",
            &["CH".into()]
        )
        .is_ok());
    }

    #[test]
    fn redirects_are_fatal_and_do_not_reach_the_target() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let location = format!("http://{}", target.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            // Drain headers and the declared body before closing the socket.
            // A single read can leave request bytes pending and trigger TCP RST.
            let mut received = Vec::new();
            let header_end = loop {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                received.push(byte[0]);
                if received.ends_with(b"\r\n\r\n") {
                    break received.len();
                }
            };
            let headers = std::str::from_utf8(&received[..header_end]).unwrap();
            let length: usize = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse().unwrap())
                .unwrap_or(0);
            stream.read_exact(&mut vec![0; length]).unwrap();
            write!(stream, "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        let error = send(&request(
            &url,
            &["unrestricted".into()],
            false,
            "P0",
            "",
            "planner",
        ))
        .unwrap_err();
        assert!(error.message.contains("redirect"), "{error:?}");
        assert!(error.report.is_some());
        server.join().unwrap();
        assert_eq!(
            target.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn registered_destination_requires_consistent_region() {
        assert!(super::validate_destination(
            "https://api.infomaniak.com/v1",
            "https://api.infomaniak.com/",
            "EU",
            &["CH".into()]
        )
        .is_err());
        assert!(super::validate_destination(
            "https://api.infomaniak.com/v1",
            "https://api.infomaniak.com/",
            "CH",
            &["CH".into()]
        )
        .is_ok());
    }

    #[test]
    fn destination_cannot_claim_swiss_residency_or_another_provider() {
        let tags = vec!["CH".to_string()];
        for (url, provider) in [
            (
                "https://api.openai.com/v1/chat/completions",
                "https://api.openai.com",
            ),
            (
                "https://api.openai.com/v1/chat/completions",
                "https://api.infomaniak.com/",
            ),
            (
                "https://api.infomaniak.com.evil.example/v1",
                "https://api.infomaniak.com/",
            ),
        ] {
            let mut req = request(url, &tags, false, "P1", "CH", "planner");
            req.provider_id = provider;
            let error = send(&req).unwrap_err();
            assert!(
                error.report.is_none(),
                "must refuse before sending: {error:?}"
            );
            assert!(error.message.contains("destination"), "{error:?}");
        }
    }

    #[test]
    fn remote_cleartext_with_a_key_is_refused_before_connecting() {
        let mut req = request("http://192.0.2.1/v1", &[], false, "P0", "", "planner");
        req.authorization = Some("Bearer secret");
        let error = send(&req).unwrap_err();
        assert!(error.message.contains("HTTPS"), "{error:?}");
        assert!(error.report.is_none());
    }

    #[test]
    fn remote_cleartext_without_a_key_and_localhost_are_refused() {
        for url in ["http://192.0.2.1/v1", "http://localhost:1/v1"] {
            let error = send(&request(url, &[], false, "P0", "", "planner")).unwrap_err();
            assert!(error.message.contains("HTTPS"));
            assert!(error.report.is_none());
        }
    }

    #[test]
    fn response_body_is_bounded() {
        let error = super::read_body(std::io::repeat(b'x').take(1_048_577)).unwrap_err();
        assert!(error.contains("size"));
    }

    #[test]
    fn local_mode_opens_no_socket() {
        if std::env::var_os("LOCAL_ISOLATED").is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "send::tests::local_mode_opens_no_socket"])
                .env("LOCAL_ISOLATED", "1")
                .env_remove("SIDGED_LOCAL")
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
        let hits = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::clone(&hits);
        let server = thread::spawn(move || {
            if listener.accept().is_ok() {
                seen.fetch_add(1, Ordering::SeqCst);
            }
        });
        let tags = vec!["CH".to_string()];
        let error = send(&request(
            &format!("http://127.0.0.1:{port}/v1/chat/completions"),
            &tags,
            true,
            "P0",
            "CH",
            "planner",
        ))
        .unwrap_err();
        assert!(error.message.contains("local mode"), "{}", error.message);
        assert!(error.report.is_none());
        drop(server);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn an_unknown_profile_and_a_foreign_region_do_not_connect() {
        let tags = vec!["CH".to_string()];
        let error = send(&request(
            "http://127.0.0.1:9/nope",
            &tags,
            false,
            "P9",
            "CH",
            "planner",
        ))
        .unwrap_err();
        assert!(error.message.contains("P0-P3"), "{}", error.message);
        let error = send(&request(
            "http://127.0.0.1:9/nope",
            &tags,
            false,
            "P0",
            "EU",
            "planner",
        ))
        .unwrap_err();
        assert!(error.message.contains("residency"), "{}", error.message);
    }

    #[test]
    fn a_post_returns_the_body_and_a_report_for_that_call() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let body = r#"{"choices":[{"message":{"content":"{\"v\":\"0.1\"}"}}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        let tags = vec!["unrestricted".into()];
        let response = send(&request(
            &format!("http://127.0.0.1:{port}/v1/chat/completions"),
            &tags,
            false,
            "P1",
            "CH",
            "planner",
        ))
        .unwrap();
        assert_eq!(response.status, 200);
        assert!(response.body.contains("choices"), "{}", response.body);
        assert_eq!(response.report["call_at"], "2026-10-15T01:02:03Z");
        assert!(response.report["provider"]["id"]
            .as_str()
            .unwrap()
            .starts_with("http://127.0.0.1:"));
        assert!(response.report["provider_profile"]["effective"].is_null());
        assert!(response.report["id"].as_str().unwrap().starts_with("pr-"));
        server.join().unwrap();
    }
}

fn validate_gemini(request: &SendRequest) -> Result<(), String> {
    let is_gemini = |value: &str| {
        url::Url::parse(value)
            .ok()
            .is_some_and(|url| url.host_str() == Some("generativelanguage.googleapis.com"))
    };
    if !is_gemini(request.provider_id) && !is_gemini(request.url) {
        return Ok(());
    }
    if request
        .provider_project
        .is_none_or(|project| project.trim().is_empty())
    {
        return Err(
            "Gemini requires a billing project (SIDGED_GEMINI_PROJECT or provider_project)".into(),
        );
    }
    if request.profile != "P0" {
        return Err("Gemini Developer API requires profile P0".into());
    }
    let url = url::Url::parse(request.url).map_err(|_| "invalid destination URL")?;
    // The reviewed surface is only the stateless OpenAI-compatible endpoint.
    if url.path() != "/v1beta/openai/chat/completions" || url.query().is_some() {
        return Err("unsupported Gemini endpoint or parameters".into());
    }
    let body: serde_json::Value =
        serde_json::from_slice(request.body).map_err(|_| "unsupported Gemini request body")?;
    if !body.is_object() || unsupported_gemini_params(&body) {
        return Err("unsupported Gemini grounding, caching, File or Live API parameters".into());
    }
    Ok(())
}

fn unsupported_gemini_params(value: &serde_json::Value) -> bool {
    fn forbidden_fields(value: &serde_json::Value, names: &[&str]) -> bool {
        value.as_object().is_some_and(|map| {
            map.keys().any(|key| {
                let normalized: String = key
                    .chars()
                    .filter(|c| *c != '_')
                    .flat_map(char::to_lowercase)
                    .collect();
                names.contains(&normalized.as_str())
            })
        })
    }
    fn parts(value: &serde_json::Value) -> bool {
        value.as_array().is_some_and(|items| {
            items
                .iter()
                .any(|part| forbidden_fields(part, &["filedata", "fileuri"]))
        })
    }
    fn parameters(value: &serde_json::Value) -> bool {
        forbidden_fields(
            value,
            &[
                "googlesearch",
                "googlesearchretrieval",
                "grounding",
                "cachedcontent",
                "filedata",
                "fileuri",
                "files",
                "sessionresumption",
                "live",
                "bidigeneratecontent",
            ],
        ) || value["tools"].as_array().is_some_and(|tools| {
            tools.iter().any(|tool| {
                forbidden_fields(
                    tool,
                    &["googlesearch", "googlesearchretrieval", "retrieval"],
                )
            })
        }) || parts(&value["parts"])
            || ["contents", "messages"].iter().any(|field| {
                value[*field].as_array().is_some_and(|items| {
                    items
                        .iter()
                        .any(|item| parts(&item["parts"]) || parts(&item["content"]))
                })
            })
    }
    // Inspect protocol objects only; function schemas and arbitrary JSON data
    // may legitimately use the same field names.
    parameters(value)
        || parameters(&value["extra_body"])
        || parameters(&value["extra_body"]["google"])
}

#[cfg(test)]
#[test]
fn gemini_parameters_are_checked_only_at_protocol_locations() {
    use serde_json::json;
    assert!(!unsupported_gemini_params(&json!({"tools": [{
        "type": "function", "function": {"name": "list", "parameters": {
            "type": "object", "properties": {
                "files": {"type": "array"}, "live": {"type": "object"},
                "grounding": {"type": "object"}, "cachedContent": {"type": "string"},
                "sessionResumption": {"type": "object"}
            }
        }}
    }]})));
    for body in [
        json!({"tools": [{"google_search": {}}]}),
        json!({"tools": [{"googleSearchRetrieval": {}}]}),
        json!({"cachedContent": "id"}),
        json!({"cached_content": "id"}),
        json!({"sessionResumption": {}}),
        json!({"contents": [{"parts": [{"file_data": {"file_uri": "id"}}]}]}),
        json!({"messages": [{"content": [{"fileUri": "id"}]}]}),
        json!({"extra_body": {"google": {"cached_content": "id"}}}),
    ] {
        assert!(unsupported_gemini_params(&body), "{body}");
    }
}

/// xAI (0007 amendment, residency.md): profile P0 only, the reviewed
/// OpenAI-compatible endpoint only, a JSON object body. Residency (unrestricted
/// only, GLOBAL) is enforced by `validate_destination`.
/// Whether a URL names the xAI host, as the gateway's URL parser normalizes it
/// (percent-encoding, case, a trailing dot).
pub fn is_xai(value: &str) -> bool {
    url::Url::parse(value).ok().is_some_and(|url| {
        url.host_str()
            .is_some_and(|host| host.trim_end_matches('.') == "api.x.ai")
    })
}

fn validate_xai(request: &SendRequest) -> Result<(), String> {
    if !is_xai(request.provider_id) && !is_xai(request.url) {
        return Ok(());
    }
    if request.profile != "P0" {
        return Err("xAI requires profile P0 (unverified)".into());
    }
    let url = url::Url::parse(request.url).map_err(|_| "invalid destination URL")?;
    if url.path() != "/v1/chat/completions" || url.query().is_some() || url.fragment().is_some() {
        return Err("unsupported xAI endpoint (only /v1/chat/completions)".into());
    }
    let body: serde_json::Value =
        serde_json::from_slice(request.body).map_err(|_| "unsupported xAI request body")?;
    if !body.is_object() {
        return Err("unsupported xAI request body".into());
    }
    Ok(())
}

/// A provider API key read from a file (compose secret or mounted file), never
/// from the environment. `Debug`/`Display` are redacted so it cannot reach
/// logs, errors or the audit chain by formatting.
/// The key file must be a regular 0600 file owned by the reading uid.
pub fn check_key_file_meta(mode: u32, owner: u32, euid: u32) -> Result<(), String> {
    if mode & 0o7777 != 0o600 {
        return Err(format!("mode {:04o}, must be 0600", mode & 0o7777));
    }
    if owner != euid {
        return Err(format!("owner uid {owner} is not the reading uid {euid}"));
    }
    Ok(())
}

pub struct ApiKey(String);

impl ApiKey {
    pub fn from_file(path: &std::path::Path) -> Result<Self, String> {
        use std::io::Read as _;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|err| {
                if err.raw_os_error() == Some(libc::ELOOP) {
                    format!("API key file {}: symlink refused", path.display())
                } else {
                    format!("API key file {}: {}", path.display(), err.kind())
                }
            })?;
        let meta = file
            .metadata()
            .map_err(|err| format!("API key file {}: {}", path.display(), err.kind()))?;
        if !meta.is_file() {
            return Err(format!(
                "API key file {} is not a regular file",
                path.display()
            ));
        }
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        check_key_file_meta(meta.mode(), meta.uid(), euid)
            .map_err(|why| format!("API key file {}: {why}", path.display()))?;
        let mut raw = String::new();
        file.read_to_string(&mut raw)
            .map_err(|err| format!("API key file {}: {}", path.display(), err.kind()))?;
        let key = raw.trim();
        if key.is_empty() {
            return Err(format!("API key file {} is empty", path.display()));
        }
        // Printable ASCII only (no BOM, no non-ASCII, no controls): an invalid
        // header value would otherwise be echoed by the HTTP client's error.
        if !key.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(format!(
                "API key file {} must hold one key of printable ASCII on one line",
                path.display()
            ));
        }
        let key = Self(key.to_string());
        zeroize::Zeroize::zeroize(&mut raw);
        Ok(key)
    }

    /// The raw key, for the one caller that builds the Authorization header.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The Authorization header value; zeroized when dropped.
    pub fn bearer(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(format!("Bearer {}", self.0))
    }
}

impl Drop for ApiKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey(<redacted>)")
    }
}

impl std::fmt::Display for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A planner credential **reference** (0007 R10, R10a). It names where the key
/// is; the gateway reads the key only inside `send_with_credential`, after
/// every check, so a refused call never opens the file. `File` uses the
/// `ApiKey::from_file` checks. `Env` names a variable that is read at send
/// time and is refused for xAI. `Fixed` is for library callers that already
/// hold a key; it is kept in `Zeroizing`. `Debug` never shows key bytes.
pub enum KeySource {
    File(std::path::PathBuf),
    Env(String),
    Fixed(zeroize::Zeroizing<String>),
}

impl KeySource {
    pub fn fixed(key: impl Into<String>) -> Self {
        Self::Fixed(zeroize::Zeroizing::new(key.into()))
    }

    /// Reads the key now and returns the Authorization header value. Errors
    /// name the source (path or variable name), never the key.
    pub fn bearer(&self) -> Result<zeroize::Zeroizing<String>, String> {
        match self {
            Self::File(path) => Ok(ApiKey::from_file(path)?.bearer()),
            Self::Env(name) => {
                let key = zeroize::Zeroizing::new(
                    std::env::var(name).map_err(|_| format!("{name} is not set"))?,
                );
                bearer_from(key.trim(), name)
            }
            Self::Fixed(key) => bearer_from(key.trim(), "the API key"),
        }
    }
}

/// Same text rule as `ApiKey::from_file`: one non-empty key of printable ASCII.
fn bearer_from(key: &str, source: &str) -> Result<zeroize::Zeroizing<String>, String> {
    if key.is_empty() {
        return Err(format!("{source} is empty"));
    }
    if !key.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!("{source} must hold one key of printable ASCII"));
    }
    Ok(zeroize::Zeroizing::new(format!("Bearer {key}")))
}

impl std::fmt::Debug for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(path) => write!(f, "KeySource::File({})", path.display()),
            Self::Env(name) => write!(f, "KeySource::Env({name})"),
            Self::Fixed(_) => f.write_str("KeySource::Fixed(<redacted>)"),
        }
    }
}
