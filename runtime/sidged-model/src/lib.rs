//! A planner turns a prompt into plan JSON.
//!
//! `StubPlanner` returns a fixed document and is what tests and CI call.
//! `OpenAiPlanner` asks the privacy gateway to post to the OpenAI
//! chat-completions path. A base URL with no path gets `/v1/chat/completions`.
//! A base URL that already has a path, such as Gemini's `.../v1beta/openai`,
//! gets only `/chat/completions`. HTTP 429 and 503 are retried three times.
//! Local mode never opens a socket. No key is baked in.

use std::io::Read;
use std::sync::Mutex;
use std::time::Duration;

use sidged_gateway::{send_with_credential, utc_stamp, EgressError, KeySource, SendRequest};

pub trait Planner {
    /// Real network destination, if this planner uses a hosted transport.
    fn destination(&self) -> Option<String> {
        None
    }
    /// Refuse unsupported destinations before grant reservation and approval.
    fn preflight(&self, _prompt: &str) -> Result<(), String> {
        Ok(())
    }
    /// Exact outbound bytes for the Core pre-send check; absent for local/stub planners.
    fn request_body(&self, _prompt: &str) -> Option<Vec<u8>> {
        None
    }
    fn plan(&self, prompt: &str) -> Result<String, String>;
    /// Preserve gateway failure kinds for callers that need an audit reason.
    fn plan_checked(&self, prompt: &str) -> Result<String, EgressError> {
        self.plan(prompt).map_err(EgressError::from)
    }
    fn reports(&self) -> Vec<String> {
        Vec::new()
    }
    /// The local-mode model endpoint (0004 R9d): no egress, so no egress
    /// reservation; its plan is still untrusted and fully gated.
    fn is_local_model(&self) -> bool {
        false
    }
    /// A note audited once before the planner runs.
    fn start_note(&self) -> Option<String> {
        None
    }
}

pub struct StubPlanner {
    pub document: String,
}

impl Planner for StubPlanner {
    fn plan(&self, _prompt: &str) -> Result<String, String> {
        Ok(self.document.clone())
    }
}

pub struct OpenAiPlanner {
    pub base_url: String,
    pub provider_id: String,
    pub model: String,
    pub provider_project: Option<String>,
    /// Credential reference; the gateway reads the key at send time (0007 R10a).
    pub credential: Option<KeySource>,
    pub local: bool,
    pub profile: String,
    pub region: String,
    pub residency: Vec<String>,
    pub now: Option<String>,
    reports: Mutex<Vec<String>>,
    retry_limit: u32,
}

impl OpenAiPlanner {
    pub fn new(
        base_url: impl Into<String>,
        model: impl Into<String>,
        api_key: Option<String>,
        residency: Vec<String>,
        region: impl Into<String>,
        provider_id: impl Into<String>,
    ) -> Self {
        let base_url = base_url.into();
        Self {
            provider_id: provider_id.into(),
            base_url,
            model: model.into(),
            credential: api_key.filter(|key| !key.is_empty()).map(KeySource::fixed),
            provider_project: std::env::var("SIDGED_GEMINI_PROJECT").ok(),
            local: false,
            profile: "P0".into(),
            region: region.into(),
            residency,
            now: None,
            reports: Mutex::new(Vec::new()),
            retry_limit: MAX_ATTEMPTS,
        }
    }

    /// A guard reservation and approval cover one transport attempt only.
    pub fn without_retries(mut self) -> Self {
        self.retry_limit = 1;
        self
    }

    pub fn reports(&self) -> Vec<String> {
        self.reports.lock().expect("planner reports").clone()
    }
}

const MAX_ATTEMPTS: u32 = 3;

enum Attempt {
    Retryable(u16),
    Fatal(EgressError),
}

impl OpenAiPlanner {
    fn post_completion(&self, url: &str, prompt: &str, attempt: u32) -> Result<String, Attempt> {
        let bytes = self
            .request_body(prompt)
            .ok_or_else(|| Attempt::Fatal("planner request body unavailable".into()))?;
        let stamp = self.now.clone().unwrap_or_else(utc_stamp);
        let step = format!("planner-{attempt}");
        let response = send_with_credential(
            &SendRequest {
                url,
                provider_id: &self.provider_id,
                profile: &self.profile,
                provider_project: self.provider_project.as_deref(),
                residency: &self.residency,
                region: &self.region,
                // 0007 R11-A/R13 require Core-derived input classes. This
                // transport-level message label differs from the guard's
                // query/documents.text read-log set; the specs do not define
                // a planner prompt-to-record mapping. Keep the distinction
                // until that mapping is specified.
                data_classes: &["communications.content"],
                fields: &["messages"],
                body: &bytes,
                authorization: None,
                call_at: &stamp,
                step: &step,
                local: self.local,
            },
            self.credential.as_ref(),
        );
        match response {
            Ok(sent) => {
                self.reports
                    .lock()
                    .expect("planner reports")
                    .push(sent.report.to_string());
                if sent.status == 429 || sent.status == 503 {
                    return Err(Attempt::Retryable(sent.status));
                }
                if !(200..300).contains(&sent.status) {
                    return Err(Attempt::Fatal(
                        format!("planner HTTP {}", sent.status).into(),
                    ));
                }
                let body: serde_json::Value = serde_json::from_str(&sent.body)
                    .map_err(|err| Attempt::Fatal(err.to_string().into()))?;
                body["choices"][0]["message"]["content"]
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| Attempt::Fatal("planner response has no message content".into()))
            }
            Err(mut err) => {
                if let Some(report) = err.report.take() {
                    self.reports
                        .lock()
                        .expect("planner reports")
                        .push(report.to_string());
                }
                Err(Attempt::Fatal(err))
            }
        }
    }
}

impl Planner for OpenAiPlanner {
    fn preflight(&self, prompt: &str) -> Result<(), String> {
        let body = self
            .request_body(prompt)
            .ok_or("planner request body unavailable")?;
        let url = completions_url(&self.base_url);
        sidged_gateway::preflight(
            &SendRequest {
                url: &url,
                provider_id: &self.provider_id,
                provider_project: self.provider_project.as_deref(),
                profile: &self.profile,
                residency: &self.residency,
                region: &self.region,
                // 0007 R11-A/R13 require Core-derived input classes. This
                // transport-level message label differs from the guard's
                // query/documents.text read-log set; the specs do not define
                // a planner prompt-to-record mapping. Keep the distinction
                // until that mapping is specified.
                data_classes: &["communications.content"],
                fields: &["messages"],
                body: &body,
                authorization: None,
                call_at: "",
                step: "planner",
                local: self.local,
            },
            self.credential.as_ref(),
        )
        .map_err(|error| error.message)
    }
    fn request_body(&self, prompt: &str) -> Option<Vec<u8>> {
        serde_json::to_vec(&serde_json::json!({
            "model":self.model,"temperature":0,
            "messages":[{"role":"user","content":prompt}],
        }))
        .ok()
    }
    fn destination(&self) -> Option<String> {
        Some(completions_url(&self.base_url))
    }
    fn reports(&self) -> Vec<String> {
        OpenAiPlanner::reports(self)
    }
    fn plan(&self, prompt: &str) -> Result<String, String> {
        self.plan_checked(prompt).map_err(|error| error.message)
    }
    fn plan_checked(&self, prompt: &str) -> Result<String, EgressError> {
        let url = completions_url(&self.base_url);
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match self.post_completion(&url, prompt, attempt) {
                Ok(content) => return Ok(content),
                Err(Attempt::Retryable(_)) if attempt < self.retry_limit => {
                    std::thread::sleep(backoff_after(attempt))
                }
                Err(Attempt::Retryable(status)) => {
                    return Err(format!("planner HTTP {status} after {attempt} attempts").into())
                }
                Err(Attempt::Fatal(message)) => return Err(message),
            }
        }
    }
}

/// Wait before the next try. `attempt` is the failed try, starting at 1.
/// The delay doubles and stays at or below two seconds.
fn backoff_after(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(4);
    Duration::from_millis(50u64.saturating_mul(1u64 << shift))
}

/// `https://host` gets `/v1/chat/completions`. A base URL that already has a
/// path, such as Gemini's `.../v1beta/openai`, gets only `/chat/completions`.
pub fn completions_url(base_url: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let after_scheme = base.split_once("://").map(|(_, rest)| rest).unwrap_or(base);
    if after_scheme.contains('/') {
        format!("{base}/chat/completions")
    } else {
        format!("{base}/v1/chat/completions")
    }
}

pub fn read_http_request(mut stream: impl Read) -> Result<String, String> {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    let mut header = Vec::new();
    loop {
        let n = stream.read(&mut byte).map_err(|err| err.to_string())?;
        if n == 0 {
            break;
        }
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
        if header.len() > 8192 {
            return Err("request header is too large".into());
        }
    }
    let text = String::from_utf8_lossy(&header);
    let length = text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse::<usize>().ok()
        } else {
            None
        }
    });
    if let Some(length) = length {
        buffer.resize(length, 0);
        stream
            .read_exact(&mut buffer)
            .map_err(|err| err.to_string())?;
    }
    Ok(format!("{text}{}", String::from_utf8_lossy(&buffer)))
}

#[cfg(test)]
mod tests {
    use std::io::{ErrorKind, Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use super::{
        backoff_after, completions_url, read_http_request, OpenAiPlanner, Planner, StubPlanner,
    };

    #[test]
    fn constructor_residency_refuses_an_unregistered_destination() {
        let planner = OpenAiPlanner::new(
            "https://anything.example",
            "demo",
            None,
            vec!["CH".into()],
            "CH",
            "https://anything.example",
        );
        assert_eq!(planner.residency, vec!["CH".to_string()]);
        assert_eq!(planner.region, "CH");
        assert_eq!(planner.provider_id, "https://anything.example");
        assert!(planner
            .plan("private prompt")
            .unwrap_err()
            .contains("residency is unknown"));
        assert!(planner.reports().is_empty());
    }

    #[test]
    fn backoff_grows_and_stays_bounded() {
        let first = backoff_after(1);
        let second = backoff_after(2);
        let third = backoff_after(3);
        assert!(first >= Duration::from_millis(1));
        assert!(second > first);
        assert!(third > second);
        assert!(backoff_after(8) <= Duration::from_secs(2));
        assert!(backoff_after(30) <= Duration::from_secs(2));
    }

    struct Script {
        port: u16,
        hits: Arc<AtomicUsize>,
        paths: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
        server: thread::JoinHandle<()>,
    }

    fn scripted_server(statuses: Vec<u16>, ok_body: &'static str) -> Script {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let hits_thread = Arc::clone(&hits);
        let paths_thread = Arc::clone(&paths);
        let stop_thread = Arc::clone(&stop);
        let server = thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let request = read_http_request(&mut stream).unwrap_or_default();
                        let path = request.lines().next().unwrap_or("").to_string();
                        paths_thread.lock().unwrap().push(path);
                        let n = hits_thread.fetch_add(1, Ordering::SeqCst);
                        let status = statuses.get(n).copied().unwrap_or(500);
                        let body = if status == 200 { ok_body } else { "" };
                        let response = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                        stream.write_all(response.as_bytes()).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_millis(200)))
                            .unwrap();
                        let _ = stream.read(&mut [0u8; 1]);
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(err) => panic!("accept failed: {err}"),
                }
            }
        });
        Script {
            port,
            hits,
            paths,
            stop,
            server,
        }
    }

    impl Script {
        fn finish(self) -> (usize, Vec<String>) {
            self.stop.store(true, Ordering::SeqCst);
            self.server.join().unwrap();
            (
                self.hits.load(Ordering::SeqCst),
                self.paths.lock().unwrap().clone(),
            )
        }
    }

    #[test]
    fn completions_url_appends_v1_when_the_base_has_no_path() {
        assert_eq!(
            completions_url("https://api.openai.com"),
            "https://api.openai.com/v1/chat/completions"
        );
        assert_eq!(
            completions_url("https://api.openai.com/"),
            "https://api.openai.com/v1/chat/completions"
        );
        assert_eq!(
            completions_url("http://127.0.0.1:8080"),
            "http://127.0.0.1:8080/v1/chat/completions"
        );
    }

    #[test]
    fn completions_url_appends_only_chat_completions_when_the_base_has_a_path() {
        assert_eq!(
            completions_url("https://generativelanguage.googleapis.com/v1beta/openai"),
            "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
        );
        assert_eq!(
            completions_url("https://generativelanguage.googleapis.com/v1beta/openai/"),
            "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
        );
        assert_eq!(
            completions_url("https://api.x.ai/v1"),
            "https://api.x.ai/v1/chat/completions"
        );
        assert_eq!(
            completions_url("https://api.openai.com/v1"),
            "https://api.openai.com/v1/chat/completions"
        );
    }

    #[test]
    fn the_stub_returns_its_document() {
        let planner = StubPlanner {
            document: "{\"v\":\"0.1\"}".into(),
        };
        assert_eq!(planner.plan("ignored").unwrap(), "{\"v\":\"0.1\"}");
    }

    #[test]
    fn the_openai_provider_posts_chat_completions() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream).unwrap();
            assert!(request.starts_with("POST /v1/chat/completions "));
            assert!(request.contains("Bearer test-key"));
            assert!(request.contains("\"model\":\"demo\""));
            assert!(request.contains("moderate the comment"));
            let body = r#"{"choices":[{"message":{"content":"{\"v\":\"0.1\",\"steps\":[]}"}}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            let _ = stream.read(&mut [0u8; 1]);
        });
        let planner = OpenAiPlanner::new(
            format!("http://127.0.0.1:{port}"),
            "demo",
            Some("test-key".into()),
            vec!["unrestricted".into()],
            "",
            format!("http://127.0.0.1:{port}"),
        );
        let plan = planner.plan("moderate the comment").unwrap();
        assert!(plan.contains("\"v\":\"0.1\""));
        let reports = (&planner as &dyn Planner).reports();
        assert_eq!(reports.len(), 1);
        let document: serde_json::Value = serde_json::from_str(&reports[0]).unwrap();
        assert!(document["id"].as_str().unwrap().starts_with("pr-"));
        assert!(document["provider_profile"]["effective"].is_null());
        server.join().unwrap();
    }

    #[test]
    fn local_mode_does_not_call_the_provider() {
        if std::env::var_os("LOCAL_ISOLATED").is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::local_mode_does_not_call_the_provider"])
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
        let script = scripted_server(vec![200], r#"{"choices":[{"message":{"content":"{}"}}]}"#);
        let mut planner = OpenAiPlanner::new(
            format!("http://127.0.0.1:{}", script.port),
            "demo",
            None,
            vec!["unrestricted".into()],
            "",
            format!("http://127.0.0.1:{}", script.port),
        );
        planner.local = true;
        let error = planner.plan("moderate the comment").unwrap_err();
        let (hits, _) = script.finish();
        assert!(error.contains("local mode"), "{error}");
        assert_eq!(hits, 0);
        assert!(planner.reports().is_empty());
    }

    #[test]
    fn the_provider_retries_429_then_returns_the_plan() {
        let body = r#"{"choices":[{"message":{"content":"{\"v\":\"0.1\"}"}}]}"#;
        let script = scripted_server(vec![429, 200], body);
        let planner = OpenAiPlanner::new(
            format!("http://127.0.0.1:{}/v1", script.port),
            "demo",
            Some("test-key".into()),
            vec!["unrestricted".into()],
            "",
            format!("http://127.0.0.1:{}/v1", script.port),
        );
        let plan = planner.plan("moderate the comment").unwrap();
        let (hits, paths) = script.finish();
        assert_eq!(hits, 2);
        assert!(
            paths[0].starts_with("POST /v1/chat/completions "),
            "{paths:?}"
        );
        assert!(plan.contains("\"v\":\"0.1\""));
    }

    #[test]
    fn the_provider_stops_after_three_503_responses() {
        let body = r#"{"choices":[{"message":{"content":"{\"v\":\"0.1\"}"}}]}"#;
        let script = scripted_server(vec![503, 503, 503, 503, 200], body);
        let planner = OpenAiPlanner::new(
            format!("http://127.0.0.1:{}", script.port),
            "demo",
            None,
            vec!["unrestricted".into()],
            "",
            format!("http://127.0.0.1:{}", script.port),
        );
        let error = planner.plan("moderate the comment").unwrap_err();
        let (hits, _) = script.finish();
        assert!(error.contains("503"), "{error}");
        assert_eq!(hits, 3, "503 retries must stay bounded");
    }

    #[test]
    fn the_provider_does_not_retry_a_500() {
        let script = scripted_server(
            vec![500, 200],
            r#"{"choices":[{"message":{"content":"{}"}}]}"#,
        );
        let planner = OpenAiPlanner::new(
            format!("http://127.0.0.1:{}", script.port),
            "demo",
            None,
            vec!["unrestricted".into()],
            "",
            format!("http://127.0.0.1:{}", script.port),
        );
        let error = planner.plan("moderate the comment").unwrap_err();
        let (hits, _) = script.finish();
        assert!(error.contains("500"), "{error}");
        assert_eq!(hits, 1);
    }
}
