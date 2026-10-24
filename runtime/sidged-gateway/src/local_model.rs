// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Local model endpoint (0004 R9d).
//!
//! Local mode has no egress and no listening socket. The only outbound
//! connection it may make is ONE connect to the statically configured model
//! endpoint: by default an AF_UNIX socket whose SO_PEERCRED uid must equal the
//! configured model uid; `127.0.0.1:<port>` is only a fallback (no peer
//! check is possible there). Outside local mode the AF_UNIX endpoint may be
//! used too, because it is not egress; the loopback fallback may not (R9d). The model's reply is untrusted: callers treat it
//! as a proposed plan that still goes through verify, grant, Cedar and
//! approval.
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelEndpoint {
    /// Default: AF_UNIX socket, peer uid checked against `uid`.
    Unix { path: PathBuf, uid: u32 },
    /// Fallback: `127.0.0.1:<port>` only.
    Loopback { port: u16 },
}

impl ModelEndpoint {
    /// Audit/start note for the loopback fallback: over TCP there is
    /// no peer uid check, so any local process could serve the model.
    pub fn risk_note(&self) -> Option<String> {
        match self {
            ModelEndpoint::Unix { .. } => None,
            ModelEndpoint::Loopback { port } => Some(format!(
                "local model loopback fallback 127.0.0.1:{port} (explicit config model.endpoint tcp:127.0.0.1:{port}): no peer uid check, any local process that binds the port can serve or observe model traffic; prefer model.endpoint unix:<path> with model.uid"
            )),
        }
    }
}

/// `config.json` `model.endpoint` (0004 R9, 0005 R8):
/// `{"endpoint": "unix:<absolute path>", "uid": <model uid>}` (default) or
/// `{"endpoint": "tcp:127.0.0.1:<port>"}` (explicit only, no peer check).
/// `model` may also be a plain model-name string, or carry `"name"`; without
/// `endpoint` there is no local model. The pre-ratification `local_model` key
/// is refused so a stale config is never silently ignored.
pub fn model_endpoint(config: &serde_json::Value) -> Result<Option<ModelEndpoint>, String> {
    if !config["local_model"].is_null() {
        return Err("config local_model was renamed to model.endpoint (0004 R9): use model {\"endpoint\": \"unix:<path>\", \"uid\": <uid>} or {\"endpoint\": \"tcp:127.0.0.1:<port>\"}".into());
    }
    let model = &config["model"];
    let Some(object) = model.as_object() else {
        if model.is_null() || model.is_string() {
            return Ok(None);
        }
        return Err("config model must be a name or an object".into());
    };
    if let Some(key) = object.keys().find(|k| {
        !matches!(
            k.as_str(),
            "name" | "endpoint" | "uid" | "digest" | "output"
        )
    }) {
        return Err(format!("config model: unknown key {key:?}"));
    }
    // What the linguist is asked to emit (0017 L3a); sidged-cli reads it, every reader checks it.
    if object
        .get("output")
        .is_some_and(|o| o.as_str() != Some("full") && o.as_str() != Some("compact"))
    {
        return Err("config model.output must be \"full\" or \"compact\"".into());
    }
    // The served weights by hash (0011 R8), as the node verified them before starting the model.
    if let Some(digest) = object.get("digest") {
        let ok = digest.as_object().is_some_and(|d| {
            d.len() == 2
                && d.get("alg").and_then(serde_json::Value::as_str) == Some("sha-256")
                && d.get("value")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|v| {
                        v.len() == 64
                            && v.bytes()
                                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                    })
        });
        if !ok {
            return Err(
                "config model.digest must be {\"alg\": \"sha-256\", \"value\": <64 lowercase hex>}"
                    .into(),
            );
        }
    }
    if object.get("name").is_some_and(|n| !n.is_string()) {
        return Err("config model.name must be a string".into());
    }
    let Some(endpoint) = object.get("endpoint") else {
        if object.contains_key("uid") {
            return Err("config model.uid needs model.endpoint unix:<path>".into());
        }
        return Ok(None);
    };
    let endpoint = endpoint
        .as_str()
        .ok_or("config model.endpoint must be a string")?;
    if let Some(path) = endpoint.strip_prefix("unix:") {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err("config model.endpoint unix:<path> must be an absolute path".into());
        }
        let uid = object
            .get("uid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or("config model.endpoint unix:<path> needs model.uid (the model uid)")?;
        return Ok(Some(ModelEndpoint::Unix { path, uid }));
    }
    if let Some(port) = endpoint.strip_prefix("tcp:127.0.0.1:") {
        if object.contains_key("uid") {
            return Err(
                "config model.uid applies only to unix:<path> (no peer uid over TCP)".into(),
            );
        }
        // Canonical decimal only (no sign, no leading zero, ASCII digits),
        // so one endpoint has exactly one spelling in config and audit.
        let canonical =
            !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && !port.starts_with('0');
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|p| canonical && *p != 0)
            .ok_or("config model.endpoint tcp:127.0.0.1:<port> needs a port 1-65535")?;
        return Ok(Some(ModelEndpoint::Loopback { port }));
    }
    Err(format!(
        "config model.endpoint must be unix:<absolute path> or tcp:127.0.0.1:<port>, got {endpoint:?}"
    ))
}

/// Peer uid of a connected AF_UNIX stream (SO_PEERCRED).
pub fn unix_peer_uid(stream: &UnixStream) -> Result<u32, String> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(format!(
            "model socket peer uid unavailable: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(cred.uid)
}

/// The one local model connection of a Core process.
pub struct LocalModel {
    endpoint: ModelEndpoint,
    used: AtomicBool,
}

impl LocalModel {
    pub fn endpoint(&self) -> &ModelEndpoint {
        &self.endpoint
    }

    pub fn new(endpoint: ModelEndpoint) -> Self {
        Self {
            endpoint,
            used: AtomicBool::new(false),
        }
    }

    /// POST `body` to `/v1/chat/completions` once; returns the response body.
    pub fn complete(&self, body: &str) -> Result<String, String> {
        // AF_UNIX with the peer-uid check is not egress and may be used in any mode;
        // TCP loopback has no peer check and stays local-mode only (0004 R9d).
        if matches!(self.endpoint, ModelEndpoint::Loopback { .. }) && !super::is_local() {
            return Err("the loopback model endpoint is only used in local mode (0004 R9d)".into());
        }
        if self.used.swap(true, Ordering::SeqCst) {
            return Err("a local model client makes at most one model connect (0004 R9d)".into());
        }
        let request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let timeout = Some(Duration::from_secs(120));
        let response = match &self.endpoint {
            ModelEndpoint::Unix { path, uid } => {
                let mut stream = UnixStream::connect(path)
                    .map_err(|e| format!("local model socket {}: {e}", path.display()))?;
                let peer = unix_peer_uid(&stream)?;
                if peer != *uid {
                    return Err(format!(
                        "local model socket peer uid {peer} is not the configured model uid {uid}; refused (0004 R9d)"
                    ));
                }
                stream
                    .set_read_timeout(timeout)
                    .map_err(|e| e.to_string())?;
                exchange(&mut stream, &request)?
            }
            ModelEndpoint::Loopback { port } => {
                let addr = std::net::SocketAddr::from(([127, 0, 0, 1], *port));
                let mut stream = std::net::TcpStream::connect(addr)
                    .map_err(|e| format!("local model 127.0.0.1:{port}: {e}"))?;
                stream
                    .set_read_timeout(timeout)
                    .map_err(|e| e.to_string())?;
                exchange(&mut stream, &request)?
            }
        };
        let (head, body) = response
            .split_once("\r\n\r\n")
            .ok_or("local model: malformed HTTP response")?;
        let status = head.lines().next().unwrap_or("");
        if status.split_whitespace().nth(1) != Some("200") {
            return Err(format!("local model: {status}"));
        }
        let chunked = head.lines().skip(1).any(|line| {
            line.split_once(':').is_some_and(|(k, v)| {
                k.trim().eq_ignore_ascii_case("transfer-encoding")
                    && v.to_ascii_lowercase().contains("chunked")
            })
        });
        if chunked {
            decode_chunked(body)
        } else {
            Ok(body.to_string())
        }
    }
}

fn decode_chunked(mut rest: &str) -> Result<String, String> {
    let mut out = Vec::new();
    loop {
        let (size_line, after_size) = rest
            .split_once("\r\n")
            .ok_or("local model: malformed chunked response")?;
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let size =
            usize::from_str_radix(hex_part, 16).map_err(|_| "local model: invalid chunk size")?;
        if size == 0 {
            return String::from_utf8(out).map_err(|_| "local model: response is not UTF-8".into());
        }
        let bytes = after_size.as_bytes();
        if bytes.len() < size + 2 || &bytes[size..size + 2] != b"\r\n" {
            return Err("local model: truncated chunked response".into());
        }
        out.extend_from_slice(&bytes[..size]);
        rest = std::str::from_utf8(&bytes[size + 2..])
            .map_err(|_| "local model: response is not UTF-8")?;
    }
}

fn exchange(stream: &mut (impl Read + Write), request: &str) -> Result<String, String> {
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("local model write: {e}"))?;
    let mut out = Vec::new();
    stream
        .take(16 * 1024 * 1024)
        .read_to_end(&mut out)
        .map_err(|e| format!("local model read: {e}"))?;
    String::from_utf8(out).map_err(|_| "local model: response is not UTF-8".into())
}
