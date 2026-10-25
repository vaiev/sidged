// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Model -1 on the device itself (WP 9b).
//!
//! When `<app data>/models/linguist.gguf` exists, the app starts the bundled llama-server
//! (`libllama_server.so` in the APK's native library directory) on a Unix socket in a
//! private directory of the app (`<app data>/run/`, 0700), with no TCP port. The weights
//! are identified by their SHA-256 (0011 R8): if `models/linguist.gguf.sha256` exists the
//! file must match it, and the digest is written next to the endpoint in the workspace
//! `config.json`, with `model.output` from the weights' `vaikor.linguist.output` key
//! (0017 L3b). The endpoint is set only after the server answers, so `linguist.run`
//! never points at a model that is not there. A server already answering on the socket is
//! reused only when it was started with the same weights (`run/linguist.served`). The Core checks the peer uid on every
//! connection (0004 R9d), which here is the app's own uid.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use vaikor_cli::linguist::LinguistOutput;

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
const SERVER_LIB: &str = "libllama_server.so";
const STARTUP: Duration = Duration::from_secs(60);

/// Where the bundled server, the weights and the socket live.
pub struct Layout {
    pub server: PathBuf,
    pub model: PathBuf,
    pub socket: PathBuf,
    pub workspace: PathBuf,
}

impl Layout {
    /// The layout for an app whose native libraries are in `native_dir`.
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    pub fn new(app_data: &Path, native_dir: &Path, workspace: &Path) -> Self {
        Self::with_server(app_data, &native_dir.join(SERVER_LIB), workspace)
    }

    /// The layout with an explicit server binary (the desktop node's llama-server).
    pub fn with_server(app_data: &Path, server: &Path, workspace: &Path) -> Self {
        Self {
            server: server.to_path_buf(),
            model: app_data.join("models").join("linguist.gguf"),
            socket: app_data.join("run").join("linguist.sock"),
            workspace: workspace.to_path_buf(),
        }
    }
}

#[cfg_attr(target_os = "android", allow(dead_code))]
/// The desktop node's llama-server: `VAIKOR_LLAMA_SERVER`, else the one
/// `scripts/setup-companion-toolchain.sh --with-llama` builds.
pub fn desktop_server() -> Option<PathBuf> {
    std::env::var_os("VAIKOR_LLAMA_SERVER")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| {
                PathBuf::from(home)
                    .join(".local/share/vaikor-toolchain/llama.cpp/build/bin/llama-server")
            })
        })
        .filter(|path| path.is_file())
}

/// The directory this library was loaded from (the APK's native library directory).
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn native_library_dir() -> Option<PathBuf> {
    let maps = fs::read_to_string("/proc/self/maps").ok()?;
    maps.lines()
        .filter_map(|line| line.split_whitespace().nth(5))
        .find(|path| path.ends_with("/libvaikor_companion_app_lib.so"))
        .and_then(|path| Path::new(path).parent().map(Path::to_path_buf))
}

/// SHA-256 of the weights, cached in `<model>.verified` by size and mtime so a restart
/// does not read 400 MB again.
fn model_digest(model: &Path) -> Result<String, String> {
    let meta = fs::metadata(model).map_err(|e| format!("{}: {e}", model.display()))?;
    let stamp = format!("{} {}", meta.len(), meta.mtime());
    let cache = model.with_extension("gguf.verified");
    if let Ok(text) = fs::read_to_string(&cache) {
        if let Some((cached_stamp, digest)) = text.trim().rsplit_once(' ') {
            if cached_stamp == stamp {
                return Ok(digest.to_string());
            }
        }
    }
    let mut file = fs::File::open(model).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let _ = fs::write(&cache, format!("{stamp} {digest}\n"));
    Ok(digest)
}

fn healthy(socket: &Path) -> bool {
    let Ok(mut stream) = UnixStream::connect(socket) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    if stream
        .write_all(b"GET /health HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200")
}

/// The output form the weights declare (0017 L3b).
fn model_output(layout: &Layout) -> Result<LinguistOutput, String> {
    vaikor_cli::gguf::linguist_output(&layout.model)
}

/// Merge the model endpoint into the workspace `config.json`, keeping other members. The
/// whole `model` member is replaced, so a stale `output` goes with the old weights.
fn write_endpoint(layout: &Layout, digest: &str, output: LinguistOutput) -> Result<(), String> {
    let path = layout.workspace.join("config.json");
    let mut config: Value = match fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| format!("config.json: {e}"))?,
        Err(_) => json!({}),
    };
    let object = config
        .as_object_mut()
        .ok_or("config.json must be an object")?;
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    let mut model = json!({
        "endpoint": format!("unix:{}", layout.socket.display()),
        "uid": uid,
        "digest": {"alg": "sha-256", "value": digest},
    });
    if output == LinguistOutput::Compact {
        model["output"] = json!("compact");
    }
    object.insert("model".into(), model);
    fs::write(&path, config.to_string()).map_err(|e| e.to_string())
}

/// Start the on-device model if its weights are present; returns the running server, or
/// `None` when this device has no weights (the canvas then offers intents without a model).
pub fn start(layout: &Layout) -> Result<Option<Child>, String> {
    if !layout.model.exists() {
        return Ok(None);
    }
    if !layout.workspace.join("manifest.json").exists() {
        return Ok(None);
    }
    let digest = model_digest(&layout.model)?;
    let pinned = layout.model.with_extension("gguf.sha256");
    if let Ok(expected) = fs::read_to_string(&pinned) {
        let expected = expected.split_whitespace().next().unwrap_or_default();
        if expected != digest {
            return Err(format!(
                "model digest {digest} does not match the pinned {expected}"
            ));
        }
    }
    // The form the weights were trained on; an unknown one is not started (0017 L3b).
    let output = model_output(layout)?;
    // sun_path holds 108 bytes including the terminating NUL.
    if layout.socket.as_os_str().len() > 100 {
        return Err(format!(
            "socket path too long for AF_UNIX: {}",
            layout.socket.display()
        ));
    }
    let run_dir = layout.socket.parent().ok_or("socket without directory")?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(run_dir)
        .map_err(|e| e.to_string())?;
    // The digest of the weights the server on the socket was started with, kept next to the
    // socket in the private run directory: a healthy server is reused only for the same weights.
    let served = layout.socket.with_extension("served");
    if healthy(&layout.socket) {
        let running = fs::read_to_string(&served).unwrap_or_default();
        if running.trim() != digest {
            return Err(
                "a model server for other weights is running on the socket; stop it (restart the app)"
                    .into(),
            );
        }
        write_endpoint(layout, &digest, output)?;
        return Ok(None);
    }
    let _ = fs::remove_file(&layout.socket);
    fs::write(&served, &digest).map_err(|e| format!("{}: {e}", served.display()))?;
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get().min(6));
    let child = Command::new(&layout.server)
        .arg("-m")
        .arg(&layout.model)
        .arg("--host")
        .arg(&layout.socket)
        .args(["-c", "4096", "-t", &threads.to_string(), "--no-webui"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("{}: {e}", layout.server.display()))?;
    let started = Instant::now();
    while started.elapsed() < STARTUP {
        if healthy(&layout.socket) {
            write_endpoint(layout, &digest, output)?;
            return Ok(Some(child));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err("the on-device model did not start within 60 s".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header-only GGUF v3 with `general.architecture` and, if given, the output key.
    fn gguf(output: Option<&str>) -> Vec<u8> {
        fn string(out: &mut Vec<u8>, text: &str) {
            out.extend((text.len() as u64).to_le_bytes());
            out.extend(text.as_bytes());
        }
        let mut pairs = vec![("general.architecture", "qwen3")];
        pairs.extend(output.map(|value| ("vaikor.linguist.output", value)));
        let mut out = b"GGUF".to_vec();
        out.extend(3u32.to_le_bytes());
        out.extend(0u64.to_le_bytes());
        out.extend((pairs.len() as u64).to_le_bytes());
        for (key, value) in pairs {
            string(&mut out, key);
            out.extend(8u32.to_le_bytes());
            string(&mut out, value);
        }
        out
    }

    fn config(workspace: &Path) -> Value {
        serde_json::from_str(&fs::read_to_string(workspace.join("config.json")).unwrap()).unwrap()
    }

    #[test]
    fn the_declared_output_form_goes_into_the_config() {
        let dir =
            std::env::temp_dir().join(format!("vaikor-local-model-form-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let workspace = dir.join("workspace");
        fs::create_dir_all(dir.join("models")).unwrap();
        fs::create_dir_all(&workspace).unwrap();
        let layout = Layout::new(&dir, &dir.join("lib"), &workspace);

        fs::write(&layout.model, gguf(Some("compact"))).unwrap();
        let output = model_output(&layout).unwrap();
        write_endpoint(&layout, "00", output).unwrap();
        let compact = config(&workspace);
        assert_eq!(compact["model"]["output"], "compact");
        assert_eq!(
            vaikor_cli::linguist::LinguistOutput::from_config(&compact).unwrap(),
            vaikor_cli::linguist::LinguistOutput::Compact
        );

        // Weights without the key speak the full form; the stale compact setting goes.
        fs::write(&layout.model, gguf(None)).unwrap();
        let output = model_output(&layout).unwrap();
        write_endpoint(&layout, "00", output).unwrap();
        let full = config(&workspace);
        assert!(full["model"].get("output").is_none(), "{full}");
        assert_eq!(
            vaikor_cli::linguist::LinguistOutput::from_config(&full).unwrap(),
            vaikor_cli::linguist::LinguistOutput::Full
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_running_server_is_reused_only_for_the_weights_it_was_started_with() {
        let dir =
            std::env::temp_dir().join(format!("vaikor-local-model-reuse-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let workspace = dir.join("workspace");
        fs::create_dir_all(dir.join("models")).unwrap();
        fs::create_dir_all(dir.join("run")).unwrap();
        fs::create_dir_all(&workspace).unwrap();
        fs::write(workspace.join("manifest.json"), "{}").unwrap();
        // No server may be started here: the binary would fail.
        let layout = Layout::with_server(&dir, Path::new("/bin/false"), &workspace);
        // A healthy server already listens on the socket.
        let listener = std::os::unix::net::UnixListener::bind(&layout.socket).unwrap();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut request = [0u8; 256];
                let _ = stream.read(&mut request);
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
            }
        });
        fs::write(&layout.model, gguf(Some("compact"))).unwrap();
        let digest = model_digest(&layout.model).unwrap();
        let served = layout.socket.with_extension("served");

        // Unknown or other weights behind the socket: refused, nothing written.
        for record in [None, Some("0".repeat(64))] {
            if let Some(record) = &record {
                fs::write(&served, record).unwrap();
            }
            let err = start(&layout).unwrap_err();
            assert!(err.contains("other weights"), "{err}");
            assert!(!workspace.join("config.json").exists());
        }

        // The server was started with these weights: reused, with their form.
        fs::write(&served, &digest).unwrap();
        assert!(start(&layout).unwrap().is_none());
        let reused = config(&workspace);
        assert_eq!(reused["model"]["output"], "compact");
        assert_eq!(reused["model"]["digest"]["value"], digest.as_str());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_unknown_output_form_refuses_to_start_and_sets_no_endpoint() {
        let dir =
            std::env::temp_dir().join(format!("vaikor-local-model-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let workspace = dir.join("workspace");
        fs::create_dir_all(dir.join("models")).unwrap();
        fs::create_dir_all(&workspace).unwrap();
        fs::write(workspace.join("manifest.json"), "{}").unwrap();
        // A server that would answer if it were started.
        let layout = Layout::with_server(&dir, Path::new("/bin/true"), &workspace);
        fs::write(&layout.model, gguf(Some("v0.2"))).unwrap();
        let err = start(&layout).unwrap_err();
        assert!(err.contains("vaikor.linguist.output"), "{err}");
        assert!(!workspace.join("config.json").exists());
        assert!(!layout.socket.parent().unwrap().exists());
        // Not a GGUF at all: refused as well.
        fs::write(&layout.model, b"weights").unwrap();
        assert!(start(&layout).unwrap_err().contains("GGUF"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn digest_is_cached_and_endpoint_merges_into_config() {
        let dir = std::env::temp_dir().join(format!("vaikor-local-model-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let workspace = dir.join("workspace");
        fs::create_dir_all(dir.join("models")).unwrap();
        fs::create_dir_all(&workspace).unwrap();
        let layout = Layout::new(&dir, &dir.join("lib"), &workspace);
        fs::write(&layout.model, b"weights").unwrap();
        let digest = model_digest(&layout.model).unwrap();
        assert_eq!(
            digest,
            "9a129038d9a00aed0cf6a7ea059ca50a813449061ab87848cf1a13eafdf33b2c"
        );
        assert!(
            fs::read_to_string(layout.model.with_extension("gguf.verified"))
                .unwrap()
                .contains(&digest)
        );
        fs::write(
            workspace.join("config.json"),
            r#"{"timezone":"Europe/Zurich"}"#,
        )
        .unwrap();
        write_endpoint(&layout, &digest, LinguistOutput::Full).unwrap();
        let config: Value =
            serde_json::from_str(&fs::read_to_string(workspace.join("config.json")).unwrap())
                .unwrap();
        assert_eq!(config["timezone"], "Europe/Zurich");
        assert!(config["model"]["endpoint"]
            .as_str()
            .unwrap()
            .ends_with("run/linguist.sock"));
        assert_eq!(config["model"]["digest"]["value"], digest.as_str());
        fs::remove_dir_all(dir).unwrap();
    }

    /// Real server and weights: `VAIKOR_LM_E2E=<dir with lib/libllama_server.so and
    /// models/linguist.gguf> cargo test -p vaikor-companion-app -- --ignored`.
    #[test]
    #[ignore]
    fn a_real_server_starts_and_the_core_understands_through_it() {
        let dir = PathBuf::from(std::env::var("VAIKOR_LM_E2E").unwrap());
        let workspace = dir.join("workspace");
        let _ = fs::remove_dir_all(&workspace);
        let core =
            vaikor_companion_core::commands::CompanionCore::with_workspace(workspace.clone())
                .unwrap();
        core.dispatch("node.init", &json!({"timezone": "Europe/Zurich"}))
            .unwrap();
        let layout = Layout::new(&dir, &dir.join("lib"), &workspace);
        let started = Instant::now();
        let child = start(&layout).unwrap();
        eprintln!("server ready after {:?}", started.elapsed());
        assert_eq!(
            core.dispatch("node.status", &json!({})).unwrap()["model"],
            true
        );
        for utterance in [
            "Erinner mi morn am füfi a d Stüürerklärig",
            "Steu mr e Timer uf e haubi Stund",
        ] {
            let t = Instant::now();
            let out = core
                .dispatch("linguist.run", &json!({"utterance": utterance}))
                .unwrap();
            eprintln!("{:?} {} {}", t.elapsed(), utterance, out["envelope"]);
            assert!(out["envelope"]["intent"].is_string(), "{out}");
        }
        if let Some(mut child) = child {
            child.kill().unwrap();
        }
    }

    #[test]
    fn no_weights_means_no_model_and_a_pin_mismatch_refuses() {
        let dir =
            std::env::temp_dir().join(format!("vaikor-local-model-pin-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let workspace = dir.join("workspace");
        fs::create_dir_all(dir.join("models")).unwrap();
        fs::create_dir_all(&workspace).unwrap();
        fs::write(workspace.join("manifest.json"), "{}").unwrap();
        let layout = Layout::new(&dir, &dir.join("lib"), &workspace);
        assert!(start(&layout).unwrap().is_none());
        fs::write(&layout.model, b"weights").unwrap();
        fs::write(layout.model.with_extension("gguf.sha256"), "00").unwrap();
        assert!(start(&layout).unwrap_err().contains("does not match"));
        fs::remove_dir_all(dir).unwrap();
    }
}
