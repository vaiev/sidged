//! System config store (turnkey WP b1).
//!
//! Non-secret settings only: the local-mode latch input (0007 R2), the
//! approval uids (0004 R9, R9c), a ratified provider id with an optional
//! billing project and a credential **reference** (0007 R3, R10, R10a), the
//! local model endpoint (0004 R9d) and the interface preference. Key bytes are
//! never stored here: a credential is the absolute path of a key file that the
//! gateway checks and reads at send time. Any string that matches the
//! vkr.pii/1 `secret` detector (0007 R12) is refused.
//!
//! The file is written atomically (`O_EXCL|O_NOFOLLOW` temp file, 0600, fsync,
//! rename, fsync of the directory) into a directory owned by the writer and not
//! group/other writable, and loaded only from a regular file owned by the Core
//! uid with no group/other bits.

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use vaikor_gateway::local_model::{model_endpoint, ModelEndpoint};

/// Format version of the stored document.
pub const VERSION: &str = "0.1";
/// Larger files are refused before parsing.
const MAX_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderId {
    Infomaniak,
    Gemini,
    Xai,
}

impl ProviderId {
    /// Ratified registry entries only (0007 R3, :18-22). Nothing else parses.
    pub fn parse(id: &str) -> Result<Self, String> {
        match id {
            "infomaniak" => Ok(Self::Infomaniak),
            "gemini" => Ok(Self::Gemini),
            "xai" => Ok(Self::Xai),
            other => Err(format!(
                "provider {other:?} is not in the 0007 gateway registry; ratified: infomaniak, gemini, xai"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Infomaniak => "infomaniak",
            Self::Gemini => "gemini",
            Self::Xai => "xai",
        }
    }

    /// The registry origin the gateway binds residency to (0007 R3).
    pub fn origin(self) -> &'static str {
        match self {
            Self::Infomaniak => "https://api.infomaniak.com",
            Self::Gemini => "https://generativelanguage.googleapis.com",
            Self::Xai => "https://api.x.ai",
        }
    }

    /// The reviewed OpenAI-compatible base URL, where the registry fixes one
    /// (0007 :20 Gemini `/v1beta/openai`, :22 xAI `/v1`). Infomaniak's path is
    /// product-specific, so it has none.
    pub fn base_url(self) -> Option<&'static str> {
        match self {
            Self::Infomaniak => None,
            Self::Gemini => Some("https://generativelanguage.googleapis.com/v1beta/openai"),
            Self::Xai => Some("https://api.x.ai/v1"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRef {
    pub id: ProviderId,
    /// Gemini billing project (0007 :129); required for Gemini, refused otherwise.
    pub project: Option<String>,
    /// Absolute path of a key file (0007 R10a reference). Never key bytes.
    pub credential: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalUids {
    pub approver: u32,
    pub non_approvers: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interface {
    /// `vaikor-tui` in a terminal.
    Tui,
    /// The offline static shell file, a viewer only (no listener; approvals
    /// stay on the approval socket, 0004 R9).
    StaticShell,
}

impl Interface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tui => "tui",
            Self::StaticShell => "static-shell",
        }
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "tui" => Ok(Self::Tui),
            "static-shell" => Ok(Self::StaticShell),
            other => Err(format!(
                "interface {other:?} is not available; use tui or static-shell (no listener exists)"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemConfig {
    pub local: bool,
    pub interface: Interface,
    pub provider: Option<ProviderRef>,
    pub approval: Option<ApprovalUids>,
    pub model: Option<ModelEndpoint>,
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            local: false,
            interface: Interface::Tui,
            provider: None,
            approval: None,
            model: None,
        }
    }
}

/// Validate a stored document. `core_uid` is the uid the Core runs as.
pub fn parse(value: &serde_json::Value, core_uid: u32) -> Result<SystemConfig, String> {
    refuse_key_material(value)?;
    let object = value
        .as_object()
        .ok_or("system config must be a JSON object")?;
    only_keys(
        object,
        "",
        &[
            "v",
            "mode",
            "local",
            "interface",
            "provider",
            "approval",
            "model",
        ],
    )?;
    if object.get("v").and_then(|v| v.as_str()) != Some(VERSION) {
        return Err(format!("system config version must be {VERSION:?}"));
    }
    match object.get("mode").and_then(|v| v.as_str()) {
        Some("personal") => {}
        Some("swarm") => return Err(
            "mode swarm is not available: no mesh exists in this build (0006 R4 not implemented)"
                .into(),
        ),
        _ => return Err("system config mode must be \"personal\"".into()),
    }
    // 0007 R2: a present non-boolean local is refused.
    let local = match object.get("local") {
        None => false,
        Some(serde_json::Value::Bool(local)) => *local,
        Some(_) => return Err("system config local must be a boolean (0007 R2)".into()),
    };
    let interface = Interface::parse(
        object
            .get("interface")
            .and_then(|v| v.as_str())
            .ok_or("system config interface must be a string")?,
    )?;
    let provider = object.get("provider").map(parse_provider).transpose()?;
    let approval = object
        .get("approval")
        .map(|a| parse_approval(a, core_uid))
        .transpose()?;
    if local && approval.is_some() {
        return Err("local mode has no approval channel; remove approval (0004 R9)".into());
    }
    let model = match object.get("model") {
        None => None,
        Some(model) => {
            if !local {
                return Err(
                    "model.endpoint is the local mode model; set local true (0004 R9d)".into(),
                );
            }
            Some(
                model_endpoint(&serde_json::json!({ "model": model }))?
                    .ok_or("config model.endpoint is required in model")?,
            )
        }
    };
    Ok(SystemConfig {
        local,
        interface,
        provider,
        approval,
        model,
    })
}

fn parse_provider(value: &serde_json::Value) -> Result<ProviderRef, String> {
    let object = value.as_object().ok_or("provider must be an object")?;
    only_keys(object, "provider.", &["id", "project", "credential"])?;
    let id = ProviderId::parse(
        object
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("provider.id must be a string")?,
    )?;
    let project = match object.get("project") {
        None => None,
        Some(project) => Some(
            project
                .as_str()
                .ok_or("provider.project must be a string")?
                .to_string(),
        ),
    };
    match (id, &project) {
        (ProviderId::Gemini, Some(p)) if !p.trim().is_empty() => {}
        (ProviderId::Gemini, _) => {
            return Err("gemini needs provider.project (billing project, 0007)".into())
        }
        (_, Some(_)) => return Err("provider.project applies only to gemini".into()),
        (_, None) => {}
    }
    let credential = match object.get("credential") {
        None => None,
        Some(credential) => {
            let object = credential
                .as_object()
                .ok_or("provider.credential must be an object")?;
            if object.len() != 1 || !object.contains_key("file") {
                return Err(
                    "provider.credential must be {\"file\": <absolute path>}; keychain references are not implemented"
                        .into(),
                );
            }
            let path = object["file"]
                .as_str()
                .ok_or("provider.credential.file must be a string")?;
            let path = PathBuf::from(path);
            if !path.is_absolute() || path.as_os_str().as_encoded_bytes().contains(&0) {
                return Err("provider.credential.file must be an absolute path".into());
            }
            Some(path)
        }
    };
    Ok(ProviderRef {
        id,
        project,
        credential,
    })
}

/// The identity part of the R9c rules that a config can be checked for
/// (0004 R9, R9c). `vaikor guard` still runs every R9c start check.
pub fn check_approval(approval: &ApprovalUids, core_uid: u32) -> Result<(), String> {
    if approval.approver == 0 {
        return Err("approve_uid 0 (root) is refused (0004 R9c)".into());
    }
    if approval.approver == core_uid {
        return Err(format!(
            "approve_uid {} is the Core uid (0004 R9)",
            approval.approver
        ));
    }
    if approval.non_approvers.is_empty() {
        return Err(
            "approval.non_approver_uids must list every agent, launcher, worker and model uid (0004 R9c)"
                .into(),
        );
    }
    if approval.non_approvers.contains(&0) {
        return Err("a non-approver uid is root (0004 R9c)".into());
    }
    if approval.non_approvers.contains(&approval.approver) {
        return Err(format!(
            "approve_uid {} is also a non-approver uid (0004 R9)",
            approval.approver
        ));
    }
    if approval.non_approvers.contains(&core_uid) {
        return Err(
            "a non-approver uid equals the Core uid; run the Core under its own uid (0004 R9c)"
                .into(),
        );
    }
    Ok(())
}

fn parse_approval(value: &serde_json::Value, core_uid: u32) -> Result<ApprovalUids, String> {
    let object = value.as_object().ok_or("approval must be an object")?;
    only_keys(object, "approval.", &["approve_uid", "non_approver_uids"])?;
    let uid = |v: &serde_json::Value| v.as_u64().and_then(|n| u32::try_from(n).ok());
    let approver = object
        .get("approve_uid")
        .and_then(uid)
        .ok_or("approval.approve_uid must be a uid")?;
    let non_approvers = object
        .get("non_approver_uids")
        .and_then(|v| v.as_array())
        .ok_or("approval.non_approver_uids must be a list of uids")?
        .iter()
        .map(|v| uid(v).ok_or_else(|| format!("approval.non_approver_uids: invalid uid {v}")))
        .collect::<Result<Vec<_>, _>>()?;
    let approval = ApprovalUids {
        approver,
        non_approvers,
    };
    check_approval(&approval, core_uid)?;
    Ok(approval)
}

fn only_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    prefix: &str,
    allowed: &[&str],
) -> Result<(), String> {
    match object.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(key) => Err(format!(
            "system config: unknown key {prefix}{key} (only references and non-secret settings are stored)"
        )),
        None => Ok(()),
    }
}

/// 0007 R12 `secret` detector over every key and string value. The matched
/// text is never echoed.
fn refuse_key_material(value: &serde_json::Value) -> Result<(), String> {
    let hit = |text: &str| vaikor_gateway::egress_check::detect(text).contains(&"secret");
    match value {
        serde_json::Value::String(text) if hit(text) => Err(
            "system config holds something that looks like key material (vkr.pii/1 secret); store a key file reference instead"
                .into(),
        ),
        serde_json::Value::Array(items) => items.iter().try_for_each(refuse_key_material),
        serde_json::Value::Object(map) => map.iter().try_for_each(|(key, value)| {
            refuse_key_material(&serde_json::Value::String(key.clone()))?;
            refuse_key_material(value)
        }),
        _ => Ok(()),
    }
}

/// The stored form; `parse(to_value(c)) == c`.
pub fn to_value(config: &SystemConfig) -> serde_json::Value {
    let mut out = serde_json::json!({
        "v": VERSION,
        "mode": "personal",
        "local": config.local,
        "interface": config.interface.as_str(),
    });
    if let Some(provider) = &config.provider {
        let mut p = serde_json::json!({ "id": provider.id.as_str() });
        if let Some(project) = &provider.project {
            p["project"] = project.clone().into();
        }
        if let Some(path) = &provider.credential {
            p["credential"] = serde_json::json!({ "file": path.to_string_lossy() });
        }
        out["provider"] = p;
    }
    if let Some(approval) = &config.approval {
        out["approval"] = serde_json::json!({
            "approve_uid": approval.approver,
            "non_approver_uids": approval.non_approvers,
        });
    }
    match &config.model {
        Some(ModelEndpoint::Unix { path, uid }) => {
            out["model"] = serde_json::json!({
                "endpoint": format!("unix:{}", path.to_string_lossy()),
                "uid": uid,
            });
        }
        Some(ModelEndpoint::Loopback { port }) => {
            out["model"] = serde_json::json!({ "endpoint": format!("tcp:127.0.0.1:{port}") });
        }
        None => {}
    }
    out
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

/// Load from a private regular file owned by `core_uid`, then validate.
pub fn load(path: &Path, core_uid: u32) -> Result<SystemConfig, String> {
    let shown = path.display();
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|err| {
            if err.raw_os_error() == Some(libc::ELOOP) {
                format!("system config {shown}: symlink refused")
            } else {
                format!("system config {shown}: {}", err.kind())
            }
        })?;
    let meta = file
        .metadata()
        .map_err(|err| format!("system config {shown}: {}", err.kind()))?;
    if !meta.is_file() {
        return Err(format!("system config {shown} is not a regular file"));
    }
    if meta.uid() != core_uid {
        return Err(format!(
            "system config {shown}: owner uid {} is not the Core uid {core_uid}",
            meta.uid()
        ));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(format!(
            "system config {shown}: mode {:04o} has group/other bits, must be 0600",
            meta.mode() & 0o7777
        ));
    }
    if meta.len() > MAX_BYTES {
        return Err(format!("system config {shown} is too large"));
    }
    let mut text = String::new();
    Read::by_ref(&mut file)
        .take(MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|err| format!("system config {shown}: {}", err.kind()))?;
    if text.len() as u64 > MAX_BYTES {
        return Err(format!("system config {shown} is too large"));
    }
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|_| format!("system config {shown} is not valid JSON"))?;
    parse(&value, core_uid)
}

/// Write `config` to `path` atomically as a 0600 file owned by this process.
pub fn save(path: &Path, config: &SystemConfig) -> Result<(), String> {
    let mut text = serde_json::to_string_pretty(&to_value(config)).map_err(|e| e.to_string())?;
    text.push('\n');
    write_private(path, text.as_bytes())
}

/// Atomic private write: refuses a symlink or foreign target and a directory
/// that is not owned by this uid or is group/other writable. Used for the
/// config and for a key file written by `vaikor init`.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let shown = path.display();
    let name = path
        .file_name()
        .ok_or_else(|| format!("{shown}: no file name"))?;
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let dir_meta = std::fs::symlink_metadata(dir)
        .map_err(|err| format!("directory {}: {}", dir.display(), err.kind()))?;
    let uid = euid();
    if !dir_meta.is_dir() || dir_meta.uid() != uid || dir_meta.mode() & 0o022 != 0 {
        return Err(format!(
            "directory {} must be a real directory owned by uid {uid} and not group/other writable",
            dir.display()
        ));
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(format!("{shown} is a symlink; refused"))
        }
        Ok(meta) if !meta.is_file() || meta.uid() != uid => {
            return Err(format!(
                "{shown} exists and is not a regular file owned by uid {uid}"
            ))
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(format!("{shown}: {}", err.kind())),
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(
        ".{}.tmp-{}-{nonce}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)
            .map_err(|err| format!("{}: {}", tmp.display(), err.kind()))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|err| format!("{}: {}", tmp.display(), err.kind()))?;
        std::fs::rename(&tmp, path).map_err(|err| format!("{shown}: {}", err.kind()))?;
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|err| format!("directory {}: {}", dir.display(), err.kind()))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Where `vaikor init` and `vaikor guard --system-config` look by default:
/// `$STATE_DIRECTORY` (systemd `StateDirectory=`), else
/// `$XDG_CONFIG_HOME/vaikor`, else `$HOME/.config/vaikor`.
pub fn default_path() -> Result<PathBuf, String> {
    let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty());
    if let Some(state) = var("STATE_DIRECTORY") {
        // systemd may list several directories separated by ':'.
        let first = state
            .to_string_lossy()
            .split(':')
            .next()
            .unwrap_or_default()
            .to_string();
        return Ok(PathBuf::from(first).join("config.json"));
    }
    if let Some(xdg) = var("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg).join("vaikor").join("config.json"));
    }
    if let Some(home) = var("HOME") {
        return Ok(PathBuf::from(home)
            .join(".config")
            .join("vaikor")
            .join("config.json"));
    }
    Err("no config path: pass --config <file> (STATE_DIRECTORY, XDG_CONFIG_HOME and HOME are unset)".into())
}
