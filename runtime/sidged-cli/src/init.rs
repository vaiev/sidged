//! `sidged init` wizard (turnkey WP b3).
//!
//! Writes the system config (see `system_config`) after a short dialogue on an
//! interactive terminal. Only Personal Intelligence exists in this build, only
//! ratified providers are offered (0007 R3), and no question configures a
//! network listener. A key is either a reference to an existing key file,
//! checked like `ApiKey::from_file`, or typed with echo off and written to its
//! own 0600 file under the state directory; the config itself only holds the path
//! (0007 R10a). Output names a credential as `configured`, `not configured` or
//! `invalid`, never with key bytes or a prefix. Approver uids follow 0004 R9,
//! R9c. A non-TTY is refused.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::system_config::{
    self, check_approval, ApprovalUids, Interface, ProviderId, ProviderRef, SystemConfig,
};

pub trait Terminal {
    /// Show `prompt`, read one echoed line (without the newline).
    fn ask(&mut self, prompt: &str) -> Result<String, String>;
    /// Show `prompt` with terminal echo off, read one line into `Zeroizing`.
    fn ask_secret(&mut self, prompt: &str) -> Result<Zeroizing<String>, String>;
    fn say(&mut self, text: &str);
}

pub struct InitOptions<'a> {
    pub state_dir: &'a Path,
    pub config_path: &'a Path,
    /// The uid the Core runs as (the uid running `sidged init`).
    pub core_uid: u32,
}

const HEADER: &str = "sidged init: Personal Intelligence (the only mode in this build).\n\
This writes local settings only and configures no network listener.";
const TRIES: usize = 3;

pub fn run_init(term: &mut dyn Terminal, opts: &InitOptions) -> Result<SystemConfig, String> {
    if !opts.state_dir.is_absolute() {
        return Err("state directory must be absolute".into());
    }
    term.say(HEADER);
    let path = opts.config_path;
    let mut config = match std::fs::symlink_metadata(path) {
        Ok(_) => system_config::load(path, opts.core_uid).map_err(|e| {
            format!(
                "existing config {}: {e}; fix or remove it first",
                path.display()
            )
        })?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => SystemConfig::default(),
        Err(err) => {
            return Err(format!(
                "existing config {}: {}",
                path.display(),
                err.kind()
            ))
        }
    };

    config.local = ask_local(term, config.local)?;
    let mut pending_key: Option<Zeroizing<String>> = None;
    if config.local {
        if config.approval.take().is_some() {
            term.say("approval removed: local mode has no approval channel (0004 R9)");
        }
        config.model = ask_model(term, config.model.take())?;
        if config.provider.is_some() {
            term.say("provider kept; local mode refuses all egress (0007 R2)");
        }
    } else {
        config.model = None;
        config.provider = ask_provider(term, config.provider.take())?;
        if let Some(provider) = config.provider.as_mut() {
            if provider.id == ProviderId::Gemini {
                provider.project = Some(ask_project(term, provider.project.take())?);
            }
            pending_key = ask_credential(term, provider, opts.state_dir)?;
        }
        config.approval = ask_approval(term, config.approval.take(), opts.core_uid)?;
    }
    config.interface = ask_interface(term, config.interface)?;

    // Validate the whole document before anything is written.
    let config = system_config::parse(&system_config::to_value(&config), opts.core_uid)?;
    let dir = parent(path);
    ensure_private_dir(dir)?;
    let mut new_key = None;
    if let (Some(key), Some(provider)) = (&pending_key, &config.provider) {
        let file = provider
            .credential
            .as_deref()
            .ok_or("internal: entered key without a key file path")?;
        ensure_private_dir(parent(file))?;
        use std::os::unix::fs::PermissionsExt;
        if std::fs::symlink_metadata(parent(file))
            .map_err(|e| e.to_string())?
            .permissions()
            .mode()
            & 0o7777
            != 0o700
        {
            return Err("credentials directory must have mode 0700".into());
        }
        let mut bytes = Zeroizing::new(key.as_bytes().to_vec());
        bytes.push(b'\n');
        let is_new = match std::fs::symlink_metadata(file) {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => return Err(format!("key metadata: {}", error.kind())),
        };
        system_config::write_private(file, &bytes)?;
        if is_new {
            new_key = Some(file);
        }
    }
    drop(pending_key);
    if let Err(error) = system_config::save(path, &config) {
        if let Some(file) = new_key {
            std::fs::remove_file(file)
                .map_err(|cleanup| format!("{error}; key cleanup failed: {}", cleanup.kind()))?;
        }
        return Err(error);
    }
    if let Some(provider) = &config.provider {
        term.say(&format!(
            "credential for {}: {}",
            provider.id.as_str(),
            credential_status(provider.credential.as_deref())
        ));
    }
    let shown = serde_json::to_string_pretty(&system_config::to_value(&config))
        .map_err(|e| e.to_string())?;
    term.say(&format!("wrote {} (0600):\n{shown}", path.display()));
    Ok(config)
}

fn parent(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// Create a missing directory as 0700; an existing one is checked by
/// `write_private` (owned by this uid, not group/other writable).
fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::symlink_metadata(dir) {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("directory {}: {}", dir.display(), e.kind())),
        Err(err) => Err(format!("directory {}: {}", dir.display(), err.kind())),
    }
}

/// `configured` / `not configured` / `invalid (...)`. Never key bytes: the
/// reason comes from `ApiKey::from_file`, which names only the path.
fn credential_status(file: Option<&Path>) -> String {
    match file {
        None => "not configured".into(),
        Some(file) => match sidged_gateway::ApiKey::from_file(file) {
            Ok(_) => "configured".into(),
            Err(why) => format!("invalid ({why})"),
        },
    }
}

fn ask_local(term: &mut dyn Terminal, current: bool) -> Result<bool, String> {
    let prompt = format!(
        "Local mode: no egress and no approval channel (0007 R2) [y/n] (empty keeps {}): ",
        if current { "y" } else { "n" }
    );
    for _ in 0..TRIES {
        match term.ask(&prompt)?.trim() {
            "" => return Ok(current),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => term.say("answer y or n"),
        }
    }
    Err("local mode: no valid answer".into())
}

fn ask_provider(
    term: &mut dyn Terminal,
    current: Option<ProviderRef>,
) -> Result<Option<ProviderRef>, String> {
    let shown = current.as_ref().map_or("none", |p| p.id.as_str());
    let prompt = format!(
        "Provider: infomaniak (CH), gemini (GLOBAL, unrestricted data only), xai (GLOBAL, unrestricted data only) or none (empty keeps {shown}, - removes): "
    );
    for _ in 0..TRIES {
        let answer = term.ask(&prompt)?;
        match answer.trim() {
            "" => return Ok(current),
            "-" | "none" => return Ok(None),
            text => match ProviderId::parse(text) {
                Ok(id) if current.as_ref().is_some_and(|p| p.id == id) => return Ok(current),
                Ok(id) => {
                    return Ok(Some(ProviderRef {
                        id,
                        project: None,
                        credential: None,
                    }))
                }
                // Never echo the input: it is not a ratified provider.
                Err(_) => {
                    term.say("not a ratified provider; choose infomaniak, gemini, xai or none")
                }
            },
        }
    }
    Err("no ratified provider chosen; ratified: infomaniak, gemini, xai".into())
}

fn ask_project(term: &mut dyn Terminal, current: Option<String>) -> Result<String, String> {
    let prompt = format!(
        "Gemini billing project id (required; empty keeps {}): ",
        current.as_deref().unwrap_or("none")
    );
    for _ in 0..TRIES {
        let answer = term.ask(&prompt)?;
        match (answer.trim(), &current) {
            ("", Some(project)) => return Ok(project.clone()),
            ("", None) => term.say("a billing project is required for gemini"),
            (text, _) => return Ok(text.to_string()),
        }
    }
    Err("gemini needs a billing project".into())
}

/// Updates `provider.credential`; returns a typed key that still has to be
/// written to its file once the whole config is valid.
fn ask_credential(
    term: &mut dyn Terminal,
    provider: &mut ProviderRef,
    state_dir: &Path,
) -> Result<Option<Zeroizing<String>>, String> {
    let prompt = format!(
        "API key source: f = path to an existing key file, e = enter the key now (input hidden), empty keeps {}, - removes: ",
        credential_status(provider.credential.as_deref())
    );
    for _ in 0..TRIES {
        match term.ask(&prompt)?.trim() {
            "" => return Ok(None),
            "-" => {
                provider.credential = None;
                return Ok(None);
            }
            "f" => {
                let answer = term.ask("Key file path (absolute): ")?;
                let file = PathBuf::from(answer.trim());
                if !file.is_absolute() {
                    return Err("credential: invalid (the key file path must be absolute)".into());
                }
                sidged_gateway::ApiKey::from_file(&file)
                    .map_err(|why| format!("credential: invalid ({why})"))?;
                term.say("credential: configured (key file check passed)");
                provider.credential = Some(file);
                return Ok(None);
            }
            "e" => {
                let key = term.ask_secret("API key (input hidden): ")?;
                let trimmed = Zeroizing::new(key.trim().to_string());
                drop(key);
                if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err(
                        "credential: invalid (one key of printable ASCII on one line)".into(),
                    );
                }
                provider.credential = Some(
                    state_dir
                        .join("credentials")
                        .join(format!("{}.key", provider.id.as_str())),
                );
                return Ok(Some(trimmed));
            }
            _ => term.say("answer f, e, - or press enter"),
        }
    }
    Err("credential: no valid answer".into())
}

fn ask_approval(
    term: &mut dyn Terminal,
    current: Option<ApprovalUids>,
    core_uid: u32,
) -> Result<Option<ApprovalUids>, String> {
    let shown = current
        .as_ref()
        .map_or("none".to_string(), |a| a.approver.to_string());
    let answer = term.ask(&format!(
        "Approver uid: a separate user who answers approvals, never root or the Core uid (empty keeps {shown}, - removes): "
    ))?;
    let approver = match answer.trim() {
        "" => return Ok(current),
        "-" => return Ok(None),
        text => text
            .parse::<u32>()
            .map_err(|_| "approver uid must be a number".to_string())?,
    };
    let list = term
        .ask("Non-approver uids: every agent, launcher, worker and model uid, comma-separated: ")?;
    let non_approvers = crate::parse_uid_list(list.trim())?;
    let approval = ApprovalUids {
        approver,
        non_approvers,
    };
    check_approval(&approval, core_uid)?;
    Ok(Some(approval))
}

fn ask_model(
    term: &mut dyn Terminal,
    current: Option<sidged_gateway::local_model::ModelEndpoint>,
) -> Result<Option<sidged_gateway::local_model::ModelEndpoint>, String> {
    let shown = match &current {
        Some(sidged_gateway::local_model::ModelEndpoint::Unix { path, .. }) => {
            format!("unix:{}", path.display())
        }
        Some(sidged_gateway::local_model::ModelEndpoint::Loopback { port }) => {
            format!("tcp:127.0.0.1:{port}")
        }
        None => "none".into(),
    };
    let answer = term.ask(&format!(
        "Local model endpoint: unix:<absolute path> or tcp:127.0.0.1:<port> (empty keeps {shown}, - removes): "
    ))?;
    let endpoint = match answer.trim() {
        "" => return Ok(current),
        "-" => return Ok(None),
        text => text.to_string(),
    };
    let mut model = serde_json::json!({ "endpoint": endpoint });
    if endpoint.starts_with("unix:") {
        let uid = term.ask("Model uid: ")?;
        let uid: u32 = uid
            .trim()
            .parse()
            .map_err(|_| "model uid must be a number".to_string())?;
        model["uid"] = uid.into();
    }
    sidged_gateway::local_model::model_endpoint(&serde_json::json!({ "model": model }))
}

fn ask_interface(term: &mut dyn Terminal, current: Interface) -> Result<Interface, String> {
    let prompt = format!(
        "Interface: tui, or static-shell (the offline file viewer; approvals stay on the approval socket) (empty keeps {}): ",
        current.as_str()
    );
    for _ in 0..TRIES {
        match term.ask(&prompt)?.trim() {
            "" => return Ok(current),
            text => match Interface::parse(text) {
                Ok(interface) => return Ok(interface),
                Err(_) => term.say("answer tui or static-shell"),
            },
        }
    }
    Err("interface: no valid answer".into())
}

/// Refuse unless stdin and stdout are terminals (fail closed: a script or a
/// pipe cannot run the wizard, so a key is never read from a pipe).
pub fn require_tty() -> Result<(), String> {
    // SAFETY: isatty has no preconditions.
    let tty = unsafe { libc::isatty(0) == 1 && libc::isatty(1) == 1 };
    if tty {
        Ok(())
    } else {
        Err(
            "sidged init needs an interactive terminal (stdin and stdout must be a TTY); refused"
                .into(),
        )
    }
}

/// The real terminal: unbuffered reads from fd 0 (no stray copy of a key in a
/// read buffer), prompts on stdout, echo off via termios for `ask_secret`.
pub struct TtyTerminal;

const MAX_LINE: usize = 4096;

fn read_line_fd0(buf: &mut Vec<u8>) -> Result<(), String> {
    loop {
        let mut byte = 0u8;
        // SAFETY: reads at most one byte into a valid local.
        let n = unsafe { libc::read(0, (&mut byte as *mut u8).cast(), 1) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("terminal read: {}", err.kind()));
        }
        if n == 0 {
            return Err("end of input".into());
        }
        if byte == b'\n' {
            return Ok(());
        }
        if buf.len() >= MAX_LINE {
            return Err("terminal line too long".into());
        }
        buf.push(byte);
    }
}

fn show(prompt: &str) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(prompt.as_bytes());
    let _ = out.flush();
}

/// Restores the saved termios on drop (also on an early return).
struct EchoOff(libc::termios);

impl EchoOff {
    fn new() -> Result<Self, String> {
        // SAFETY: termios is plain data; tcgetattr fills it.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: fd 0 is checked to be a TTY by require_tty; pointer is valid.
        if unsafe { libc::tcgetattr(0, &mut saved) } != 0 {
            return Err("cannot read terminal settings".into());
        }
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        quiet.c_lflag |= libc::ECHONL;
        // SAFETY: valid termios pointer.
        if unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &quiet) } != 0 {
            return Err("cannot turn terminal echo off".into());
        }
        Ok(Self(saved))
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: restores the settings read in `new`.
        unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &self.0) };
    }
}

impl Terminal for TtyTerminal {
    fn ask(&mut self, prompt: &str) -> Result<String, String> {
        show(prompt);
        let mut buf = Vec::new();
        read_line_fd0(&mut buf)?;
        let text = String::from_utf8(buf).map_err(|_| "answer is not UTF-8".to_string())?;
        Ok(text.trim_end_matches('\r').to_string())
    }

    fn ask_secret(&mut self, prompt: &str) -> Result<Zeroizing<String>, String> {
        // Echo goes off before the prompt is shown.
        let _echo = EchoOff::new()?;
        show(prompt);
        let mut buf = Zeroizing::new(Vec::with_capacity(MAX_LINE));
        read_line_fd0(&mut buf)?;
        match String::from_utf8(std::mem::take(&mut *buf)) {
            Ok(text) => Ok(Zeroizing::new(text)),
            Err(err) => {
                let mut bytes = err.into_bytes();
                zeroize::Zeroize::zeroize(&mut bytes);
                Err("the key is not UTF-8".into())
            }
        }
    }

    fn say(&mut self, text: &str) {
        println!("{text}");
    }
}
