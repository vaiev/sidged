//! Trusted UI approval channel for consequential steps (0004 R9, R9c).
//!
//! The Core owns this channel. A generated view cannot approve. Non-interactive
//! runs deny. The only channel is a Unix socket in an operator-provisioned
//! directory; every connection is authenticated with SO_PEERCRED against the
//! configured approver uid. There is no TTY and no HTTP approval path. Timeout
//! and the kill switch are denials.

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ffi::CString;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Audit binding recorded on every approval when a host check could not be
/// fully evaluated (0004 R9c): the operator attests what the Core could not.
pub const OPERATOR_ATTESTED: &str = "operator-attested";

/// What R9c start checks do not detect (0004 R9c operator attestation).
pub const R9C_UNDETECTED: [&str; 6] = [
    "su-password",
    "stored-credentials",
    "keys",
    "setuid-helpers",
    "sudo-doas-other-paths",
    "container-runtimes",
];

/// The audit field on the channel start and on every approval.
/// Structured form of an `attestation=R9c undetected=a,b` text.
pub fn r9c_fields(text: &str) -> (Option<String>, Vec<String>) {
    let mut attestation = None;
    let mut undetected = Vec::new();
    for word in text.split_whitespace() {
        if let Some(value) = word.strip_prefix("attestation=") {
            attestation = Some(value.to_string());
        } else if let Some(value) = word.strip_prefix("undetected=") {
            undetected = value
                .split(',')
                .filter(|v| !v.is_empty())
                .map(str::to_string)
                .collect();
        }
    }
    (attestation, undetected)
}

pub fn r9c_attestation_text() -> String {
    format!("attestation=R9c undetected={}", R9C_UNDETECTED.join(","))
}

/// Unclear sudo/doas rules refuse unless the operator attests; with
/// `--operator-attest` every approval is labelled operator-attested.
pub fn attestation_verdict(
    unclear: &[String],
    operator_attest: bool,
) -> Result<Option<&'static str>, String> {
    if operator_attest {
        return Ok(Some(OPERATOR_ATTESTED));
    }
    if unclear.is_empty() {
        return Ok(None);
    }
    Err(format!(
        "sudo/doas rules could not be evaluated clearly ({}); refusing the approval channel unless --operator-attest is given (0004 R9c)",
        unclear.join("; ")
    ))
}

/// Core-created binding. Nonces are random, and consumed even on denial.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub plan_digest: String,
    pub step: String,
    pub capability: String,
    pub args_digest: String,
    pub sent_url_sha256: Option<String>,
    pub scope: Option<serde_json::Value>,
    pub scope_digest: Option<String>,
    pub nonce: String,
}
impl std::fmt::Debug for ApprovalRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalRequest")
            .field("step", &self.step)
            .finish_non_exhaustive()
    }
}
impl ApprovalRequest {
    pub fn new(
        plan_digest: &str,
        step: &str,
        capability: &str,
        args: &serde_json::Value,
    ) -> Result<Self, String> {
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;
        Ok(Self {
            plan_digest: plan_digest.into(),
            step: step.into(),
            capability: capability.into(),
            args_digest: format!(
                "{:x}",
                Sha256::digest(sidged_grant::canonicalize(args).as_bytes())
            ),
            sent_url_sha256: None,
            scope: None,
            scope_digest: None,
            nonce: nonce.iter().map(|b| format!("{b:02x}")).collect(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDecision {
    pub granted: bool,
    pub actor: String,
    pub at: String,
}

pub trait ApprovalChannel {
    fn decide(&self, request: &ApprovalRequest, now: &str) -> ApprovalDecision;
    /// True only when the authenticated answer echoed this scope digest.
    fn standing_scope_approved(&self, _request: &ApprovalRequest) -> bool {
        false
    }
    /// Authenticated owner revocations; `*` revokes all stored scopes.
    fn take_revocations(&self) -> Vec<String> {
        Vec::new()
    }
    fn killed(&self) -> bool {
        false
    }
    /// Drain refusals encountered while waiting; the executor persists them.
    fn take_stale_responses(&self) -> usize {
        0
    }
    /// Drain socket peers rejected by SO_PEERCRED as observed uids; every exit
    /// path audits them (0004 R9).
    fn take_rejected_peers(&self) -> Vec<u32> {
        Vec::new()
    }
    /// Why the channel refused to start; every request is then denied.
    fn refusal(&self) -> Option<&str> {
        None
    }
    /// `Some(OPERATOR_ATTESTED)` when R9c host checks were unclear.
    fn attestation(&self) -> Option<&str> {
        None
    }
    /// The configured approver uid, recorded on approvals.
    fn approver_uid(&self) -> Option<u32> {
        None
    }
    /// Stop accepting connections (before the final drain).
    fn shutdown(&self) {}
    /// `attestation=R9c undetected=...` for every approval.
    fn r9c_attestation(&self) -> Option<String> {
        None
    }
    /// The same text, once, for the channel-start audit event.
    fn take_channel_start(&self) -> Option<String> {
        None
    }
}

/// A channel the Core refused to start (0004 R9): denies everything, with the reason.
#[derive(Debug, Clone)]
pub struct Refused {
    reason: String,
}

impl ApprovalChannel for Refused {
    fn decide(&self, _request: &ApprovalRequest, now: &str) -> ApprovalDecision {
        denial(&self.reason, now)
    }
    fn refusal(&self) -> Option<&str> {
        Some(&self.reason)
    }
}

/// Approval configuration. Agent/launcher uids are configured explicitly
/// (`--agent-uid`); the process parent is only an extra, advisory check.
pub struct ChannelConfig<'a> {
    pub mode: Option<&'a str>,
    pub timeout: Duration,
    pub approver: Option<u32>,
    pub agents: &'a [u32],
    pub local: bool,
    /// `--operator-attest`: the operator attests R9c where sudo/doas rules
    /// are unclear; every approval is then audited as operator-attested.
    pub operator_attest: bool,
}

/// Open the approval channel. Never fails open: anything it forbids yields a
/// `Refused` channel. Local mode has no channel at all.
pub fn open_channel(config: &ChannelConfig) -> Box<dyn ApprovalChannel> {
    let refuse = |why: String| -> Box<dyn ApprovalChannel> {
        Box::new(Refused {
            reason: format!("approval channel refused: {why}"),
        })
    };
    match config.mode {
        None => Box::new(NonInteractive),
        Some(_) if config.local => refuse("local mode has no approval channel".into()),
        Some(mode) => match mode.strip_prefix("unix:") {
            Some(path) => match SocketApproval::bind(Path::new(path), config) {
                Ok(channel) => Box::new(channel),
                Err(err) => refuse(err),
            },
            None => refuse(
                "only --approve unix:<path> with --approve-uid and --agent-uid is supported (0004 R9)".into(),
            ),
        },
    }
}

/// Disable core dumps and same-uid ptrace attach of the Core (0004 R9c).
pub fn harden_process() -> Result<(), String> {
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NonInteractive;

impl ApprovalChannel for NonInteractive {
    fn decide(&self, _request: &ApprovalRequest, now: &str) -> ApprovalDecision {
        ApprovalDecision {
            granted: false,
            actor: "non-interactive".into(),
            at: now.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FixedApproval {
    pub granted: bool,
    pub actor: String,
}

impl ApprovalChannel for FixedApproval {
    fn decide(&self, _request: &ApprovalRequest, now: &str) -> ApprovalDecision {
        ApprovalDecision {
            granted: self.granted,
            actor: self.actor.clone(),
            at: now.into(),
        }
    }
}

fn denial(reason: &str, now: &str) -> ApprovalDecision {
    ApprovalDecision {
        granted: false,
        actor: reason.into(),
        at: now.into(),
    }
}

fn stale_response(line: &str, request: &ApprovalRequest) -> bool {
    let parts: Vec<_> = line.split_whitespace().collect();
    matches!(parts.len(), 7 | 8)
        && matches!(parts[0], "approve" | "deny")
        && parts[5] != request.nonce
}

fn decision_from_line(
    line: Option<&str>,
    request: &ApprovalRequest,
    now: &str,
    killed: &Mutex<bool>,
) -> ApprovalDecision {
    let Some(line) = line else {
        return denial("timeout", now);
    };
    let parts: Vec<_> = line.split_whitespace().collect();
    if parts == ["kill"] {
        *killed.lock().expect("kill flag") = true;
        return kill_decision(now);
    }
    if !matches!(parts.len(), 7 | 8) || !matches!(parts[0], "approve" | "deny") {
        return denial("invalid approval response", now);
    }
    for (actual, expected, reason) in [
        (
            parts[6],
            request.plan_digest.as_str(),
            "mismatched plan digest",
        ),
        (parts[2], request.step.as_str(), "mismatched step"),
        (
            parts[3],
            request.capability.as_str(),
            "mismatched capability",
        ),
        (
            parts[4],
            request.args_digest.as_str(),
            "mismatched args digest",
        ),
        (
            parts[5],
            request.nonce.as_str(),
            "mismatched or replayed nonce",
        ),
    ] {
        if actual != expected {
            return denial(reason, now);
        }
    }
    ApprovalDecision {
        granted: parts[0] == "approve",
        actor: "approver".into(),
        at: now.into(),
    }
}

fn kill_decision(now: &str) -> ApprovalDecision {
    ApprovalDecision {
        granted: false,
        actor: "kill-switch".into(),
        at: now.into(),
    }
}

enum HubMsg {
    Response(String),
    Kill,
}

type PeerCheck = fn(&UnixStream) -> Result<u32, String>;

/// The approval socket (0004 R9). Every connection's SO_PEERCRED uid must equal
/// the approver uid; others are rejected and recorded for the audit log.
pub struct SocketApproval {
    rx: Mutex<Receiver<HubMsg>>,
    killed: Arc<Mutex<bool>>,
    timeout: Duration,
    used: Mutex<HashSet<String>>,
    stale: Mutex<usize>,
    rejected: Arc<Mutex<Vec<u32>>>,
    closed: Arc<AtomicBool>,
    addr: String,
    approver: u32,
    attestation: Option<&'static str>,
    pending: Arc<Mutex<Option<ApprovalRequest>>>,
    scope_approved: Mutex<Option<String>>,
    revoked: Arc<Mutex<Vec<String>>>,
    started: AtomicBool,
}

impl SocketApproval {
    /// All R9c startup checks, then bind in the validated directory.
    fn bind(path: &Path, config: &ChannelConfig) -> Result<Self, String> {
        let approver = config
            .approver
            .ok_or("--approve-uid <uid> is required for --approve unix:<path> (0004 R9)")?;
        let ids = Identities {
            core_euid: unsafe { libc::geteuid() },
            core_ruid: unsafe { libc::getuid() },
            parent: launcher_uids()?,
            approver,
            agents: config.agents.to_vec(),
        };
        check_identities(&ids)?;
        let mut warnings = Vec::new();
        let table = r9c_proc_scan(
            &ProcSource::host(),
            ids.core_euid,
            &core_groups(),
            &ids.agents,
        )?;
        let scope = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
            .ok()
            .and_then(|s| s.trim().parse().ok());
        let shared = core_uid_shared(&table, ids.core_euid, std::process::id());
        if let Some(warning) = ptrace_verdict(scope, shared)? {
            warnings.push(warning);
        }
        let sockets = container_sockets();
        let gid =
            user_gid(approver).ok_or(format!("approver uid {approver} has no passwd entry"))?;
        let core_gid = unsafe { libc::getegid() };
        let mut subjects = Vec::new();
        for &agent in &ids.agents {
            // A missing /usr/bin/id refuses; any other lookup failure too
            // (group membership decides root-equivalence, 0004 R9c).
            let (names, gids) = groups_of(agent)?;
            if let Some(risk) = container_root(agent, &names, &gids, &sockets) {
                return Err(risk);
            }
            if let Some(risk) = privileged_group(agent, &gids, core_gid, gid) {
                return Err(risk);
            }
            let name = user_name(agent).ok_or(format!("uid {agent} has no passwd entry"))?;
            subjects.push(Subject {
                name,
                uid: agent,
                groups: names,
                gids,
            });
        }
        let approver_name = user_name(approver).unwrap_or_else(|| approver.to_string());
        let core_name = user_name(ids.core_euid).unwrap_or_else(|| ids.core_euid.to_string());
        let targets = switch_targets(&[(&approver_name, approver), (&core_name, ids.core_euid)]);
        let unclear = match evaluate_switch(&load_host_rules(), &subjects, &targets) {
            Switch::Hit(rule) => return Err(rule),
            Switch::Unclear(why) => vec![why],
            Switch::Clean => Vec::new(),
        };
        let attestation = attestation_verdict(&unclear, config.operator_attest)?;
        for warning in warnings.iter().chain(&unclear) {
            eprintln!("warning (0004 R9c): {warning}");
        }
        Self::listen(
            path,
            config.timeout,
            approver,
            gid,
            ids.core_euid,
            &ids.agents,
            peer_uid,
            attestation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn listen(
        path: &Path,
        timeout: Duration,
        approver: u32,
        gid: u32,
        core: u32,
        agents: &[u32],
        check: PeerCheck,
        attestation: Option<&'static str>,
    ) -> Result<Self, String> {
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or("approval socket needs a provisioned directory")?;
        let name = path
            .file_name()
            .ok_or("approval socket needs a file name")?;
        let dir_fd = open_approval_dir(dir, core, gid, agents)?;
        let before = fstat(&dir_fd)?;
        let listener = bind_socket(&dir_fd, path, core, gid)?;
        // The path must still name the directory we validated (no swap since).
        let same_dir = std::fs::symlink_metadata(dir).is_ok_and(|m| {
            use std::os::unix::fs::MetadataExt;
            m.ino() == before.st_ino && m.dev() == before.st_dev
        });
        if !same_dir {
            drop(listener);
            let cname = CString::new(name.as_bytes()).map_err(|e| e.to_string())?;
            let _ = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), cname.as_ptr(), 0) };
            return Err("approval directory changed after validation; refusing".into());
        }
        Ok(Self::serve(
            listener,
            format!("unix:{}", path.display()),
            timeout,
            approver,
            check,
            attestation,
        ))
    }

    fn serve(
        listener: UnixListener,
        addr: String,
        timeout: Duration,
        approver: u32,
        check: PeerCheck,
        attestation: Option<&'static str>,
    ) -> Self {
        let (tx, rx) = mpsc::channel();
        let killed = Arc::new(Mutex::new(false));
        let pending = Arc::new(Mutex::new(None));
        let revoked = Arc::new(Mutex::new(Vec::new()));
        let revocations = Arc::clone(&revoked);
        let rejected = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(AtomicBool::new(false));
        let (flag, current, refused, stop) = (
            Arc::clone(&killed),
            Arc::clone(&pending),
            Arc::clone(&rejected),
            Arc::clone(&closed),
        );
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut stream) = conn else { continue };
                // SO_PEERCRED on EVERY connection, before reading anything.
                match check(&stream) {
                    Ok(uid) if uid == approver => {}
                    observed => {
                        refused
                            .lock()
                            .expect("rejected peers")
                            .push(observed.unwrap_or(u32::MAX));
                        continue;
                    }
                }
                if stop.load(Ordering::SeqCst) {
                    continue;
                }
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut line = String::new();
                if BufReader::new((&stream).take(8192))
                    .read_line(&mut line)
                    .is_err()
                {
                    continue;
                }
                // Serialize command dispatch with shutdown, so final drains
                // cannot miss a revocation accepted by this listener.
                let mut accepted_revocations = revocations.lock().expect("revocations");
                if stop.load(Ordering::SeqCst) {
                    continue;
                }
                if line.trim() == "request" {
                    let value = current.lock().expect("pending request").as_ref().map(|r: &ApprovalRequest| {
                        serde_json::json!({"plan_digest":r.plan_digest,"step":r.step,"capability":r.capability,
                            "args_digest":r.args_digest,"sent_url_sha256":r.sent_url_sha256,"nonce":r.nonce,
                            "scope":r.scope,"scope_digest":r.scope_digest})
                    });
                    let _ = writeln!(
                        stream,
                        "{}",
                        serde_json::to_string(&value).expect("request JSON")
                    );
                    continue;
                }
                if let Some(target) = line.trim().strip_prefix("revoke ") {
                    if target == "*"
                        || (target.len() == 64 && target.bytes().all(|b| b.is_ascii_hexdigit()))
                    {
                        accepted_revocations.push(target.to_string());
                        let _ = writeln!(stream, "ok");
                    }
                    continue;
                }
                let message = if line.trim() == "kill" {
                    *flag.lock().expect("kill flag") = true;
                    HubMsg::Kill
                } else {
                    HubMsg::Response(line)
                };
                let _ = tx.send(message);
                let _ = writeln!(stream, "ok");
            }
        });
        Self {
            rx: Mutex::new(rx),
            killed,
            timeout,
            used: Mutex::new(HashSet::new()),
            stale: Mutex::new(0),
            rejected,
            closed,
            addr,
            approver,
            attestation,
            pending,
            scope_approved: Mutex::new(None),
            revoked,
            started: AtomicBool::new(false),
        }
    }

    fn wait(&self, request: &ApprovalRequest, now: &str) -> ApprovalDecision {
        let deadline = Instant::now() + self.timeout;
        let rx = self.rx.lock().expect("approval queue");
        loop {
            if Instant::now() >= deadline {
                return denial("timeout", now);
            }
            let message = rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
            if *self.killed.lock().expect("kill flag") {
                return kill_decision(now);
            }
            match message {
                Ok(HubMsg::Response(line)) => {
                    if stale_response(&line, request) {
                        *self.stale.lock().expect("stale responses") += 1;
                        continue;
                    }
                    let decision = decision_from_line(Some(&line), request, now, &self.killed);
                    let fields: Vec<_> = line.split_whitespace().collect();
                    let valid_scope = request.scope.as_ref().is_some_and(|scope| {
                        scope["standing"] == true
                            && request.scope_digest.as_deref()
                                == Some(
                                    format!(
                                        "{:x}",
                                        Sha256::digest(
                                            sidged_grant::canonicalize(scope).as_bytes()
                                        )
                                    )
                                    .as_str(),
                                )
                    });
                    if decision.granted
                        && valid_scope
                        && fields.len() == 8
                        && request.scope_digest.as_deref() == Some(fields[7])
                    {
                        *self.scope_approved.lock().expect("scope approval") =
                            request.scope_digest.clone();
                    }
                    return decision;
                }
                Ok(HubMsg::Kill) => return kill_decision(now),
                Err(_) => return denial("timeout", now),
            }
        }
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }
}

impl ApprovalChannel for SocketApproval {
    fn standing_scope_approved(&self, request: &ApprovalRequest) -> bool {
        request.scope_digest.is_some()
            && *self.scope_approved.lock().expect("scope approval") == request.scope_digest
    }
    fn take_revocations(&self) -> Vec<String> {
        std::mem::take(&mut *self.revoked.lock().expect("revocations"))
    }
    fn decide(&self, request: &ApprovalRequest, now: &str) -> ApprovalDecision {
        if *self.killed.lock().expect("kill flag") {
            return kill_decision(now);
        }
        if self.closed.load(Ordering::SeqCst) {
            return denial("approval channel closed", now);
        }
        if !self
            .used
            .lock()
            .expect("used nonces")
            .insert(request.nonce.clone())
        {
            return denial("replayed nonce", now);
        }
        *self.scope_approved.lock().expect("scope approval") = None;
        *self.pending.lock().expect("pending request") = Some(request.clone());
        let decision = self.wait(request, now);
        *self.pending.lock().expect("pending request") = None;
        decision
    }
    fn take_stale_responses(&self) -> usize {
        std::mem::take(&mut *self.stale.lock().expect("stale responses"))
    }
    fn take_rejected_peers(&self) -> Vec<u32> {
        std::mem::take(&mut *self.rejected.lock().expect("rejected peers"))
    }
    fn killed(&self) -> bool {
        *self.killed.lock().expect("kill flag")
    }
    fn attestation(&self) -> Option<&str> {
        self.attestation
    }
    fn approver_uid(&self) -> Option<u32> {
        Some(self.approver)
    }
    fn r9c_attestation(&self) -> Option<String> {
        Some(r9c_attestation_text())
    }
    fn take_channel_start(&self) -> Option<String> {
        (!self.started.swap(true, Ordering::SeqCst)).then(r9c_attestation_text)
    }
    fn shutdown(&self) {
        let _dispatch = self.revoked.lock().expect("revocations");
        self.closed.store(true, Ordering::SeqCst);
    }
}

/// `sidged kill unix:<path>` and approver clients: Unix socket only.
pub fn post_approval(addr: &str, body: &str) -> Result<(), String> {
    let path = addr
        .strip_prefix("unix:")
        .ok_or("approval is only reachable over unix:<path> (0004 R9)")?;
    let mut stream = UnixStream::connect(path).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    writeln!(stream, "{body}").map_err(|e| e.to_string())?;
    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .map_err(|_| "approval rejected".to_string())?;
    if reply == "ok\n" {
        Ok(())
    } else {
        Err("approval rejected".into())
    }
}

/// The uids the R9c identity rules compare.
#[derive(Debug, Clone)]
pub struct Identities {
    pub core_euid: u32,
    pub core_ruid: u32,
    pub parent: [u32; 2],
    pub approver: u32,
    pub agents: Vec<u32>,
}

/// R9c identity rules (pure, so every rule has a unit test).
pub fn check_identities(ids: &Identities) -> Result<(), String> {
    let core = [ids.core_euid, ids.core_ruid];
    if ids.approver == 0 {
        return Err("--approve-uid 0 (root) is refused (0004 R9c)".into());
    }
    if core.contains(&ids.approver) {
        return Err(format!(
            "--approve-uid {} is the Core uid (0004 R9)",
            ids.approver
        ));
    }
    if ids.agents.is_empty() {
        return Err("--non-approver-uid <uid> (alias --agent-uid, or config approval.non_approver_uids) is required: configure every agent, launcher, worker and model uid explicitly (0004 R9c)".into());
    }
    if ids.agents.contains(&0) {
        return Err("an agent/launcher uid is root (0004 R9c)".into());
    }
    if ids.agents.contains(&ids.approver) || ids.parent.contains(&ids.approver) {
        return Err(format!(
            "--approve-uid {} is also an agent/launcher/parent uid (0004 R9)",
            ids.approver
        ));
    }
    if core
        .iter()
        .any(|c| ids.agents.contains(c) || ids.parent.contains(c))
    {
        return Err("the Core uid equals an agent/launcher/parent uid; run the Core under its own uid (0004 R9c)".into());
    }
    Ok(())
}

/// yama ptrace_scope: < 1 (or no yama) lets same-uid processes attach. That is
/// refused when another process shares the Core uid, otherwise a warning.
pub fn ptrace_verdict(scope: Option<u8>, core_uid_shared: bool) -> Result<Option<String>, String> {
    match scope {
        Some(s) if s >= 1 => Ok(None),
        _ if core_uid_shared => {
            Err("yama ptrace_scope < 1 and another process runs as the Core uid (0004 R9c)".into())
        }
        _ => Ok(Some(
            "yama ptrace_scope < 1 (or unavailable); the Core uid must stay unique".into(),
        )),
    }
}

const CAP_SYS_PTRACE: u32 = 19;

/// One process as read from /proc/<pid>/status.
#[derive(Debug, Clone, Default)]
pub struct ProcInfo {
    pub pid: u32,
    pub uids: [u32; 2],
    pub cap_eff: u64,
}

/// The Core's effective gid plus its supplementary groups.
fn core_groups() -> Vec<u32> {
    // SAFETY: getgroups with a correctly sized buffer.
    let mut groups = vec![0 as libc::gid_t; 256];
    let n = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
    groups.truncate(usize::try_from(n).unwrap_or(0));
    groups.push(unsafe { libc::getegid() });
    groups
}

/// Where the R9c process scan reads from; injectable for tests.
pub struct ProcSource {
    /// The proc root (`/proc`).
    pub root: std::path::PathBuf,
    /// The mount table (`/proc/self/mountinfo`).
    pub mountinfo: std::path::PathBuf,
}

impl ProcSource {
    pub fn host() -> Self {
        Self {
            root: "/proc".into(),
            mountinfo: "/proc/self/mountinfo".into(),
        }
    }
}

const SCAN_INCOMPLETE: &str = "approval_scan_incomplete (0004 R9c)";

/// The options of the effective `/proc` mount (last one wins): `hidepid=`
/// and `gid=`. `None` when no proc mount at `/proc` is listed.
pub fn proc_mount_options(mountinfo: &str) -> Option<(Option<String>, Option<u32>)> {
    let mut found = None;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(sep) = fields.iter().position(|f| *f == "-") else {
            continue;
        };
        if fields.get(4) != Some(&"/proc") || fields.get(sep + 1) != Some(&"proc") {
            continue;
        }
        let (mut hidepid, mut gid) = (None, None);
        for opt in fields.get(sep + 3).copied().unwrap_or("").split(',') {
            if let Some(v) = opt.strip_prefix("hidepid=") {
                hidepid = Some(v.to_string());
            } else if let Some(v) = opt.strip_prefix("gid=") {
                gid = v.parse().ok();
            }
        }
        found = Some((hidepid, gid));
    }
    found
}

/// 0004 R9c process scan, fail-closed when blind: refuses with
/// `approval_scan_incomplete` if `/proc` hides processes (hidepid other than
/// 0/off) from a non-root Core outside the mount's `gid=` group, if the
/// mount table is unreadable or lists no proc mount, if any
/// `/proc/<pid>/status` is unreadable, or if no foreign-uid process is
/// visible at all. `--operator-attest` does not cover this (it covers only
/// unclear sudo/doas rules, 0005 R3b). Then the CAP_SYS_PTRACE check.
///
/// PID namespaces and containers: a Core started in its own minimal PID
/// namespace (a container, `unshare --pid`, a systemd unit with
/// `PrivatePIDs=`) sees only its own processes, so the scan finds no other
/// uid and refuses with `approval_scan_incomplete`. That is intended: the
/// agents' CAP_SYS_PTRACE cannot be checked from there, and 0004 R9c says
/// "Any other check that cannot be evaluated refuses the channel". Run the
/// Core in the host PID namespace; with `hidepid`, put the core uid in the
/// /proc mount's `gid=` group. `--operator-attest` does not lift this.
pub fn r9c_proc_scan(
    source: &ProcSource,
    core_euid: u32,
    core_groups: &[u32],
    agents: &[u32],
) -> Result<Vec<ProcInfo>, String> {
    let mountinfo = std::fs::read_to_string(&source.mountinfo)
        .map_err(|e| format!("{SCAN_INCOMPLETE}: mount table unreadable ({})", e.kind()))?;
    let (hidepid, gid) = proc_mount_options(&mountinfo)
        .ok_or(format!("{SCAN_INCOMPLETE}: no proc mount at /proc"))?;
    if let Some(mode) = hidepid.filter(|h| !matches!(h.as_str(), "0" | "off")) {
        if core_euid != 0 && !gid.is_some_and(|g| core_groups.contains(&g)) {
            return Err(format!(
                "{SCAN_INCOMPLETE}: /proc is mounted hidepid={mode} and the core uid is not in its gid= group; other uids' processes are invisible"
            ));
        }
    }
    let (table, complete) = proc_table_at(&source.root);
    if !complete {
        return Err(format!(
            "{SCAN_INCOMPLETE}: a /proc/<pid>/status is unreadable; CAP_SYS_PTRACE cannot be checked"
        ));
    }
    if let Some(risk) = ptrace_capable_agent(&table, agents) {
        return Err(risk);
    }
    if !table
        .iter()
        .any(|p| p.uids.iter().any(|&uid| uid != core_euid))
    {
        return Err(format!(
            "{SCAN_INCOMPLETE}: no process of another uid is visible in /proc (blind scan)"
        ));
    }
    Ok(table)
}

fn proc_table_at(root: &Path) -> (Vec<ProcInfo>, bool) {
    let mut table = Vec::new();
    let mut complete = true;
    let Ok(entries) = std::fs::read_dir(root) else {
        return (table, false);
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        match std::fs::read_to_string(entry.path().join("status")) {
            Ok(status) => {
                let mut info = ProcInfo {
                    pid,
                    ..Default::default()
                };
                for line in status.lines() {
                    if let Some(v) = line.strip_prefix("Uid:") {
                        let ids: Vec<u32> = v
                            .split_whitespace()
                            .take(2)
                            .filter_map(|x| x.parse().ok())
                            .collect();
                        if ids.len() == 2 {
                            info.uids = [ids[0], ids[1]];
                        }
                    } else if let Some(v) = line.strip_prefix("CapEff:") {
                        info.cap_eff = u64::from_str_radix(v.trim(), 16).unwrap_or(u64::MAX);
                    }
                }
                table.push(info);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => complete = false,
        }
    }
    (table, complete)
}

/// Refuse when any running agent process holds CAP_SYS_PTRACE.
pub fn ptrace_capable_agent(table: &[ProcInfo], agents: &[u32]) -> Option<String> {
    table
        .iter()
        .find(|p| {
            p.uids.iter().any(|u| agents.contains(u)) && p.cap_eff & (1 << CAP_SYS_PTRACE) != 0
        })
        .map(|p| {
            format!(
                "agent process {} (uid {}) holds CAP_SYS_PTRACE (0004 R9c)",
                p.pid, p.uids[0]
            )
        })
}

fn core_uid_shared(table: &[ProcInfo], core: u32, me: u32) -> bool {
    table.iter().any(|p| p.pid != me && p.uids.contains(&core))
}

/// Groups that are root-equivalent through a rootful container daemon.
/// Root-equivalent groups (0004 R9c: "at least docker, podman, lxd, incus,
/// disk, libvirt"). Membership of any non-approver uid refuses the channel.
pub const ROOT_EQUIVALENT_GROUPS: [&str; 6] =
    ["docker", "podman", "lxd", "incus", "disk", "libvirt"];
const CONTAINER_SOCKETS: [&str; 4] = [
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/podman/podman.sock",
    "/var/run/podman/podman.sock",
];

/// Whether `agent` (with `groups` gids) can open a socket with this owner/mode.
pub fn socket_accessible(owner: u32, group: u32, mode: u32, agent: u32, groups: &[u32]) -> bool {
    (owner == agent && mode & 0o600 == 0o600)
        || (groups.contains(&group) && mode & 0o060 == 0o060)
        || mode & 0o006 == 0o006
}

/// Gids of a user via `/usr/bin/id -G`. A missing helper refuses (0004 R9c).
fn id_groups_with(id: Option<std::process::Command>, name: &str) -> Result<Vec<u32>, String> {
    let Some(mut id) = id else {
        return Err("helper /usr/bin/id missing; refusing the approval channel (0004 R9c)".into());
    };
    let out = id
        .args(["-G", "--", name])
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("/usr/bin/id: {}", e.kind()))?;
    if !out.status.success() {
        return Err(format!("/usr/bin/id -G {name} failed"));
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .map(|g| {
            g.parse()
                .map_err(|_| "malformed /usr/bin/id output".to_string())
        })
        .collect()
}

/// Group names and gids of a uid, from `/usr/bin/id`.
fn groups_of(uid: u32) -> Result<(Vec<String>, Vec<u32>), String> {
    let name = user_name(uid).ok_or(format!("uid {uid} has no passwd entry"))?;
    let gids = id_groups_with(trusted_command("id"), &name)?;
    let names = gids
        .iter()
        .filter_map(|g| {
            let gr = unsafe { libc::getgrgid(*g) };
            (!gr.is_null()).then(|| {
                unsafe { std::ffi::CStr::from_ptr((*gr).gr_name) }
                    .to_string_lossy()
                    .into_owned()
            })
        })
        .collect();
    Ok((names, gids))
}

/// Container-group membership or an accessible rootful socket counts as root.
pub fn container_root(
    agent: u32,
    names: &[String],
    gids: &[u32],
    sockets: &[(String, u32, u32, u32)],
) -> Option<String> {
    if let Some(group) = names
        .iter()
        .find(|n| ROOT_EQUIVALENT_GROUPS.contains(&n.as_str()))
    {
        return Some(format!(
            "agent uid {agent} is in the {group} group (root-equivalent, 0004 R9c)"
        ));
    }
    sockets
        .iter()
        .find(|(_, owner, group, mode)| socket_accessible(*owner, *group, *mode, agent, gids))
        .map(|(path, ..)| {
            format!("agent uid {agent} can open the rootful container socket {path} (0004 R9c)")
        })
}

fn container_sockets() -> Vec<(String, u32, u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    CONTAINER_SOCKETS
        .iter()
        .filter_map(|p| {
            std::fs::metadata(p)
                .ok()
                .map(|m| (p.to_string(), m.uid(), m.gid(), m.mode()))
        })
        .collect()
}

/// Outcome of the sudo/doas check: a clear hit refuses; anything that could
/// not be evaluated is `Unclear` (warn + operator-attested), never clean.
#[derive(Debug, PartialEq, Eq)]
pub enum Switch {
    Clean,
    Hit(String),
    Unclear(String),
}

/// A `permit` or unknown rule line whose identity could not be located.
fn doas_unparsed(conf: &str) -> bool {
    conf.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .any(|l| {
            let first = l.split_whitespace().next().unwrap_or("");
            if first == "deny" {
                return l.split_whitespace().count() < 2;
            }
            if first != "permit" {
                return true;
            }
            let opens = l.matches('{').count();
            let closes = l.matches('}').count();
            if opens != closes {
                return true;
            }
            let spaced = l.replace('{', " { ").replace('}', " } ");
            let words: Vec<&str> = spaced.split_whitespace().collect();
            let options = ["nopass", "nolog", "persist", "keepenv", "setenv"];
            let mut i = 1;
            let mut depth = 0i32;
            while let Some(w) = words.get(i) {
                match *w {
                    "{" => depth += 1,
                    "}" => {
                        depth -= 1;
                        if depth < 0 {
                            return true;
                        }
                    }
                    w if depth > 0 || options.contains(&w) => {}
                    _ => break,
                }
                i += 1;
            }
            depth != 0 || words.get(i).is_none()
        })
}

fn user_gid(uid: u32) -> Option<u32> {
    let pw = unsafe { libc::getpwuid(uid) };
    (!pw.is_null()).then(|| unsafe { (*pw).pw_gid })
}

/// One fstat of an open directory.
fn fstat(fd: &OwnedFd) -> Result<libc::stat, String> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(st)
}

/// An ancestor must be owned by root or the Core, must not be group- or
/// world-writable, and must not be sticky (a /tmp-like ancestor is refused).
pub fn ancestor_ok(owner: u32, mode: u32, core: u32, agents: &[u32]) -> bool {
    (owner == 0 || owner == core)
        && !agents.contains(&owner)
        && mode & 0o022 == 0
        && mode & 0o1000 == 0
}

/// A non-approver uid in the core or approver group could reach the socket
/// or the directory (0004 R9c): refuse.
pub fn privileged_group(
    uid: u32,
    gids: &[u32],
    core_gid: u32,
    approver_gid: u32,
) -> Option<String> {
    gids.iter()
        .find(|g| **g == core_gid || **g == approver_gid)
        .map(|g| format!("non-approver uid {uid} is in the core or approver group {g} (0004 R9c)"))
}

/// umask in effect while the Core binds the socket: 0660 on creation.
pub const BIND_UMASK: libc::mode_t = 0o117;

/// The umask is process-wide: the Core opens the approval channel during
/// startup, and every umask-sensitive section in this crate holds this lock.
pub(crate) static UMASK_LOCK: Mutex<()> = Mutex::new(());

/// Threads of this process (D4).
pub fn task_count() -> usize {
    std::fs::read_dir("/proc/self/task").map_or(0, |d| d.count())
}

/// The umask is process-wide, so the approval socket must be bound while
/// the Core is still single-threaded (D4).
pub fn single_thread_violation(count: usize) -> Option<String> {
    (count != 1).then(|| format!("{count} threads at approval bind; the Core must be single-threaded here (umask is process-wide)"))
}

/// The real `sidged` binary checks D4 right before it opens the approval
/// channel, in debug and release builds alike: more than one thread, or
/// an unreadable /proc/self/task, refuses the channel. Library callers (and
/// test binaries, which always run several threads) do not call it.
pub fn require_single_threaded() -> Result<(), String> {
    require_single_threaded_with(task_count())
}

pub fn require_single_threaded_with(count: usize) -> Result<(), String> {
    match single_thread_violation(count) {
        Some(violation) => Err(format!("approval channel refused: {violation}")),
        None => Ok(()),
    }
}

/// Restores the saved umask on every exit path, including panics.
pub struct UmaskGuard(libc::mode_t);

impl UmaskGuard {
    pub fn set(mask: libc::mode_t) -> Self {
        Self(unsafe { libc::umask(mask) })
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        unsafe { libc::umask(self.0) };
    }
}

/// Create the socket in the validated setgid directory under umask 0117
/// (so it is 0660 core uid : approver group), verify that with lstat before
/// `listen`, and otherwise unlink it and refuse (0004 R9c @0c4695c).
pub fn bind_socket(
    dir_fd: &OwnedFd,
    path: &Path,
    core: u32,
    gid: u32,
) -> Result<UnixListener, String> {
    let name = path
        .file_name()
        .ok_or("approval socket needs a file name")?;
    let cname = CString::new(name.as_bytes()).map_err(|e| e.to_string())?;
    let bytes = path.as_os_str().as_bytes();
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= addr.sun_path.len() {
        return Err("approval socket path is too long".into());
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let sock = unsafe { OwnedFd::from_raw_fd(raw) };
    let len = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
    let bound = {
        let _lock = UMASK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _umask = UmaskGuard::set(BIND_UMASK);
        unsafe {
            libc::bind(
                sock.as_raw_fd(),
                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                len as libc::socklen_t,
            )
        }
    };
    if bound != 0 {
        return Err(format!(
            "approval socket {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let fd = dir_fd.as_raw_fd();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let placed =
        unsafe { libc::fstatat(fd, cname.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0;
    if !placed
        || st.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || st.st_mode & 0o777 != 0o660
        || st.st_uid != core
        || st.st_gid != gid
    {
        drop(sock);
        let _ = unsafe { libc::unlinkat(fd, cname.as_ptr(), 0) };
        return Err(
            "approval socket must be 0660 core uid : approver group (setgid directory, umask 0117; 0004 R9c)"
                .into(),
        );
    }
    if unsafe { libc::listen(sock.as_raw_fd(), 16) } != 0 {
        let err = std::io::Error::last_os_error();
        drop(sock);
        let _ = unsafe { libc::unlinkat(fd, cname.as_ptr(), 0) };
        return Err(format!("approval socket listen: {err}"));
    }
    Ok(UnixListener::from(sock))
}

/// The approval directory itself: owner = Core uid, group = approver gid,
/// mode 2750 or 2710. Setgid is required so the socket the Core binds
/// inherits the approver group.
pub fn approval_dir_ok(owner: u32, group: u32, mode: u32, core: u32, approver_gid: u32) -> bool {
    owner == core && group == approver_gid && matches!(mode & 0o7777, 0o2750 | 0o2710)
}

/// Walk from / to `dir` with openat(O_NOFOLLOW|O_DIRECTORY), checking every
/// ancestor. The Core never creates the directory: a missing component, a
/// symlink, or a wrong owner/mode refuses. Returns the open directory.
pub fn open_approval_dir(
    dir: &Path,
    core: u32,
    approver_gid: u32,
    agents: &[u32],
) -> Result<OwnedFd, String> {
    if !dir.is_absolute() {
        return Err("approval directory must be an absolute path".into());
    }
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let root = unsafe { libc::open(c"/".as_ptr(), flags) };
    if root < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut fd = unsafe { OwnedFd::from_raw_fd(root) };
    let mut walked = std::path::PathBuf::from("/");
    for component in dir.components() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => name,
            _ => return Err("approval directory must not contain . or ..".into()),
        };
        let st = fstat(&fd)?;
        if !ancestor_ok(st.st_uid, st.st_mode, core, agents) {
            return Err(format!(
                "approval directory ancestor {} is writable by or owned by someone other than root/the Core (0004 R9c)",
                walked.display()
            ));
        }
        walked.push(name);
        let cname = CString::new(name.as_bytes()).map_err(|e| e.to_string())?;
        let next = unsafe { libc::openat(fd.as_raw_fd(), cname.as_ptr(), flags) };
        if next < 0 {
            let err = std::io::Error::last_os_error();
            return Err(match err.raw_os_error() {
                Some(libc::ENOENT) => format!(
                    "approval directory {} does not exist; the operator must provision it (owner Core uid, group approver gid, mode 2750/2710)",
                    walked.display()
                ),
                Some(libc::ELOOP) | Some(libc::ENOTDIR) => {
                    format!("approval directory component {} is a symlink or not a directory", walked.display())
                }
                _ => format!("approval directory {}: {err}", walked.display()),
            });
        }
        fd = unsafe { OwnedFd::from_raw_fd(next) };
    }
    let st = fstat(&fd)?;
    if !approval_dir_ok(st.st_uid, st.st_gid, st.st_mode, core, approver_gid) {
        return Err(format!(
            "approval directory {} must be owned by the Core uid {core}, group approver gid {approver_gid}, mode 2750 or 2710 (setgid; 0004 R9c)",
            dir.display()
        ));
    }
    Ok(fd)
}

/// Real and effective uid of the process that launched the Core (0004 R9).
/// Fails closed when they cannot be read.
fn launcher_uids() -> Result<[u32; 2], String> {
    let parent = unsafe { libc::getppid() };
    let status = std::fs::read_to_string(format!("/proc/{parent}/status"))
        .map_err(|e| format!("cannot read launcher uid ({e}); refusing socket approval"))?;
    let line = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .ok_or("cannot read launcher uid; refusing socket approval")?;
    let ids: Vec<u32> = line
        .split_whitespace()
        .take(2)
        .map(|v| v.parse().map_err(|_| "malformed launcher uid".to_string()))
        .collect::<Result<_, _>>()?;
    match ids[..] {
        [real, effective] => Ok([real, effective]),
        _ => Err("malformed launcher uid".into()),
    }
}

fn user_name(uid: u32) -> Option<String> {
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) };
    Some(name.to_string_lossy().into_owned())
}

/// The only helpers the Core runs for R9c checks, at fixed absolute paths.
pub const HELPERS: [&str; 3] = ["/usr/bin/sudo", "/usr/bin/doas", "/usr/bin/id"];

/// A helper only from `HELPERS`, with a cleared environment and a fixed
/// PATH; never resolved through the inherited PATH. Missing: `None`.
fn trusted_command(name: &str) -> Option<std::process::Command> {
    let path = HELPERS
        .iter()
        .map(Path::new)
        .find(|p| p.file_name().is_some_and(|n| n == name))?;
    if !path.is_file() {
        return None;
    }
    let mut command = std::process::Command::new(path);
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C");
    Some(command)
}

/// Names and uids a non-approver uid must not switch to (root is implicit).
fn switch_targets(users: &[(&str, u32)]) -> Vec<String> {
    users
        .iter()
        .flat_map(|(name, uid)| [name.to_string(), uid.to_string()])
        .collect()
}

/// A non-approver uid as the sudoers/doas parser sees it.
#[derive(Debug, Clone)]
pub struct Subject {
    pub name: String,
    pub uid: u32,
    pub groups: Vec<String>,
    pub gids: Vec<u32>,
}

/// The host's sudo/doas rule files, read directly (no sudo/doas binary is
/// run; a missing binary is no switch path, 0004 R9c @0c4695c). `Err` =
/// present but unreadable.
#[derive(Debug, Default)]
pub struct HostRules {
    pub sudoers: Vec<(String, Result<String, String>)>,
    pub doas: Option<Result<String, String>>,
}

fn read_rule_file(path: &Path) -> Option<Result<String, String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Some(Ok(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => Some(Err(e.kind().to_string())),
    }
}

/// sudo skips files in an includedir whose name contains '.' or ends in '~'.
pub fn sudoers_d_included(name: &str) -> bool {
    !name.contains('.') && !name.ends_with('~')
}

pub fn load_host_rules() -> HostRules {
    let mut rules = HostRules::default();
    if let Some(r) = read_rule_file(Path::new("/etc/sudoers")) {
        rules.sudoers.push(("/etc/sudoers".into(), r));
    }
    match std::fs::read_dir("/etc/sudoers.d") {
        Ok(entries) => {
            let mut names: Vec<_> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| sudoers_d_included(n))
                .collect();
            names.sort();
            for name in names {
                let path = Path::new("/etc/sudoers.d").join(&name);
                if let Some(r) = read_rule_file(&path) {
                    rules.sudoers.push((path.display().to_string(), r));
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => rules
            .sudoers
            .push(("/etc/sudoers.d".into(), Err(e.kind().to_string()))),
    }
    rules.doas = read_rule_file(Path::new("/etc/doas.conf"));
    rules
}

enum Rule {
    Skip,
    Hit(String),
    Unclear(String),
}

fn is_alias_name(word: &str) -> bool {
    word != "ALL"
        && word.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && word
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// One sudoers line for one subject. Anything not clearly understood is
/// `Unclear`, never clean.
fn sudoers_line(line: &str, who: &Subject, targets: &[String]) -> Rule {
    let line = line.trim();
    if line.is_empty() {
        return Rule::Skip;
    }
    for dir in ["#includedir /etc/sudoers.d", "@includedir /etc/sudoers.d"] {
        if line == dir {
            return Rule::Skip;
        }
    }
    if line.starts_with("#include") || line.starts_with('@') {
        return Rule::Unclear(format!("include the Core does not follow: {line}"));
    }
    if line.starts_with('#') && !line[1..].starts_with(|c: char| c.is_ascii_digit()) {
        return Rule::Skip;
    }
    if line.ends_with('\\') {
        return Rule::Unclear("continued sudoers line".into());
    }
    if line.starts_with("Defaults") {
        return Rule::Skip;
    }
    for alias in ["User_Alias", "Runas_Alias"] {
        if line.starts_with(alias) {
            return Rule::Unclear(format!("{alias} not evaluated"));
        }
    }
    if line.starts_with("Host_Alias") || line.starts_with("Cmnd_Alias") {
        return Rule::Skip;
    }
    let Some((left, right)) = line.split_once('=') else {
        return Rule::Unclear(format!("unparsed sudoers line: {line}"));
    };
    let words: Vec<&str> = left.split_whitespace().collect();
    if words.len() < 2 {
        return Rule::Unclear(format!("unparsed sudoers line: {line}"));
    }
    let user_words = &words[..words.len() - 1];
    if user_words
        .windows(2)
        .any(|pair| !pair[0].ends_with(',') && !pair[1].starts_with(','))
    {
        return Rule::Unclear(format!("multi-token sudoers host or user list: {line}"));
    }
    let joined = user_words.join("");
    let users: Vec<&str> = joined
        .split(',')
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .collect();
    let mut matched = false;
    for user in &users {
        if user.starts_with('!') || is_alias_name(user) {
            return Rule::Unclear(format!("negated or aliased sudoers user: {line}"));
        }
        let hit = *user == "ALL"
            || *user == who.name
            || user.strip_prefix('#') == Some(&who.uid.to_string())
            || user
                .strip_prefix("%#")
                .is_some_and(|g| who.gids.iter().any(|x| x.to_string() == g))
            || user
                .strip_prefix('%')
                .is_some_and(|g| !g.starts_with('#') && who.groups.iter().any(|x| x == g));
        matched |= hit;
    }
    if !matched {
        return Rule::Skip;
    }
    let right = right.trim();
    if !right.starts_with('(') {
        return Rule::Hit(format!("{line} (runas defaults to root)"));
    }
    let mut rest = right;
    while let Some(open) = rest.find('(') {
        let Some(close) = rest[open..].find(')') else {
            return Rule::Unclear(format!("unbalanced runas list: {line}"));
        };
        let runas = &rest[open + 1..open + close];
        let runas_users = runas.split(':').next().unwrap_or("");
        for u in runas_users
            .split(',')
            .map(str::trim)
            .filter(|u| !u.is_empty())
        {
            if u.starts_with('!') || is_alias_name(u) {
                return Rule::Unclear(format!("negated or aliased runas: {line}"));
            }
        }
        if sudo_switch(&format!("({runas})"), targets).is_some() {
            return Rule::Hit(line.to_string());
        }
        rest = &rest[open + close + 1..];
    }
    Rule::Skip
}

/// Clear hits refuse; unreadable or ambiguous rules are `Unclear`.
pub fn evaluate_switch(rules: &HostRules, subjects: &[Subject], targets: &[String]) -> Switch {
    let mut unclear = Vec::new();
    for (path, text) in &rules.sudoers {
        let text = match text {
            Ok(text) => text,
            Err(why) => {
                unclear.push(format!("{path} unreadable ({why})"));
                continue;
            }
        };
        for line in text.lines() {
            for who in subjects {
                match sudoers_line(line, who, targets) {
                    Rule::Skip => {}
                    Rule::Hit(rule) => {
                        return Switch::Hit(format!(
                            "non-approver uid {} can sudo to the approver, core uid or root: {rule} ({path}, 0004 R9c)",
                            who.uid
                        ))
                    }
                    Rule::Unclear(why) => unclear.push(format!("{path}: {why}")),
                }
            }
            if subjects.is_empty() {
                break;
            }
        }
    }
    match &rules.doas {
        None => {}
        Some(Err(why)) => unclear.push(format!("/etc/doas.conf unreadable ({why})")),
        Some(Ok(conf)) => {
            for who in subjects {
                let ids = [who.name.clone(), who.uid.to_string()];
                let mut groups = who.groups.clone();
                groups.extend(who.gids.iter().map(u32::to_string));
                if let Some(rule) = doas_switch(conf, &ids, &groups, targets) {
                    return Switch::Hit(format!(
                        "non-approver uid {} can doas to the approver, core uid or root: {rule} (0004 R9c)",
                        who.uid
                    ));
                }
            }
            if doas_unparsed(conf) {
                unclear.push("doas.conf has rules the Core cannot parse".into());
            }
        }
    }
    unclear.dedup();
    if unclear.is_empty() {
        Switch::Clean
    } else {
        Switch::Unclear(unclear.join("; "))
    }
}

/// A `sudo -l` rule line whose runas list contains ALL, root, or a target
/// (name, uid, or #uid).
fn sudo_switch(listing: &str, targets: &[String]) -> Option<String> {
    listing.lines().map(str::trim).find_map(|line| {
        let runas = line.strip_prefix('(')?.split(')').next()?;
        let users = runas.split(':').next().unwrap_or("");
        users
            .split(',')
            .map(str::trim)
            .any(|u| {
                let bare = u.strip_prefix('#').unwrap_or(u);
                u == "ALL"
                    || u == "root"
                    || bare == "0"
                    || targets.iter().any(|t| t == u || t == bare)
            })
            .then(|| line.to_string())
    })
}

/// A `permit` rule in doas.conf for the agent (name or uid, or one of its
/// groups by name or gid) whose target is the approver (name or uid) or root,
/// the default when `as` is absent. `setenv { ... }` blocks are skipped as a
/// whole.
fn doas_switch(
    conf: &str,
    agent: &[String],
    groups: &[String],
    approver: &[String],
) -> Option<String> {
    conf.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .find_map(|line| {
            let spaced = line.replace('{', " { ").replace('}', " } ");
            let words: Vec<&str> = spaced.split_whitespace().collect();
            if words.first() != Some(&"permit") {
                return None;
            }
            let options = ["nopass", "nolog", "persist", "keepenv", "setenv"];
            let mut i = 1;
            let mut depth = 0;
            while let Some(w) = words.get(i) {
                match *w {
                    "{" => depth += 1,
                    "}" => depth -= 1,
                    w if depth > 0 || options.contains(&w) => {}
                    _ => break,
                }
                i += 1;
            }
            let rest = &words[i..];
            let identity = *rest.first()?;
            let matches = agent.iter().any(|a| a == identity)
                || identity
                    .strip_prefix(':')
                    .is_some_and(|g| groups.iter().any(|x| x == g));
            let target = rest
                .iter()
                .position(|w| *w == "as")
                .and_then(|i| rest.get(i + 1).copied())
                .unwrap_or("root");
            (matches && (target == "root" || target == "0" || approver.iter().any(|a| a == target)))
                .then(|| line.to_string())
        })
}

fn peer_uid(stream: &UnixStream) -> Result<u32, String> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut size,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(cred.uid)
}

/// Test-only: apply the socket's response rules to a sequence of lines.
#[cfg(test)]
pub(crate) fn decide_from_lines(
    lines: &str,
    request: &ApprovalRequest,
    now: &str,
) -> (ApprovalDecision, usize) {
    let killed = Mutex::new(false);
    let mut stale = 0;
    for line in lines.lines() {
        if stale_response(line, request) {
            stale += 1;
            continue;
        }
        return (decision_from_line(Some(line), request, now, &killed), stale);
    }
    (denial("timeout", now), stale)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;

    static N: AtomicUsize = AtomicUsize::new(0);
    const APPROVER: u32 = 4242;

    fn me() -> u32 {
        unsafe { libc::geteuid() }
    }
    fn my_gid() -> u32 {
        unsafe { libc::getegid() }
    }
    fn ok_peer(_: &UnixStream) -> Result<u32, String> {
        Ok(APPROVER)
    }
    fn bad_peer(_: &UnixStream) -> Result<u32, String> {
        Ok(APPROVER + 1)
    }

    /// $HOME/sidged-ap-<pid>-<n>/approval (2750, owner = us as "Core",
    /// group = our gid standing in for the approver gid).
    /// A non-sticky base for real directory walks: the sticky /tmp is
    /// itself refused as an ancestor (0004 R9c).
    fn test_base() -> PathBuf {
        std::env::var_os("SIDGED_TEST_APPROVAL_BASE")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
            .unwrap()
    }
    fn provisioned(mode: u32) -> PathBuf {
        let base = test_base().join(format!(
            "sidged-ap-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let dir = base.join("approval");
        let _umask = UMASK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        dir
    }
    fn hub(dir: &Path, timeout: Duration, check: PeerCheck) -> SocketApproval {
        SocketApproval::listen(
            &dir.join("control.sock"),
            timeout,
            APPROVER,
            my_gid(),
            me(),
            &[],
            check,
            None,
        )
        .unwrap()
    }
    fn cleanup(dir: &Path) {
        std::fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }
    fn refusal(channel: &dyn ApprovalChannel) -> String {
        channel
            .refusal()
            .expect("channel must be refused")
            .to_string()
    }
    fn config<'a>(mode: &'a str, agents: &'a [u32], local: bool) -> ChannelConfig<'a> {
        ChannelConfig {
            mode: Some(mode),
            timeout: Duration::from_millis(10),
            approver: Some(APPROVER),
            agents,
            local,
            operator_attest: false,
        }
    }
    fn request() -> ApprovalRequest {
        ApprovalRequest::new("plan", "send", "cap", &serde_json::json!({"to":"ada"})).unwrap()
    }
    fn response(r: &ApprovalRequest) -> String {
        format!(
            "approve ada {} {} {} {} {}",
            r.step, r.capability, r.args_digest, r.nonce, r.plan_digest
        )
    }
    fn ids() -> Identities {
        Identities {
            core_euid: 1001,
            core_ruid: 1001,
            parent: [1000, 1000],
            approver: 2001,
            agents: vec![1000, 1002],
        }
    }

    // --- identities (binding (1), (2)) ---
    #[test]
    fn identities_valid_configuration_passes() {
        assert!(check_identities(&ids()).is_ok());
    }
    #[test]
    fn approve_uid_root_or_core_is_refused() {
        let mut i = ids();
        i.approver = 0;
        assert!(check_identities(&i).unwrap_err().contains("root"));
        let mut i = ids();
        i.approver = 1001;
        assert!(check_identities(&i).unwrap_err().contains("Core uid"));
        let mut i = ids();
        i.core_ruid = 2001;
        assert!(check_identities(&i).is_err());
    }
    #[test]
    fn agent_uids_must_be_explicit_and_not_root() {
        let mut i = ids();
        i.agents.clear();
        assert!(check_identities(&i).unwrap_err().contains("--agent-uid"));
        let mut i = ids();
        i.agents.push(0);
        assert!(check_identities(&i).unwrap_err().contains("root"));
    }
    #[test]
    fn approver_equal_to_agent_launcher_or_parent_is_refused() {
        let mut i = ids();
        i.agents.push(2001);
        assert!(check_identities(&i).is_err());
        let mut i = ids();
        i.parent = [2001, 2001];
        assert!(check_identities(&i).is_err());
    }
    #[test]
    fn core_uid_equal_to_agent_launcher_or_parent_is_refused() {
        let mut i = ids();
        i.agents.push(1001);
        assert!(check_identities(&i).unwrap_err().contains("own uid"));
        let mut i = ids();
        i.parent = [1001, 1001];
        assert!(check_identities(&i).unwrap_err().contains("own uid"));
    }
    #[test]
    fn launcher_uids_are_read() {
        let [real, effective] = launcher_uids().unwrap();
        assert_eq!((real, effective), (unsafe { libc::getuid() }, me()));
    }

    // --- ptrace / yama / CAP_SYS_PTRACE (binding (1)) ---
    #[test]
    fn yama_below_one_refuses_when_core_uid_is_shared_else_warns() {
        assert_eq!(ptrace_verdict(Some(1), true), Ok(None));
        assert_eq!(ptrace_verdict(Some(2), true), Ok(None));
        assert!(ptrace_verdict(Some(0), true).is_err());
        assert!(ptrace_verdict(None, true).is_err());
        assert!(ptrace_verdict(Some(0), false).unwrap().is_some());
        assert!(ptrace_verdict(None, false).unwrap().is_some());
    }
    #[test]
    fn agent_with_cap_sys_ptrace_is_refused() {
        let p = |uid, cap| ProcInfo {
            pid: 7,
            uids: [uid, uid],
            cap_eff: cap,
        };
        assert!(ptrace_capable_agent(&[p(1000, 1 << 19)], &[1000]).is_some());
        assert!(ptrace_capable_agent(&[p(1000, 1 << 21)], &[1000]).is_none());
        assert!(ptrace_capable_agent(&[p(3000, 1 << 19)], &[1000]).is_none());
        assert!(core_uid_shared(&[p(1001, 0)], 1001, 99));
        assert!(!core_uid_shared(
            &[ProcInfo {
                pid: 99,
                uids: [1001, 1001],
                cap_eff: 0
            }],
            1001,
            99
        ));
    }
    #[test]
    fn harden_process_clears_dumpable() {
        harden_process().unwrap();
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
    }

    // --- container root equivalence (binding (3)) ---
    #[test]
    fn docker_or_podman_group_or_accessible_socket_counts_as_root() {
        let none: Vec<(String, u32, u32, u32)> = Vec::new();
        assert!(container_root(1000, &["docker".into()], &[999], &none).is_some());
        assert!(container_root(1000, &["podman".into()], &[998], &none).is_some());
        assert!(container_root(1000, &["users".into()], &[100], &none).is_none());
        // 0004 R9c: every root-equivalent group refuses; the spec list
        // is pinned here and must match the constant (one loop).
        let spec = ["docker", "podman", "lxd", "incus", "disk", "libvirt"];
        assert_eq!(ROOT_EQUIVALENT_GROUPS, spec);
        for group in spec {
            assert!(
                container_root(1000, &[group.to_string()], &[990], &none).is_some(),
                "{group}"
            );
        }
        let sock = |owner, group, mode| vec![("/run/docker.sock".to_string(), owner, group, mode)];
        assert!(
            container_root(1000, &[], &[999], &sock(0, 999, 0o140660)).is_some(),
            "group rw"
        );
        assert!(
            container_root(1000, &[], &[100], &sock(0, 999, 0o140666)).is_some(),
            "world rw"
        );
        assert!(
            container_root(1000, &[], &[100], &sock(1000, 999, 0o140600)).is_some(),
            "owner"
        );
        assert!(container_root(1000, &[], &[100], &sock(0, 999, 0o140660)).is_none());
    }

    // --- sudo/doas (binding (4)) ---
    #[test]
    fn sudo_and_doas_hits_are_detected() {
        let any =
            "User agent may run the following commands on host:\n    (ALL : ALL) NOPASSWD: ALL\n";
        assert!(sudo_switch(any, &switch_targets(&[("approver", 2001)])).is_some());
        assert!(sudo_switch(
            "    (approver) /usr/bin/sidged\n",
            &switch_targets(&[("approver", 2001)])
        )
        .is_some());
        assert!(sudo_switch(
            "    (#2001) /bin/sh\n",
            &switch_targets(&[("approver", 2001)])
        )
        .is_some());
        assert!(sudo_switch(
            "    (backup) /usr/bin/tar\n",
            &switch_targets(&[("approver", 2001)])
        )
        .is_none());
        let groups = ["agent".to_string(), "wheel".to_string()];
        let agent = ["agent".to_string(), "1000".to_string()];
        let approver = ["approver".to_string(), "2001".to_string()];
        let doas = |conf: &str| doas_switch(conf, &agent, &groups, &approver).is_some();
        assert!(doas("permit nopass agent as approver\n"));
        assert!(doas("permit :wheel\n"));
        assert!(doas("permit nopass setenv { PATH } agent as approver\n"));
        assert!(doas("permit setenv {PATH -HOME} agent as approver\n"));
        assert!(doas("permit nopass 1000 as approver\n"));
        assert!(doas("permit nopass agent as 2001\n"));
        assert!(doas("permit agent as 0\n"));
        assert!(!doas("permit nopass agent as 3003\n"));
        assert!(!doas("# permit agent\ndeny agent\n"));
    }
    #[test]
    fn unclear_doas_rules_are_never_clean() {
        assert!(doas_unparsed("permit setenv { PATH agent as approver\n"));
        assert!(doas_unparsed("permit\n"));
        assert!(doas_unparsed("permit nopass\n"));
        assert!(doas_unparsed("macro = agent\n"));
        assert!(!doas_unparsed("permit nopass agent as backup\n"));
        let who = Subject {
            name: "agent".into(),
            uid: 1000,
            groups: vec!["agent".into()],
            gids: vec![1000],
        };
        assert!(matches!(
            sudoers_line("agent host1, host2 = (root) NOPASSWD: ALL", &who, &[]),
            Rule::Unclear(_)
        ));
    }
    #[test]
    fn operator_attested_channel_reports_it() {
        let dir = provisioned(0o2750);
        let path = dir.join("control.sock");
        let hub = SocketApproval::listen(
            &path,
            Duration::from_millis(10),
            APPROVER,
            my_gid(),
            me(),
            &[],
            ok_peer,
            Some(OPERATOR_ATTESTED),
        )
        .unwrap();
        assert_eq!(hub.attestation(), Some(OPERATOR_ATTESTED));
        assert_eq!(hub.approver_uid(), Some(APPROVER));
        drop(hub);
        cleanup(&dir);
    }

    // --- directory (final spec) ---
    #[test]
    fn missing_approval_dir_is_refused_and_not_created() {
        let dir = provisioned(0o2750).join("absent");
        let err = open_approval_dir(&dir, me(), my_gid(), &[]).unwrap_err();
        assert!(
            err.contains("does not exist") && err.contains("provision"),
            "{err}"
        );
        assert!(!dir.exists());
        cleanup(dir.parent().unwrap());
    }
    #[test]
    fn symlinked_component_is_refused() {
        let dir = provisioned(0o2750);
        let link = dir.parent().unwrap().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        let err = open_approval_dir(&link, me(), my_gid(), &[]).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        cleanup(&dir);
    }
    #[test]
    fn approval_dir_owner_group_and_mode_are_enforced() {
        for mode in [0o2750, 0o2710] {
            let dir = provisioned(mode);
            assert!(
                open_approval_dir(&dir, me(), my_gid(), &[]).is_ok(),
                "{mode:o}"
            );
            cleanup(&dir);
        }
        // Without setgid the socket would not inherit the approver group.
        for mode in [0o750, 0o710, 0o700, 0o770, 0o755, 0o751, 0o2770, 0o2755] {
            let dir = provisioned(mode);
            assert!(
                open_approval_dir(&dir, me(), my_gid(), &[]).is_err(),
                "{mode:o}"
            );
            cleanup(&dir);
        }
        let dir = provisioned(0o2750);
        assert!(
            open_approval_dir(&dir, me() + 1, my_gid(), &[]).is_err(),
            "owner must be the Core"
        );
        assert!(
            open_approval_dir(&dir, me(), my_gid() + 1, &[]).is_err(),
            "group must be the approver gid"
        );
        cleanup(&dir);
    }
    #[test]
    fn every_ancestor_is_checked() {
        assert!(ancestor_ok(0, 0o40755, 1001, &[1000]));
        assert!(
            !ancestor_ok(0, 0o41777, 1001, &[1000]),
            "sticky /tmp-like ancestor (2ec8992 R9c)"
        );
        assert!(
            !ancestor_ok(0, 0o41755, 1001, &[1000]),
            "any sticky ancestor"
        );
        assert!(ancestor_ok(1001, 0o40700, 1001, &[1000]));
        assert!(!ancestor_ok(1000, 0o40755, 1001, &[1000]), "agent-owned");
        assert!(!ancestor_ok(3000, 0o40755, 1001, &[1000]), "foreign owner");
        assert!(!ancestor_ok(0, 0o40775, 1001, &[1000]), "group-writable");
        assert!(
            !ancestor_ok(1001, 0o41777, 1001, &[1000]),
            "sticky but not root-owned"
        );
        // Real walk: a group-writable ancestor deep in the path refuses.
        let dir = provisioned(0o2750);
        let base = dir.parent().unwrap();
        std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o770)).unwrap();
        let err = open_approval_dir(&dir, me(), my_gid(), &[]).unwrap_err();
        assert!(err.contains("ancestor"), "{err}");
        std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o700)).unwrap();
        // The Core uid treated as agent-owned ancestor also refuses.
        assert!(open_approval_dir(&dir, me(), my_gid(), &[me()]).is_err());
        assert!(open_approval_dir(Path::new("relative/dir"), me(), my_gid(), &[]).is_err());
        cleanup(&dir);
    }
    #[test]
    fn socket_is_0660_with_the_approver_group() {
        let dir = provisioned(0o2750);
        let hub = hub(&dir, Duration::from_millis(10), ok_peer);
        let meta = std::fs::symlink_metadata(dir.join("control.sock")).unwrap();
        assert_eq!(
            (meta.mode() & 0o777, meta.gid(), meta.uid()),
            (0o660, my_gid(), me())
        );
        drop(hub);
        cleanup(&dir);
    }

    // --- SO_PEERCRED on every connection ---
    static CHECKS: AtomicUsize = AtomicUsize::new(0);
    fn counting_peer(_: &UnixStream) -> Result<u32, String> {
        Ok(if CHECKS.fetch_add(1, Ordering::SeqCst) == 1 {
            APPROVER + 7
        } else {
            APPROVER
        })
    }
    #[test]
    fn peer_uid_is_checked_on_every_connection() {
        let dir = provisioned(0o2750);
        let hub = Arc::new(hub(&dir, Duration::from_secs(2), counting_peer));
        let path = dir.join("control.sock");
        let r = request();
        let worker = Arc::clone(&hub);
        let expected = r.clone();
        let decision = thread::spawn(move || worker.decide(&expected, "now"));
        while hub.pending.lock().unwrap().is_none() {
            thread::sleep(Duration::from_millis(1));
        }
        let addr = format!("unix:{}", path.display());
        let mut first = UnixStream::connect(&path).unwrap();
        writeln!(first, "request").unwrap();
        let mut pending = String::new();
        first.read_to_string(&mut pending).unwrap();
        assert!(
            pending.contains(&r.nonce),
            "1st: approver reads the pending request"
        );
        assert!(
            post_approval(&addr, &response(&r)).is_err(),
            "2nd: other uid, rejected"
        );
        post_approval(&addr, &response(&r)).unwrap();
        assert!(decision.join().unwrap().granted);
        assert!(CHECKS.load(Ordering::SeqCst) >= 3);
        assert_eq!(
            hub.take_rejected_peers(),
            vec![APPROVER + 7],
            "observed uid recorded"
        );
        cleanup(&dir);
    }
    #[test]
    fn wrong_peer_cannot_kill_or_approve() {
        let dir = provisioned(0o2750);
        let hub = hub(&dir, Duration::from_millis(10), bad_peer);
        assert!(post_approval(hub.addr(), "kill").is_err());
        assert!(!hub.killed());
        assert_eq!(hub.decide(&request(), "now").actor, "timeout");
        assert_eq!(hub.take_rejected_peers(), vec![APPROVER + 1]);
        assert!(hub.take_rejected_peers().is_empty());
        drop(hub);
        cleanup(&dir);
    }

    // --- removed paths ---
    #[test]
    fn http_bearer_endpoint_is_gone_and_its_port_refuses_connections() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        for mode in [addr.to_string(), format!("http://{addr}/v1/approval")] {
            let channel = open_channel(&config(&mode, &[1000], false));
            assert!(refusal(channel.as_ref()).contains("only --approve unix:"));
            assert!(
                std::net::TcpStream::connect(addr).is_err(),
                "nothing listens on {addr}"
            );
        }
        assert!(post_approval(&addr.to_string(), "kill")
            .unwrap_err()
            .contains("unix:"));
        assert!(
            std::env::var_os("SIDGED_APPROVAL_SECRET_FILE").is_none()
                || post_approval(&addr.to_string(), "kill").is_err()
        );
    }
    #[test]
    fn no_tty_approval_path() {
        for local in [false, true] {
            let channel = open_channel(&config("tty", &[1000], local));
            let reason = refusal(channel.as_ref());
            assert!(!reason.contains("--approve tty"), "{reason}");
            assert!(!channel.decide(&request(), "now").granted);
        }
    }
    #[test]
    fn socket_without_approve_uid_or_agents_fails_closed() {
        let dir = provisioned(0o2750);
        let mode = format!("unix:{}", dir.join("control.sock").display());
        let mut c = config(&mode, &[1000], false);
        c.approver = None;
        assert!(refusal(open_channel(&c).as_ref()).contains("--approve-uid"));
        let none: [u32; 0] = [];
        assert!(
            refusal(open_channel(&config(&mode, &none, false)).as_ref()).contains("--agent-uid")
        );
        assert!(!dir.join("control.sock").exists());
        cleanup(&dir);
    }
    #[test]
    fn local_mode_opens_no_socket() {
        let dir = provisioned(0o2750);
        let mode = format!("unix:{}", dir.join("control.sock").display());
        let channel = open_channel(&config(&mode, &[1000], true));
        assert!(refusal(channel.as_ref()).contains("local mode"));
        assert!(!dir.join("control.sock").exists());
        cleanup(&dir);
    }
    #[test]
    fn same_uid_on_the_socket_is_refused() {
        // In tests the parent (cargo) shares our uid, so the real bind refuses too.
        let dir = provisioned(0o2750);
        let mode = format!("unix:{}", dir.join("control.sock").display());
        let mut c = config(&mode, &[1000], false);
        c.approver = Some(me());
        assert!(refusal(open_channel(&c).as_ref()).contains("Core uid"));
        assert!(!dir.join("control.sock").exists());
        cleanup(&dir);
    }

    // --- decision logic over the socket ---
    fn exchange(change: impl FnOnce(&mut ApprovalRequest)) -> ApprovalDecision {
        let dir = provisioned(0o2750);
        let hub = hub(&dir, Duration::from_millis(300), ok_peer);
        let r = request();
        let mut echo = r.clone();
        change(&mut echo);
        post_approval(hub.addr(), &response(&echo)).unwrap();
        let decision = hub.decide(&r, "now");
        drop(hub);
        cleanup(&dir);
        decision
    }
    #[test]
    fn valid_bound_approval() {
        let d = exchange(|_| {});
        assert!(d.granted);
        assert_eq!(d.actor, "approver");
    }
    #[test]
    fn mismatched_bindings_are_denied() {
        assert!(!exchange(|r| r.plan_digest = "wrong".into()).granted);
        assert!(!exchange(|r| r.step = "other".into()).granted);
        assert!(!exchange(|r| r.capability = "other".into()).granted);
        assert!(!exchange(|r| r.args_digest = "wrong".into()).granted);
    }
    #[test]
    fn replay_timeout_kill_stale_and_shutdown() {
        let dir = provisioned(0o2750);
        let hub = Arc::new(hub(&dir, Duration::from_millis(300), ok_peer));
        let r = request();
        post_approval(hub.addr(), &response(&r)).unwrap();
        assert!(hub.decide(&r, "now").granted);
        post_approval(hub.addr(), &response(&r)).unwrap();
        assert!(!hub.decide(&r, "now").granted, "replayed nonce");
        let next = request();
        post_approval(hub.addr(), &response(&r)).unwrap();
        post_approval(hub.addr(), &response(&next)).unwrap();
        assert!(hub.decide(&next, "now").granted);
        assert!(hub.take_stale_responses() >= 1);
        post_approval(
            hub.addr(),
            &response(&request()).replacen("approve", "deny", 1),
        )
        .unwrap();
        assert!(!hub.decide(&request(), "now").granted);
        post_approval(hub.addr(), "approve ada").unwrap();
        assert!(!hub.decide(&request(), "now").granted, "legacy unbound");
        assert_eq!(hub.decide(&request(), "now").actor, "timeout");
        hub.shutdown();
        assert_eq!(
            hub.decide(&request(), "now").actor,
            "approval channel closed"
        );
        let addr = hub.addr().to_string();
        let sender = thread::spawn(move || post_approval(&addr, "kill"));
        let _ = sender.join();
        drop(hub);
        cleanup(&dir);
    }
    #[test]
    fn kill_interrupts_a_waiting_approval() {
        let dir = provisioned(0o2750);
        let hub = hub(&dir, Duration::from_secs(2), ok_peer);
        let addr = hub.addr().to_string();
        let sender = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            post_approval(&addr, "kill").unwrap()
        });
        assert_eq!(hub.decide(&request(), "now").actor, "kill-switch");
        sender.join().unwrap();
        assert!(hub.killed());
        drop(hub);
        cleanup(&dir);
    }
    #[test]
    fn nonce_is_fresh_and_digest_is_canonical() {
        let a = ApprovalRequest::new("plan", "s", "c", &serde_json::json!({"a":1,"b":2})).unwrap();
        let b = ApprovalRequest::new(
            "plan",
            "s",
            "c",
            &serde_json::from_str("{\"b\":2,\"a\":1}").unwrap(),
        )
        .unwrap();
        assert_eq!(
            a.args_digest,
            "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
        );
        assert_eq!(a.args_digest, b.args_digest);
        assert_ne!(a.nonce, b.nonce);
    }

    // --- 2ec8992 R9c: sticky ancestors, setgid/umask socket, all non-approver uids, helpers ---
    #[test]
    fn approval_dir_under_sticky_tmp_is_refused() {
        let base = std::env::temp_dir().join(format!(
            "sidged-sticky-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let dir = base.join("approval");
        let umask = UMASK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::fs::create_dir_all(&dir).unwrap();
        drop(umask);
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        let sticky = std::fs::metadata(std::env::temp_dir()).unwrap().mode() & 0o1000 != 0;
        let result = open_approval_dir(&dir, me(), my_gid(), &[]);
        std::fs::remove_dir_all(&base).unwrap();
        if sticky {
            assert!(result.unwrap_err().contains("ancestor"));
        }
    }
    #[test]
    fn socket_is_0660_core_approver_via_setgid_dir_and_umask() {
        let dir = provisioned(0o2750);
        let dir_fd = open_approval_dir(&dir, me(), my_gid(), &[]).unwrap();
        let path = dir.join("control.sock");
        let listener = bind_socket(&dir_fd, &path, me(), my_gid()).unwrap();
        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(
            (meta.mode() & 0o777, meta.uid(), meta.gid()),
            (0o660, me(), my_gid())
        );
        assert_eq!(BIND_UMASK, 0o117);
        drop(listener);
        cleanup(&dir);
    }
    #[test]
    fn socket_with_the_wrong_group_after_bind_is_refused_and_removed() {
        let dir = provisioned(0o2750);
        let dir_fd = open_approval_dir(&dir, me(), my_gid(), &[]).unwrap();
        let path = dir.join("control.sock");
        let err = bind_socket(&dir_fd, &path, me(), my_gid() + 1).unwrap_err();
        assert!(err.contains("0660"), "{err}");
        assert!(
            std::fs::symlink_metadata(&path).is_err(),
            "refused socket is unlinked"
        );
        cleanup(&dir);
    }
    #[test]
    fn a_missing_id_helper_refuses() {
        assert!(id_groups_with(None, "agent")
            .unwrap_err()
            .contains("/usr/bin/id"));
        if let Some(cmd) = trusted_command("id") {
            let name = user_name(me()).unwrap();
            assert!(id_groups_with(Some(cmd), &name)
                .unwrap()
                .contains(&my_gid()));
        }
    }
    #[test]
    fn non_approver_uid_in_core_or_approver_group_is_refused() {
        assert!(privileged_group(4000, &[100, 2001], 1001, 2001).is_some());
        assert!(privileged_group(4000, &[100, 1001], 1001, 2001).is_some());
        assert!(privileged_group(4000, &[100], 1001, 2001).is_none());
    }
    #[test]
    fn switch_to_the_core_uid_is_a_hit_for_sudo_and_doas() {
        let targets = switch_targets(&[("approver", 2001), ("sidged-core", 1001)]);
        assert!(sudo_switch("    (sidged-core) /bin/sh\n", &targets).is_some());
        assert!(sudo_switch("    (#1001) /bin/sh\n", &targets).is_some());
        assert!(sudo_switch("    (backup) /bin/tar\n", &targets).is_none());
        let who = ["llama".to_string(), "4000".to_string()];
        assert!(doas_switch("permit llama as sidged-core\n", &who, &[], &targets).is_some());
        assert!(doas_switch("permit llama as 1001\n", &who, &[], &targets).is_some());
    }
    #[test]
    fn helpers_only_at_fixed_paths_with_cleared_env() {
        assert_eq!(HELPERS, ["/usr/bin/sudo", "/usr/bin/doas", "/usr/bin/id"]);
        if let Some(cmd) = trusted_command("id") {
            assert_eq!(cmd.get_program(), "/usr/bin/id");
            let envs: Vec<_> = cmd.get_envs().collect();
            assert!(envs.iter().any(|(k, v)| *k == "PATH"
                && *v == Some(std::ffi::OsStr::new("/usr/sbin:/usr/bin:/sbin:/bin"))));
        }
        assert!(trusted_command("ls").is_none(), "not a whitelisted helper");
        assert!(trusted_command("../bin/sh").is_none());
    }
    // --- sudoers/doas parsed directly; umask guard; R9c attestation ---
    fn subject(name: &str, uid: u32, groups: &[(&str, u32)]) -> Subject {
        Subject {
            name: name.into(),
            uid,
            groups: groups.iter().map(|(n, _)| n.to_string()).collect(),
            gids: groups.iter().map(|(_, g)| *g).collect(),
        }
    }
    fn sudoers(text: &str) -> HostRules {
        HostRules {
            sudoers: vec![("/etc/sudoers".into(), Ok(text.into()))],
            doas: None,
        }
    }
    #[test]
    fn debian_without_doas_or_sudo_is_clean_not_operator_attested() {
        let agent = [subject("agent", 1000, &[("agent", 1000)])];
        let targets = switch_targets(&[("approver", 2001), ("sidged-core", 1001)]);
        assert_eq!(
            evaluate_switch(&HostRules::default(), &agent, &targets),
            Switch::Clean
        );
        // A missing binary is never unclear by itself; only rules decide.
        assert_eq!(
            evaluate_switch(
                &sudoers(
                    "root ALL=(ALL:ALL) ALL\nDefaults env_reset\n#includedir /etc/sudoers.d\n"
                ),
                &agent,
                &targets
            ),
            Switch::Clean
        );
    }
    #[test]
    fn sudoers_rules_are_parsed_directly() {
        let agent = [subject("agent", 1000, &[("agent", 1000), ("wheel", 10)])];
        let targets = switch_targets(&[("approver", 2001), ("sidged-core", 1001)]);
        let verdict = |text: &str| evaluate_switch(&sudoers(text), &agent, &targets);
        for hit in [
            "agent ALL=(ALL) NOPASSWD: ALL\n",
            "%wheel ALL=(root) ALL\n",
            "agent ALL=/bin/ls\n",
            "ALL ALL=(ALL) ALL\n",
            "#1000 ALL=(sidged-core) ALL\n",
            "agent host1=(approver) /usr/bin/sidged\n",
            "%#10 ALL=(#2001) ALL\n",
            "agent ALL=(backup:wheel) /bin/tar, (approver) /bin/sh\n",
        ] {
            assert!(matches!(verdict(hit), Switch::Hit(_)), "{hit}");
        }
        for clean in [
            "agent ALL=(backup) /bin/tar\n",
            "other ALL=(ALL) ALL\n",
            "# agent ALL=(ALL) ALL\n",
        ] {
            assert_eq!(verdict(clean), Switch::Clean, "{clean}");
        }
        for unclear in [
            "User_Alias ADMINS = agent\nADMINS ALL=(ALL) ALL\n",
            "Runas_Alias R = approver\n",
            "@include /opt/extra\n",
            "agent ALL=(ALL) \\\n  ALL\n",
            "!agent ALL=(ALL) ALL\n",
            "this is not sudoers\n",
        ] {
            assert!(matches!(verdict(unclear), Switch::Unclear(_)), "{unclear}");
        }
        let unreadable = HostRules {
            sudoers: vec![("/etc/sudoers".into(), Err("permission denied".into()))],
            doas: None,
        };
        assert!(matches!(
            evaluate_switch(&unreadable, &agent, &targets),
            Switch::Unclear(_)
        ));
    }
    #[test]
    fn doas_conf_is_parsed_directly_without_the_binary() {
        let agent = [subject("agent", 1000, &[("wheel", 10)])];
        let targets = switch_targets(&[("approver", 2001)]);
        let doas = |conf: Result<String, String>| HostRules {
            sudoers: vec![],
            doas: Some(conf),
        };
        assert!(matches!(
            evaluate_switch(&doas(Ok("permit :wheel\n".into())), &agent, &targets),
            Switch::Hit(_)
        ));
        assert_eq!(
            evaluate_switch(
                &doas(Ok("permit agent as backup\n".into())),
                &agent,
                &targets
            ),
            Switch::Clean
        );
        assert!(matches!(
            evaluate_switch(&doas(Err("unreadable".into())), &agent, &targets),
            Switch::Unclear(_)
        ));
        assert!(matches!(
            evaluate_switch(&doas(Ok("permit {\n".into())), &agent, &targets),
            Switch::Unclear(_)
        ));
    }
    #[test]
    fn sudoers_d_skips_files_sudo_skips() {
        assert!(sudoers_d_included("90-agents"));
        assert!(
            !sudoers_d_included("README.txt"),
            "names with a dot are skipped by sudo"
        );
        assert!(!sudoers_d_included("agents~"));
    }
    /// Reads the umask without changing it for others: callers hold
    /// UMASK_LOCK, the same lock bind_socket takes (no parallel-test race).
    fn current_umask_locked() -> libc::mode_t {
        let old = unsafe { libc::umask(0o022) };
        unsafe { libc::umask(old) };
        old
    }
    fn current_umask() -> libc::mode_t {
        let _held = UMASK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        current_umask_locked()
    }
    #[test]
    fn umask_is_restored_after_successful_and_failed_binds() {
        let dir = provisioned(0o2750);
        let dir_fd = open_approval_dir(&dir, me(), my_gid(), &[]).unwrap();
        let before = {
            let _held = UMASK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let before = current_umask_locked();
            assert_ne!(before, BIND_UMASK);
            let guard = UmaskGuard::set(BIND_UMASK);
            assert_eq!(current_umask_locked(), BIND_UMASK);
            drop(guard);
            assert_eq!(current_umask_locked(), before);
            before
        };
        let ok = bind_socket(&dir_fd, &dir.join("ok.sock"), me(), my_gid());
        assert!(ok.is_ok());
        assert_eq!(current_umask(), before, "after a successful bind");
        let wrong_group = bind_socket(&dir_fd, &dir.join("bad.sock"), me(), my_gid() + 1);
        assert!(wrong_group.is_err());
        assert_eq!(current_umask(), before, "after a refused bind");
        let missing = bind_socket(&dir_fd, &dir.join("absent/x.sock"), me(), my_gid());
        assert!(missing.is_err());
        assert_eq!(current_umask(), before, "after a failed bind(2)");
        drop(ok);
        cleanup(&dir);
    }
    #[test]
    fn r9c_attestation_lists_what_is_not_detected() {
        let text = r9c_attestation_text();
        assert!(text.starts_with("attestation=R9c undetected="), "{text}");
        for item in [
            "su-password",
            "stored-credentials",
            "keys",
            "setuid-helpers",
            "container-runtimes",
            "sudo-doas-other-paths",
        ] {
            assert!(text.contains(item), "{item}: {text}");
        }
        assert!(!text.contains(OPERATOR_ATTESTED));
        let dir = provisioned(0o2750);
        let hub = hub(&dir, Duration::from_millis(10), ok_peer);
        assert_eq!(hub.r9c_attestation().as_deref(), Some(text.as_str()));
        assert_eq!(
            hub.attestation(),
            None,
            "attestation=R9c is separate from operator-attested"
        );
        assert!(hub.take_channel_start().is_some());
        assert!(hub.take_channel_start().is_none(), "start is audited once");
        drop(hub);
        cleanup(&dir);
    }

    // --- lead decision: unclear sudo/doas refuses unless --operator-attest ---
    #[test]
    fn unclear_rules_refuse_without_operator_attest() {
        let unclear = vec!["sudoers unreadable".to_string()];
        let err = attestation_verdict(&unclear, false).unwrap_err();
        assert!(
            err.contains("--operator-attest") && err.contains("sudoers unreadable"),
            "{err}"
        );
    }
    #[test]
    fn operator_attest_allows_and_labels_every_approval() {
        let unclear = vec!["sudoers unreadable".to_string()];
        assert_eq!(
            attestation_verdict(&unclear, true),
            Ok(Some(OPERATOR_ATTESTED))
        );
        assert_eq!(attestation_verdict(&[], true), Ok(Some(OPERATOR_ATTESTED)));
    }
    #[test]
    fn no_automatic_operator_attested_label() {
        assert_eq!(attestation_verdict(&[], false), Ok(None));
    }
    #[test]
    fn channel_without_non_approver_uids_is_refused() {
        let dir = provisioned(0o2750);
        let mode = format!("unix:{}", dir.join("control.sock").display());
        let mut c = config(&mode, &[], false);
        c.operator_attest = true;
        let why = refusal(open_channel(&c).as_ref());
        assert!(why.contains("--non-approver-uid"), "{why}");
        assert!(!dir.join("control.sock").exists());
        cleanup(&dir);
    }

    // --- D4: no extra threads at bind time (checked in the real binary) ---
    #[test]
    fn single_thread_check_is_a_hard_refusal_in_every_build() {
        // Not a debug_assert: release builds refuse too.
        assert!(require_single_threaded_with(1).is_ok());
        let err = require_single_threaded_with(2).unwrap_err();
        assert!(err.contains("2 threads"), "{err}");
        assert!(
            require_single_threaded_with(0).is_err(),
            "unreadable /proc refuses"
        );
    }

    #[test]
    fn single_thread_violation_is_reported_for_extra_threads() {
        assert_eq!(single_thread_violation(1), None);
        let why = single_thread_violation(3).unwrap();
        assert!(why.contains("3 threads"), "{why}");
        assert!(task_count() >= 1);
    }
}

#[cfg(test)]
mod r9c_scan_tests {
    //! 0004 R9c: a blind process scan (hidepid without the gid= group, no
    //! foreign uid visible, an unreadable status) refuses the channel.
    use super::{r9c_proc_scan, ProcSource};
    use std::path::PathBuf;

    const CORE: u32 = 2000;
    const AGENT: u32 = 1001;
    const PROCVIEW: u32 = 3000;
    const PTRACE: u64 = 1 << 19;

    struct FakeProc(PathBuf);
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    /// One directory level, 0700 set explicitly (independent of the umask).
    fn mkdir(p: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir(p).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    /// A file, 0644 set explicitly (independent of the umask).
    fn write(p: &std::path::Path, text: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(p, text).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    impl FakeProc {
        /// A fresh fixture per call: tag + pid + counter, never shared.
        fn new(tag: &str, proc_opts: Option<&str>) -> Self {
            let d = std::env::temp_dir().join(format!(
                "sidged-r9c-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            ));
            mkdir(&d);
            mkdir(&d.join("proc"));
            let mut mi = String::from("21 26 0:20 / /sys rw,nosuid shared:7 - sysfs sysfs rw\n");
            if let Some(opts) = proc_opts {
                mi.push_str(&format!(
                    "22 26 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc {opts}\n"
                ));
            }
            write(&d.join("mountinfo"), &mi);
            FakeProc(d)
        }
        fn process(&self, pid: u32, uid: u32, cap: u64) -> &Self {
            let p = self.0.join("proc").join(pid.to_string());
            mkdir(&p);
            write(
                &p.join("status"),
                &format!("Name:\tx\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nCapEff:\t{cap:016x}\n"),
            );
            self
        }
        fn unreadable(&self, pid: u32) -> &Self {
            // a directory in place of the file: unreadable even for root
            let p = self.0.join("proc").join(pid.to_string());
            mkdir(&p);
            mkdir(&p.join("status"));
            self
        }
        fn source(&self) -> ProcSource {
            ProcSource {
                root: self.0.join("proc"),
                mountinfo: self.0.join("mountinfo"),
            }
        }
        fn scan(&self, groups: &[u32]) -> Result<usize, String> {
            r9c_proc_scan(&self.source(), CORE, groups, &[AGENT]).map(|t| t.len())
        }
    }
    impl Drop for FakeProc {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn incomplete(r: Result<usize, String>) -> bool {
        r.is_err_and(|e| e.starts_with("approval_scan_incomplete"))
    }

    #[test]
    fn hidepid_without_the_gid_group_refuses() {
        for opts in [
            "rw,hidepid=2,gid=3000",
            "rw,hidepid=invisible,gid=3000",
            "rw,hidepid=1",
        ] {
            let f = FakeProc::new("nogroup", Some(opts));
            f.process(1, 0, 0).process(50, CORE, 0);
            assert!(incomplete(f.scan(&[CORE])), "{opts}");
        }
    }

    #[test]
    fn hidepid_with_group_and_a_ptrace_capable_agent_refuses() {
        let f = FakeProc::new("ptrace", Some("rw,hidepid=2,gid=3000"));
        f.process(1, 0, 0)
            .process(40, AGENT, PTRACE)
            .process(50, CORE, 0);
        let e = f.scan(&[CORE, PROCVIEW]).unwrap_err();
        assert!(e.contains("CAP_SYS_PTRACE"), "{e}");
    }

    #[test]
    fn hidepid_with_group_and_clean_is_ok() {
        let f = FakeProc::new("clean", Some("rw,hidepid=2,gid=3000"));
        f.process(1, 0, 0)
            .process(40, AGENT, 0)
            .process(50, CORE, 0);
        assert_eq!(f.scan(&[CORE, PROCVIEW]), Ok(3));
    }

    // Flake fix: another test may hold the process-wide bind umask (0117)
    // while this fixture is built; the fixture must not depend on the umask.
    #[test]
    fn fixture_is_independent_of_the_process_umask() {
        let _lock = super::UMASK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _umask = super::UmaskGuard::set(super::BIND_UMASK);
        let f = FakeProc::new("umask", Some("rw"));
        f.process(1, 0, 0).process(50, CORE, 0);
        assert_eq!(f.scan(&[CORE]), Ok(2));
    }

    #[test]
    fn no_hidepid_and_clean_is_ok() {
        for opts in [Some("rw"), Some("rw,hidepid=0"), Some("rw,hidepid=off")] {
            let f = FakeProc::new("plain", opts);
            f.process(1, 0, 0).process(50, CORE, 0);
            assert_eq!(f.scan(&[CORE]), Ok(2), "{opts:?}");
        }
    }

    #[test]
    fn an_unreadable_status_refuses() {
        let f = FakeProc::new("unreadable", Some("rw"));
        f.process(1, 0, 0).process(50, CORE, 0).unreadable(60);
        assert!(incomplete(f.scan(&[CORE])));
    }

    #[test]
    fn no_foreign_uid_visible_refuses() {
        let f = FakeProc::new("alone", Some("rw"));
        f.process(50, CORE, 0).process(51, CORE, 0);
        assert!(incomplete(f.scan(&[CORE])));
    }

    #[test]
    fn missing_proc_mount_or_mountinfo_refuses() {
        let f = FakeProc::new("nomount", None);
        f.process(1, 0, 0).process(50, CORE, 0);
        assert!(incomplete(f.scan(&[CORE])));
        let mut src = f.source();
        src.mountinfo = f.0.join("absent");
        assert!(r9c_proc_scan(&src, CORE, &[CORE], &[AGENT]).is_err());
    }

    #[test]
    fn root_core_sees_everything_under_hidepid() {
        let f = FakeProc::new("root", Some("rw,hidepid=2"));
        f.process(1, 0, 0).process(40, AGENT, 0);
        assert_eq!(
            r9c_proc_scan(&f.source(), 0, &[0], &[AGENT]).map(|t| t.len()),
            Ok(2)
        );
    }
}

#[cfg(test)]
#[path = "approval_standing_tests.rs"]
mod standing_tests;
