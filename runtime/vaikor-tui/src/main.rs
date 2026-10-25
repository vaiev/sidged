//! `vaikor-tui` Demo 1 (unsigned preview, no provenance).
//!
//! Core + TUI (demo user):
//!   vaikor-tui run --log <file> --log-key <hexfile> --grant <token.json>
//!     --trusted-issuer <did> --approve unix:<path> --approve-uid <uid>
//!     --non-approver-uid <uid>[,..] [--approve-timeout <s>] [--operator-attest]
//!     [--task <text>] [--seconds <n>] [--gemini-project <id>] [--policy <cedar>]
//!     --audience <aud> (or VAIKOR_AUDIENCE)
//!   provider: Gemini (cloud call) via vaikor-gateway; project id from
//!   --gemini-project or VAIKOR_GEMINI_PROJECT (required).
//!   key: VAIKOR_API_KEY_FILE only (0600, own uid, no symlink).
//! Approver (second terminal, approver uid):
//!   vaikor-tui approve unix:<path>
//!   vaikor-tui revoke unix:<path> <64hex|*>
//! Audit tools (non-interactive):
//!   vaikor-tui log-pubkey --log-key <PATH>
//!   (verify with: vaikor log verify <file> --public <hex>, 0005 R7)
//! TTY keys in the TUI: a = show privacy report + request approval, q = quit.
use std::io::{BufRead, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use vaikor_tui::{key_action, load_key, render, App, Core, CoreConfig, GatewaySender, KeyAction};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("log-pubkey") => vaikor_tui::logkey::log_pubkey_command(&args[1..]),
        Some("run") => run(&args[1..]),
        Some("approve") => approve(&args[1..]),
        Some("revoke") => revoke(&args[1..]),
        Some("issue-grant") => issue_grant(&args[1..]),
        _ => Err("usage: vaikor-tui run ... | vaikor-tui approve unix:<path> | vaikor-tui revoke unix:<path> <64hex|*> | vaikor-tui log-pubkey --log-key <PATH> (see --help in source header)".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vaikor-tui: {e}");
            ExitCode::from(1)
        }
    }
}

fn value<'a>(args: &'a [String], i: &mut usize, name: &str) -> Result<&'a str, String> {
    *i += 1;
    args.get(*i)
        .map(String::as_str)
        .ok_or(format!("{name} needs a value"))
}

fn read_seed(path: &str) -> Result<[u8; 32], String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("--log-key: {}", e.kind()))?;
    let t = text.trim();
    if t.len() != 64 {
        return Err("log key must be 32 bytes hex".into());
    }
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = u8::from_str_radix(&t[2 * i..2 * i + 2], 16).map_err(|_| "log key must be hex")?;
    }
    Ok(seed)
}

fn run(args: &[String]) -> Result<(), String> {
    vaikor_tui::require_build_sha(vaikor_tui::GIT_SHA)?;
    vaikor_tui::check_run_flags(args)?;
    // SAFETY: isatty has no preconditions.
    vaikor_tui::require_tty(
        unsafe { libc::isatty(0) } == 1,
        unsafe { libc::isatty(1) } == 1,
    )?;
    vaikor_cli::harden_process()?;
    let (mut log, mut log_key, mut grant, mut approve) = (None, None, None, None);
    let (mut issuers, mut agents, mut approver) = (Vec::new(), Vec::new(), None);
    let (mut timeout, mut attest) = (Duration::from_secs(120), false);
    let (mut task, mut secs) = ("Ship Demo 1".to_string(), 25 * 60u64);
    let mut project: Option<String> = None;
    let mut policy_file: Option<String> = None;
    let mut audience: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--log" => log = Some(PathBuf::from(value(args, &mut i, "--log")?)),
            "--log-key" => log_key = Some(read_seed(value(args, &mut i, "--log-key")?)?),
            "--grant" => grant = Some(value(args, &mut i, "--grant")?.to_string()),
            "--trusted-issuer" => {
                issuers.push(value(args, &mut i, "--trusted-issuer")?.to_string())
            }
            "--approve" => approve = Some(value(args, &mut i, "--approve")?.to_string()),
            "--approve-uid" => {
                approver = Some(
                    value(args, &mut i, "--approve-uid")?
                        .parse::<u32>()
                        .map_err(|_| "--approve-uid: invalid")?,
                )
            }
            "--non-approver-uid" | "--agent-uid" => agents.extend(vaikor_cli::parse_uid_list(
                value(args, &mut i, "--non-approver-uid")?,
            )?),
            "--approve-timeout" => {
                timeout = Duration::from_secs(
                    value(args, &mut i, "--approve-timeout")?
                        .parse()
                        .map_err(|_| "--approve-timeout: invalid")?,
                )
            }
            "--operator-attest" => attest = true,
            "--gemini-project" => {
                project = Some(value(args, &mut i, "--gemini-project")?.to_string())
            }
            "--policy" => policy_file = Some(value(args, &mut i, "--policy")?.to_string()),
            "--audience" => audience = Some(value(args, &mut i, "--audience")?.to_string()),
            "--task" => task = value(args, &mut i, "--task")?.to_string(),
            "--seconds" => {
                secs = value(args, &mut i, "--seconds")?
                    .parse()
                    .map_err(|_| "--seconds: invalid")?
            }
            other => return Err(format!("unknown argument {other}")),
        }
        i += 1;
    }
    let grant_doc: Option<serde_json::Value> = match &grant {
        Some(p) => Some(
            serde_json::from_str(
                &std::fs::read_to_string(p).map_err(|e| format!("--grant: {}", e.kind()))?,
            )
            .map_err(|_| "--grant: invalid JSON")?,
        ),
        None => None,
    };
    // Owner policy (Cedar): --policy <file>, default the built-in demo policy.
    let policy = match &policy_file {
        Some(p) => std::fs::read_to_string(p).map_err(|e| format!("--policy: {}", e.kind()))?,
        None => vaikor_tui::DEMO_POLICY.to_string(),
    };
    let key = load_key(
        std::env::var("VAIKOR_API_KEY").ok(),
        std::env::var_os("VAIKOR_API_KEY_FILE").as_deref(),
    );
    // The channel binds its socket in the single-threaded start phase (R9c).
    vaikor_cli::require_single_threaded()?;
    let channel = vaikor_cli::open_channel(&vaikor_cli::ChannelConfig {
        mode: approve.as_deref(),
        timeout,
        approver,
        agents: &agents,
        local: false,
        operator_attest: attest,
    });
    if let Some(reason) = channel.refusal() {
        eprintln!("{reason}");
    }
    let project = vaikor_tui::require_project(
        project
            .or_else(|| std::env::var("VAIKOR_GEMINI_PROJECT").ok())
            .as_deref(),
    )?;
    let sender = GatewaySender {
        step: Default::default(),
        project,
    };
    let mut core = Core::open(
        CoreConfig {
            log_path: log.as_deref(),
            log_seed: log_key,
            grant: grant_doc.as_ref(),
            trusted_issuers: issuers,
            policy: Some(&policy),
            audience: audience.or_else(|| std::env::var("VAIKOR_AUDIENCE").ok()),
            now: None,
        },
        channel.as_ref(),
        &sender,
    )?;
    let mut app = App::new(&task, secs);
    app.set_operator_attested(channel.attestation() == Some(vaikor_cli::OPERATOR_ATTESTED));
    let start = Instant::now();
    let mut terminal = ratatui::init();
    let result = (|| -> std::io::Result<()> {
        loop {
            app.tick(start.elapsed().as_secs());
            terminal.draw(|f| render(&app, f))?;
            if app.awaiting_approval() {
                // The report is on screen now; the Core asks the approver.
                let _ = app.ask_cloud(&mut core, key.as_ref().ok());
                continue;
            }
            if event::poll(Duration::from_millis(250))? {
                if let Event::Key(k) = event::read()? {
                    if k.kind != KeyEventKind::Press {
                        continue;
                    }
                    if let KeyCode::Char(c) = k.code {
                        match key_action(c) {
                            KeyAction::Quit => return Ok(()),
                            KeyAction::RequestApproval => app.request_approval(),
                            KeyAction::None => {}
                        }
                    }
                }
            }
        }
    })();
    ratatui::restore();
    channel.shutdown();
    result.map_err(|e| e.to_string())
}

/// Approver client: shows the pending binding and answers on the socket.
fn approval_command(path: &str, line: &str) -> Result<String, String> {
    let mut stream = UnixStream::connect(path).map_err(|e| format!("connect: {}", e.kind()))?;
    stream
        .write_all(line.as_bytes())
        .map_err(|e| e.to_string())?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| e.to_string())?;
    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .map_err(|e| e.to_string())?;
    Ok(reply)
}

fn revoke(args: &[String]) -> Result<(), String> {
    let [socket, target] = args else {
        return Err("usage: vaikor-tui revoke unix:<path> <64hex|*>".into());
    };
    if target != "*" && (target.len() != 64 || !target.bytes().all(|b| b.is_ascii_hexdigit())) {
        return Err("revoke target must be 64 hex digits or *".into());
    }
    let path = socket
        .strip_prefix("unix:")
        .ok_or("revoke requires unix:<path>")?;
    let reply = approval_command(path, &format!("revoke {target}\n"))?;
    if reply.trim() != "ok" {
        return Err("revocation was not accepted".into());
    }
    println!("revoke: queued (the Core applies and audits the revocation)");
    Ok(())
}

fn approve(args: &[String]) -> Result<(), String> {
    let path = args
        .first()
        .and_then(|a| a.strip_prefix("unix:"))
        .ok_or("usage: vaikor-tui approve unix:<path>")?;
    let ask = |line: &str| approval_command(path, line);
    let pending: serde_json::Value =
        serde_json::from_str(ask("request\n")?.trim()).map_err(|_| "unreadable request")?;
    if pending.is_null() {
        return Err("no approval pending".into());
    }
    let f = |k: &str| pending[k].as_str().unwrap_or("").to_string();
    println!(
        "Approval request:\n  step: {}\n  capability: {}\n  args_sha256: {}\n  plan_digest: {}",
        f("step"),
        f("capability"),
        f("args_digest"),
        f("plan_digest")
    );
    let mut scope_digest = if let Some(scope) = pending.get("scope").filter(|s| !s.is_null()) {
        use sha2::{Digest, Sha256};
        let digest = format!(
            "{:x}",
            Sha256::digest(vaikor_grant::canonicalize(scope).as_bytes())
        );
        if pending["scope_digest"].as_str() != Some(digest.as_str()) {
            return Err("invalid standing scope digest".into());
        }
        println!("standing approval: {}", vaikor_grant::canonicalize(scope));
        format!(" {digest}")
    } else {
        String::new()
    };
    if scope_digest.is_empty() {
        print!("approve? [y/s = single call, N = deny] ");
    } else {
        print!("approve? [y = standing scope, s = single call, N = deny] ");
    }
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut answer)
        .map_err(|e| e.to_string())?;
    if answer.trim() == "s" {
        scope_digest.clear(); // 0004 R9b: omit the scope binding for one call.
    }
    let verb = if matches!(answer.trim(), "y" | "s") {
        "approve"
    } else {
        "deny"
    };
    let line = format!(
        "{verb} approver {} {} {} {} {}{scope_digest}\n",
        f("step"),
        f("capability"),
        f("args_digest"),
        f("nonce"),
        f("plan_digest")
    );
    let reply = ask(&line)?;
    println!("{verb}: {}", reply.trim());
    Ok(())
}

/// `vaikor-tui issue-grant --issuer-key <file> --holder <did:key> --audience <id>
/// [--minutes <1..60>] [--messages <n>]`: prints the signed grant JSON. The key
/// file must be 0600, owned by the caller, not a symlink.
fn issue_grant(args: &[String]) -> Result<(), String> {
    use vaikor_tui::issue::*;
    let (mut key, mut holder, mut audience) = (None, None, None);
    let (mut lifetime, mut messages) = (DEFAULT_LIFETIME_SECS, 1u64);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--issuer-key" => key = Some(value(args, &mut i, "--issuer-key")?.to_string()),
            "--holder" => holder = Some(value(args, &mut i, "--holder")?.to_string()),
            "--audience" => audience = Some(value(args, &mut i, "--audience")?.to_string()),
            "--minutes" => lifetime = minutes_to_secs(value(args, &mut i, "--minutes")?)?,
            "--messages" => {
                messages = value(args, &mut i, "--messages")?
                    .parse()
                    .map_err(|_| "--messages: invalid")?
            }
            other => return Err(format!("unknown argument {other}")),
        }
        i += 1;
    }
    let key = key.ok_or("--issuer-key is required")?;
    // Same strict file checks as API keys: 0600, own uid, no symlink.
    let secret = vaikor_tui::ApiKey::from_file(std::path::Path::new(&key))?;
    let seed = parse_seed_hex(secret.expose())?;
    let grant = issue_cloud_grant(
        &seed,
        &GrantOptions {
            holder: holder.ok_or("--holder is required")?,
            audience: vaikor_tui::require_audience(
                audience
                    .or_else(|| std::env::var("VAIKOR_AUDIENCE").ok())
                    .as_deref(),
            )?,
            now: vaikor_gateway::utc_stamp(),
            lifetime_secs: lifetime,
            messages,
        },
    )?;
    println!("{grant}");
    Ok(())
}
