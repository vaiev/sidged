//! `sidged run` checks a plan. `sidged guard` runs the CH residency scenario.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use sidged_cli::{execute, parse_run_args, post_approval, ApprovalChannel, RunInput};
use sidged_grant::run_grant_vectors;
use sidged_guard::{run_from_env_with_credential, LogTarget};
use sidged_log::verify_file;

fn main() -> ExitCode {
    // 0004 R9c: no core dumps, no same-uid ptrace attach of the Core.
    if let Err(message) = sidged_cli::harden_process() {
        eprintln!("sidged: cannot set PR_SET_DUMPABLE 0: {message}");
        return ExitCode::from(2);
    }
    let args: Vec<String> = env::args().skip(1).collect();
    if let Err(message) = refuse_local_approval(&args) {
        eprintln!("sidged: {message}");
        return ExitCode::from(2);
    }
    match args.first().map(String::as_str) {
        Some("keygen") => keygen(&args[1..]),
        Some("init") => init_cmd(&args[1..]),
        Some("task") => task_cmd(&args[1..]),
        Some("mandate") => mandate_cmd(&args[1..]),
        Some("record") => record_cmd(&args[1..]),
        Some("guard") => guard(&args[1..]),
        Some("run") => run(),
        Some("vectors") => vectors(&args[1..]),
        Some("kill") => kill(&args[1..]),
        Some("log") => log_cmd(&args[1..]),
        Some("swarm") => swarm_cmd(&args[1..]),
        Some("linguist-eval") => linguist_eval_cmd(&args[1..]),
        Some("--version" | "-V") => {
            println!(
                "sidged {} ({})",
                env!("CARGO_PKG_VERSION"),
                env!("SIDGED_GIT_SHA")
            );
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: sidged --version\n       sidged run <plan.json> <catalog.json> --policy <file> --grant <token.json> (--trusted-issuer <did> | --keys <dir>) (--holder-key <seed-file> | --dry-run) [--log-key <seed-file>] [--log <file>] [--approve unix:<path> --approve-uid <approver-uid> --non-approver-uid <uid>[,<uid>...] [--operator-attest]] [--approve-timeout <seconds>] [--audience <id>] [--now <utc>]\n       sidged keygen <new-directory>\n       sidged mandate renew --workspace <dir>   (interactive terminal only, typed confirmation; the owner key re-signs the node mandate for 30 days (0002 R23); renewal through the Trusted UI is WP 17)\n       sidged init [--config <file>] [--state-dir <dir>]   (interactive terminal only; writes the system config: local mode, ratified provider id + key file reference, approval uids, interface; no listener)\n       sidged guard <scenario-dir> [--keys <dir>] [--system-config <file>] --log <file> --log-key <key> [--local] [--approve unix:<path> --approve-uid <approver-uid> --non-approver-uid <uid>[,<uid>...] [--operator-attest]]\n       sidged kill <unix:path>\n       approval (0004 R9, R9c): a Unix socket only (no TTY, no HTTP endpoint); every connection's SO_PEERCRED uid must equal --approve-uid (never 0, never the Core uid); --non-approver-uid (alias --agent-uid) lists every agent, launcher, worker and model/llama uid explicitly and every R9c check applies to each; local mode (SIDGED_LOCAL=1, --local or config \"local\": true) refuses to start with any approval flag and denies consequential steps\n       operator requirements: provision only the approval directory, e.g. /run/sidged/approval/ for --approve unix:/run/sidged/approval/control.sock (owner = Core uid, group = approver gid, mode 2750 or 2710 (setgid); every ancestor owned by root or the Core, not group/world-writable, not sticky; no symlinks); the Core binds the socket itself with umask 0117 and refuses unless lstat shows 0660 core:approver; no non-approver uid may be in the core or approver group; run the Core under its own uid; non-approver uids must not be root, hold CAP_SYS_PTRACE, be in a root-equivalent group (docker, podman, lxd, incus, disk, libvirt), reach a rootful container socket, or sudo/doas to the approver, the core uid or root. Helpers run only as /usr/bin/sudo, /usr/bin/doas, /usr/bin/id with a cleared environment; a missing /usr/bin/id refuses; a missing sudo/doas binary is no switch path (the Core parses /etc/sudoers, /etc/sudoers.d/* and /etc/doas.conf itself); unreadable or ambiguous rules refuse the channel unless --operator-attest is given, and then every approval is audited as approval_binding=operator-attested; --non-approver-uid is repeatable and also read from config approval.non_approver_uids, and none refuses; every approval and the channel start are audited with attestation=R9c and the list of what is not detected\n       local mode model (0004 R9d, R9): SIDGED_PROVIDER=local with config key model.endpoint: model {{\"endpoint\": \"unix:<absolute path>\", \"uid\": <model uid>}} (default; SO_PEERCRED-checked, one connect, no bind/listen); model {{\"endpoint\": \"tcp:127.0.0.1:<port>\"}} is used only when set explicitly, never as an automatic fallback: no peer uid check, any local process that binds the port can serve or observe model traffic; its start is audited with this risk note\n       sidged log verify <file> --public <hex>\n       sidged vectors <test-vectors-dir>\n       sidged linguist-eval render-prompt|score|serve (--socket <path> | --config <config.json>)   (Model -1 release gate: JSONL rows on stdin, one JSON line per row on stdout; serve asks the local model endpoint)\n       sidged record write|read|delete|retention|import|expire --grant <token.json> --trusted-issuer <did> --policy <file> --log-key <key> [--store <dir>] [--log <file>]");
            ExitCode::from(2)
        }
    }
}

fn run() -> ExitCode {
    let mut args = Vec::new();
    let mut input = env::args().skip(1);
    while let Some(arg) = input.next() {
        if arg == "--keys" {
            let Some(dir) = input.next() else {
                eprintln!("--keys needs a directory");
                return ExitCode::from(2);
            };
            match sidged_guard::issuer_from_keys(Path::new(&dir)) {
                Ok(did) => args.extend(["--trusted-issuer".into(), did]),
                Err(message) => {
                    eprintln!("{message}");
                    return ExitCode::from(2);
                }
            }
        } else {
            args.push(arg);
        }
    }
    let parsed = match parse_run_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let plan: serde_json::Value = match fs::read_to_string(&parsed.plan)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
    {
        Some(value) => value,
        None => {
            eprintln!("could not read plan {}", parsed.plan);
            return ExitCode::from(1);
        }
    };
    let catalog: serde_json::Value = match fs::read_to_string(&parsed.catalog)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
    {
        Some(value) => value,
        None => {
            eprintln!("could not read catalog {}", parsed.catalog);
            return ExitCode::from(1);
        }
    };
    let policy = match fs::read_to_string(&parsed.policy) {
        Ok(text) => text,
        Err(_) => {
            eprintln!("could not read policy {}", parsed.policy);
            return ExitCode::from(1);
        }
    };
    let grant: serde_json::Value = match fs::read_to_string(&parsed.grant)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
    {
        Some(value) => value,
        None => {
            eprintln!("could not read grant {}", parsed.grant);
            return ExitCode::from(1);
        }
    };
    let trusted_refs: Vec<&str> = parsed.trusted_issuers.iter().map(String::as_str).collect();
    let timeout = Duration::from_secs(parsed.approve_timeout);
    let channel = match approval_channel(
        parsed.approve.as_deref(),
        timeout,
        parsed.approve_uid,
        &parsed.agent_uids,
        parsed.operator_attest,
        parsed.local || sidged_gateway::is_local(),
    ) {
        Ok(channel) => channel,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let seed = match read_seed(parsed.log_key.as_deref()) {
        Ok(seed) => seed,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let holder = match parsed
        .holder_key
        .as_deref()
        .map(|path| sidged_cli::engine::HolderKey::from_file(Path::new(path)))
        .transpose()
    {
        Ok(holder) => holder,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let resolved = match sidged_log::log_path(parsed.log.as_deref(), seed.is_some()) {
        Ok(path) => path,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let audit =
        resolved
            .as_deref()
            .zip(seed.as_ref())
            .map(|(path, seed)| sidged_cli::AuditTarget {
                path: Path::new(path),
                seed,
            });
    match execute(&RunInput {
        audit,
        dry_run: parsed.dry_run,
        plan: &plan,
        catalog: &catalog,
        policy: &policy,
        audience: &parsed.audience,
        grant: Some(&grant),
        holder: holder
            .as_ref()
            .map(|key| key as &dyn sidged_cli::engine::Presenter),
        now: parsed.now.as_deref(),
        region: None,
        trusted_issuers: &trusted_refs,
        approval: channel.as_ref(),
        provider: &parsed.provider,
        profile: &parsed.profile,
        local: parsed.local,
    }) {
        Ok(report) => {
            println!("capabilities {}", report.capabilities.len());
            println!("approvals {}", report.approvals.len());
            println!("privacy-reports {}", report.reports.len());
            println!("audit-events {}", report.events.len());
            ExitCode::SUCCESS
        }
        Err(failure) => {
            for event in failure
                .events
                .iter()
                .filter(|event| event.decision == "deny")
            {
                eprintln!("audit deny {} {}", event.step, event.capability);
            }
            eprintln!("{}", failure.message);
            ExitCode::from(1)
        }
    }
}

/// `sidged linguist-eval`: score Model -1 replies through the runtime linguist path
/// (`sidged_cli::linguist_eval`); `serve` asks the node's local model endpoint.
/// `--compact` selects the compact output (0017 L3a, L8) as `model.output` does in a node
/// config; with `--config` the config decides.
fn linguist_eval_cmd(args: &[String]) -> ExitCode {
    use sidged_cli::linguist::{IntentCatalog, LinguistOutput, LocalLinguist};
    use sidged_cli::linguist_eval::{run, Mode};
    const USAGE: &str = "usage: sidged linguist-eval render-prompt [--compact] | score | \
        serve (--socket <path> [--compact] | --config <config.json>)";
    let Some(mode) = args.first().and_then(|m| Mode::parse(m)) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let mut rest: Vec<&String> = args[1..].iter().collect();
    let compact = match rest.iter().position(|a| *a == "--compact") {
        Some(at) if matches!(mode, Mode::RenderPrompt | Mode::Serve) => {
            rest.remove(at);
            true
        }
        Some(_) => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
        None => false,
    };
    let form = if compact {
        LinguistOutput::Compact
    } else {
        LinguistOutput::Full
    };
    let rest: Vec<String> = rest.into_iter().cloned().collect();
    let config = match (mode, &rest[..]) {
        (Mode::RenderPrompt | Mode::Score, []) => None,
        // The socket serve-local-linguist.sh starts, served under this uid.
        (Mode::Serve, [flag, path]) if flag == "--socket" => Some(serde_json::json!({"model": {
            "endpoint": format!("unix:{path}"), "uid": unsafe { libc::geteuid() },
            "output": if compact { "compact" } else { "full" }}})),
        (Mode::Serve, [flag, file]) if flag == "--config" && !compact => {
            match fs::read_to_string(file)
                .map_err(|e| e.to_string())
                .and_then(|text| serde_json::from_str(&text).map_err(|e| e.to_string()))
            {
                Ok(config) => Some(config),
                Err(message) => {
                    eprintln!("sidged linguist-eval: {file}: {message}");
                    return ExitCode::from(2);
                }
            }
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let model = match config.as_ref().map(LocalLinguist::from_config) {
        None => None,
        Some(Ok(Some(model))) => Some(model),
        Some(Ok(None)) => {
            eprintln!("sidged linguist-eval: no model.endpoint configured");
            return ExitCode::from(2);
        }
        Some(Err(message)) => {
            eprintln!("sidged linguist-eval: {message}");
            return ExitCode::from(2);
        }
    };
    let catalog = match IntentCatalog::builtin() {
        Ok(catalog) => catalog,
        Err(message) => {
            eprintln!("sidged linguist-eval: {message}");
            return ExitCode::from(1);
        }
    };
    let model = model
        .as_ref()
        .map(|m| m as &dyn sidged_cli::linguist::LinguistModel);
    match run(
        &catalog,
        mode,
        form,
        model,
        std::io::stdin().lock(),
        std::io::stdout().lock(),
    ) {
        Ok(0) => ExitCode::SUCCESS,
        Ok(bad) => {
            eprintln!("sidged linguist-eval: {bad} malformed row(s)");
            ExitCode::from(1)
        }
        Err(message) => {
            eprintln!("sidged linguist-eval: {message}");
            ExitCode::from(1)
        }
    }
}

fn vectors(args: &[String]) -> ExitCode {
    let Some(dir) = args.first() else {
        eprintln!("usage: sidged vectors <test-vectors-dir>");
        return ExitCode::from(2);
    };
    match run_grant_vectors(&PathBuf::from(dir)) {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}

fn approval_channel(
    mode: Option<&str>,
    timeout: Duration,
    uid: Option<u32>,
    agents: &[u32],
    operator_attest: bool,
    local: bool,
) -> Result<Box<dyn ApprovalChannel>, String> {
    // 0004 R9 (leads decision): local mode has no approval channel at all.
    // Refuse to start before any socket is created; consequential steps in
    // local mode are denied.
    if local && (mode.is_some() || uid.is_some() || !agents.is_empty()) {
        return Err(LOCAL_APPROVAL_REFUSED.into());
    }
    if (uid.is_some() || !agents.is_empty()) && !mode.is_some_and(|m| m.starts_with("unix:")) {
        return Err("--approve-uid/--agent-uid require --approve unix:<path>".into());
    }
    // D4: the umask used at bind is process-wide; nothing may have
    // spawned a thread before the approval channel opens. Hard check.
    sidged_cli::require_single_threaded()?;
    // 0004 R9: a refused channel denies (and audits) every consequential step.
    let channel = sidged_cli::open_channel(&sidged_cli::ChannelConfig {
        mode,
        timeout,
        approver: uid,
        agents,
        local,
        operator_attest,
    });
    if let Some(reason) = channel.refusal() {
        eprintln!("{reason}");
    } else if let Some(path) = mode.and_then(|m| m.strip_prefix("unix:")) {
        eprintln!("{path}");
    }
    Ok(channel)
}

/// 0004 R9: `config.json` `"local": true` is a local-mode input too and
/// must be known before any approval channel exists.
fn config_local(dir: &str) -> bool {
    std::fs::read_to_string(Path::new(dir).join("config.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .is_some_and(|config| config["local"] == true)
}

fn kill(args: &[String]) -> ExitCode {
    let Some(addr) = args.first() else {
        eprintln!("usage: sidged kill <unix:path>");
        return ExitCode::from(2);
    };
    match post_approval(addr, "kill") {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}

fn guard(args: &[String]) -> ExitCode {
    let Some(dir) = args.first() else {
        eprintln!("usage: sidged guard <scenario-dir> [--keys <dir>] [--system-config <file>] --log <file> --log-key <key> [--local] [--approve unix:<path> --approve-uid <approver-uid> --non-approver-uid <uid>[,<uid>...] [--operator-attest]] [--approve-timeout <seconds>]");
        return ExitCode::from(2);
    };
    let mut keys = None;
    let mut local = false;
    let mut approve = None;
    let mut timeout = 30u64;
    let mut approve_uid = None;
    let mut agent_uids = Vec::new();
    let mut operator_attest = false;
    let mut log_path = None;
    let mut log_key = None;
    let mut system_config = None;
    let mut flags = args.iter().skip(1);
    while let Some(flag) = flags.next() {
        match flag.as_str() {
            "--keys" => {
                let Some(dir) = flags.next() else {
                    eprintln!("--keys needs a directory");
                    return ExitCode::from(2);
                };
                keys = Some(Path::new(dir));
            }
            "--local" => local = true,
            "--operator-attest" => operator_attest = true,
            "--approve" => approve = flags.next().map(String::as_str),
            "--approve-uid" => {
                let Some(uid) = flags.next().and_then(|text| text.parse::<u32>().ok()) else {
                    eprintln!("--approve-uid needs uid");
                    return ExitCode::from(2);
                };
                approve_uid = Some(uid);
            }
            "--agent-uid" | "--non-approver-uid" => {
                match flags.next().map(|t| sidged_cli::parse_uid_list(t)) {
                    Some(Ok(list)) => agent_uids.extend(list),
                    _ => {
                        eprintln!("--non-approver-uid needs uid[,uid...]");
                        return ExitCode::from(2);
                    }
                }
            }
            "--approve-timeout" => {
                timeout = flags
                    .next()
                    .and_then(|text| text.parse().ok())
                    .unwrap_or(30);
            }
            "--log" => log_path = flags.next().map(String::as_str),
            "--log-key" => log_key = flags.next().map(String::as_str),
            "--system-config" => {
                let Some(path) = flags.next() else {
                    eprintln!("--system-config needs a file");
                    return ExitCode::from(2);
                };
                system_config = Some(Path::new(path));
            }
            other => {
                eprintln!("unknown argument {other}");
                return ExitCode::from(2);
            }
        }
    }
    // Turnkey WP b1: the system config (written by `sidged init`) is loaded
    // only from a private file owned by this uid; anything invalid refuses.
    let system = match system_config.map(load_system_config).transpose() {
        Ok(system) => system,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let local = local || config_local(dir) || system.as_ref().is_some_and(|s| s.local);
    if let Err(message) = sidged_gateway::resolve_local(local) {
        eprintln!("{message}");
        return ExitCode::from(2);
    }
    // 0004 R9c (lead decision): non-approver uids also come from
    // config.json approval.non_approver_uids; malformed config refuses.
    if let Ok(text) = std::fs::read_to_string(Path::new(dir).join("config.json")) {
        let config = match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(config) => config,
            Err(_) => serde_json::Value::Null,
        };
        match sidged_cli::config_non_approver_uids(&config) {
            Ok(list) => agent_uids.extend(list),
            Err(message) => {
                eprintln!("{message}");
                return ExitCode::from(2);
            }
        }
    }
    // 0004 R9/R9c: a CLI flag cannot replace the configured approver identity.
    if let (Some(cli_uid), Some(uids)) = (
        approve_uid,
        system.as_ref().and_then(|s| s.approval.as_ref()),
    ) {
        if cli_uid != uids.approver {
            eprintln!("--approve-uid conflicts with system config approval.approve_uid; refused");
            return ExitCode::from(2);
        }
    }
    if approve_uid.is_some() {
        eprintln!("approval: approver uid from cli");
    } else if system.as_ref().and_then(|s| s.approval.as_ref()).is_some() {
        eprintln!("approval: approver uid from system config");
    }
    // System config approval uids apply only together with --approve.
    if let (Some(_), Some(uids)) = (approve, system.as_ref().and_then(|s| s.approval.as_ref())) {
        approve_uid = approve_uid.or(Some(uids.approver));
        agent_uids.extend(&uids.non_approvers);
    }
    let channel = match approval_channel(
        approve,
        Duration::from_secs(timeout),
        approve_uid,
        &agent_uids,
        operator_attest,
        local || sidged_gateway::is_local(),
    ) {
        Ok(channel) => channel,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let provider = env::var("SIDGED_PROVIDER").unwrap_or_else(|_| "stub".into());
    let provider_ref = system.as_ref().and_then(|s| s.provider.as_ref());
    let base_url = match system_base_url(env::var("SIDGED_BASE_URL").ok(), provider_ref) {
        Ok(url) => url,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let model = env::var("SIDGED_MODEL").ok();
    // 0007 R10a: only the credential reference is resolved here; the gateway
    // reads the key at send time, after the §5 checks.
    let fallback = provider_ref.and_then(|p| p.credential.as_deref());
    let credential = match planner_credential(base_url.as_deref(), fallback) {
        Ok(credential) => credential,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let seed = match read_seed(log_key) {
        Ok(seed) => seed,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let resolved = match sidged_log::log_path(log_path, seed.is_some()) {
        Ok(path) => path,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let log = match (resolved.as_deref(), seed.as_ref()) {
        (Some(path), Some(seed)) => Some(LogTarget {
            path: Path::new(path),
            seed,
        }),
        _ => {
            eprintln!("--log-key is required to write the audit log");
            return ExitCode::from(2);
        }
    };
    match run_from_env_with_credential(
        &PathBuf::from(dir),
        &provider,
        base_url.as_deref(),
        model.as_deref(),
        credential,
        channel.as_ref(),
        log,
        keys,
    ) {
        Ok(report) => {
            println!("capabilities {}", report.capabilities);
            println!("approvals {}", report.approvals);
            println!("privacy-reports {}", report.privacy_reports);
            println!("audit-events {}", report.audit_events);
            println!("residency {}", report.residency.join(","));
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}

fn log_cmd(args: &[String]) -> ExitCode {
    if args.first().map(String::as_str) != Some("verify")
        || args.get(2).map(String::as_str) != Some("--public")
        || args.len() < 4
    {
        eprintln!("usage: sidged log verify <file> --public <hex>");
        return ExitCode::from(2);
    }
    let public = match unhex(&args[3]) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            key
        }
        _ => {
            eprintln!("--public needs 32 bytes of hex");
            return ExitCode::from(2);
        }
    };
    match verify_file(Path::new(&args[1]), &public) {
        Ok(count) => {
            println!("audit-entries {count}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}

fn read_seed(path: Option<&str>) -> Result<Option<[u8; 32]>, String> {
    let Some(path) = path else {
        return Ok(None);
    };
    let meta = fs::symlink_metadata(path).map_err(|err| err.to_string())?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(format!(
            "log key {path} is a symlink or not a regular file; refused"
        ));
    }
    let text = fs::read_to_string(path).map_err(|err| err.to_string())?;
    let bytes = unhex(text.trim())?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "log key must be 32 bytes".to_string())?;
    if sidged_guard::is_rfc8032_test_seed(&seed) {
        return Err("RFC 8032 test keys are forbidden as the audit log key (--log-key)".into());
    }
    Ok(Some(seed))
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 {
        return Err("odd hex".into());
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let hi = hex_value(bytes[index])?;
        let lo = hex_value(bytes[index + 1])?;
        out.push((hi << 4) | lo);
        index += 2;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("bad hex".into()),
    }
}

fn record_cmd(args: &[String]) -> ExitCode {
    match records::run(args) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(if message.starts_with("usage:") { 2 } else { 1 })
        }
    }
}
mod records;

fn keygen(args: &[String]) -> ExitCode {
    use std::io::{Read, Write};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let result = (|| -> Result<(), String> {
        if args.len() != 1 {
            return Err("usage: sidged keygen <new-directory>".into());
        }
        let dir = Path::new(&args[0]);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(dir)
            .map_err(|e| e.to_string())?;
        let mut random = fs::File::open("/dev/urandom").map_err(|e| e.to_string())?;
        for role in ["issuer", "holder"] {
            let mut seed = [0u8; 32];
            random.read_exact(&mut seed).map_err(|e| e.to_string())?;
            let path = dir.join(format!("{role}.key"));
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| e.to_string())?;
            let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
            writeln!(file, "{hex}").map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            println!(
                "{role} {} {}",
                sidged_grant::did_key(&sidged_log::public_key(&seed)),
                path.display()
            );
        }
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

/// Planner credential reference: `SIDGED_API_KEY_FILE` (a compose secret or
/// mounted file) is preferred. xAI accepts only the file: an API key in the
/// environment is refused (RONI files audit; 0007 xAI entry). Never both.
/// Nothing is opened or copied here (0007 R10a): the gateway reads the key at
/// send time, after the local latch, audit log, destination, grant,
/// reservation and approval checks.
fn planner_credential(
    base_url: Option<&str>,
    fallback: Option<&Path>,
) -> Result<Option<sidged_gateway::KeySource>, String> {
    let env_key = env::var("SIDGED_API_KEY").ok().filter(|k| !k.is_empty());
    let file = env::var_os("SIDGED_API_KEY_FILE").filter(|p| !p.is_empty());
    let xai = base_url.is_some_and(sidged_gateway::is_xai);
    match (env_key, file) {
        (Some(_), Some(_)) => Err("set SIDGED_API_KEY_FILE or SIDGED_API_KEY, not both".into()),
        (Some(_), None) if xai => Err(
            "xAI needs its API key from a file (SIDGED_API_KEY_FILE); SIDGED_API_KEY in the environment is refused".into(),
        ),
        (Some(_), None) => Ok(Some(sidged_gateway::KeySource::Env(
            "SIDGED_API_KEY".into(),
        ))),
        (None, Some(path)) => Ok(Some(sidged_gateway::KeySource::File(path.into()))),
        (None, None) => Ok(fallback.map(|path| sidged_gateway::KeySource::File(path.into()))),
    }
}

/// 0004 R9 (leads decision): in local mode there is no approval channel. Any
/// approval flag refuses startup before parsing, I/O or socket creation.
fn refuse_local_approval(args: &[String]) -> Result<(), String> {
    let local =
        env::var("SIDGED_LOCAL").is_ok_and(|v| v == "1") || args.iter().any(|a| a == "--local");
    let approval = args.iter().any(|a| {
        // any approval flag: --approve, --approve-uid, --approve-timeout, = forms
        a == "--approve"
            || a.starts_with("--approve-")
            || a.starts_with("--approve=")
            || a.starts_with("--agent-uid")
            || a.starts_with("--non-approver-uid")
            || a == "--operator-attest"
    });
    if local && approval {
        return Err(LOCAL_APPROVAL_REFUSED.into());
    }
    Ok(())
}

const LOCAL_APPROVAL_REFUSED: &str = "local mode (SIDGED_LOCAL=1 / --local) has no approval channel; remove --approve/--approve-uid/--approve-timeout. Consequential steps are denied in local mode (0004 R9)";

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn load_system_config(path: &Path) -> Result<sidged_cli::system_config::SystemConfig, String> {
    sidged_cli::system_config::load(path, euid())
}

/// The planner base URL: SIDGED_BASE_URL must name the configured provider's
/// registry origin (0007 R3); without it, the registry base URL is used where
/// the registry fixes one (Gemini, xAI). Exact prefix match, so any other
/// spelling of the host is refused (fail closed).
fn system_base_url(
    env_url: Option<String>,
    provider: Option<&sidged_cli::system_config::ProviderRef>,
) -> Result<Option<String>, String> {
    let Some(provider) = provider else {
        return Ok(env_url);
    };
    match env_url {
        Some(url) => {
            let origin = provider.id.origin();
            if url == origin || url.starts_with(&format!("{origin}/")) {
                Ok(Some(url))
            } else {
                Err(format!(
                    "SIDGED_BASE_URL does not match the system config provider {} ({origin})",
                    provider.id.as_str()
                ))
            }
        }
        None => Ok(provider.id.base_url().map(str::to_string)),
    }
}

/// `sidged init [--config <file>]` (turnkey WP b3): interactive terminal only,
/// or `sidged init --workspace <dir>` (WP 5 turnkey workspace bootstrap).
fn init_cmd(args: &[String]) -> ExitCode {
    if args.len() == 2 && args[0] == "--workspace" {
        let ws = PathBuf::from(&args[1]);
        match sidged_cli::turnkey::bootstrap_workspace(&ws) {
            Ok(manifest) => {
                println!("{}", serde_json::to_string_pretty(&manifest).unwrap());
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("sidged init: {e}");
                return ExitCode::from(1);
            }
        }
    }
    let mut config_path = None;
    let mut state_dir = PathBuf::from("/var/lib/sidged");
    let mut pairs = args.chunks_exact(2);
    for pair in &mut pairs {
        match pair[0].as_str() {
            "--config" => config_path = Some(PathBuf::from(&pair[1])),
            "--state-dir" => state_dir = PathBuf::from(&pair[1]),
            _ => {
                eprintln!("usage: sidged init [--config <file>] [--state-dir <dir>] | sidged init --workspace <dir>");
                return ExitCode::from(2);
            }
        }
    }
    if !pairs.remainder().is_empty() {
        eprintln!("usage: sidged init [--config <file>] [--state-dir <dir>] | sidged init --workspace <dir>");
        return ExitCode::from(2);
    }
    if !state_dir.is_absolute() {
        eprintln!("state directory must be absolute");
        return ExitCode::from(2);
    }
    let path = config_path.map_or_else(sidged_cli::system_config::default_path, Ok);
    if let Err(message) = sidged_cli::init::require_tty() {
        eprintln!("sidged: {message}");
        return ExitCode::from(2);
    }
    // Resolve the config path independently of the absolute state directory.
    let path = match path.and_then(|p| {
        if p.is_absolute() {
            Ok(p)
        } else {
            env::current_dir()
                .map(|cwd| cwd.join(p))
                .map_err(|e| e.to_string())
        }
    }) {
        Ok(path) => path,
        Err(message) => {
            eprintln!("sidged: {message}");
            return ExitCode::from(2);
        }
    };
    let options = sidged_cli::init::InitOptions {
        config_path: &path,
        state_dir: &state_dir,
        core_uid: euid(),
    };
    match sidged_cli::init::run_init(&mut sidged_cli::init::TtyTerminal, &options) {
        Ok(_) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("sidged init: {message}");
            ExitCode::from(1)
        }
    }
}

fn task_cmd(args: &[String]) -> ExitCode {
    let Some(prompt) = args.first() else {
        eprintln!("usage: sidged task \"<prompt>\" [--workspace <dir>] [--hybrid]");
        return ExitCode::from(2);
    };
    let mut workspace = env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".sidged-os");
    let mut hybrid = false;
    let mut idx = 1;
    while idx < args.len() {
        match args[idx].as_str() {
            "--workspace" => {
                idx += 1;
                let Some(dir) = args.get(idx) else {
                    eprintln!("--workspace needs a directory");
                    return ExitCode::from(2);
                };
                workspace = PathBuf::from(dir);
            }
            "--hybrid" => hybrid = true,
            other => {
                eprintln!("unknown argument {other}");
                return ExitCode::from(2);
            }
        }
        idx += 1;
    }
    match sidged_cli::turnkey::execute_turnkey_task(&workspace, prompt, hybrid) {
        Ok(summary) => {
            println!("{}", serde_json::to_string_pretty(&summary).unwrap());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("sidged task: {e}");
            ExitCode::from(1)
        }
    }
}

/// `sidged mandate renew --workspace <dir>` (0002 R23): an owner action, so it refuses
/// without an interactive terminal and asks for a typed confirmation, as `sidged init` does.
/// Renewal through the Trusted UI with user verification is WP 17.
fn mandate_cmd(args: &[String]) -> ExitCode {
    let usage = "usage: sidged mandate renew --workspace <dir>   (interactive terminal only; the owner key re-signs the node mandate for 30 days; Trusted UI renewal is WP 17)";
    let workspace = match args {
        [renew, flag, dir] if renew == "renew" && flag == "--workspace" => PathBuf::from(dir),
        _ => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    };
    if sidged_cli::init::require_tty().is_err() {
        eprintln!("sidged mandate renew needs an interactive terminal (stdin and stdout must be a TTY); refused");
        return ExitCode::from(2);
    }
    match sidged_cli::turnkey::renew_mandate(&mut sidged_cli::init::TtyTerminal, &workspace) {
        Ok(_) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("sidged mandate renew: {message}");
            ExitCode::from(1)
        }
    }
}

/// `sidged swarm measure` (Spec 0015 S11): the v0.1 swarm prototype, only in a build with
/// the feature `experimental` (ROADMAP v0.5, 11g).
#[cfg(feature = "experimental")]
fn swarm_cmd(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("measure") => {
            let mut log_key = None;
            let mut log_path = None;
            let mut image_digest = None;
            let mut nonce = None;
            let mut pairs = args[1..].chunks_exact(2);
            for pair in &mut pairs {
                match pair[0].as_str() {
                    "--log-key" => log_key = Some(pair[1].as_str()),
                    "--log" => log_path = Some(Path::new(&pair[1])),
                    "--image-digest" => image_digest = Some(pair[1].as_str()),
                    "--nonce" => nonce = Some(pair[1].as_str()),
                    _ => {}
                }
            }
            let (Some(key_str), Some(log), Some(digest), Some(nonce)) =
                (log_key, log_path, image_digest, nonce)
            else {
                eprintln!(
                    "usage: sidged swarm measure --log-key <file> --log <file> --image-digest <sha256:hex> --nonce <str>"
                );
                return ExitCode::from(2);
            };
            let seed = match read_seed(Some(key_str)) {
                Ok(Some(s)) => s,
                Ok(None) => return ExitCode::from(2),
                Err(e) => {
                    eprintln!("sidged swarm: {e}");
                    return ExitCode::from(2);
                }
            };
            match sidged_cli::swarm::produce_measurement(&seed, digest, log, nonce) {
                Ok(report) => {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("sidged swarm: {e}");
                    ExitCode::from(1)
                }
            }
        }
        _ => {
            eprintln!(
                "usage: sidged swarm measure --log-key <file> --log <file> --image-digest <sha256:hex> --nonce <str>"
            );
            ExitCode::from(2)
        }
    }
}

/// Without the feature `experimental` the swarm prototype is not in this binary.
#[cfg(not(feature = "experimental"))]
fn swarm_cmd(_args: &[String]) -> ExitCode {
    eprintln!(
        "sidged swarm: the swarm prototype is experimental and not part of this build (ROADMAP v0.5)"
    );
    ExitCode::from(2)
}
