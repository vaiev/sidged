//! `sidged init` wizard logic (turnkey WP b3), driven by a scripted terminal.
//! Personal Intelligence only; ratified providers only (0007 R3 registry);
//! credentials are references or a separate 0600 key file, never config
//! content (0007 R10a); approver uid rules (0004 R9, R9c); no port, no swarm.
use std::collections::VecDeque;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use sidged_cli::init::{run_init, InitOptions, Terminal};
use sidged_cli::system_config::{self, Interface, ProviderId};

const KEY: &str = "Zq9TESTwizardKeyMaterial77";
const CORE: u32 = 990;

#[derive(Default)]
struct Script {
    answers: VecDeque<(&'static str, String)>,
    secrets: VecDeque<String>,
    prompts: Vec<String>,
    said: Vec<String>,
    secret_prompts: Vec<String>,
}

impl Script {
    fn new(answers: &[(&'static str, &str)], secrets: &[&str]) -> Self {
        Self {
            answers: answers.iter().map(|(p, a)| (*p, a.to_string())).collect(),
            secrets: secrets.iter().map(|s| s.to_string()).collect(),
            ..Self::default()
        }
    }

    /// Everything the wizard showed: prompts and messages.
    fn shown(&self) -> String {
        let mut all = self.prompts.join("\n");
        all.push('\n');
        all.push_str(&self.said.join("\n"));
        all.push('\n');
        all.push_str(&self.secret_prompts.join("\n"));
        all
    }
}

impl Terminal for Script {
    fn ask(&mut self, prompt: &str) -> Result<String, String> {
        self.prompts.push(prompt.to_string());
        let (expected, answer) = self.answers.pop_front().ok_or("end of input")?;
        assert!(
            prompt.contains(expected),
            "prompt {prompt:?} does not contain {expected:?}"
        );
        Ok(answer)
    }
    fn ask_secret(&mut self, prompt: &str) -> Result<zeroize::Zeroizing<String>, String> {
        self.secret_prompts.push(prompt.to_string());
        self.secrets
            .pop_front()
            .map(zeroize::Zeroizing::new)
            .ok_or_else(|| "end of input".to_string())
    }
    fn say(&mut self, text: &str) {
        self.said.push(text.to_string());
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sidged-init-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn opts(path: &Path) -> InitOptions<'_> {
    InitOptions {
        config_path: path,
        state_dir: path.parent().unwrap(),
        core_uid: CORE,
    }
}

#[test]
fn entered_key_goes_to_a_separate_private_file_with_echo_off() {
    let dir = scratch("entered");
    let path = dir.join("config.json");
    let mut term = Script::new(
        &[
            ("Local mode", "n"),
            ("Provider", "xai"),
            ("API key source", "e"),
            ("Approver uid", "1001"),
            ("Non-approver uids", "1002, 1003"),
            ("Interface", ""),
        ],
        &[KEY],
    );
    let config = run_init(&mut term, &opts(&path)).unwrap();
    // The key was read through the echo-off path only.
    assert_eq!(term.secret_prompts.len(), 1);
    assert!(term.secret_prompts[0].contains("input hidden"));
    let provider = config.provider.as_ref().unwrap();
    assert_eq!(provider.id, ProviderId::Xai);
    let key_file = provider.credential.clone().unwrap();
    assert_eq!(key_file, dir.join("credentials").join("xai.key"));
    let meta = std::fs::symlink_metadata(&key_file).unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o600);
    assert_eq!(meta.uid(), euid());
    assert_eq!(std::fs::read_to_string(&key_file).unwrap().trim(), KEY);
    let saved = std::fs::read_to_string(&path).unwrap();
    assert!(!saved.contains(KEY), "{saved}");
    let shown = term.shown();
    assert!(
        !shown.contains(KEY) && !shown.contains(&KEY[..4]),
        "{shown}"
    );
    assert!(shown.contains("configured"), "{shown}");
    assert!(
        shown.contains(path.to_str().unwrap()),
        "prints what it wrote: {shown}"
    );
    assert_eq!(config.interface, Interface::Tui);
    let approval = config.approval.unwrap();
    assert_eq!(
        (approval.approver, approval.non_approvers),
        (1001, vec![1002, 1003])
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn only_ratified_providers_are_offered_and_others_are_refused() {
    let dir = scratch("providers");
    let path = dir.join("config.json");
    let mut term = Script::new(
        &[
            ("Local mode", "n"),
            ("Provider", "openai"),
            ("Provider", "anthropic"),
            ("Provider", "grok-cloud"),
        ],
        &[],
    );
    let error = run_init(&mut term, &opts(&path)).unwrap_err();
    assert!(error.contains("infomaniak, gemini, xai"), "{error}");
    assert!(!path.exists());
    let shown = term.shown().to_lowercase();
    for word in [
        "swarm",
        "port",
        "8080",
        "0.0.0.0",
        "web",
        "anthropic",
        "openai",
    ] {
        let offered = term
            .prompts
            .iter()
            .chain(&term.said)
            .any(|p| p.to_lowercase().contains(word));
        assert!(!offered, "{word} offered: {shown}");
    }
    assert!(term.prompts[1].contains("infomaniak") && term.prompts[1].contains("gemini"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn gemini_requires_a_billing_project() {
    let dir = scratch("gemini");
    let path = dir.join("config.json");
    let mut term = Script::new(
        &[
            ("Local mode", "n"),
            ("Provider", "gemini"),
            ("Gemini billing project", ""),
            ("Gemini billing project", "billing-project"),
            ("API key source", ""),
            ("Approver uid", ""),
            ("Interface", "static-shell"),
        ],
        &[],
    );
    let config = run_init(&mut term, &opts(&path)).unwrap();
    let provider = config.provider.unwrap();
    assert_eq!(provider.project.as_deref(), Some("billing-project"));
    assert!(provider.credential.is_none());
    assert!(config.approval.is_none());
    assert_eq!(config.interface, Interface::StaticShell);
    assert!(term.said.join("\n").contains("not configured"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn approver_uid_zero_or_core_uid_is_refused() {
    for bad in ["0", "990"] {
        let dir = scratch(&format!("approver-{bad}"));
        let path = dir.join("config.json");
        let mut term = Script::new(
            &[
                ("Local mode", "n"),
                ("Provider", "none"),
                ("Approver uid", bad),
                ("Non-approver uids", "1002"),
            ],
            &[],
        );
        let error = run_init(&mut term, &opts(&path)).unwrap_err();
        assert!(error.contains("0004 R9"), "{bad}: {error}");
        assert!(!path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn a_key_file_reference_is_checked_and_reported_without_its_bytes() {
    let dir = scratch("file-ref");
    let path = dir.join("config.json");
    let key = dir.join("own.key");
    std::fs::write(&key, format!("{KEY}\n")).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut term = Script::new(
        &[
            ("Local mode", "n"),
            ("Provider", "infomaniak"),
            ("API key source", "f"),
            ("Key file path", key.to_str().unwrap()),
        ],
        &[],
    );
    let error = run_init(&mut term, &opts(&path)).unwrap_err();
    assert!(
        error.contains("invalid") && error.contains("0600"),
        "{error}"
    );
    assert!(!error.contains(KEY) && !term.shown().contains(KEY));
    assert!(!path.exists());
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut term = Script::new(
        &[
            ("Local mode", "n"),
            ("Provider", "infomaniak"),
            ("API key source", "f"),
            ("Key file path", key.to_str().unwrap()),
            ("Approver uid", ""),
            ("Interface", ""),
        ],
        &[],
    );
    let config = run_init(&mut term, &opts(&path)).unwrap();
    assert_eq!(
        config.provider.unwrap().credential.as_deref(),
        Some(key.as_path())
    );
    let shown = term.shown();
    assert!(shown.contains("configured") && !shown.contains(KEY) && !shown.contains(&KEY[..4]));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn local_mode_has_no_approval_questions_and_may_name_a_model_endpoint() {
    let dir = scratch("local");
    let path = dir.join("config.json");
    let mut term = Script::new(
        &[
            ("Local mode", "y"),
            ("Local model endpoint", "unix:/run/sidged/model.sock"),
            ("Model uid", "993"),
            ("Interface", ""),
        ],
        &[],
    );
    let config = run_init(&mut term, &opts(&path)).unwrap();
    assert!(config.local);
    assert!(config.approval.is_none());
    assert!(config.model.is_some());
    assert!(!term.prompts.iter().any(|p| p.contains("Approver")));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn empty_answers_keep_the_existing_config_and_dash_removes_the_reference() {
    let dir = scratch("keep");
    let path = dir.join("config.json");
    let key = dir.join("own.key");
    std::fs::write(&key, KEY).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let existing = system_config::parse(
        &serde_json::json!({"v": "0.1", "mode": "personal", "local": false,
            "interface": "static-shell",
            "provider": {"id": "xai", "credential": {"file": key}},
            "approval": {"approve_uid": 41001, "non_approver_uids": [41002]}}),
        euid(),
    )
    .unwrap();
    system_config::save(&path, &existing).unwrap();
    let keep = InitOptions {
        config_path: &path,
        state_dir: &dir,
        core_uid: euid(),
    };
    let mut term = Script::new(
        &[
            ("Local mode", ""),
            ("Provider", ""),
            ("API key source", ""),
            ("Approver uid", ""),
            ("Interface", ""),
        ],
        &[],
    );
    assert_eq!(run_init(&mut term, &keep).unwrap(), existing);
    let mut term = Script::new(
        &[
            ("Local mode", ""),
            ("Provider", ""),
            ("API key source", "-"),
            ("Approver uid", "-"),
            ("Interface", ""),
        ],
        &[],
    );
    let config = run_init(&mut term, &keep).unwrap();
    assert!(config.provider.unwrap().credential.is_none());
    assert!(config.approval.is_none());
    assert_eq!(system_config::load(&path, euid()).unwrap(), {
        let mut c = existing.clone();
        c.provider.as_mut().unwrap().credential = None;
        c.approval = None;
        c
    });
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn an_invalid_existing_config_is_refused_not_overwritten() {
    let dir = scratch("invalid");
    let path = dir.join("config.json");
    std::fs::write(&path, r#"{"v":"0.1","mode":"swarm"}"#).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut term = Script::new(&[], &[]);
    let keep = InitOptions {
        config_path: &path,
        state_dir: &dir,
        core_uid: euid(),
    };
    let error = run_init(&mut term, &keep).unwrap_err();
    assert!(error.contains("existing config"), "{error}");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        r#"{"v":"0.1","mode":"swarm"}"#
    );
    std::fs::remove_dir_all(dir).unwrap();
}

struct BlockConfigSave {
    script: Script,
    path: PathBuf,
}
impl Terminal for BlockConfigSave {
    fn ask(&mut self, prompt: &str) -> Result<String, String> {
        if prompt.starts_with("Interface") {
            std::fs::create_dir(&self.path).unwrap();
        }
        self.script.ask(prompt)
    }
    fn ask_secret(&mut self, prompt: &str) -> Result<zeroize::Zeroizing<String>, String> {
        self.script.ask_secret(prompt)
    }
    fn say(&mut self, text: &str) {
        self.script.say(text);
    }
}

fn failed_save_key(preexisting: bool) {
    let dir = scratch(if preexisting {
        "save-existing"
    } else {
        "save-new"
    });
    let path = dir.join("config.json");
    let key = dir.join("credentials/xai.key");
    if preexisting {
        std::fs::create_dir(key.parent().unwrap()).unwrap();
        std::fs::set_permissions(
            key.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(&key, KEY).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut terminal = BlockConfigSave {
        script: Script::new(
            &[
                ("Local mode", "n"),
                ("Provider", "xai"),
                ("API key source", "e"),
                ("Approver uid", ""),
                ("Interface", ""),
            ],
            &[KEY],
        ),
        path: path.clone(),
    };
    let error = run_init(&mut terminal, &opts(&path)).unwrap_err();
    assert!(error.contains("not a regular file"), "{error}");
    assert_eq!(
        key.exists(),
        preexisting,
        "only a newly written key is removed"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn failed_config_save_removes_a_new_key() {
    failed_save_key(false);
}

#[test]
fn failed_config_save_keeps_a_preexisting_key() {
    failed_save_key(true);
}
