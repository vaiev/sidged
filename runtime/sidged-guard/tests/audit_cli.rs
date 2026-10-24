use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Fixture {
    dir: PathBuf,
    issuer: String,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("sidged-audit-cli-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("a")).unwrap();
        fs::create_dir_all(dir.join("b")).unwrap();
        let keys: serde_json::Value = serde_json::from_str(include_str!(
            "../../../spec/test-vectors/keys/rfc8032-test-keys.json"
        ))
        .unwrap();
        let owner = &keys["keys"][0];
        let holder = &keys["keys"][1];
        let decode = |s: &str| -> [u8; 32] {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        };
        let seed = decode(owner["secret_key_hex"].as_str().unwrap());
        let issuer = sidged_grant::did_key(&decode(owner["public_key_hex"].as_str().unwrap()));
        let sub = sidged_grant::did_key(&decode(holder["public_key_hex"].as_str().unwrap()));
        let cap = "urn:sidged:capability:calendar.free_slots";
        let grant = sidged_grant::attach_signature(
            &serde_json::json!({
                "v":"0.1", "id":"tok-cli-audit1", "iss":issuer, "sub":sub,
                "aud":"did:example:hosted", "iat":"2026-10-14T12:00:00Z", "exp":"2026-10-14T12:30:00Z",
                "cnf":{"kid":sub}, "chain":[],
                "rights":[{"action":"calendar.free_slots","resource":cap,"constraints":{"max_uses":1}}]
            }),
            &seed,
            &issuer,
        );
        fs::write(dir.join("grant.json"), grant.to_string()).unwrap();
        fs::write(
            dir.join("plan.json"),
            serde_json::json!({"v":"0.1","steps":[{"id":"one","kind":"call","capability":cap,"args":{}}]})
                .to_string(),
        )
        .unwrap();
        fs::write(dir.join("catalog.json"), serde_json::json!([{"id":cap,"effects":["read"],"data_classes":[],"consequential":false,"cost":{"class":"free"}}]).to_string()).unwrap();
        fs::write(
            dir.join("policy.cedar"),
            "permit(principal, action, resource);",
        )
        .unwrap();
        fs::write(dir.join("key"), "42".repeat(32)).unwrap();
        fs::write(
            dir.join("holder.key"),
            holder["secret_key_hex"].as_str().unwrap(),
        )
        .unwrap();
        fs::write(dir.join("stranger.key"), "57".repeat(32)).unwrap();
        for key in ["holder.key", "stranger.key"] {
            fs::set_permissions(dir.join(key), fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self { dir, issuer }
    }
    /// An effectful run (with `key`) presents the grant with the holder's key file.
    fn run(&self, cwd: &str, state: Option<&Path>, home: &Path, key: bool, dry: bool) -> Output {
        let holder = self.dir.join("holder.key");
        self.run_as(cwd, state, home, key, dry, key.then_some(holder.as_path()))
    }
    fn run_as(
        &self,
        cwd: &str,
        state: Option<&Path>,
        home: &Path,
        key: bool,
        dry: bool,
        holder: Option<&Path>,
    ) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sidged"));
        cmd.current_dir(self.dir.join(cwd))
            .env_remove("XDG_STATE_HOME")
            .env("HOME", home)
            .arg("run")
            .arg(self.dir.join("plan.json"))
            .arg(self.dir.join("catalog.json"))
            .arg("--policy")
            .arg(self.dir.join("policy.cedar"))
            .arg("--grant")
            .arg(self.dir.join("grant.json"))
            .args([
                "--trusted-issuer",
                &self.issuer,
                "--audience",
                "did:example:hosted",
                "--now",
                "2026-10-14T12:10:00Z",
            ]);
        if let Some(state) = state {
            cmd.env("XDG_STATE_HOME", state);
        }
        if key {
            cmd.arg("--log-key").arg(self.dir.join("key"));
        }
        if dry {
            cmd.arg("--dry-run");
        }
        if let Some(holder) = holder {
            cmd.arg("--holder-key").arg(holder);
        }
        cmd.output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn default_chain_is_shared_across_cwds_and_effects_fail_closed() {
    let fixture = Fixture::new();
    let state = fixture.dir.join("state");
    let home = fixture.dir.join("home");
    let denied = fixture.run("a", Some(&state), &home, false, false);
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("audit log"));
    assert!(fixture
        .run("a", Some(&state), &home, false, true)
        .status
        .success());
    assert!(!state.exists());
    let first = fixture.run("a", Some(&state), &home, true, false);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let path = state.join("sidged/audit.log");
    assert!(String::from_utf8_lossy(&first.stderr).contains(path.to_str().unwrap()));
    assert!(path.exists());
    let second = fixture.run("b", Some(&state), &home, true, false);
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("grant denied"));
    assert!(fixture.run("b", None, &home, true, false).status.success());
    assert!(home.join(".local/state/sidged/audit.log").exists());
    let blocked = fixture.dir.join("blocked");
    fs::write(&blocked, "a file cannot be a state directory").unwrap();
    let denied = fixture.run("a", Some(&blocked), &home, true, false);
    assert!(!denied.status.success());
    assert!(!String::from_utf8_lossy(&denied.stdout).contains("audit-events"));
}

/// 0002 R25: `sidged run` presents the grant with `--holder-key`; without it, or with a key
/// that is not the grant's holder, an effectful run refuses and leaves no reservation.
#[test]
fn an_effectful_run_needs_the_holders_key() {
    let fixture = Fixture::new();
    let state = fixture.dir.join("state");
    let home = fixture.dir.join("home");
    let stranger = fixture.dir.join("stranger.key");
    for holder in [None, Some(stranger.as_path())] {
        let denied = fixture.run_as("a", Some(&state), &home, true, false, holder);
        assert!(!denied.status.success(), "{holder:?}");
        let stderr = String::from_utf8_lossy(&denied.stderr);
        assert!(stderr.contains("grant"), "{stderr}");
    }
    // The right key in a file others can read, or behind a symlink, is refused before any step.
    let loose = fixture.dir.join("loose.key");
    fs::copy(fixture.dir.join("holder.key"), &loose).unwrap();
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).unwrap();
    let link = fixture.dir.join("link.key");
    std::os::unix::fs::symlink(fixture.dir.join("holder.key"), &link).unwrap();
    for (holder, why) in [(&loose, "must be 0600"), (&link, "symlink")] {
        let denied = fixture.run_as("a", Some(&state), &home, true, false, Some(holder));
        assert!(!denied.status.success(), "{holder:?}");
        let stderr = String::from_utf8_lossy(&denied.stderr);
        assert!(stderr.contains(why), "{stderr}");
    }
    let path = state.join("sidged/audit.log");
    let seed = [0x42; 32];
    let events = sidged_log::read_events(&path, &sidged_log::public_key(&seed)).unwrap();
    assert!(events.iter().all(|e| e.decision == "deny"), "{events:?}");
    let ran = fixture.run("a", Some(&state), &home, true, false);
    assert!(
        ran.status.success(),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
}
