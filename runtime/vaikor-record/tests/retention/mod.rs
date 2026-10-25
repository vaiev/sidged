use super::*;

struct Fixture {
    root: PathBuf,
    _cleanup: Cleanup,
    store: Store,
    old: String,
    grant: Value,
    key: String,
}
impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "record-retention-regression-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let mut store = Store::open(&root, &[42; 32], vec![]).unwrap();
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../../spec/test-vectors/records/records.json"
        ))
        .unwrap();
        let mut value = vectors["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == "record.check.001")
            .unwrap()["input"]["record"]
            .clone();
        value["retention"] = json!({"until":null,"on_expiry":"delete"});
        let record = Record::sign(value, &[42; 32]).unwrap();
        let old = record.digest().unwrap();
        store
            .atomic(&old, &record.canonical_bytes().unwrap())
            .unwrap();
        let key = vaikor_grant::did_key(&vaikor_log::public_key(&[42; 32]));
        let clock = now();
        let grant = vaikor_grant::attach_signature(
            &json!({"v":"0.1","id":"retention-regression","iss":key,"sub":key,
                "aud":"store","iat":clock,"exp":vaikor_grant::add_rfc3339_z(&clock,3600).unwrap(),
                "cnf":{"kid":key},"chain":[],"rights":[
                    {"action":"read","resource":"tag:vaikor.com,2026:record:health/*"},
                    {"action":"retain","resource":"tag:vaikor.com,2026:record:health/*"}]}),
            &[42; 32],
            &key,
        );
        store.crash_at = Some("remove-error");
        Self {
            _cleanup: Cleanup(root.clone()),
            root,
            store,
            old,
            grant,
            key,
        }
    }
    fn replace(&mut self, mode: &str) -> (Result<String>, String) {
        let access = Access {
            grant: Some(&self.grant),
            holder: &self.key,
            audience: "store",
            policy: &vaikor_grant::PermitAll,
        };
        let result = self.store.set_retention(
            &self.old,
            json!({"until":"2000-01-01T00:00:00Z","on_expiry":mode}),
            &access,
        );
        let intent: Value =
            serde_json::from_slice(&fs::read(self.root.join("records/.retention-intent")).unwrap())
                .unwrap();
        let new = intent["new"].as_str().unwrap().to_owned();
        assert!(self.root.join("records").join(&self.old).exists());
        assert!(self.root.join("records").join(&new).exists());
        (result, new)
    }
    fn read_old(&mut self) -> Result<Record> {
        let mut step = self
            .store
            .begin_step("tag:vaikor.com,2026:capability:notes.write", Value::Null);
        let access = Access {
            grant: Some(&self.grant),
            holder: &self.key,
            audience: "store",
            policy: &vaikor_grant::PermitAll,
        };
        self.store.read(&mut step, &self.old, &access)
    }
}
struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn retention_recovery_does_not_spend_capped_uses() {
    let mut f = Fixture::new("capped-recovery");
    f.grant["rights"][1]["constraints"] = json!({"max_uses":1});
    f.grant = vaikor_grant::attach_signature(&f.grant, &[42; 32], &f.key);
    let (result, new) = f.replace("delete");
    assert!(result.unwrap_err().contains("injected remove I/O failure"));
    // Failed recovery at entry points must not reserve another use.
    assert!(f.store.audit_events().is_err());
    assert!(f.read_old().is_err());
    f.store.crash_at = None;
    let events = f.store.audit_events().unwrap();
    assert_eq!(
        events.iter().filter(|event| event.usage.is_some()).count(),
        1
    );
    assert!(!f.root.join("records").join(&f.old).exists());
    assert!(f.root.join("records").join(new).exists());
    assert!(!f.store.intent_path().exists());
}

#[test]
fn remove_error_after_commit_refuses_old_on_live_store() {
    let mut f = Fixture::new("live");
    let (result, new) = f.replace("delete");
    if let Ok(returned) = result {
        assert_eq!(returned, new);
        assert!(
            !f.root.join("records").join(&f.old).exists(),
            "Ok requires old removal"
        );
    } else {
        assert!(result.unwrap_err().contains("injected remove I/O failure"));
    }
    assert!(
        f.read_old().is_err(),
        "public read exposed superseded old record"
    );
}

#[test]
fn remove_error_then_sweep_and_reopen_cannot_resurrect_old() {
    let mut f = Fixture::new("reopen");
    let (result, new) = f.replace("delete");
    assert!(result.unwrap_err().contains("injected remove I/O failure"));
    // Let maintenance retry removal. Recovery must precede expiring the replacement.
    f.store.crash_at = None;
    f.store.expire_sweep().unwrap();
    if f.root.join("records/.retention-intent").exists() {
        assert!(
            f.root.join("records").join(&new).exists(),
            "expired new while intent open"
        );
    }
    // Release the original store lock before reopening the same directory.
    let root = f.root.clone();
    drop(f.store);
    let mut reopened = Store::open(&root, &[42; 32], vec![]).unwrap();
    let mut step = reopened.begin_step("tag:vaikor.com,2026:capability:notes.write", Value::Null);
    assert!(reopened
        .read(
            &mut step,
            &f.old,
            &Access {
                grant: Some(&f.grant),
                holder: &f.key,
                audience: "store",
                policy: &vaikor_grant::PermitAll
            }
        )
        .is_err());
}

#[test]
fn sweep_does_not_expire_new_digest_in_open_intent() {
    let mut f = Fixture::new("pending-new");
    let (result, new) = f.replace("tombstone");
    assert!(result.unwrap_err().contains("injected remove I/O failure"));
    let path = f.root.join("records").join(new);
    let before = fs::read(&path).unwrap();
    // Tombstoning uses atomic replacement, so a remove fault alone cannot stop
    // an incorrectly ordered sweep from destroying the signed replacement.
    let _ = f.store.expire_sweep();
    assert!(f.root.join("records/.retention-intent").exists());
    assert_eq!(
        fs::read(path).unwrap(),
        before,
        "sweep expired new while intent open"
    );
}
