// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! The signed record of a `sidged task` run goes through the record store (ROADMAP 11g):
//! it is an immutable, content-addressed entry under `records/`, readable with a grant of
//! the store, and `records/latest-record.json` only points to it.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sidged_cli::linguist::{IntentCatalog, LinguistModel, Ordered};
use sidged_cli::turnkey::{
    bootstrap_workspace, execute_turnkey_task_with, TurnkeyTaskSummary, RECORD_LOG_FILE,
};
use sidged_record::store::{Access, Store};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sidged-record-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    bootstrap_workspace(&dir).unwrap();
    dir
}

struct OneReply(String);

impl LinguistModel for OneReply {
    fn propose(&self, _system: &str, _user: &str) -> Result<String, String> {
        Ok(self.0.clone())
    }
}

fn task(dir: &Path, intent: &str, slots: &[(&str, &str)]) -> TurnkeyTaskSummary {
    // The Core keeps only slot values the utterance contains.
    let utterance: Vec<&str> = slots.iter().map(|(_, v)| *v).collect();
    let slots = Ordered(
        slots
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    );
    let envelope = IntentCatalog::builtin()
        .unwrap()
        .derive("en", Some(intent), &slots)
        .unwrap();
    let model = OneReply(serde_json::to_string(&envelope).unwrap());
    execute_turnkey_task_with(dir, &utterance.join(" "), false, &model).unwrap()
}

fn seed(dir: &Path, name: &str) -> [u8; 32] {
    let text = fs::read_to_string(dir.join("keys").join(name)).unwrap();
    let text = text.trim();
    let mut seed = [0u8; 32];
    for (i, slot) in seed.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap();
    }
    seed
}

/// The node's record store as an owner tool would open it: the workspace, the store's
/// audit chain under the log key, records signed by the node's executor key.
fn open_store(dir: &Path) -> Store {
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap();
    Store::open_with_owner_and_log(
        dir,
        &dir.join("logs").join(RECORD_LOG_FILE),
        &seed(dir, "log.key"),
        vec![manifest["edge1_did"].as_str().unwrap().to_string()],
        manifest["owner_did"].as_str().unwrap(),
    )
    .unwrap()
}

fn read_grant(dir: &Path) -> Value {
    let log_seed = seed(dir, "log.key");
    let did = sidged_grant::did_key(&sidged_log::public_key(&log_seed));
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sidged_grant::attach_signature(
        &json!({"v": "0.1", "id": "task-record-test", "iss": did, "sub": did, "aud": "owner-tool",
            "iat": sidged_grant::format_rfc3339_z(seconds),
            "exp": sidged_grant::format_rfc3339_z(seconds + 600),
            "cnf": {"kid": did}, "chain": [],
            "rights": [{"action": "read", "resource": "urn:sidged:record:documents/*"}]}),
        &log_seed,
        &did,
    )
}

fn read_record(dir: &Path, id: &str) -> Result<Value, String> {
    let digest = id.strip_prefix("urn:sidged:record:").unwrap();
    let grant = read_grant(dir);
    let mut store = open_store(dir);
    let access = Access {
        grant: Some(&grant),
        holder: grant["sub"].as_str().unwrap(),
        audience: "owner-tool",
        policy: &sidged_grant::PermitAll,
    };
    let mut step = store.begin_step(grant["sub"].as_str().unwrap(), Value::Null);
    store
        .read(&mut step, digest, &access)
        .map(|r| r.as_value().clone())
}

#[test]
fn a_task_record_is_readable_through_the_record_store() {
    let dir = scratch("store");
    let timer = task(&dir, "timer.set", &[("duration", "10 minutes")]);
    assert_eq!(timer.steps_executed, 1, "{timer:?}");
    let first = timer.record_id.clone().unwrap();
    let record = read_record(&dir, &first).unwrap();
    assert_eq!(
        record["content"]["summary"],
        "1 of 1 steps completed on this node"
    );
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(record["sig"]["signer"], manifest["edge1_did"]);
    let pointer = |dir: &Path| -> Value {
        serde_json::from_str(&fs::read_to_string(dir.join("records/latest-record.json")).unwrap())
            .unwrap()
    };
    assert_eq!(pointer(&dir)["record"], first.as_str());

    // A second run adds a record; the first stays as it was and the pointer moves.
    let note = task(&dir, "task.note", &[("content", "buy milk")]);
    let second = note.record_id.clone().unwrap();
    assert_ne!(first, second);
    assert_eq!(pointer(&dir)["record"], second.as_str());
    assert_eq!(read_record(&dir, &first).unwrap(), record);
    assert_eq!(
        read_record(&dir, &second).unwrap()["content"]["summary"],
        "1 of 1 steps completed on this node"
    );
    // The store audited the import on its chain.
    let log_seed = seed(&dir, "log.key");
    let events = sidged_log::Chain::open(&dir.join("logs").join(RECORD_LOG_FILE), &log_seed)
        .unwrap()
        .read_events()
        .unwrap();
    assert!(events
        .iter()
        .any(|e| e.step == "import" && e.decision == "allow" && e.capability == first));
    let _ = fs::remove_dir_all(dir);
}
