//! Offline, Core-owned record storage. Grant presentation, holder identity and
//! policy are supplied by the authenticated Core call boundary, never a module.
//! Capped uses are reserved durably in the signed runtime audit ledger before effects.
//!
//! The owner is configured by the Core (default: its local did:key). The same Ed25519
//! key currently signs three disjoint message encodings: Records start with a
//! dCBOR map byte, grants with a JCS `{`, and audit messages with an ASCII hex
//! chain hash followed by `.`. These signing languages cannot overlap; callers
//! must never expose a raw signing oracle. Separate derived keys would require
//! an explicit migration of existing signer anchors and logs.
//!
//! Tombstones are content-free retention receipts and are intentionally not
//! Records. Until an owner purge API exists, stop the Core (release store.lock),
//! remove the selected tombstone files under records/, and sync the directory.
//! This offline owner maintenance does not remove the signed audit history.
use crate::{decode, digest, encode, Record};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    rc::{Rc, Weak},
};
use vaikor_core::AuditEvent;
use vaikor_grant::{resource_covers, PolicyHook, Request};

type Result<T> = std::result::Result<T, String>;

/// The Core authenticates `holder` and configures audience and policy. The store
/// verifies the presented token's signatures, trust, lifetime and coverage on
/// every operation. Grant issuance trusts only the local Core; Record signer
/// anchors passed to `open` do not confer grant issuance authority.
/// Caller clocks cannot enter through the access context.
///
/// ```compile_fail
/// let access = vaikor_record::store::Access {
///     now: "2000-01-01T00:00:00Z",
///     ..vaikor_record::store::Access::missing()
/// };
/// ```
pub struct Access<'a> {
    pub grant: Option<&'a Value>,
    pub holder: &'a str,
    pub audience: &'a str,
    pub policy: &'a dyn PolicyHook,
}
impl Access<'_> {
    pub fn missing() -> Self {
        Self {
            grant: None,
            holder: "",
            audience: "",
            policy: &vaikor_grant::DenyAll,
        }
    }
}
struct Policy<'a>(&'a dyn PolicyHook);
impl PolicyHook for Policy<'_> {
    fn permit(&self, token: &vaikor_grant::Token, request: &Request) -> bool {
        self.0.permit(token, request)
    }
}

/// Unforgeable read set collected by the Core for one writing step.
/// Keep this in the runtime, never expose it to a writer/module.
pub struct ReadSet {
    store: u64,
    inputs: Rc<RefCell<Vec<(String, Record)>>>,
    source: String,
    plan: Value,
}

struct StepReads {
    source: String,
    plan: Value,
    inputs: Weak<RefCell<Vec<(String, Record)>>>,
}

pub struct Store {
    root: PathBuf,
    // Recovery also runs when creating a shared-reference step handle.
    chain: RefCell<vaikor_log::Chain>,
    seed: [u8; 32],
    trusted: Vec<String>,
    owner: String,
    grant_roots: Vec<String>,
    id: u64,
    steps: RefCell<Vec<StepReads>>,
    // Serialize stores even when they are configured with different log paths.
    _lock: File,
    #[cfg(test)]
    append_fault: bool,
    #[cfg(test)]
    crash_at: Option<&'static str>,
}
fn now() -> String {
    vaikor_grant::format_rfc3339_z(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Core clock before epoch")
            .as_secs() as i64,
    )
}
impl Store {
    /// Default configuration uses the local Core identity as owner.
    pub fn open(root: &Path, seed: &[u8; 32], trusted: Vec<String>) -> Result<Self> {
        Self::open_with_log(root, &root.join("audit.log"), seed, trusted)
    }
    /// Configure the signed audit chain while preserving the store lock.
    pub fn open_with_log(
        root: &Path,
        log: &Path,
        seed: &[u8; 32],
        trusted: Vec<String>,
    ) -> Result<Self> {
        Self::open_with_owner_and_log(
            root,
            log,
            seed,
            trusted,
            &vaikor_grant::did_key(&vaikor_log::public_key(seed)),
        )
    }
    /// Owner identity comes from trusted Core configuration, never write input.
    pub fn open_with_owner(
        root: &Path,
        seed: &[u8; 32],
        trusted: Vec<String>,
        owner: &str,
    ) -> Result<Self> {
        Self::open_with_owner_and_log(root, &root.join("audit.log"), seed, trusted, owner)
    }
    pub fn open_with_owner_and_log(
        root: &Path,
        log: &Path,
        seed: &[u8; 32],
        mut trusted: Vec<String>,
        owner: &str,
    ) -> Result<Self> {
        vaikor_grant::resolve_did_key(owner).map_err(|e| e.to_string())?;
        fs::create_dir_all(root).map_err(|e| e.to_string())?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join("store.lock"))
            .map_err(|e| e.to_string())?;
        vaikor_log::oslock::try_lock_exclusive(&lock)
            .map_err(|e| format!("record store is locked: {e}"))?;
        fs::create_dir_all(root.join("records")).map_err(|e| e.to_string())?;
        let chain = vaikor_log::Chain::open(log, seed)?;
        // Persist the newly created audit and records directory entries before
        // any operation can rely on a durable append in this directory.
        File::open(root)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        trusted.push(vaikor_grant::did_key(&vaikor_log::public_key(seed)));
        static ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let store = Self {
            root: root.to_owned(),
            chain: RefCell::new(chain),
            seed: *seed,
            owner: owner.into(),
            grant_roots: vec![vaikor_grant::did_key(&vaikor_log::public_key(seed))],
            trusted,
            id: ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            steps: RefCell::new(vec![]),
            _lock: lock,
            #[cfg(test)]
            append_fault: false,
            #[cfg(test)]
            crash_at: None,
        };
        store.recover_retention()?;
        for entry in fs::read_dir(root.join("records")).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') && name.ends_with(".tmp") {
                store.audit("recover-temp", &name, None, None, &Ok(()))?;
                fs::remove_file(entry.path()).map_err(|e| e.to_string())?;
                store.sync_dir()?;
            }
        }
        Ok(store)
    }
    /// Audit a boundary refusal before an input can be decoded as a Record.
    pub fn audit_refusal(&mut self, operation: &str, raw: &[u8], reason: &str) -> Result<()> {
        self.recover_retention()?;
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(raw));
        self.audit(
            operation,
            &digest,
            None,
            None,
            &Err::<(), _>(reason.to_owned()),
        )
    }
    /// Audit a Core boundary refusal for an already identified Record.
    pub fn audit_record_refusal(
        &mut self,
        operation: &str,
        digest: &str,
        reason: &str,
    ) -> Result<()> {
        self.recover_retention()?;
        self.audit(
            operation,
            digest,
            None,
            self.load(digest).ok().as_ref().map(Record::class),
            &Err::<(), _>(reason.to_owned()),
        )
    }
    pub fn audit_events(&mut self) -> Result<Vec<AuditEvent>> {
        self.recover_retention()?;
        self.chain.borrow_mut().read_events()
    }
    /// Core-only boundary: source and plan come from the executing plan, never
    /// from a module. Keep the handle in Core across all reads and writes.
    /// Live handles for the same source and plan share reads, preventing a
    /// second handle from erasing the writing step's input labels.
    pub fn begin_step(&self, source: &str, plan: Value) -> ReadSet {
        // This content-free handle has no error return. Retry recovery here;
        // every operation using the handle propagates any remaining failure.
        let _ = self.recover_retention();
        let mut steps = self.steps.borrow_mut();
        steps.retain(|s| s.inputs.strong_count() > 0);
        let inputs = steps
            .iter()
            .find(|s| s.source == source && s.plan == plan)
            .and_then(|s| s.inputs.upgrade())
            .unwrap_or_else(|| {
                let inputs = Rc::new(RefCell::new(vec![]));
                steps.push(StepReads {
                    source: source.into(),
                    plan: plan.clone(),
                    inputs: Rc::downgrade(&inputs),
                });
                inputs
            });
        ReadSet {
            store: self.id,
            inputs,
            source: source.into(),
            plan,
        }
    }

    fn audit(
        &self,
        op: &str,
        d: &str,
        access: Option<&Access<'_>>,
        class: Option<&str>,
        result: &Result<impl Sized>,
    ) -> Result<()> {
        // Verify the locked inode before append, including after an earlier partial write.
        self.chain.borrow_mut().read_events()?;
        #[cfg(test)]
        if self.append_fault {
            return Err("injected audit append I/O failure".into());
        }
        self.chain.borrow_mut().append(&AuditEvent {
            step: op.into(),
            capability: format!("tag:vaikor.com,2026:record:{d}"),
            effects: vec![op.into()],
            data_classes: class.map(|c| vec![c.into()]).unwrap_or_default(),
            actor: access.map(|a| json!({"holder":a.holder,"grant_id":a.grant.map(|g| &g["id"]),"issuer_kid":a.grant.map(|g| &g["sig"]["kid"])}).to_string()).unwrap_or_else(|| "intrinsic:R8".into()),
            at: now(),
            decision: if result.is_ok() { "allow" } else { "deny" }.into(),
            reason: result.as_ref().err().cloned(),
            privacy_report: None,
            usage: None,
            approval: None,
        })
    }
    fn path(&self, d: &str) -> Result<PathBuf> {
        if URL_SAFE_NO_PAD
            .decode(d)
            .map_err(|_| "malformed digest")?
            .len()
            != 32
            || d.len() != 43
        {
            return Err("malformed digest".into());
        }
        Ok(self.root.join("records").join(d))
    }
    fn load(&self, d: &str) -> Result<Record> {
        if let Some(intent) = self.open_retention_intent()? {
            if intent["old"].as_str() == Some(d) {
                return Err("record superseded by open retention intent".into());
            }
        }
        let bytes = fs::read(self.path(d)?).map_err(|e| e.to_string())?;
        let r = Record::check(decode(&bytes).map_err(|e| e.to_string())?, &self.trusted)
            .map_err(|e| e.to_string())?;
        if r.digest().map_err(|e| e.to_string())? != d {
            return Err("digest mismatch".into());
        }
        Ok(r)
    }
    fn permit(
        &mut self,
        r: &Record,
        action: &str,
        access: &Access<'_>,
    ) -> Result<Vec<(String, usize)>> {
        let resource = r.resource().map_err(|e| e.to_string())?;
        let clock = now();
        let roots: Vec<&str> = self.grant_roots.iter().map(String::as_str).collect();
        let token =
            vaikor_grant::accept_presented(access.grant.ok_or("grant denied")?, &clock, &roots)
                .map_err(|e| e.to_string())?;
        let tags: Vec<&str> = r.as_value()["residency"]["tags"]
            .as_array()
            .ok_or("malformed residency")?
            .iter()
            .map(|t| t.as_str().ok_or("malformed residency"))
            .collect::<std::result::Result<_, _>>()?;
        vaikor_grant::authorise(
            &token,
            &Request {
                holder: access.holder,
                audience: access.audience,
                action,
                resource: Some(&resource),
                data_classes: &[r.class()],
                residency: &tags,
            },
            Some(&clock),
            &Policy(access.policy),
        )
        .map_err(|e| e.to_string())?;
        // Replay the locked, verified chain, using the same account keys and
        // signed spend events as vaikor run. Check every ancestor before any
        // reservation so a denied child cannot consume an ancestor's uses.
        let history = self.chain.borrow_mut().read_events()?;
        let document = access.grant.ok_or("grant denied")?;
        let documents = document["chain"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(std::iter::once(document));
        let mut reservations = Vec::new();
        for (link, doc) in token
            .chain
            .iter()
            .chain(std::iter::once(&token.link))
            .zip(documents)
        {
            if link.budget != vaikor_grant::Budget::default() {
                return Err("grant denied: budget requires runtime reservation ledger".into());
            }
            let key = doc["id"]
                .as_str()
                .filter(|id| !id.is_empty())
                .map(|id| json!([link.iss, id]).to_string());
            let mut rights = link.rights.clone();
            for event in &history {
                if let Some((spent_key, index, uses)) = &event.usage {
                    if key.as_ref() != Some(spent_key) {
                        continue;
                    }
                    let right = rights
                        .get_mut(*index)
                        .ok_or("grant denied: audit right index")?;
                    if let Some(left) = right.constraints.max_uses.as_mut() {
                        *left = left
                            .checked_sub(*uses)
                            .ok_or("grant denied: audit uses exceed grant")?;
                    }
                }
            }
            let selected = rights
                .iter()
                .position(|right| {
                    right.action == action
                        && resource_covers(&right.resource, &resource)
                        && right.constraints.max_uses.is_none_or(|left| left >= 1)
                        && right.constraints.max_amount.is_none()
                        && right
                            .constraints
                            .data_classes
                            .as_ref()
                            .is_none_or(|cs| cs.iter().any(|c| c == r.class()))
                })
                .ok_or("grant denied: no covering right with uses remaining")?;
            if rights[selected].constraints.max_uses.is_some() {
                reservations.push((
                    key.ok_or("grant denied: missing token id for audit ledger")?,
                    selected,
                ));
            }
        }
        Ok(reservations)
    }

    // Call only after all logical checks; durable spends precede the effect.
    fn spend(
        &mut self,
        r: &Record,
        action: &str,
        reservations: Vec<(String, usize)>,
    ) -> Result<()> {
        let clock = now();
        let digest = r.digest().map_err(|e| e.to_string())?;
        for (key, index) in reservations {
            #[cfg(test)]
            if self.append_fault {
                return Err("injected audit append I/O failure".into());
            }
            self.chain.borrow_mut().append(&AuditEvent {
                step: action.into(),
                capability: format!("tag:vaikor.com,2026:record:{digest}"),
                effects: Vec::new(),
                data_classes: Vec::new(),
                actor: "core".into(),
                at: clock.clone(),
                decision: "spend".into(),
                reason: Some("null".into()),
                privacy_report: None,
                usage: Some((key, index, 1)),
                approval: None,
            })?;
        }
        Ok(())
    }

    // Panicking models abrupt process termination: no error cleanup is run.
    #[cfg(test)]
    fn crash_point(&self, step: &str) {
        assert_ne!(self.crash_at, Some(step), "injected crash after {step}");
    }

    fn atomic(&self, d: &str, bytes: &[u8]) -> Result<()> {
        let path = self.path(d)?;
        let tmp = self.root.join("records").join(format!(".{d}.tmp"));
        let result = (|| {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| e.to_string())?;
            #[cfg(test)]
            self.crash_point("create");
            f.write_all(bytes).map_err(|e| e.to_string())?;
            #[cfg(test)]
            self.crash_point("write");
            f.sync_all().map_err(|e| e.to_string())?;
            #[cfg(test)]
            self.crash_point("file-sync");
            fs::rename(&tmp, path).map_err(|e| e.to_string())?;
            #[cfg(test)]
            self.crash_point("rename");
            self.sync_dir()?;
            #[cfg(test)]
            self.crash_point("directory-sync");
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(tmp);
        }
        result
    }
    fn sync_dir(&self) -> Result<()> {
        File::open(self.root.join("records"))
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())
    }
    fn intent_path(&self) -> PathBuf {
        self.root.join("records/.retention-intent")
    }
    fn open_retention_intent(&self) -> Result<Option<Value>> {
        match fs::read(self.intent_path()) {
            Ok(bytes) => {
                let intent: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                self.path(intent["old"].as_str().ok_or("invalid retention intent")?)?;
                self.path(intent["new"].as_str().ok_or("invalid retention intent")?)?;
                Ok(Some(intent))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
    fn recover_retention(&self) -> Result<()> {
        let Some(intent) = self.open_retention_intent()? else {
            return Ok(());
        };
        let old = intent["old"].as_str().ok_or("invalid retention intent")?;
        let new = intent["new"].as_str().ok_or("invalid retention intent")?;
        let old_path = self.path(old)?;
        let new_path = self.path(new)?;
        if new_path.try_exists().map_err(|e| e.to_string())? {
            // Audit before mutation; retain the intent if either operation fails.
            self.audit("recover-retention", new, None, None, &Ok(()))?;
            if old != new && old_path.try_exists().map_err(|e| e.to_string())? {
                self.remove(old)?;
            }
            self.sync_dir()?;
        }
        #[cfg(test)]
        self.crash_point("old-remove");
        fs::remove_file(self.intent_path()).map_err(|e| e.to_string())?;
        #[cfg(test)]
        self.crash_point("intent-remove");
        self.sync_dir()?;
        #[cfg(test)]
        self.crash_point("intent-clear-sync");
        Ok(())
    }
    fn retention_intent(&self, old: &str, new: &str) -> Result<()> {
        let tmp = self.root.join("records/.retention.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| e.to_string())?;
        #[cfg(test)]
        self.crash_point("intent-create");
        file.write_all(
            &serde_json::to_vec(&json!({"old":old,"new":new})).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        #[cfg(test)]
        self.crash_point("intent-write");
        file.sync_all().map_err(|e| e.to_string())?;
        #[cfg(test)]
        self.crash_point("intent-file-sync");
        fs::rename(tmp, self.intent_path()).map_err(|e| e.to_string())?;
        #[cfg(test)]
        self.crash_point("intent-rename");
        self.sync_dir()?;
        #[cfg(test)]
        self.crash_point("intent-sync");
        Ok(())
    }
    fn remove(&self, d: &str) -> Result<()> {
        #[cfg(test)]
        if self.crash_at == Some("remove-error") {
            return Err(std::io::Error::other("injected remove I/O failure").to_string());
        }
        fs::remove_file(self.path(d)?).map_err(|e| e.to_string())?;
        #[cfg(test)]
        self.crash_point("unlink");
        self.sync_dir()
    }
    fn expire(&mut self, r: &Record) -> Result<()> {
        let d = r.digest().map_err(|e| e.to_string())?;
        self.audit("expire", &d, None, Some(r.class()), &Ok(()))?;
        let v = r.as_value();
        if v["retention"]["on_expiry"] == "delete" {
            self.remove(&d)
        } else {
            self.atomic(&d, &encode(&json!({"digest":d,"class":v["class"],"provenance":v["provenance"],"retention":v["retention"]})).map_err(|e| e.to_string())?)
        }
    }
    fn read_inner(&mut self, d: &str, access: &Access<'_>) -> Result<Record> {
        let result = self.load(d).and_then(|r| {
            let reservations = self.permit(&r, "read", access)?;
            Ok((r, reservations))
        });
        let class = result
            .as_ref()
            .ok()
            .map(|(r, _)| r.class().to_owned())
            .or_else(|| self.load(d).ok().map(|r| r.class().to_owned()));
        if let Ok((r, _)) = &result {
            if r.expired().map_err(|e| e.to_string())? {
                self.audit(
                    "read",
                    d,
                    Some(access),
                    class.as_deref(),
                    &Err::<(), _>("expired".into()),
                )?;
                self.expire(r)?;
                return Err("expired".into());
            }
        }
        let result = result.and_then(|(r, reservations)| {
            self.spend(&r, "read", reservations)?;
            Ok(r)
        });
        self.audit("read", d, Some(access), class.as_deref(), &result)?;
        result
    }
    /// Reads enforce the Core clock and require a Core-held step context.
    ///
    /// ```compile_fail
    /// fn without_step(store: &mut vaikor_record::store::Store) {
    ///     store.read("digest", &vaikor_record::store::Access::missing()).unwrap();
    /// }
    /// ```
    pub fn read(&mut self, step: &mut ReadSet, d: &str, access: &Access<'_>) -> Result<Record> {
        self.recover_retention()?;
        if step.store != self.id {
            let result = Err("foreign read set".into());
            self.audit(
                "read",
                d,
                Some(access),
                self.load(d).ok().as_ref().map(Record::class),
                &result,
            )?;
            return result;
        }
        let r = self.read_inner(d, access)?;
        let mut inputs = step.inputs.borrow_mut();
        if !inputs.iter().any(|(digest, _)| digest == d) {
            inputs.push((d.into(), r.clone()));
        }
        Ok(r)
    }
    /// Writes require an explicit Core step, even for fresh, non-derived data.
    /// Null owner/created fields request Core values; conflicting claims fail.
    ///
    /// ```compile_fail
    /// fn without_step(store: &mut vaikor_record::store::Store) {
    ///     store.write(serde_json::json!({}), &vaikor_record::store::Access::missing()).unwrap();
    /// }
    /// ```
    pub fn write(&mut self, value: Value, reads: &ReadSet, access: &Access<'_>) -> Result<String> {
        self.recover_retention()?;
        self.write_inner(value, reads, access)
    }
    fn write_inner(
        &mut self,
        mut value: Value,
        reads: &ReadSet,
        access: &Access<'_>,
    ) -> Result<String> {
        let fallback = digest(&value).unwrap_or_else(|_| {
            URL_SAFE_NO_PAD.encode(Sha256::digest(value.to_string().as_bytes()))
        });
        let presented_class = value["class"].as_str().map(str::to_owned);
        let result = (|| {
            if !value.is_object() {
                return Err("malformed record".into());
            }
            let provenance = value["provenance"]
                .as_object()
                .ok_or("malformed provenance")?;
            if provenance
                .keys()
                .any(|k| !["source", "created", "derived_from", "plan"].contains(&k.as_str()))
            {
                return Err("unknown provenance member".into());
            }
            let created = now();
            if reads.store != self.id {
                return Err("foreign read set".into());
            }
            for (supplied, expected) in [
                (&value["owner"], json!(self.owner)),
                (&value["provenance"]["created"], json!(created)),
                (&value["provenance"]["source"], json!(reads.source)),
                (&value["provenance"]["plan"], reads.plan.clone()),
            ] {
                if !supplied.is_null() && supplied != &expected {
                    return Err("writer claim mismatch".into());
                }
            }
            value["owner"] = json!(self.owner);
            value["provenance"]["created"] = json!(created);
            value["provenance"]["source"] = json!(reads.source);
            value["provenance"]["plan"] = reads.plan.clone();
            Record::sign(value.clone(), &self.seed).map_err(|e| e.to_string())?;
            let inputs = reads.inputs.borrow();
            if !inputs.is_empty() {
                let mut labels = vec![];
                for (d, snapshot) in inputs.iter() {
                    let r = self.load(d).map_err(|e| format!("missing input: {e}"))?;
                    if r.as_value() != snapshot.as_value() {
                        return Err("changed input".into());
                    }
                    if r.expired().map_err(|e| e.to_string())? {
                        return Err("expired input".into());
                    }
                    labels.push((
                        r.class().to_owned(),
                        r.as_value()["residency"]["tags"]
                            .as_array()
                            .ok_or("malformed residency")?
                            .iter()
                            .map(|t| t.as_str().map(str::to_owned).ok_or("malformed residency"))
                            .collect::<std::result::Result<_, _>>()?,
                    ));
                }
                let (class, tags) = crate::derive_record_labels(&labels)?;
                // The shared helper treats an undeclared input conservatively.
                // Never turn a known restriction into empty (unrestricted) tags.
                if labels
                    .iter()
                    .flat_map(|(_, ts)| ts)
                    .any(|t| t != "unrestricted" && !tags.contains(t))
                {
                    return Err("residency-unsupported".into());
                }
                value["class"] = json!(class);
                value["residency"]["tags"] = json!(tags);
                value["provenance"]["derived_from"] =
                    json!(inputs.iter().map(|(d, _)| d).collect::<Vec<_>>());
            } else if value["provenance"]["derived_from"]
                .as_array()
                .is_some_and(|ds| !ds.is_empty())
            {
                return Err("derived write requires Core read set".into());
            }
            let r = Record::sign(value, &self.seed).map_err(|e| e.to_string())?;
            let reservations = self.permit(&r, "write", access)?;
            if r.expired().map_err(|e| e.to_string())? {
                return Err("expired".into());
            }
            self.spend(&r, "write", reservations)?;
            Ok(r)
        })();
        let d = result
            .as_ref()
            .ok()
            .and_then(|r| r.digest().ok())
            .unwrap_or(fallback);
        self.audit(
            "write",
            &d,
            Some(access),
            result
                .as_ref()
                .ok()
                .map(Record::class)
                .or(presented_class.as_deref()),
            &result,
        )?;
        let r = result?;
        self.atomic(&d, &r.canonical_bytes().map_err(|e| e.to_string())?)?;
        Ok(d)
    }
    pub fn import(&mut self, bytes: &[u8], access: &Access<'_>) -> Result<String> {
        self.recover_retention()?;
        let decoded = decode(bytes);
        let d = decoded
            .as_ref()
            .ok()
            .and_then(|v| digest(v).ok())
            .unwrap_or_else(|| URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)));
        let presented_class = decoded
            .as_ref()
            .ok()
            .and_then(|v| v["class"].as_str())
            .map(str::to_owned);
        let result = decoded
            .map_err(|e| e.to_string())
            .and_then(|v| Record::check(v, &self.trusted).map_err(|e| e.to_string()))
            .and_then(|r| {
                let reservations = self.permit(&r, "import", access)?;
                if r.expired().map_err(|e| e.to_string())? {
                    return Err("expired".into());
                }
                self.spend(&r, "import", reservations)?;
                Ok(r)
            });
        self.audit(
            "import",
            &d,
            Some(access),
            result
                .as_ref()
                .ok()
                .map(Record::class)
                .or(presented_class.as_deref()),
            &result,
        )?;
        let r = result?;
        self.atomic(&d, &r.canonical_bytes().map_err(|e| e.to_string())?)?;
        Ok(d)
    }
    pub fn delete(&mut self, d: &str, access: &Access<'_>) -> Result<()> {
        self.recover_retention()?;
        let result = self.load(d).and_then(|r| {
            let reservations = self.permit(&r, "delete", access)?;
            self.spend(&r, "delete", reservations)
        });
        self.audit(
            "delete",
            d,
            Some(access),
            self.load(d).ok().as_ref().map(Record::class),
            &result,
        )?;
        result?;
        self.remove(d)
    }
    /// Returns the new digest: retention is signed content and cannot mutate in place.
    /// Only locally signed Records can be changed. A covering retain grant may
    /// extend retention, including to null. The replacement is durable before
    /// removing the old address. A durable intent lets open finish interrupted
    /// replacements before serving reads.
    /// A deadline in the past is
    /// accepted and makes the replacement immediately expired.
    pub fn set_retention(
        &mut self,
        d: &str,
        retention: Value,
        access: &Access<'_>,
    ) -> Result<String> {
        self.recover_retention()?;
        let result = (|| {
            let r = self.load(d)?;
            let reservations = self.permit(&r, "retain", access)?;
            if r.expired().map_err(|e| e.to_string())? {
                return Err("expired".into());
            }
            if r.as_value()["sig"]["signer"]
                != vaikor_grant::did_key(&vaikor_log::public_key(&self.seed))
            {
                return Err("imported retention requires original signer".into());
            }
            let mut v = r.as_value().clone();
            v["retention"] = retention;
            let replacement = Record::sign(v, &self.seed).map_err(|e| e.to_string())?;
            self.spend(&r, "retain", reservations)?;
            Ok(replacement)
        })();
        self.audit(
            "retention",
            d,
            Some(access),
            self.load(d).ok().as_ref().map(Record::class),
            &result,
        )?;
        let r = result?;
        let new = r.digest().map_err(|e| e.to_string())?;
        self.audit("retention", &new, Some(access), Some(r.class()), &Ok(()))?;
        let bytes = r.canonical_bytes().map_err(|e| e.to_string())?;
        // Keep the old version until the replacement and its directory entry
        // are durable. Never introduce a window with neither version present.
        if new != d {
            self.retention_intent(d, &new)?;
        }
        self.atomic(&new, &bytes)?;
        self.recover_retention()?;
        Ok(new)
    }
    /// Core retention maintenance has intrinsic authority under R8; it cannot read content.
    pub fn expire_sweep(&mut self) -> Result<usize> {
        self.recover_retention()?;
        let result = fs::read_dir(self.root.join("records")).map_err(|e| e.to_string());
        self.audit("expire-sweep", "store", None, None, &result)?;
        let mut count = 0;
        for entry in result? {
            let result = entry.map_err(|e| e.to_string());
            self.audit("expire-sweep", "store", None, None, &result)?;
            let Ok(entry) = result else { continue };
            let name = entry.file_name().to_string_lossy().into_owned();
            let result = (|| {
                let bytes = fs::read(self.path(&name)?).map_err(|e| e.to_string())?;
                let v = decode(&bytes).map_err(|e| e.to_string())?;
                // A tombstone has exactly these four members, and never content.
                if v.as_object().is_some_and(|m| {
                    m.len() == 4
                        && ["digest", "class", "provenance", "retention"]
                            .iter()
                            .all(|k| m.contains_key(*k))
                }) && v["digest"] == name
                {
                    return Ok(None);
                }
                self.load(&name).map(Some)
            })();
            self.audit(
                "expire-check",
                &name,
                None,
                result
                    .as_ref()
                    .ok()
                    .and_then(|r| r.as_ref())
                    .map(Record::class),
                &result,
            )?;
            if let Ok(Some(r)) = result {
                if r.expired().map_err(|e| e.to_string())? {
                    self.expire(&r)?;
                    count += 1;
                }
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
#[path = "../tests/retention/mod.rs"]
mod retention_regressions;

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn draft(mut v: Value) -> Value {
        v["owner"] = Value::Null;
        v["provenance"]["created"] = Value::Null;
        v
    }

    #[test]
    fn crashes_preserve_retention_and_same_digest_rewrites() {
        for case in 0..4 {
            let rewrite = case == 1;
            for stage in [
                "create",
                "write",
                "file-sync",
                "rename",
                "directory-sync",
                "unlink",
                "old-remove",
                "remove-error",
                "intent-create",
                "intent-write",
                "intent-file-sync",
                "intent-rename",
                "intent-sync",
                "intent-remove",
                "intent-clear-sync",
            ] {
                let root = std::env::temp_dir().join(format!(
                    "vaikor-crash-{}-{case}-{stage}",
                    std::process::id()
                ));
                let _ = fs::remove_dir_all(&root);
                let _cleanup = TempDir(root.clone());
                let mut store = Store::open(&root, &[42; 32], vec![]).unwrap();
                let vectors: Value = serde_json::from_str(include_str!(
                    "../../../spec/test-vectors/records/records.json"
                ))
                .unwrap();
                let mut value = vectors["vectors"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|v| v["id"] == "record.check.001")
                    .unwrap()["input"]["record"]
                    .clone();
                value["retention"]["until"] = if case == 3 {
                    json!("2099-01-01T00:00:00Z")
                } else {
                    Value::Null
                };
                let record = Record::sign(value.clone(), &[42; 32]).unwrap();
                let d = record.digest().unwrap();
                let bytes = record.canonical_bytes().unwrap();
                store.atomic(&d, &bytes).unwrap();
                let key = vaikor_grant::did_key(&vaikor_log::public_key(&[42; 32]));
                let clock = now();
                let rights: Vec<Value> = ["write", "read", "delete", "retain", "import"]
                    .iter()
                    .map(|a| json!({"action":a,"resource":"tag:vaikor.com,2026:record:health/*"}))
                    .collect();
                let grant = vaikor_grant::attach_signature(
                    &json!({"v":"0.1","id":"append-fault","iss":key,"sub":key,"aud":"store","iat":clock,"exp":vaikor_grant::add_rfc3339_z(&clock, 3600).unwrap(),"cnf":{"kid":key},"chain":[],"rights":rights}),
                    &[42; 32],
                    &key,
                );
                let access = Access {
                    grant: Some(&grant),
                    holder: &key,
                    audience: "store",
                    policy: &vaikor_grant::PermitAll,
                };

                let retention = if case >= 2 {
                    json!({"until": if case == 3 { vaikor_grant::add_rfc3339_z(&now(), -1).unwrap() } else { "2000-01-01T00:00:00Z".into() },"on_expiry":"delete"})
                } else {
                    json!({"until":null,"on_expiry":"tombstone"})
                };
                let mut updated = record.as_value().clone();
                updated["retention"] = retention.clone();
                let replacement = Record::sign(updated, &[42; 32]).unwrap();
                let new = replacement.digest().unwrap();
                store.crash_at = Some(stage);
                let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if rewrite {
                        // Import exercises atomic replacement over an existing target.
                        store.import(&bytes, &access).unwrap();
                    } else {
                        let result = store.set_retention(&d, retention, &access);
                        if stage == "remove-error" {
                            assert!(result.unwrap_err().contains("injected remove I/O failure"));
                            assert!(store.intent_path().exists());
                            assert!(store.load(&d).is_err(), "open intent exposes old record");
                            let mut reads = store.begin_step("test", Value::Null);
                            assert!(store.read(&mut reads, &d, &access).is_err());
                            assert!(store
                                .expire_sweep()
                                .unwrap_err()
                                .contains("injected remove I/O failure"));
                            assert!(store
                                .audit_events()
                                .unwrap_err()
                                .contains("injected remove I/O failure"));
                            assert!(store
                                .audit_refusal("test", b"input", "denied")
                                .unwrap_err()
                                .contains("injected remove I/O failure"));
                            assert!(store
                                .audit_record_refusal("test", &d, "denied")
                                .unwrap_err()
                                .contains("injected remove I/O failure"));
                            assert!(store
                                .import(&bytes, &access)
                                .unwrap_err()
                                .contains("injected remove I/O failure"));
                            assert!(store
                                .delete(&new, &access)
                                .unwrap_err()
                                .contains("injected remove I/O failure"));
                            assert!(store
                                .write(draft(value.clone()), &reads, &access)
                                .unwrap_err()
                                .contains("injected remove I/O failure"));
                            assert!(store.path(&new).unwrap().exists());
                            assert!(store.intent_path().exists());
                        } else {
                            result.unwrap();
                        }
                    }
                }));
                assert_eq!(
                    interrupted.is_err(),
                    stage != "remove-error"
                        && (!rewrite
                            || ![
                                "unlink",
                                "old-remove",
                                "intent-create",
                                "intent-write",
                                "intent-file-sync",
                                "intent-rename",
                                "intent-sync",
                                "intent-remove",
                                "intent-clear-sync"
                            ]
                            .contains(&stage))
                );
                drop(store);
                let mut store = Store::open(&root, &[42; 32], vec![]).unwrap();
                let committed = !rewrite
                    && [
                        "rename",
                        "directory-sync",
                        "unlink",
                        "old-remove",
                        "remove-error",
                        "intent-remove",
                        "intent-clear-sync",
                    ]
                    .contains(&stage);
                if committed {
                    assert!(
                        !root.join("records").join(&d).exists(),
                        "old survives {stage}"
                    );
                    assert!(
                        store
                            .audit_events()
                            .unwrap()
                            .iter()
                            .any(|e| e.step == "recover-retention")
                            || ["old-remove", "intent-remove", "intent-clear-sync"]
                                .contains(&stage)
                    );
                    if case >= 2 {
                        let mut reads = store.begin_step("test", Value::Null);
                        assert!(store.read(&mut reads, &d, &access).is_err());
                        assert!(store.read(&mut reads, &new, &access).is_err());
                    }
                }
                assert!(!store.intent_path().exists());
                if !committed && !rewrite {
                    let mut reads = store.begin_step("test", Value::Null);
                    assert_eq!(
                        store.read(&mut reads, &d, &access).unwrap().as_value(),
                        record.as_value()
                    );
                }
                let old = store.load(&d).ok();
                let new_record = store.load(&new).ok();
                assert!(
                    (committed && case >= 2) || old.is_some() || new_record.is_some(),
                    "lost record after {stage}"
                );
                if let Some(old) = old {
                    assert_eq!(old.canonical_bytes().unwrap(), bytes);
                }
                if let Some(new_record) = new_record {
                    assert_eq!(new_record.as_value(), replacement.as_value());
                }
                let events = store.audit_events().unwrap();
                let effects: Vec<_> = events
                    .iter()
                    .filter(|e| e.step == "retention" || e.step == "import")
                    .collect();
                assert_eq!(effects.len(), if rewrite { 1 } else { 2 });
                assert!(effects.iter().all(|e| e.decision == "allow"));
                assert_eq!(
                    effects[0].capability,
                    format!("tag:vaikor.com,2026:record:{d}")
                );
                if !rewrite {
                    assert_eq!(
                        effects[1].capability,
                        format!("tag:vaikor.com,2026:record:{new}")
                    );
                }
                assert!(fs::read_dir(root.join("records")).unwrap().all(|e| !e
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")));
                drop(store);
                fs::remove_dir_all(root).unwrap();
            }
        }
    }

    #[test]
    fn crashes_during_tombstone_rewrite_preserve_complete_old_or_new_content() {
        for stage in ["create", "write", "file-sync", "rename", "directory-sync"] {
            let root = std::env::temp_dir().join(format!(
                "vaikor-tombstone-crash-{}-{stage}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            let _cleanup = TempDir(root.clone());
            let mut store = Store::open(&root, &[42; 32], vec![]).unwrap();
            let vectors: Value = serde_json::from_str(include_str!(
                "../../../spec/test-vectors/records/records.json"
            ))
            .unwrap();
            let mut value = vectors["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["id"] == "record.check.001")
                .unwrap()["input"]["record"]
                .clone();
            value["retention"] = json!({"until":"2000-01-01T00:00:00Z","on_expiry":"tombstone"});
            let record = Record::sign(value, &[42; 32]).unwrap();
            let d = record.digest().unwrap();
            let old = record.canonical_bytes().unwrap();
            let v = record.as_value();
            let tombstone = json!({"digest":d,"class":v["class"],"provenance":v["provenance"],"retention":v["retention"]});
            store.atomic(&d, &old).unwrap();
            store.crash_at = Some(stage);
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || store.expire(&record)
            ))
            .is_err());
            drop(store);
            let mut store = Store::open(&root, &[42; 32], vec![]).unwrap();
            let bytes = fs::read(store.path(&d).unwrap()).unwrap();
            if ["rename", "directory-sync"].contains(&stage) {
                assert_eq!(decode(&bytes).unwrap(), tombstone);
            } else {
                assert_eq!(store.load(&d).unwrap().as_value(), record.as_value());
                assert_eq!(bytes, old);
            }
            let events = store.audit_events().unwrap();
            assert_eq!(events[0].step, "expire");
            assert_eq!(events[0].decision, "allow");
            assert_eq!(
                events[0].capability,
                format!("tag:vaikor.com,2026:record:{d}")
            );
            assert!(events[1..].iter().all(|e| e.step == "recover-temp"));
            drop(store);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn append_io_failure_prevents_new_files_and_preserves_existing_files() {
        let root = std::env::temp_dir().join(format!("vaikor-append-fault-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let _cleanup = TempDir(root.clone());
        let mut store = Store::open(&root, &[42; 32], vec![]).unwrap();
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../spec/test-vectors/records/records.json"
        ))
        .unwrap();
        let mut value = vectors["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == "record.check.001")
            .unwrap()["input"]["record"]
            .clone();
        value["retention"]["until"] = Value::Null;
        let record = Record::sign(value.clone(), &[42; 32]).unwrap();
        let d = record.digest().unwrap();
        let bytes = record.canonical_bytes().unwrap();
        store.atomic(&d, &bytes).unwrap();
        let key = vaikor_grant::did_key(&vaikor_log::public_key(&[42; 32]));
        let clock = now();
        let rights: Vec<Value> = ["write", "read", "delete", "retain", "import"]
            .iter()
            .map(|a| json!({"action":a,"resource":"tag:vaikor.com,2026:record:health/*"}))
            .collect();
        let grant = vaikor_grant::attach_signature(
            &json!({"v":"0.1","id":"append-fault","iss":key,"sub":key,"aud":"store","iat":clock,"exp":vaikor_grant::add_rfc3339_z(&clock, 3600).unwrap(),"cnf":{"kid":key},"chain":[],"rights":rights}),
            &[42; 32],
            &key,
        );
        let access = Access {
            grant: Some(&grant),
            holder: &key,
            audience: "store",
            policy: &vaikor_grant::PermitAll,
        };
        store.append_fault = true;
        value["content"] = json!("new content");
        assert!(store
            .write(
                draft(value),
                &store.begin_step("tag:vaikor.com,2026:capability:notes.write", Value::Null),
                &access
            )
            .unwrap_err()
            .contains("append"));
        assert!(store
            .read(
                &mut store.begin_step("tag:vaikor.com,2026:capability:notes.write", Value::Null),
                &d,
                &access
            )
            .unwrap_err()
            .contains("append"));
        assert!(store.delete(&d, &access).unwrap_err().contains("append"));
        assert!(store
            .import(&bytes, &access)
            .unwrap_err()
            .contains("append"));
        assert!(store
            .set_retention(&d, json!({"until":null,"on_expiry":"tombstone"}), &access)
            .unwrap_err()
            .contains("append"));
        assert!(store.expire_sweep().unwrap_err().contains("append"));
        // Exercise the exact append boundary for both expiry commits, too.
        for mode in ["delete", "tombstone"] {
            let mut expired = record.as_value().clone();
            expired["retention"] = json!({"until":"2000-01-01T00:00:00Z","on_expiry":mode});
            let expired = Record::sign(expired, &[42; 32]).unwrap();
            let expired_d = expired.digest().unwrap();
            let expired_bytes = expired.canonical_bytes().unwrap();
            store.atomic(&expired_d, &expired_bytes).unwrap();
            assert!(store.expire(&expired).unwrap_err().contains("append"));
            assert_eq!(
                fs::read(store.path(&expired_d).unwrap()).unwrap(),
                expired_bytes
            );
            store.remove(&expired_d).unwrap();
        }
        assert_eq!(fs::read(store.path(&d).unwrap()).unwrap(), bytes);
        assert_eq!(fs::read_dir(root.join("records")).unwrap().count(), 1);
        assert!(store.audit_events().unwrap().is_empty());
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
}
