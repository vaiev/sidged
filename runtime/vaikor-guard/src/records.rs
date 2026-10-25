use std::{collections::HashMap, fs, path::PathBuf};
use vaikor_record::store::{Access, Store};
const USAGE: &str = "usage: vaikor record write <record.json>|read <digest>|delete <digest>|retention <digest> <retention.json>|import <record.cbor>|expire --grant <token.json> --trusted-issuer <did> --policy <file> --log-key <seed.hex> [--record-anchor <did>] [--log <file>] [--store <dir>] [--audience <id>]";
pub fn run(args: &[String]) -> Result<String, String> {
    let op = args.first().ok_or(USAGE)?;
    let count = match op.as_str() {
        "write" | "read" | "delete" | "import" => 1,
        "retention" => 2,
        "expire" => 0,
        _ => return Err(USAGE.into()),
    };
    let positional = args.get(1..1 + count).ok_or(USAGE)?;
    if positional.iter().any(|s| s.starts_with("--")) {
        return Err(USAGE.into());
    }
    let mut flags = HashMap::new();
    let mut trusted = vec![];
    let mut anchors = vec![];
    let mut rest = args[1 + count..].iter();
    while let Some(flag) = rest.next() {
        if ![
            "--grant",
            "--trusted-issuer",
            "--record-anchor",
            "--policy",
            "--log-key",
            "--log",
            "--store",
            "--audience",
        ]
        .contains(&flag.as_str())
        {
            return Err(USAGE.into());
        }
        let value = rest.next().ok_or(USAGE)?;
        if flag == "--trusted-issuer" {
            trusted.push(value.clone());
        } else if flag == "--record-anchor" {
            anchors.push(value.clone());
        } else if flags.insert(flag.as_str(), value.as_str()).is_some() {
            return Err(USAGE.into());
        }
    }
    let seed = super::read_seed(flags.get("--log-key").copied())?.ok_or("--log-key is required")?;
    let root = vaikor_guard::record_store_path(flags.get("--store").copied())?;
    eprintln!("record store: {}", root.display());
    let log = flags
        .get("--log")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("audit.log"));
    eprintln!("audit log: {}", log.display());
    let mut store = Store::open_with_log(&root, &log, &seed, anchors)?;
    let prepared = (|| {
        let grant = flags.get("--grant").map(|p| json_file(p)).transpose()?;
        let policy_path = flags.get("--policy").ok_or("--policy is required")?;
        let policy = fs::read_to_string(policy_path).map_err(|e| e.to_string())?;
        let cedar = vaikor_grant::CedarEvaluator::parse(&policy).map_err(|e| e.to_string())?;
        Ok::<_, String>((grant, cedar))
    })();
    let (grant, cedar) = match prepared {
        Ok(value) => value,
        Err(error) => {
            boundary_refusal(&mut store, op, positional, &error)?;
            return Err(error);
        }
    };
    let now = vaikor_grant::format_rfc3339_z(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs() as i64,
    );
    let refs: Vec<&str> = trusted.iter().map(String::as_str).collect();
    let accepted = grant
        .as_ref()
        .ok_or_else(|| "grant required".to_owned())
        .and_then(|g| vaikor_grant::accept_presented(g, &now, &refs).map_err(|e| e.to_string()));
    let token = match accepted {
        Ok(token) => token,
        Err(error) => {
            boundary_refusal(&mut store, op, positional, &error)?;
            return Err(error);
        }
    };
    let audience = flags.get("--audience").copied().unwrap_or("vaikor");
    if token.link.aud != audience {
        boundary_refusal(&mut store, op, positional, "audience mismatch")?;
        return Err("audience mismatch".into());
    }
    let access = Access {
        grant: grant.as_ref(),
        holder: &token.link.sub,
        audience,
        policy: &cedar,
    };
    let mut step = store.begin_step(&token.link.sub, serde_json::Value::Null);
    let mut input = |path: &str| -> Result<serde_json::Value, String> {
        let raw = fs::read(path).map_err(|e| e.to_string());
        match raw.and_then(|bytes| serde_json::from_slice(&bytes).map_err(|e| e.to_string())) {
            Ok(value) => Ok(value),
            Err(error) => {
                boundary_refusal(&mut store, op, positional, &error)?;
                Err(error)
            }
        }
    };
    // Parse before borrowing the store for the effect.
    let value = match op.as_str() {
        "write" => Some(input(&positional[0])?),
        "retention" => Some(input(&positional[1])?),
        _ => None,
    };
    match op.as_str() {
        "write" => store.write(value.unwrap(), &step, &access),
        "read" => store
            .read(&mut step, &positional[0], &access)
            .map(|r| r.as_value().to_string()),
        "delete" => store
            .delete(&positional[0], &access)
            .map(|_| "deleted".into()),
        "retention" => store.set_retention(&positional[0], value.unwrap(), &access),
        "import" => {
            let bytes = fs::read(&positional[0]).map_err(|e| e.to_string());
            match bytes {
                Ok(bytes) => store.import(&bytes, &access),
                Err(error) => {
                    store.audit_refusal(op, &[], &error)?;
                    Err(error)
                }
            }
        }
        // R8 grants the Core maintenance authority; the CLI still requires a
        // trusted, live presentation for this audience. No caller clock exists.
        "expire" => store.expire_sweep().map(|n| n.to_string()),
        _ => unreachable!(),
    }
}
fn json_file(path: &str) -> Result<serde_json::Value, String> {
    serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

fn boundary_refusal(
    store: &mut Store,
    op: &str,
    positional: &[String],
    reason: &str,
) -> Result<(), String> {
    if matches!(op, "read" | "delete" | "retention") {
        return store.audit_record_refusal(op, &positional[0], reason);
    }
    let raw = positional
        .first()
        .and_then(|p| fs::read(p).ok())
        .unwrap_or_default();
    let value = if op == "import" {
        vaikor_record::decode(&raw).ok()
    } else {
        serde_json::from_slice(&raw).ok()
    };
    match value.and_then(|v| vaikor_record::digest(&v).ok()) {
        Some(digest) => store.audit_record_refusal(op, &digest, reason),
        None => store.audit_refusal(op, &raw, reason),
    }
}
