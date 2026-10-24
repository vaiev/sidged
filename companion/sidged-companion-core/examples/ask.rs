// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Ask the node's local Model -1 the way the canvas does (`linguist.run`).
//!
//!   cargo run --example ask -- <workspace> <unix-socket> "<utterance>" ["<utterance>" ...]
//!
//! Creates the node on first use, points `model.endpoint` at the socket, and prints the
//! envelope the Core accepted, its corrections and the surface kind for each utterance.

use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::Instant;

use serde_json::json;
use sidged_companion_core::commands::CompanionCore;

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 3 {
        return Err("usage: ask <workspace> <unix-socket> <utterance>...".into());
    }
    let workspace = PathBuf::from(&args[0]);
    let socket = PathBuf::from(&args[1]);
    let core = CompanionCore::with_workspace(workspace.clone())?;
    if core.dispatch("node.status", &json!({}))?["initialized"] != true {
        core.dispatch("node.init", &json!({}))?;
    }
    let uid = std::fs::metadata(&socket)
        .map_err(|e| format!("{}: {e}", socket.display()))?
        .uid();
    let config = json!({"model": {"endpoint": format!("unix:{}", socket.display()), "uid": uid}});
    std::fs::write(workspace.join("config.json"), config.to_string()).map_err(|e| e.to_string())?;
    for utterance in &args[2..] {
        let started = Instant::now();
        let out = core.dispatch("linguist.run", &json!({"utterance": utterance}))?;
        let envelope = &out["envelope"];
        println!(
            "{:>6} ms | {utterance}\n         lang={} intent={} slots={} missing={}\n         canonical={} route={} surface={} corrections={}",
            started.elapsed().as_millis(),
            envelope["lang"],
            envelope["intent"],
            envelope["slots"],
            envelope["missing_slots"],
            envelope["canonical_intent_en"],
            envelope["suggested_route"],
            out["surface"]["kind"],
            out["corrections"],
        );
    }
    Ok(())
}
