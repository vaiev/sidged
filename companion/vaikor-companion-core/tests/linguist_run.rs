// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! `linguist.run` end to end against a model server on a real AF_UNIX socket, outside local
//! mode (0004 R9d): the call must not latch local mode, so the node keeps its swarm.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;

use serde_json::{json, Value};
use vaikor_companion_core::commands::CompanionCore;

#[test]
fn linguist_run_asks_the_configured_local_model_and_the_core_corrects_the_reply() {
    let dir = std::env::temp_dir().join(format!("vaikor-companion-model-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let core = CompanionCore::with_workspace(dir.clone()).unwrap();
    assert!(core
        .dispatch("linguist.run", &json!({"utterance": "x"}))
        .unwrap_err()
        .starts_with("node-not-initialized"));
    core.dispatch("node.init", &json!({})).unwrap();
    assert!(core
        .dispatch("linguist.run", &json!({"utterance": "x"}))
        .unwrap_err()
        .starts_with("model-not-configured"));

    let socket = dir.join("model.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let uid = std::fs::metadata(&socket).unwrap().uid();
    std::fs::write(
        dir.join("config.json"),
        json!({"model": {"endpoint": format!("unix:{}", socket.display()), "uid": uid}})
            .to_string(),
    )
    .unwrap();
    assert_eq!(
        core.dispatch("node.status", &json!({})).unwrap()["model"],
        true
    );

    // The model forgets a required slot and claims the intent is complete.
    let reply = "<think>\n</think>\n{\"v\": \"0.1\", \"lang\": \"de\", \"intent\": \"timer.set\", \
        \"slots\": {\"label\": \"the tea\"}, \"missing_slots\": [], \"clarification_needed\": false, \
        \"clarification_question_local\": null, \"canonical_intent_en\": \"Start a timer\", \
        \"suggested_route\": \"edge-local\", \"required_data_classes\": []}";
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let mut length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                length = v.trim().parse().unwrap();
            }
            if line == "\r\n" {
                break;
            }
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).unwrap();
        let request: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(request["chat_template_kwargs"]["enable_thinking"], false);
        assert!(request["messages"][1]["content"]
            .as_str()
            .unwrap()
            .ends_with("Utterance: Tee-Timer bitte"));
        let payload =
            json!({"choices": [{"message": {"role": "assistant", "content": reply}}]}).to_string();
        let mut stream = reader.into_inner();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{payload}",
            payload.len()
        )
        .unwrap();
    });
    let out = core
        .dispatch("linguist.run", &json!({"utterance": "Tee-Timer bitte"}))
        .unwrap();
    server.join().unwrap();
    assert!(
        !vaikor_gateway::is_local(),
        "the model call did not latch local mode"
    );
    assert_eq!(out["envelope"]["missing_slots"], json!(["duration"]));
    assert_eq!(out["envelope"]["suggested_route"], "clarify");
    assert_eq!(out["surface"]["kind"], "clarification");
    assert!(out["corrections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "missing_slots-corrected"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn linguist_run_follows_the_configured_compact_output() {
    let dir = std::env::temp_dir().join(format!("vaikor-companion-compact-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let core = CompanionCore::with_workspace(dir.clone()).unwrap();
    core.dispatch("node.init", &json!({})).unwrap();
    let socket = dir.join("model.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let uid = std::fs::metadata(&socket).unwrap().uid();
    std::fs::write(
        dir.join("config.json"),
        json!({"model": {"endpoint": format!("unix:{}", socket.display()), "uid": uid,
            "output": "compact"}})
        .to_string(),
    )
    .unwrap();
    let reply = "{\"v\": \"0.2\", \"lang\": \"de\", \"intent\": \"timer.set\", \"missing\": [\"duration\"], \"slots\": {\"label\": \"the tea\"}}";
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let mut length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                length = v.trim().parse().unwrap();
            }
            if line == "\r\n" {
                break;
            }
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).unwrap();
        let payload =
            json!({"choices": [{"message": {"role": "assistant", "content": reply}}]}).to_string();
        let mut stream = reader.into_inner();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{payload}",
            payload.len()
        )
        .unwrap();
        serde_json::from_slice::<Value>(&body).unwrap()
    });
    let out = core
        .dispatch("linguist.run", &json!({"utterance": "Tee-Timer bitte"}))
        .unwrap();
    let request = server.join().unwrap();
    assert_eq!(
        request["messages"][0]["content"],
        vaikor_cli::linguist::SYSTEM_PROMPT_COMPACT
    );
    assert_eq!(request["response_format"]["type"], "json_schema");
    assert!(request["response_format"]["json_schema"]["schema"]["oneOf"].is_array());
    assert_eq!(out["envelope"]["missing_slots"], json!(["duration"]));
    assert_eq!(out["corrections"], json!([]));
    let _ = std::fs::remove_dir_all(&dir);
}
