// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Tauri v2 shell for `vaikor-desktop` and `vaikor-android`.
//!
//! The webview gets one command, `companion`, which forwards to the allowlist of
//! `vaikor_companion_core::commands`. Nothing here approves, signs or executes: the
//! Trusted UI for consequential steps stays with the Core, outside the webview.

use std::path::PathBuf;
use std::sync::Mutex;

use serde_json::Value;
use tauri::Manager;
use vaikor_companion_core::commands::CompanionCore;

#[cfg(unix)]
mod local_model;

/// The on-device model server, kept alive for the life of the app.
static MODEL_SERVER: Mutex<Option<std::process::Child>> = Mutex::new(None);

/// Start Model -1 in the background when its weights are on the device (the bundled server on
/// Android, the toolchain's llama-server on a Unix desktop); the canvas shows the intent bar
/// once `node.status` reports the endpoint.
#[cfg(unix)]
fn start_local_model(app_data: PathBuf, workspace: PathBuf) {
    std::thread::spawn(move || {
        #[cfg(target_os = "android")]
        let layout = match local_model::native_library_dir() {
            Some(native) => local_model::Layout::new(&app_data, &native, &workspace),
            None => return,
        };
        #[cfg(not(target_os = "android"))]
        let layout = match local_model::desktop_server() {
            Some(server) => local_model::Layout::with_server(&app_data, &server, &workspace),
            None => return,
        };
        // Wait for the onboarding to create the node; the model joins it afterwards.
        for _ in 0..600 {
            if workspace.join("manifest.json").exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        match local_model::start(&layout) {
            Ok(child) => *MODEL_SERVER.lock().unwrap_or_else(|e| e.into_inner()) = child,
            Err(err) => {
                let _ = std::fs::write(app_data.join("models").join("last-error.txt"), err);
            }
        }
    });
}

/// The workspace of this node: `VAIKOR_WORKSPACE` if set, else `<app data>/workspace`
/// (created by the onboarding through `node.init`).
fn workspace_dir(app_data: Option<PathBuf>) -> Option<PathBuf> {
    std::env::var_os("VAIKOR_WORKSPACE")
        .map(PathBuf::from)
        .or_else(|| app_data.map(|dir| dir.join("workspace")))
}

/// The OS alarms a run asks for: (id, title, RFC 3339 instant in UTC) for every completed timer
/// or reminder step. Only what the executors returned is used, never the model's words. The
/// instant is given in UTC because the Android notification plugin parses
/// `yyyy-MM-dd'T'HH:mm:ss.SSS'Z'`: a reminder's `+02:00` offset failed there and its call never
/// returned, which froze the app.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
fn alarms(run: &Value) -> Vec<(i32, String, String)> {
    let title = run
        .pointer("/summary/canonical_intent")
        .and_then(Value::as_str)
        .unwrap_or("Vaikor");
    let steps = run.pointer("/summary/steps").and_then(Value::as_array);
    steps
        .into_iter()
        .flatten()
        .filter(|step| step["status"] == "completed")
        .filter_map(|step| {
            let output = &step["output"];
            let at = output["ends_at"].as_str().or(output["due_at"].as_str())?;
            let at = utc(at)?;
            let at = at.as_str();
            let key = output["timer_id"]
                .as_str()
                .or(output["reminder_id"].as_str())
                .unwrap_or(at);
            let id = key
                .bytes()
                .chain(at.bytes())
                .fold(17i32, |h, b| h.wrapping_mul(31).wrapping_add(i32::from(b)))
                & 0x7fff_ffff;
            Some((id, title.to_string(), at.to_string()))
        })
        .collect()
}

/// An RFC 3339 instant as RFC 3339 in UTC; `None` when it does not parse.
fn utc(at: &str) -> Option<String> {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::parse(at, &Rfc3339)
        .ok()?
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .ok()
}

#[cfg(target_os = "android")]
fn schedule_alarms<R: tauri::Runtime>(app: &tauri::AppHandle<R>, run: &Value) {
    use tauri_plugin_notification::{NotificationExt, Schedule};
    let notification = app.notification();
    let _ = notification.request_permission();
    for (id, title, at) in alarms(run) {
        let Ok(date) =
            time::OffsetDateTime::parse(&at, &time::format_description::well_known::Rfc3339)
        else {
            continue;
        };
        let _ = notification
            .builder()
            .id(id)
            .title("Vaikor")
            .body(title)
            .schedule(Schedule::At {
                date,
                repeating: false,
                allow_while_idle: true,
            })
            .show();
    }
}

#[tauri::command]
fn companion<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    core: tauri::State<'_, CompanionCore>,
    command: String,
    args: Value,
) -> Result<Value, String> {
    let result = core.dispatch(&command, &args)?;
    #[cfg(target_os = "android")]
    if command == "intent.run" {
        schedule_alarms(&app, &result);
    }
    let _ = &app;
    Ok(result)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    #[cfg(target_os = "android")]
    let builder = builder.plugin(tauri_plugin_notification::init());
    builder
        .setup(|app| {
            let app_data = app.path().app_data_dir().ok();
            let core = match workspace_dir(app_data.clone()) {
                Some(dir) => {
                    #[cfg(unix)]
                    if let Some(data) = app_data.clone() {
                        start_local_model(data, dir.clone());
                    }
                    CompanionCore::with_workspace(dir)?
                }
                None => CompanionCore::new(&Value::Array(Vec::new()))?,
            };
            app.manage(core);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![companion])
        .build(tauri::generate_context!())
        .expect("error while building the Vaikor companion")
        .run(|_, event| {
            if let tauri::RunEvent::Exit = event {
                if let Some(mut child) = MODEL_SERVER
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                {
                    let _ = child.kill();
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_completed_timer_and_reminder_outputs_become_alarms() {
        let run = json!({"summary": {"canonical_intent": "Start a timer for 10 minutes", "steps": [
            {"status": "completed", "output": {"timer_id": "timers-1", "ends_at": "2026-10-21T08:10:00Z"}},
            {"status": "completed", "output": {"reminder_id": "reminders-2", "due_at": "2026-10-21T17:00:00+02:00"}},
            {"status": "denied", "output": {"due_at": "2026-10-21T18:00:00Z"}},
            {"status": "completed", "output": {"path": "notes/inbox.md"}}
        ]}});
        let found = alarms(&run);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].2, "2026-10-21T08:10:00Z");
        // A reminder's local offset is handed on as the same instant in UTC.
        assert_eq!(found[1].2, "2026-10-21T15:00:00Z");
        assert!(found
            .iter()
            .all(|(id, title, _)| *id >= 0 && title == "Start a timer for 10 minutes"));
        assert_ne!(found[0].0, found[1].0);
    }

    #[test]
    fn an_instant_that_does_not_parse_becomes_no_alarm() {
        let run = json!({"summary": {"steps": [
            {"status": "completed", "output": {"reminder_id": "reminders-3", "due_at": "morgen um 9"}}
        ]}});
        assert!(alarms(&run).is_empty());
    }
}
