mod common;
use std::{net::TcpListener, path::Path};

#[test]
fn restricted_or_undeclared_data_is_denied_and_audited_without_http() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../demo/public-weather");
    for declaration in [
        serde_json::Value::Null,
        serde_json::json!({}),
        serde_json::json!({"tags": []}),
        serde_json::json!({"tags": ["CH"]}),
        serde_json::json!({"tags": ["EU"]}),
        serde_json::json!({"tags": ["CH-EU"]}),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let dir = std::env::temp_dir().join(format!("gemini-denial-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for name in [
            "config.json",
            "tools.json",
            "policy.cedar",
            "grant.json",
            "stub-plan.json",
        ] {
            std::fs::copy(source.join(name), dir.join(name)).unwrap();
        }
        let mut catalog: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("tools.json")).unwrap())
                .unwrap();
        // Leave the other capability unrestricted: it must not mask this declaration.
        let capability = catalog["tools"][0]["_meta"]["com.vaikor/capability"]
            .as_object_mut()
            .unwrap();
        if declaration.is_null() {
            capability.remove("residency");
        } else {
            capability.insert("residency".into(), declaration.clone());
        }
        std::fs::write(dir.join("tools.json"), catalog.to_string()).unwrap();
        let mut config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap())
                .unwrap();
        config["provider_project"] = "test-billing".into();
        std::fs::write(dir.join("config.json"), config.to_string()).unwrap();
        common::keys(&dir.join("keys"));
        let log = dir.join("audit.log");
        for base in [
            format!("http://{}/v1beta/openai", listener.local_addr().unwrap()),
            "https://generativelanguage.googleapis.com/v1beta/openai".into(),
        ] {
            let error = vaikor_guard::run_from_env(
                &dir,
                "openai",
                Some(&base),
                Some("gemini-2.5-flash"),
                None,
                &vaikor_cli::NonInteractive,
                Some(vaikor_guard::LogTarget {
                    path: &log,
                    seed: &[19; 32],
                }),
            )
            .unwrap_err();
            assert!(
                (error.contains("destination") || error.contains("residency")),
                "{declaration:?}: {error}"
            );
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            let events = vaikor_log::read_events(&log, &vaikor_log::public_key(&[19; 32])).unwrap();
            // An egress descriptor without tags is rejected while loading the
            // catalog, before a planner attempt exists to audit.
            if declaration.is_null()
                || declaration.get("tags").is_none()
                || declaration["tags"].as_array().is_some_and(Vec::is_empty)
            {
                assert!(events.is_empty());
                continue;
            }
            let last = events.last().unwrap();
            assert_eq!(last.step, "planner");
            assert_eq!(last.decision, "deny");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn public_weather_stub_guard_passes() {
    let fixture = std::env::temp_dir().join(format!("weather-fixture-{}", std::process::id()));
    let dir = common::report_only_scenario(&fixture);
    let log = std::env::temp_dir().join(format!("weather-{}.log", std::process::id()));
    let key = log.with_extension("key");
    let _ = std::fs::remove_file(&log);
    let keys = log.with_extension("keys");
    common::keys(&keys);
    std::fs::copy(keys.join("issuer.key"), &key).unwrap();
    std::env::set_var("XDG_STATE_HOME", log.with_extension("state"));
    let output = common::approved_guard(&dir, &keys, &log, &key);
    assert!(output.is_ok(), "{output:?}");
    let events =
        vaikor_log::read_events(&log, &vaikor_log::public_key(&common::seed(&key))).unwrap();
    assert!(!events.iter().any(|event| event.decision == "deny"));
    assert!(events
        .iter()
        .any(|event| event
            .privacy_report
            .as_ref()
            .is_some_and(
                |report| serde_json::from_str::<serde_json::Value>(report).unwrap()["residency"]
                    ["tags"]
                    == serde_json::json!(["unrestricted"])
            )));
    std::fs::remove_dir_all(log.with_extension("state")).unwrap();
    std::fs::remove_file(log).unwrap();
    std::fs::remove_file(key).unwrap();
    std::fs::remove_dir_all(fixture).unwrap();
    std::fs::remove_dir_all(keys).unwrap();
}

#[test]
fn billing_project_config_and_env_are_checked_before_transport() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../demo/public-weather");
    let dir = std::env::temp_dir().join(format!("gemini-project-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for name in [
        "config.json",
        "tools.json",
        "policy.cedar",
        "grant.json",
        "stub-plan.json",
    ] {
        std::fs::copy(source.join(name), dir.join(name)).unwrap();
    }
    common::keys(&dir.join("keys"));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    for (project, env, expected) in [
        (None, None, "billing project"),
        (Some("  "), None, "billing project"),
        (Some("test-billing"), None, "does not match"),
        (None, Some("env-billing"), "does not match"),
    ] {
        config.as_object_mut().unwrap().remove("provider_project");
        if let Some(project) = project {
            config["provider_project"] = project.into();
        }
        std::fs::write(dir.join("config.json"), config.to_string()).unwrap();
        let log = dir.join("audit.log");
        let key = dir.join("seed.hex");
        std::fs::write(&key, "13".repeat(32)).unwrap();
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_vaikor"));
        cmd.arg("guard")
            .arg(&dir)
            .arg("--log")
            .arg(&log)
            .arg("--log-key")
            .arg(&key)
            .env("VAIKOR_PROVIDER", "openai")
            .env(
                "VAIKOR_BASE_URL",
                if expected == "billing project" {
                    "https://generativelanguage.googleapis.com/v1beta/openai".to_string()
                } else {
                    format!("http://{}/v1beta/openai", listener.local_addr().unwrap())
                },
            )
            .env_remove("VAIKOR_LOCAL")
            .env_remove("VAIKOR_GEMINI_PROJECT");
        if let Some(env) = env {
            cmd.env("VAIKOR_GEMINI_PROJECT", env);
        }
        let output = cmd.output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success());
        assert!(text.contains(expected), "{text}");
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}
