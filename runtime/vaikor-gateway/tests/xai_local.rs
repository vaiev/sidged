//! Local mode refuses xAI before any report or socket (separate binary: the
//! local-mode latch is process-wide).
use vaikor_gateway::{send_with_credential, KeySource, SendRequest};

#[test]
fn local_mode_refuses_xai() {
    let tags = vec!["unrestricted".to_string()];
    let error = send_with_credential(
        &SendRequest {
            url: "https://api.x.ai/v1/chat/completions",
            provider_id: "https://api.x.ai",
            provider_project: None,
            profile: "P0",
            residency: &tags,
            region: "",
            data_classes: &[],
            fields: &[],
            body: b"{}",
            authorization: Some("Bearer xai-local-test"),
            call_at: "2026-10-16T09:00:00Z",
            step: "planner-1",
            local: true,
        },
        Some(&KeySource::File(std::path::PathBuf::from("unused"))),
    )
    .unwrap_err();
    assert!(
        vaikor_gateway::is_local(),
        "a conflicting request still latches local mode"
    );
    assert!(error.message.contains("local mode"), "{}", error.message);
    assert!(error.report.is_none());
}
