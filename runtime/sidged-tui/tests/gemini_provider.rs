//! Demo 1 provider = Gemini (Google AI Studio free tier) through the gateway's
//! reviewed OpenAI-compatible endpoint only; no xAI destination in the TUI.
use ratatui::{backend::TestBackend, Terminal};
use sidged_tui::*;

const GEMINI: &str = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions";

#[test]
fn destination_is_exactly_the_gemini_endpoint() {
    assert_eq!(CLOUD_URL, GEMINI);
    assert_eq!(CLOUD_PROVIDER, "https://generativelanguage.googleapis.com/");
    assert_eq!(CLOUD_REGION, "GLOBAL");
    assert_eq!(PROVIDER_ID, CLOUD_PROVIDER);
    assert!(!CLOUD_URL.contains("x.ai") && !CAPABILITY.contains("xai"));
}

#[test]
fn model_is_a_free_tier_flash_model() {
    assert_eq!(DEFAULT_MODEL, "gemini-3.1-flash-lite");
    let body: serde_json::Value = serde_json::from_slice(&demo_request_body(DEMO_PROMPT)).unwrap();
    assert_eq!(body["model"], "gemini-3.1-flash-lite");
}

#[test]
fn texts_say_cloud_call_gemini() {
    let mut app = App::new("t", 60);
    app.request_approval();
    let mut term = Terminal::new(TestBackend::new(120, 30)).unwrap();
    term.draw(|f| render(&app, f)).unwrap();
    let s: String = term
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(s.contains("cloud call (Gemini)"), "{s}");
    assert!(!s.to_lowercase().contains("grok") && !s.contains("x.ai"));
    assert!(s.contains("generativelanguage.googleapis.com"));
}

#[test]
fn gemini_project_is_required() {
    assert!(require_project(None).is_err());
    assert!(require_project(Some("  ")).is_err());
    assert_eq!(
        require_project(Some("demo-project")).unwrap(),
        "demo-project"
    );
}
