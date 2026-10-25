//! A1: countdown, banner, key loading (no network).
use ratatui::{backend::TestBackend, Terminal};
use vaikor_tui::*;

#[test]
fn countdown_formats_and_saturates() {
    assert_eq!(format_remaining(0), "00:00");
    assert_eq!(format_remaining(61), "01:01");
    assert_eq!(format_remaining(3600), "60:00");
    assert_eq!(remaining_secs(300, 120), 180);
    assert_eq!(remaining_secs(300, 999), 0);
}

#[test]
fn banner_always_rendered() {
    let mut app = App::new("Write the demo", 300);
    for step in 0..2 {
        if step == 1 {
            app.request_approval();
        }
        let mut term = Terminal::new(TestBackend::new(110, 30)).unwrap();
        term.draw(|f| render(&app, f)).unwrap();
        let buf = term.backend().buffer().clone();
        let s: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(s.contains(BANNER), "{s}");
        assert!(s.contains("Write the demo"));
        assert!(s.contains("05:00"));
    }
}

#[test]
fn key_from_environment_is_refused() {
    assert!(load_key(Some("gemini-env".into()), None).is_err());
    assert!(load_key(None, None).is_err());
}
