//! Turnkey WP d: the offline UI shell passes `scripts/tests/ui_shell_check.sh`
//! (zero network requests, CSP, no fake data, no approval UI), the checker
//! rejects injected violations, and the colour tokens meet WCAG 2.2 AA text
//! contrast in both themes (0004 R7).
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn check(dir: &Path) -> (bool, String) {
    let out = Command::new("bash")
        .arg(root().join("scripts/tests/ui_shell_check.sh"))
        .arg(dir)
        .output()
        .unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn the_shell_passes_the_static_checks() {
    let (ok, text) = check(&root().join("ui/shell"));
    assert!(ok, "{text}");
}

#[test]
fn the_checker_rejects_network_fake_data_and_approval_ui() {
    let copy = std::env::temp_dir().join(format!("sidged-ui-check-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&copy);
    std::fs::create_dir_all(&copy).unwrap();
    for name in ["index.html", "shell.css", "shell.js", "TOKENS-SOURCE.md"] {
        std::fs::copy(root().join("ui/shell").join(name), copy.join(name)).unwrap();
    }
    assert!(check(&copy).0, "pristine copy passes");
    let cases: [(&str, &str); 20] = [
        (
            "shell.css",
            ".vv-chip--primary { border-radius: var(--vv-shape-full); }",
        ),
        ("shell.css", ":root { --vv-invented: 1; }"),
        ("shell.css", ".vv-countdown-pill { display: block; }"),
        ("shell.css", ".probe { color: var(--vv-color-focus); }"),
        ("shell.js", "const probe = 'var(--vv-missing)';"),
        ("shell.css", ":root { --vv-glass-bg: transparent; }"),
        ("shell.css", ":root { --vv-motion-fast: 1ms; }"),
        ("shell.css", ":root { --vv-motion-turbo: 1ms; }"),
        ("shell.css", ":root { --vv-target: 48px; }"),
        ("shell.css", ".probe { font-family: 'Vv Sans'; }"),
        ("shell.css", ".probe { font-family: 'Vv Mono'; }"),
        ("shell.js", "fetch('/api/v1/vault');"),
        (
            "shell.js",
            "const ws = new WebSocket('ws://127.0.0.1:8080');",
        ),
        ("shell.js", "el.innerHTML = text;"),
        ("shell.js", "const sig = 'sig:ed25519:' + hash;"),
        ("shell.js", "const id = 'did:key:z6Mk';"),
        ("index.html", "<dialog class=\"vv-sheet\">Approve</dialog>"),
        ("index.html", "<span>SQLite persistent</span>"),
        ("shell.css", "@font-face { src: url(fonts/plex.woff2); }"),
        (
            "index.html",
            "<link rel=\"stylesheet\" href=\"https://fonts.googleapis.com/css2\">",
        ),
    ];
    for (file, injected) in cases {
        let path = copy.join(file);
        let original = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, format!("{original}\n{injected}\n")).unwrap();
        assert!(!check(&copy).0, "not caught in {file}: {injected}");
        std::fs::write(&path, original).unwrap();
    }
    let html = copy.join("index.html");
    let original = std::fs::read_to_string(&html).unwrap();
    std::fs::write(
        &html,
        original.replace("connect-src 'none'", "connect-src *"),
    )
    .unwrap();
    assert!(!check(&copy).0, "CSP change not caught");
    std::fs::remove_dir_all(copy).unwrap();
}

/// `--vv-color-*: #rrggbb;` inside the block that starts with `selector {`.
fn tokens(css: &str, selector: &str) -> HashMap<String, [u8; 3]> {
    let start = css
        .find(&format!("{selector} {{"))
        .unwrap_or_else(|| panic!("no {selector} block"));
    let block = &css[start..start + css[start..].find('}').unwrap()];
    block
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (name, value) = line.strip_prefix("--vv-color-")?.split_once(':')?;
            let hex = value.trim().strip_prefix('#')?.strip_suffix(';')?;
            if hex.len() != 6 {
                return None;
            }
            let byte = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).unwrap();
            Some((name.to_string(), [byte(0), byte(2), byte(4)]))
        })
        .collect()
}

fn luminance(rgb: [u8; 3]) -> f64 {
    let channel = |c: u8| {
        let c = f64::from(c) / 255.0;
        if c <= 0.04045 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * channel(rgb[0]) + 0.7152 * channel(rgb[1]) + 0.0722 * channel(rgb[2])
}

fn contrast(a: [u8; 3], b: [u8; 3]) -> f64 {
    let (x, y) = (luminance(a), luminance(b));
    (x.max(y) + 0.05) / (x.min(y) + 0.05)
}

#[test]
fn text_tokens_meet_wcag_aa_in_both_themes() {
    let css = std::fs::read_to_string(root().join("ui/shell/shell.css")).unwrap();
    for selector in [":root", "[data-theme=\"dark\"]"] {
        let t = tokens(&css, selector);
        for (fg, bg) in [
            ("on-surface", "surface"),
            ("on-surface", "surface-container-low"),
            ("on-surface", "surface-container-highest"),
            ("on-surface-variant", "surface"),
            ("on-surface-variant", "surface-container-low"),
            ("on-surface-variant", "surface-container-high"),
            ("on-primary", "primary"),
            ("on-primary-container", "primary-container"),
            ("primary", "surface"),
            // Status notes render on-surface text on the container colour;
            // the status colour is only the border (shell.css .vv-note--*).
            ("on-surface", "error-container"),
            ("on-surface", "success-container"),
            ("on-surface", "warning-container"),
        ] {
            let ratio = contrast(
                *t.get(fg).unwrap_or_else(|| panic!("{selector}: {fg}")),
                *t.get(bg).unwrap_or_else(|| panic!("{selector}: {bg}")),
            );
            assert!(ratio >= 4.5, "{selector}: {fg} on {bg} is {ratio:.2}:1");
        }
    }
}
