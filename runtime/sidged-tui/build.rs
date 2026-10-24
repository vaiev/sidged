// Embeds the commit shown in the banner (SIDGED_TUI_GIT_SHA). See
// build_sha.rs: CI/release builds without a SHA fail; the binary refuses
// `unknown` at start.
use std::process::Command;

include!("build_sha.rs");

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8(out.stdout).ok())
        .flatten()
        .map(|s| s.trim().to_owned())
}

fn main() {
    println!("cargo:rerun-if-env-changed=SIDGED_GIT_SHA");
    println!("cargo:rerun-if-env-changed=CI");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_sha.rs");
    // Re-embed on a new commit: watch HEAD, its ref and packed-refs (nearest
    // existing path, as in sidged-guard/build.rs).
    let mut watch = vec!["HEAD".to_owned(), "packed-refs".to_owned()];
    if let Some(head_ref) = git(&["symbolic-ref", "-q", "HEAD"]) {
        watch.push(head_ref);
    }
    for name in watch {
        if let Some(path) = git(&["rev-parse", "--path-format=absolute", "--git-path", &name]) {
            let mut p = std::path::PathBuf::from(path);
            while !p.exists() && p.pop() {}
            if p.exists() {
                println!("cargo:rerun-if-changed={}", p.display());
            }
        }
    }
    let ci = std::env::var("CI").is_ok_and(|v| !v.is_empty() && v != "false" && v != "0");
    let release = std::env::var("PROFILE").is_ok_and(|p| p == "release");
    let env_sha = std::env::var("SIDGED_GIT_SHA").ok();
    let head = git(&["rev-parse", "HEAD"]);
    let sha = resolve_sha(env_sha.as_deref(), head.as_deref(), ci, release)
        .unwrap_or_else(|e| panic!("sidged-tui build: {e}"));
    println!("cargo:rustc-env=SIDGED_TUI_GIT_SHA={sha}");
}
