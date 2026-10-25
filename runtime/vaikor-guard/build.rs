// Embeds the git commit SHA into the binary for `vaikor --version`
// (binary provenance, V1 spec L1). No extra crates. Falls back to "unknown"
// when git is unavailable (e.g. source tarball or container build without .git).
use std::{env, process::Command};

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_owned())
}

fn is_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn main() {
    println!("cargo:rerun-if-env-changed=VAIKOR_GIT_SHA");
    println!("cargo:rerun-if-changed=build.rs");
    // Watch HEAD, the ref it points to, and packed-refs so a new commit
    // re-embeds the SHA. Absolute paths; only existing files (a missing path
    // would make cargo rerun the script on every build).
    let mut watch = vec!["HEAD".to_owned(), "packed-refs".to_owned()];
    if let Some(head_ref) = git(&["symbolic-ref", "-q", "HEAD"]) {
        watch.push(head_ref);
    }
    for name in watch {
        if let Some(path) = git(&["rev-parse", "--path-format=absolute", "--git-path", &name]) {
            // A packed branch ref has no loose file yet; the next commit creates
            // it without touching HEAD or packed-refs. Watch the nearest existing
            // ancestor directory instead (cargo scans directories recursively).
            let mut p = std::path::PathBuf::from(&path);
            while !p.exists() {
                if !p.pop() {
                    break;
                }
            }
            if p.exists() {
                println!("cargo:rerun-if-changed={}", p.display());
            }
        }
    }
    // An explicit override (e.g. CI or a container build arg) must itself be a
    // full SHA; anything else is ignored rather than embedded.
    let sha = env::var("VAIKOR_GIT_SHA")
        .ok()
        .filter(|s| is_sha(s))
        .or_else(|| git(&["rev-parse", "HEAD"]).filter(|s| is_sha(s)))
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=VAIKOR_GIT_SHA={sha}");
}
