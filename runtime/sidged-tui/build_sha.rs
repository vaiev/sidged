// Build-time commit for the banner, shared by build.rs and tests/build_sha.rs
// (plain comments only: this file is include!d by build.rs).
//
// SIDGED_GIT_SHA (7-40 hex) wins; an explicit invalid value is refused. Else
// `git rev-parse HEAD`. A CI or release build without either fails the build;
// a dev build embeds `unknown`, which the binary refuses at start.
fn is_hex(s: &str, lengths: std::ops::RangeInclusive<usize>) -> bool {
    lengths.contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn resolve_sha(
    env_sha: Option<&str>,
    git_sha: Option<&str>,
    ci: bool,
    release: bool,
) -> Result<String, String> {
    if let Some(sha) = env_sha.map(str::trim).filter(|s| !s.is_empty()) {
        if is_hex(sha, 7..=40) {
            return Ok(sha.to_string());
        }
        return Err("SIDGED_GIT_SHA must be 7-40 hex characters".into());
    }
    if let Some(sha) = git_sha.map(str::trim).filter(|s| is_hex(s, 40..=40)) {
        return Ok(sha.to_string());
    }
    if ci || release {
        return Err(
            "SIDGED_GIT_SHA is unset and git HEAD is unavailable: a CI or release build refuses to embed 'unknown'"
                .into(),
        );
    }
    Ok("unknown".into())
}
