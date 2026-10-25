//! A CI or release build refuses to embed `unknown`; the SHA comes
//! from VAIKOR_GIT_SHA (7-40 hex) or `git rev-parse HEAD`.
#[path = "../build_sha.rs"]
mod build_sha;
use build_sha::resolve_sha;

const SHA40: &str = "392775707e38eca8edd6550bf653dcb64d5b75bb";

#[test]
fn ci_or_release_without_a_sha_fails_the_build() {
    for (ci, release) in [(true, false), (false, true), (true, true)] {
        let e = resolve_sha(None, None, ci, release).unwrap_err();
        assert!(e.contains("VAIKOR_GIT_SHA"), "{e}");
        assert!(resolve_sha(Some("unknown"), None, ci, release).is_err());
        assert!(resolve_sha(Some(""), None, ci, release).is_err());
    }
}

#[test]
fn env_sha_or_git_head_is_embedded() {
    assert_eq!(
        resolve_sha(Some("3927757"), None, true, true).unwrap(),
        "3927757"
    );
    assert_eq!(
        resolve_sha(Some(SHA40), Some("x"), true, true).unwrap(),
        SHA40
    );
    assert_eq!(resolve_sha(None, Some(SHA40), true, true).unwrap(), SHA40);
    assert_eq!(
        resolve_sha(Some(""), Some(SHA40), true, false).unwrap(),
        SHA40
    );
}

#[test]
fn an_explicit_invalid_sha_is_refused_everywhere() {
    for bad in ["not-a-sha", "39277", "g927757", "unknown"] {
        assert!(
            resolve_sha(Some(bad), Some(SHA40), false, false).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn a_dev_build_without_git_embeds_unknown_and_the_runtime_refuses() {
    assert_eq!(resolve_sha(None, None, false, false).unwrap(), "unknown");
    assert!(vaikor_tui::require_build_sha("unknown").is_err());
}
