use std::process::Command;

fn sidged(arg: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_sidged"))
        .arg(arg)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{arg} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

// `sidged --version` prints "sidged <semver> (<commit>)" where commit is a
// 40-hex git SHA or the literal "unknown" when built without git.
#[test]
fn version_prints_semver_and_commit() {
    for flag in ["--version", "-V"] {
        let line = sidged(flag);
        let line = line.trim_end();
        let rest = line.strip_prefix("sidged ").expect(line);
        let (ver, commit) = rest.split_once(' ').expect(line);
        assert_eq!(ver, env!("CARGO_PKG_VERSION"));
        let commit = commit
            .strip_prefix('(')
            .and_then(|c| c.strip_suffix(')'))
            .expect(line);
        let is_sha = commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit());
        assert!(is_sha || commit == "unknown", "bad commit: {commit}");
    }
}
