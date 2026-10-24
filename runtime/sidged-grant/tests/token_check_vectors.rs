use std::path::PathBuf;

use sidged_grant::run_grant_vectors;

#[test]
fn the_binary_check_matches_token_chain_and_token_check() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors");
    let summary = run_grant_vectors(&root).unwrap();
    assert!(summary.contains("token-chain "), "{summary}");
    assert!(summary.contains("token-check "), "{summary}");
    assert!(summary.contains("refused "), "{summary}");
    let refused: usize = summary
        .lines()
        .find_map(|line| line.strip_prefix("refused "))
        .unwrap()
        .parse()
        .unwrap();
    assert!(refused > 0, "{summary}");
}
