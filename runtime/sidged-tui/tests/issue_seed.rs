//! The issuer seed is zeroized on drop.
#[test]
fn seed_is_zeroizing() {
    let seed: zeroize::Zeroizing<[u8; 32]> =
        sidged_tui::issue::parse_seed_hex(&"03".repeat(32)).unwrap();
    assert_eq!(*seed, [3u8; 32]);
}
