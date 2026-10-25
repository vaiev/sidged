//! ApiKey::from_file refuses symlinks (O_NOFOLLOW), any mode
//! other than 0600 and a file owned by another uid.
use std::os::unix::fs::PermissionsExt;

use vaikor_gateway::ApiKey;

const KEY: &str = "xai-canary-key";

fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("vaikor-api-key-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_mode(path: &std::path::Path, mode: u32) {
    let _ = std::fs::remove_file(path);
    std::fs::write(path, format!("{KEY}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn mode_0600_owned_by_me_is_accepted() {
    let d = dir("ok");
    let p = d.join("key");
    write_mode(&p, 0o600);
    assert_eq!(ApiKey::from_file(&p).unwrap().expose(), KEY);
}

#[test]
fn other_modes_are_refused() {
    let d = dir("mode");
    let p = d.join("key");
    for mode in [0o644, 0o640, 0o604, 0o400, 0o700, 0o660] {
        write_mode(&p, mode);
        let err = ApiKey::from_file(&p).unwrap_err();
        assert!(err.contains("0600"), "{mode:o}: {err}");
        assert!(!err.contains(KEY));
    }
}

#[test]
fn symlink_is_refused() {
    let d = dir("link");
    let real = d.join("real");
    write_mode(&real, 0o600);
    let link = d.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let err = ApiKey::from_file(&link).unwrap_err();
    assert!(err.contains("symlink"), "{err}");
    assert!(!err.contains(KEY));
}

#[test]
fn foreign_owner_is_refused() {
    // /etc/passwd style: a root-owned file when we are not root. Copying is
    // not possible without privileges, so use the owner check helper directly
    // on a file we know is root-owned, and skip when running as root.
    if unsafe_euid() == 0 {
        eprintln!("skip: running as root");
        return;
    }
    let err = vaikor_gateway::check_key_file_meta(0o600, 0, unsafe_euid()).unwrap_err();
    assert!(err.contains("owner"), "{err}");
    assert!(vaikor_gateway::check_key_file_meta(0o600, unsafe_euid(), unsafe_euid()).is_ok());
    assert!(vaikor_gateway::check_key_file_meta(0o100600, unsafe_euid(), unsafe_euid()).is_ok());
}

fn unsafe_euid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    let d = dir("uid");
    let p = d.join("probe");
    std::fs::write(&p, "x").unwrap();
    std::fs::metadata(&p).unwrap().uid()
}

#[test]
fn fifo_is_refused_without_blocking() {
    let d = dir("fifo");
    let p = d.join("key");
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let (tx, rx) = std::sync::mpsc::channel();
    let path = p.clone();
    std::thread::spawn(move || tx.send(ApiKey::from_file(&path).map(|_| ())).unwrap());
    let r = rx
        .recv_timeout(std::time::Duration::from_secs(3))
        .expect("from_file blocked on a FIFO");
    assert!(r.unwrap_err().contains("regular file"));
}

// The Authorization header value is zeroized on drop.
#[test]
fn bearer_is_zeroizing() {
    let d = dir("bearer");
    let p = d.join("key");
    write_mode(&p, 0o600);
    let key = ApiKey::from_file(&p).unwrap();
    let bearer: zeroize::Zeroizing<String> = key.bearer();
    assert_eq!(bearer.as_str(), format!("Bearer {KEY}"));
}
