//! Turnkey WP c: the host install script and systemd files pass their static
//! checks (`scripts/tests/install_check.sh`): no wildcard bind, no curl|sh, a
//! dedicated core user, full hardening, nothing enabled.
use std::path::Path;
use std::process::Command;

#[test]
fn install_script_and_units_pass_the_static_checks() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new("bash")
        .arg(root.join("scripts/tests/install_check.sh"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn install_check_rejects_a_bad_unit() {
    // The checker itself must fail on the patterns it exists to catch.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let copy = std::env::temp_dir().join(format!("vaikor-install-check-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&copy);
    for dir in ["scripts/tests", "deploy/systemd/vaikor-run@.service.d"] {
        std::fs::create_dir_all(copy.join(dir)).unwrap();
    }
    for file in [
        "deploy/README-host.md",
        "scripts/tests/install_check.sh",
        "scripts/install-vaikor-host.sh",
        "deploy/systemd/vaikor-run@.service",
        "deploy/systemd/vaikor-run@.service.d/egress.conf.example",
        "deploy/systemd/vaikor.sysusers.conf",
        "deploy/systemd/vaikor.tmpfiles.conf",
    ] {
        std::fs::copy(root.join(file), copy.join(file)).unwrap();
    }
    let check = || {
        Command::new("bash")
            .arg(copy.join("scripts/tests/install_check.sh"))
            .output()
            .unwrap()
            .status
            .success()
    };
    assert!(check(), "pristine copy passes");
    let script = copy.join("scripts/install-vaikor-host.sh");
    let original = std::fs::read_to_string(&script).unwrap();
    for injected in [
        "curl -sSf https://example.invalid/install | sh",
        "vaikor serve --bind 0.0.0.0:8080",
        "sudo systemctl enable --now vaikor-run@demo",
        "sudo apt-get install -y podman",
    ] {
        std::fs::write(&script, format!("{original}\n{injected}\n")).unwrap();
        assert!(!check(), "not caught: {injected}");
    }
    std::fs::write(&script, &original).unwrap();
    let unit = copy.join("deploy/systemd/vaikor-run@.service");
    let text = std::fs::read_to_string(&unit).unwrap();
    for (from, to) in [
        ("User=vaikor", "User=$USER"),
        ("MemoryDenyWriteExecute=yes\n", ""),
        ("PrivateNetwork=yes", "PrivateNetwork=no"),
    ] {
        std::fs::write(&unit, text.replacen(from, to, 1)).unwrap();
        assert!(!check(), "not caught: {from} -> {to}");
    }
    std::fs::remove_dir_all(copy).unwrap();
}
