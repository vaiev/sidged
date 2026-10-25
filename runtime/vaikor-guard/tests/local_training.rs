//! Turnkey WP f: the local-training scripts are syntax-checked and their
//! unit tests (dataset validator, deterministic data and manifest, consent
//! gate) pass. Stdlib Python only; nothing here trains or downloads a model.
use std::path::Path;
use std::process::Command;

fn run(cmd: &mut Command) {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{:?}\n{}{}",
        cmd,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn local_training_scripts_compile_and_their_unit_tests_pass() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = root.join("local-training");
    let cache = std::env::temp_dir().join(format!("vaikor-pycache-{}", std::process::id()));
    for script in [
        "make_dataset.py",
        "validate_dataset.py",
        "experimental/train_edge_llm.py",
        "experimental/train_planner_think.py",
        "write_manifest.py",
        "core_bridge.py",
        "eval_linguist.py",
        "seeding.py",
        "make_dataset_linguist.py",
        "train_companion_linguist.py",
        "probe_linguist.py",
    ] {
        run(Command::new("python3")
            .args(["-I", "-m", "py_compile"])
            .arg(dir.join(script))
            .env("PYTHONPYCACHEPREFIX", &cache));
    }
    run(Command::new("bash")
        .arg("-n")
        .arg(dir.join("setup_gpu_cu128.sh")));
    run(Command::new("python3")
        .args(["-I", "-m", "unittest", "discover", "-s"])
        .arg(dir.join("tests"))
        .arg("-t")
        .arg(&dir)
        .env("PYTHONPYCACHEPREFIX", &cache)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        // The bridge runs this build of `vaikor`; without it, it would rebuild the binary
        // with default features over the one the other tests of this run use.
        .env("VAIKOR_BIN", env!("CARGO_BIN_EXE_vaikor")));
    let _ = std::fs::remove_dir_all(cache);
}
