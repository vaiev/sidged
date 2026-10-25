use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::process::Command;

#[test]
fn revoke_sends_a_digest_or_wildcard_on_the_approval_socket() {
    for (index, target) in ["a".repeat(64), "*".into()].iter().enumerate() {
        let path =
            std::env::temp_dir().join(format!("vaikor-revoke-{}-{index}", std::process::id()));
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_vaikor-tui"))
            .args(["revoke", &format!("unix:{}", path.display()), target])
            .spawn()
            .unwrap();
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut line = String::new();
                    stream.read_to_string(&mut line).unwrap();
                    stream.write_all(b"ok\n").unwrap();
                    return line;
                }
                if std::time::Instant::now() >= deadline {
                    return String::new();
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        });
        assert!(output.wait_with_output().unwrap().status.success());
        assert_eq!(server.join().unwrap(), format!("revoke {target}\n"));
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn revoke_rejects_invalid_targets_before_connecting() {
    for target in ["", "abc", "g", "*\nkill", &"g".repeat(64)] {
        let output = Command::new(env!("CARGO_BIN_EXE_vaikor-tui"))
            .args(["revoke", "unix:/nonexistent/vaikor/s", target])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr)
            .contains("revoke target must be 64 hex digits or *"));
    }
}

#[test]
fn approver_can_explicitly_choose_one_call_without_a_standing_scope() {
    use sha2::{Digest, Sha256};
    use std::process::Stdio;
    for (index, answer) in ["s", "y", "n"].iter().enumerate() {
        let path =
            std::env::temp_dir().join(format!("vaikor-one-call-{}-{index}", std::process::id()));
        let listener = UnixListener::bind(&path).unwrap();
        let scope = serde_json::json!({"standing":true,"provider":"test-provider","task_type":"planner","limit":{"calls":2},"expiry":"2026-10-18T10:30:00Z"});
        let digest = format!(
            "{:x}",
            Sha256::digest(vaikor_grant::canonicalize(&scope).as_bytes())
        );
        let pending = serde_json::json!({"step":"step","capability":"capability","args_digest":"args","nonce":"binding","plan_digest":"plan","scope":scope,"scope_digest":digest});
        let server = std::thread::spawn(move || {
            let (mut request, _) = listener.accept().unwrap();
            let mut line = String::new();
            request.read_to_string(&mut line).unwrap();
            assert_eq!(line, "request\n");
            writeln!(request, "{pending}").unwrap();
            drop(request);
            let (mut response, _) = listener.accept().unwrap();
            line.clear();
            response.read_to_string(&mut line).unwrap();
            response.write_all(b"ok\n").unwrap();
            line
        });
        let mut child = Command::new(env!("CARGO_BIN_EXE_vaikor-tui"))
            .args(["approve", &format!("unix:{}", path.display())])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(child.stdin.take().unwrap(), "{answer}").unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response = server.join().unwrap();
        let verb = if *answer == "n" { "deny" } else { "approve" };
        let suffix = if *answer == "s" {
            String::new()
        } else {
            format!(" {digest}")
        };
        assert_eq!(
            response,
            format!("{verb} approver step capability args binding plan{suffix}\n")
        );
        let shown = String::from_utf8_lossy(&output.stdout);
        assert!(shown.contains("single call"), "{shown}");
        assert!(shown.contains("standing approval:"), "{shown}");
        std::fs::remove_file(path).unwrap();
    }
}
