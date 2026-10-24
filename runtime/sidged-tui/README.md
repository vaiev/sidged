# sidged-tui (Demo 1, unsigned preview)

Status: prototype. A single demo flow, not a general approval client; it checks its
grant with `sidged_grant::authorise` and audits through the signed chain.

One task with a countdown and exactly one cloud call (Gemini) per human
approval, sent only through `sidged-gateway`. See the usage header in
`src/main.rs` for all `run` / `approve` / `revoke` / `issue-grant` arguments.
Use `sidged-tui revoke unix:<path> <64hex|*>` on the approval socket to
queue revocation of one standing approval digest or all standing approvals.
In `approve`, `y` accepts the displayed standing scope, `s` approves a
single call without its scope digest (0004 R9b), and `N` denies.
Quote `'*'` in the shell. The Core audits revocation with the same approver
and R11 channel binding fields as approve/deny records.

## Demo host requirements (approval channel, 0004 R9c)

The Core refuses to start the approval channel (fail-closed, audited as
`approval_channel_untrusted (...)`) whenever an R9c start check cannot be
evaluated. 0004 R9c: "Any other check that cannot be evaluated refuses the
channel." Relevant for the demo host:

- **PID namespace.** The Core must run in the host PID namespace. In a
  container, under `unshare --pid`, or in a systemd unit with
  `PrivatePIDs=`, the Core sees only its own processes. The CAP_SYS_PTRACE
  scan then finds no process of another uid and refuses with
  `approval_scan_incomplete`. This is intended, not a bug.
- **`/proc` with `hidepid`.** If `/proc` is mounted with `hidepid` other
  than `0`/`off`, the core uid must be in the mount's `gid=` group, or the
  scan refuses (`approval_scan_incomplete`). An unreadable
  `/proc/<pid>/status` refuses too.
- **CAP_SYS_PTRACE.** No non-approver uid may hold CAP_SYS_PTRACE (for
  example a rootless podman pause process). Stop such processes for the
  demo window.
- **`--operator-attest`** only covers sudo/doas rules the Core cannot read
  or evaluate (0005 R3b). It does not lift any of the refusals above. With
  it, every approval record carries `approval_binding=operator-attested`,
  and the TUI shows `approval: operator-attested (R9c)`.

## Owner policy and checks

- Owner policy: Cedar, built-in `policy.cedar` (only `egress.send` to the
  exact Gemini chat-completions URL, class `query`, residency
  `unrestricted`), or `--policy <file>`. The SHA-256 of the loaded policy is
  recorded at channel start and in every 0007 §5.3 (R13) record.
- 0007 §5.3 check A uses the owner-policy default export threshold
  (`query`, `documents.text`). There is no launcher flag to change it.
- Detector set: `sdg.pii/1`, exactly the 0007 R12 table (R12a). A `card` is a
  whole 13-19 digit run that passes Luhn; a card inside a 20+-digit run is
  not detected. Windowing (a later `sdg.pii/2`) is deferred.
