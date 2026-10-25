# Smartphone Remote Approver & A2UI Shim (`0004 R9`, `0008 R5`, `0010 §3`)

Per Spec 0008 R5–R6 ("Phones come last; shim before custom ROM") and Spec 0010 §3 ("Zero public ports"), the heavy Vaikor Core, Swarm supervisor, and local Edge LLM run on your VM / VPS / Home Host, while your smartphone connects over an authenticated private tunnel (SSH over WireGuard/Tailscale) as:

1. **Cryptographically isolated Trusted UI Approver (`0004 R9/R9c`):**
   - Connects via SSH as the dedicated `vaikor-approver` account (UID `65540`) and attaches `vaikor-tui approve` directly to `/run/vaikor/approval/control.sock`.
   - The Core's `SO_PEERCRED` check verifies on the host kernel that the approver is UID `65540` (and not the agent/Core UID).
2. **Offline A2UI Surface Viewer (`ui/shell/`):**
   - Tunnels or syncs the Core-verified A2UI view file (`view.json`) and renders the 5 ratified components (`TaskList`, `CountdownWidget`, `NoteEditor`, `WebResult`, `CloudCallTrace`) under `connect-src 'none'`.

## Usage from Smartphone (Termux / Blink / OpenSSH)

```sh
# Path A: Run Trusted Approval TUI on the host as vaikor-approver
ssh vaikor-approver@<tailscale-or-wg-host> \
  /usr/local/bin/vaikor-tui approve --socket /run/vaikor/approval/control.sock

# Path B: Helper script (from phone or laptop)
scripts/connect-mobile-shim.sh approve vaikor-approver@<tailscale-or-wg-host>
```
