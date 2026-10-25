# Registry: Intents

> **Status: Draft, not for implementation.** See [README.md](README.md) for registry rules.

The envelope `intent` declares the purpose of a message (Vaikor L6). It is a dot-separated lowercase name with at least two labels. The first label is either `sk` (reserved control intents, fully listed below), a registered **application domain**, or an `x-` private prefix. The rest of the name is free, for example `scheduling.propose` or `telemetry.report.hourly`. An intent never grants authority; the capability token and local policy do (Vaikor L2).

## Reserved Control Intents (`vkr.*`)

Only these `vkr.*` intents exist. Any other `vkr.*` intent is invalid.

| Intent | Purpose | Section |
|---|---|---|
| `vkr.pairing.request` | Start pairing | Vaikor L6 |
| `vkr.pairing.response` | Answer a pairing request (out-of-band verification data) | Vaikor L6 |
| `vkr.pairing.confirm` | Confirm pairing after owner consent | Vaikor L6 |
| `vkr.pairing.reject` | Decline pairing | Vaikor L6 |
| `vkr.negotiate` | Version, suite, form, and profile negotiation | Vaikor L6 |
| `vkr.refused` | Refusal; `data` is a refusal object | Vaikor L6 |
| `vkr.ack` | Receipt acknowledgement | Vaikor L6 |
| `vkr.revocation` | Key or device revocation notice | Vaikor L6 |
| `vkr.statement` | Owner-signed identity statements, for example after owner-key rotation | Vaikor L6 |
| `vkr.stream.setup` | Stream setup with per-session keys (F7) | Vaikor L6 |
| `vkr.stream.rekey` | Stream rekeying (F7) | Vaikor L6 |
| `vkr.summary` | Signed summary of a negotiation that commits the owner | Vaikor L6 |
| `vkr.sync` | Mesh synchronisation (F1) | Vaikor L6 |

Pairing messages (`vkr.pairing.*`) and refusals (`vkr.refused`) are the only envelopes that may omit `cap_token`, and they never carry `instructions` (Vaikor L6).

## Application Domains

| Domain | Purpose | Examples |
|---|---|---|
| `task` | Generic task requests and results | `task.request`, `task.result` |
| `scheduling` | Meetings and appointments | `scheduling.propose`, `scheduling.accept` |
| `messaging` | Sending or relaying messages for a person | `messaging.send` |
| `telemetry` | Sensor and device readings | `telemetry.report` |
| `control` | Commands to devices and actuators | `control.set`, `control.stop` |
| `negotiation` | Agent-to-agent negotiation | `negotiation.offer`, `negotiation.counter` |
| `purchase` | Orders and quotes | `purchase.quote`, `purchase.order` |
| `payment` | Payment requests and confirmations | `payment.request` |
| `share` | Sharing data or files | `share.offer`, `share.deliver` |
| `query` | Questions and lookups, including provider calls | `query.search`, `query.inference` |
| `notify` | Notifications without a requested action | `notify.info` |
| `handoff` | Delegating a task to another runtime (F6) | `handoff.request`, `handoff.result` |
