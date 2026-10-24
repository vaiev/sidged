# Registry: Intents

> **Status: Draft, not for implementation.** See [README.md](README.md) for registry rules.

The envelope `intent` declares the purpose of a message (Sidged L6). It is a dot-separated lowercase name with at least two labels. The first label is either `sk` (reserved control intents, fully listed below), a registered **application domain**, or an `x-` private prefix. The rest of the name is free, for example `scheduling.propose` or `telemetry.report.hourly`. An intent never grants authority; the capability token and local policy do (Sidged L2).

## Reserved Control Intents (`sdg.*`)

Only these `sdg.*` intents exist. Any other `sdg.*` intent is invalid.

| Intent | Purpose | Section |
|---|---|---|
| `sdg.pairing.request` | Start pairing | Sidged L6 |
| `sdg.pairing.response` | Answer a pairing request (out-of-band verification data) | Sidged L6 |
| `sdg.pairing.confirm` | Confirm pairing after owner consent | Sidged L6 |
| `sdg.pairing.reject` | Decline pairing | Sidged L6 |
| `sdg.negotiate` | Version, suite, form, and profile negotiation | Sidged L6 |
| `sdg.refused` | Refusal; `data` is a refusal object | Sidged L6 |
| `sdg.ack` | Receipt acknowledgement | Sidged L6 |
| `sdg.revocation` | Key or device revocation notice | Sidged L6 |
| `sdg.statement` | Owner-signed identity statements, for example after owner-key rotation | Sidged L6 |
| `sdg.stream.setup` | Stream setup with per-session keys (F7) | Sidged L6 |
| `sdg.stream.rekey` | Stream rekeying (F7) | Sidged L6 |
| `sdg.summary` | Signed summary of a negotiation that commits the owner | Sidged L6 |
| `sdg.sync` | Mesh synchronisation (F1) | Sidged L6 |

Pairing messages (`sdg.pairing.*`) and refusals (`sdg.refused`) are the only envelopes that may omit `cap_token`, and they never carry `instructions` (Sidged L6).

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
