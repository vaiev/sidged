# Registry: Effects

> **Status: Draft v0.1.** See [README.md](README.md) for registry rules. Normative use is VKR-L1 ([docs/specs/0001-capability.md](../../docs/specs/0001-capability.md)).

An effect is what a capability does to the world. A descriptor lists every effect it can have. `delete`, `execute`, and `egress` are consequential.

| Code | Meaning |
|---|---|
| `read` | Observe state. Does not change it and does not send it off the device by itself. |
| `write` | Create or update state. Does not by itself send data off the device. |
| `delete` | Remove or destroy state. |
| `execute` | Run a side effect that is not only a read, write, or delete. |
| `egress` | Send data off the device. Requires at least one data class. |
