# Vaikor Registries

> **Status: Draft, not for implementation. No certification program exists.**

Minimal shared vocabularies referenced by the drafts. Each registry lists codes in its first column; the [schemas](../schemas) enforce the same lists, and the tests in [validate](../validate) check that registries and schemas agree.

| Registry | Used by |
|---|---|
| [data-classes.md](data-classes.md) | `residency.data_classes` and egress policy (Vaikor L7), module manifests (Vaikor L0), privacy reports (Vaikor L7), capability token constraints (Vaikor L2) |
| [effects.md](effects.md) | Capability descriptor `effects` (VKR-L1) |
| [residency.md](residency.md) | Residency tags on content and egress (Vaikor L7). Registered tags are `CH`, `EU`, and `CH-EU`; owner tags start with `x-`. |
| [intents.md](intents.md) | Envelope `intent` (Vaikor L6), pairing (Vaikor L6), refusals (Vaikor L6) |
| [refusal-reasons.md](refusal-reasons.md) | Refusal object (Vaikor L6, Vaikor L7) |

## Rules

- Codes are lowercase ASCII, except the residency tags `CH`, `EU`, and `CH-EU`. Registered codes never change meaning; a code that is withdrawn is marked `deprecated` and is never reused.
- **Private codes** start with `x-` (for example `x-garden.watering` or `x-acme-sensor`). They need no registration, are never registered, and receivers that do not understand them treat them as unknown (fail closed where the draft says so).
- New codes are added by pull request. A change that alters the meaning of an existing code is a substantial change. The RFC process is paused until there are partners; see the [migration note](../../docs/analyse/02-SELFKIN-MIGRATION.md). Licenses and the Developer Certificate of Origin remain.
- Before v1.0 all registries are drafts and may change.
