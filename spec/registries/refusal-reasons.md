# Registry: Refusal Reasons

> **Status: Draft, not for implementation.** See [README.md](README.md) for registry rules.

Reason codes for the refusal object ([schemas/refusal.schema.json](../schemas/refusal.schema.json); Vaikor L6, Vaikor L7). A refusal carries a code, never free text, so it cannot leak memory, Adaptation Profile data, or other content (Vaikor L6). Private codes start with `x-`; a receiver that does not understand a code treats it as `policy-denied`.

| Code | Meaning | Section |
|---|---|---|
| `malformed` | Not a valid envelope or object for the negotiated version | Vaikor L6 |
| `bad-signature` | Missing or invalid signature | Vaikor L6 |
| `unsupported-version` | Unknown major version, or a member from a higher minor version | Vaikor L6 |
| `sunset-version` | Version or crypto suite is `sunset` | Vaikor L6 |
| `unsupported-form` | Form not allowed by the pairing record or not supported | Vaikor L6 |
| `unsupported-intent` | Intent not understood or not accepted | Vaikor L6 |
| `unsupported-token-format` | Token format whose attenuation the receiver cannot verify | Vaikor L2 |
| `unauthorized` | Missing token, or rights do not cover the request | Vaikor L2 |
| `expired` | Envelope or token expired | Vaikor L6/L2 |
| `replayed` | Nonce or `idem_key` already seen | Vaikor L6 |
| `wrong-audience` | `aud` does not name the receiver | Vaikor L6 |
| `out-of-sequence` | `seq` outside the configured window | Vaikor L6 |
| `revoked` | Key, device, token, or module revoked | Vaikor L6 |
| `policy-denied` | Local policy forbids the request | Vaikor L2 |
| `approval-denied` | The human declined | Vaikor L2 |
| `approval-timeout` | No human decision in time | Vaikor L2 |
| `approval-required` | First use per provider and task type, or a call over the approved limit, needs the owner's approval (spec 0007 R8) | Vaikor L7 |
| `rate-limited` | Per-peer or per-credential rate limit reached | Vaikor L6, Vaikor L7 |
| `budget-exceeded` | Message, compute, or money budget exhausted | Vaikor L6 |
| `residency-unsupported` | Destination cannot honour a residency tag | Vaikor L7, Vaikor L7 |
| `residency-unknown-tag` | Residency tag not recognised | Vaikor L7, Vaikor L7 |
| `data-class-forbidden` | Egress policy forbids a data class for this destination | Vaikor L7 |
| `profile-too-low` | Peer or provider profile below the pin or the owner's minimum | Vaikor L6, Vaikor L7 |
| `legacy-forbidden` | Owner policy forbids legacy methods for this data or action | Vaikor L6 |
| `proof-required` | Extra proof needed (fresh anonymous credential, proof-of-work, reduced quota) | Vaikor L7 |
| `unavailable` | Temporarily unable to process; retry later | Vaikor L6 |
