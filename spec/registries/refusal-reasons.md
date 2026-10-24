# Registry: Refusal Reasons

> **Status: Draft, not for implementation.** See [README.md](README.md) for registry rules.

Reason codes for the refusal object ([schemas/refusal.schema.json](../schemas/refusal.schema.json); Sidged L6, Sidged L7). A refusal carries a code, never free text, so it cannot leak memory, Adaptation Profile data, or other content (Sidged L6). Private codes start with `x-`; a receiver that does not understand a code treats it as `policy-denied`.

| Code | Meaning | Section |
|---|---|---|
| `malformed` | Not a valid envelope or object for the negotiated version | Sidged L6 |
| `bad-signature` | Missing or invalid signature | Sidged L6 |
| `unsupported-version` | Unknown major version, or a member from a higher minor version | Sidged L6 |
| `sunset-version` | Version or crypto suite is `sunset` | Sidged L6 |
| `unsupported-form` | Form not allowed by the pairing record or not supported | Sidged L6 |
| `unsupported-intent` | Intent not understood or not accepted | Sidged L6 |
| `unsupported-token-format` | Token format whose attenuation the receiver cannot verify | Sidged L2 |
| `unauthorized` | Missing token, or rights do not cover the request | Sidged L2 |
| `expired` | Envelope or token expired | Sidged L6/L2 |
| `replayed` | Nonce or `idem_key` already seen | Sidged L6 |
| `wrong-audience` | `aud` does not name the receiver | Sidged L6 |
| `out-of-sequence` | `seq` outside the configured window | Sidged L6 |
| `revoked` | Key, device, token, or module revoked | Sidged L6 |
| `policy-denied` | Local policy forbids the request | Sidged L2 |
| `approval-denied` | The human declined | Sidged L2 |
| `approval-timeout` | No human decision in time | Sidged L2 |
| `approval-required` | First use per provider and task type, or a call over the approved limit, needs the owner's approval (spec 0007 R8) | Sidged L7 |
| `rate-limited` | Per-peer or per-credential rate limit reached | Sidged L6, Sidged L7 |
| `budget-exceeded` | Message, compute, or money budget exhausted | Sidged L6 |
| `residency-unsupported` | Destination cannot honour a residency tag | Sidged L7, Sidged L7 |
| `residency-unknown-tag` | Residency tag not recognised | Sidged L7, Sidged L7 |
| `data-class-forbidden` | Egress policy forbids a data class for this destination | Sidged L7 |
| `profile-too-low` | Peer or provider profile below the pin or the owner's minimum | Sidged L6, Sidged L7 |
| `legacy-forbidden` | Owner policy forbids legacy methods for this data or action | Sidged L6 |
| `proof-required` | Extra proof needed (fresh anonymous credential, proof-of-work, reduced quota) | Sidged L7 |
| `unavailable` | Temporarily unable to process; retry later | Sidged L6 |
