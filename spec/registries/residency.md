# Registry: Residency Tags

> **Status: Draft, not for implementation.** See [README.md](README.md) for registry rules.

Residency tags say where content may be processed (Vaikor L7). Missing or empty declarations deny processing. Several restricted tags on one item combine by intersection. `unrestricted` MUST be the only tag on an item (otherwise `malformed`). Derived values combining unrestricted and restricted inputs drop `unrestricted` and carry the restricted tags. GLOBAL destinations require explicit `unrestricted`. A runtime or provider that does not recognise a tag MUST treat it as not allowed (fail closed). Owner-defined tags start with `x-`, use lowercase letters, digits, and hyphens, and are at most 64 characters in total. They are not registered.

| Tag | Meaning | Where processing is allowed |
|---|---|---|
| `CH` | Switzerland only | Switzerland |
| `EU` | EU and EEA member states only | EU and EEA |
| `CH-EU` | Switzerland, or EU and EEA member states | Switzerland, EU, and EEA |
| `unrestricted` | Explicitly no geographic restriction. Must be the only tag (0001 R8b) | Any registered region, including GLOBAL |

Gemini Developer API: `https://generativelanguage.googleapis.com:443`, profile **P0**, destination **GLOBAL**. Only explicitly `unrestricted` payloads may use it. A billing project (`VAIKOR_GEMINI_PROJECT` or `provider_project` in scenario config) is required; it declares configuration, not verified billing status. Grounding, explicit caching, File API and Live API session resumption are refused before transport.

xAI (amendment, v1 spec; implemented in the gateway): provider id `xai`, origin `https://api.x.ai:443`, OpenAI-compatible base path `/v1`, endpoint `/v1/chat/completions`, profile **P0**, destination **GLOBAL** (no residency guarantee). GLOBAL is destination metadata, not a residency tag. Only explicitly `unrestricted` payloads may pass its residency check; CH, EU, and CH-EU MUST refuse it. Residency is separate from the P0-P3 provider profile. Profile **P0** (unverified). **Decision record:** Decided by WOUFbot under the standing autonomy Roni granted (2026-10-16 10:29 "du darfsch alles selber mache", 11:19 "selbständig"); delegated, not an explicit P0 decision by Roni. xAI publishes no Vaikor provider manifest, so no P1-P3 claim can be made; same profile as Gemini Developer API. The gateway implements this entry with profile P0 required, endpoint `/v1/chat/completions` only, and the API key from a file (`VAIKOR_API_KEY_FILE`, never the environment). 0007 §5.1 (R7-R9, including standing approval) and §5.3 anonymization apply unchanged; redirects MUST remain refused.

Missing or empty tags fail closed at egress (0001 R8a). `GLOBAL` is a destination class (an endpoint with no residency guarantee), never a tag.
