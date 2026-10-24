# Examples

> **Status: Draft, not for implementation.** Examples for the v0.1 JSON Schemas in [../schemas](../schemas). Licensed under Apache-2.0 ([LICENSE-CODE](../../LICENSE-CODE)).

File names follow `<schema>.<case>.json` for valid examples and `<schema>.<case>.invalid.json` for examples that must fail. The validator in [../validate](../validate) picks the schema from the file name and checks both layers: JSON Schema and the semantic checks that JSON Schema cannot express.

Notes that apply to every example:

- **Signatures are placeholders.** Every `sig.value` is a dummy string. The validator checks structure, not cryptography.
- **Identities are fictional.** They use `did:example`, `urn:example`, and `example.org`/`example.com`/`example.net` names. No real person, provider, or product is described.
- **Times are fixed.** Timestamps are around 2026-10-09 and are not checked against the current clock, so examples do not expire.
- The `data` member of `envelope.f2-action-request.json` deliberately contains a prompt-injection sentence. It is valid: `data` is untrusted content and grants no authority (Sidged L6), so the schema has no reason to reject it. The receiving Core must ignore such text as an instruction.

## Valid examples

| File | Shows |
|---|---|
| `capability-token.root.json` | Root token from an owner to a planner agent, sender-bound with `cnf.jkt`, with rights, constraints, and budget |
| `capability-token.delegated.json` | F6 delegation one hop down: narrower resource, fewer rights, shorter lifetime, smaller budget, full chain carried |
| `envelope.f2-action-request.json` | Cross-owner (F2) action request with separate `instructions` and `data`, `aud`, `session`, `seq`, `idem_key`, `CH-EU` residency, delegated `cap_token`, and `model_ref` |
| `envelope.f1-pairing-request.json` | Pairing message (`sdg.pairing.*` intent): no `cap_token`, no `instructions` |
| `envelope.f2-refusal.json` | Refusal (`sdg.refused`) with a refusal object as `data`, no `cap_token`, no `instructions` |
| `envelope.with-extension.json` | The action request with an `ext` member using an `x-` key (Sidged L6) |
| `envelope.f3-legacy-via-proxy.json` | Telemetry from a legacy Modbus device through a proxy (Method 4): proxy in `provenance`, legacy endpoint labelled `legacy` and `unattested`, opaque attenuable token |
| `module-manifest.feature-calendar.json` | Feature module with permissions, consequential flag, egress with residency, SBOM, and SLSA provenance |
| `module-manifest.model-local.json` | Local model module with weight hashes and no egress |
| `module-manifest.legacy-proxy.json` | Self-signed (sideloaded) legacy adapter carrying `legacy` and `unattested` |
| `module-manifest.hardware-actuator.json` | Hardware module with a capability descriptor and declared safe-stop behaviour |
| `refusal.rate-limited.json` | Refusal object with a registered reason, a reference to the refused message, and `retry_after` |
| `refusal.profile-too-low.json` | Refusal stating the communication profile that would be accepted |
| `privacy-report.p0-full-gateway.json` | Call to an unverified (P0) provider in full gateway mode through an OHTTP relay, retention undeclared |
| `privacy-report.p2-verified.json` | Call to a verified P2 provider with a Privacy Pass credential and `CH-EU` residency |
| `provider-manifest.p1-search.json` | P1 self-assessment of a search service with a declared 24 hour abuse-handling retention window and identified-mode linking |
| `provider-manifest.p2-models.json` | P2 self-assessment of a model provider with OHTTP, envelope support, residency, transparency log, and audit |
| `privacy-report.p1-anonymous.json` | Anonymous call to a verified P1 search provider over a relay, with `EU` residency and declared 24 hour abuse-handling retention |
| `session-record.r0-prototype.json` | Session record of an R0 (prototype) runtime: one egress linked to its privacy report, and a Core-signed tier display showing tier 0, every profile, and the `prototype` label |
| `session-record.legacy-hop.json` | Session record with a C0 legacy hop: the Core shows tier 0 and the C0 hop next to it |
| `intent-catalog.reminder.json` | Intent catalog with one intent: two required slots, a canonical English template, and a clarification question per locale (`en`, `de`, `gsw`) |
| `linguist-envelope.gsw-missing-slot.json` | Swiss German utterance normalised to `scheduling.remind`; the `time` slot is missing, so the linguist asks locally and wakes nothing (`clarify`) |
| `linguist-envelope.en-complete.json` | English utterance with every required slot; canonical English intent and the catalog route |
| `linguist-envelope.de-unknown-intent.json` | No catalog intent fits: `intent` is null and the catalog's unknown-intent question is asked |
| `linguist-proposal.gsw-missing-slot.json` | Compact v0.2 proposal (0017 L3a) for the Swiss German reminder: only `lang`, `intent` and the given slot; the Core derives that `time` is missing |
| `linguist-proposal.gsw-composition.json` | Compact proposal of a composition: summarize, then send the result to Marco (`then` holds `intent` and `slots` only) |
| `linguist-proposal.de-unknown-intent.json` | Compact proposal where no catalog intent fits: `intent` null and no slots |

## Invalid examples

Each invalid example changes one thing in a valid example. Examples were generated from fictional data; registered codes come from [../registries](../registries). The comment explains which rule it breaks.

| File | Comment: why it must fail |
|---|---|
| `plan.duplicate-id.invalid.json` | Two steps share the id `free` (SDG-L3 R2). Semantic check |
| `plan.forward-ref.invalid.json` | `send` references `later`, which has not run yet (SDG-L3 R4). Semantic check |
| `plan.map-bound-zero.invalid.json` | `map.bound` is 0. The minimum is 1 (SDG-L3 R6) |
| `capability-descriptor.delete-not-consequential.invalid.json` | `delete` with `consequential` false (SDG-L1 R9). Semantic check |
| `capability-descriptor.egress-without-data-class.invalid.json` | `egress` with an empty `data_classes` array (SDG-L1 R10). Semantic check |
| `capability-descriptor.unknown-effect.invalid.json` | Effect `observe` is not in registries/effects.md (SDG-L1 R6) |
| `capability-token.lifetime-over-one-hour.invalid.json` | Root token valid for 3 hours. The maximum lifetime is 1 hour (Sidged L2). Semantic check |
| `capability-token.longer-lifetime.invalid.json` | Delegated token expires after its parent. Delegation may only shorten lifetime (Sidged L2). Semantic check |
| `capability-token.not-sender-bound.invalid.json` | No `cnf` member, so the token is a bearer token. Tokens must be sender-bound (Sidged L2) |
| `capability-token.widened-budget.invalid.json` | Delegated token raises the message budget above its parent's. Budgets may only narrow (Sidged L2). Semantic check |
| `capability-token.widened-rights.invalid.json` | Delegated token adds a `payments.send` right the parent never had. Rights may only narrow (Sidged L2). Semantic check |
| `envelope.bad-residency-tag.invalid.json` | Residency tag `switzerland` is neither `CH`, `EU`, `CH-EU`, nor an `x-` owner tag (Sidged L7) |
| `envelope.data-without-payload-type.invalid.json` | `data` is present without `payload_type` (Sidged L6) |
| `envelope.expires-before-issued.invalid.json` | `expires` is earlier than `issued`, so the envelope is never fresh. Semantic check |
| `envelope.ext-without-x-prefix.invalid.json` | Extension member `project` without the `x-` prefix (Sidged L6) |
| `envelope.higher-minor-version.invalid.json` | `v` is `0.2`, a version these v0.1 schemas do not define. Members and versions beyond the negotiated version are rejected (Sidged L6) |
| `envelope.refusal-with-free-text.invalid.json` | Refusal object with a free-text `detail`. Refusals carry codes only (Sidged L6) |
| `envelope.refusal-with-instructions.invalid.json` | Refusal that also requests an action. Refusals never carry `instructions` (Sidged L6) |
| `envelope.unknown-reserved-intent.invalid.json` | Intent `sdg.admin` is not one of the reserved `sdg.*` intents (registries/intents.md) |
| `envelope.unregistered-data-class.invalid.json` | Data class `healthcare` is neither registered nor `x-` prefixed (registries/data-classes.md) |
| `envelope.unregistered-intent.invalid.json` | Intent domain `gossip` is neither registered nor `x-` prefixed (registries/intents.md) |
| `envelope.f5-advertisement.invalid.json` | Form F5 in an envelope. Discovery advertisements are not envelopes (Sidged L6) |
| `envelope.instructions-without-idem-key.invalid.json` | Requests an action without `idem_key`. State-changing messages need one (Sidged L6) |
| `envelope.legacy-not-unattested.invalid.json` | Legacy endpoint in `provenance` is labelled `legacy` but not `unattested` (Sidged L6) |
| `envelope.missing-aud.invalid.json` | No `aud`. Every envelope names its recipient (Sidged L6) |
| `envelope.missing-cap-token.invalid.json` | Non-pairing message without `cap_token` (Sidged L6) |
| `envelope.token-not-bound-to-sender.invalid.json` | The capability token's holder (`sub`) is not the sending agent. Semantic check |
| `envelope.unknown-member.invalid.json` | Unknown top-level member `grant`. Unknown members are rejected (fail closed) |
| `module-manifest.actuator-without-safe-stop.invalid.json` | Actuator hardware without declared safe-stop behaviour (Sidged L8) |
| `module-manifest.bad-runtime-range.invalid.json` | Compatibility range `0.3 or newer` is not in the comparator syntax (`>=0.3 <0.4`, Sidged L0) |
| `module-manifest.legacy-not-unattested.invalid.json` | Legacy adapter without the `unattested` label (Sidged L0, Sidged L6) |
| `module-manifest.model-without-weights-hash.invalid.json` | Model module without weight hashes (Sidged L0) |
| `module-manifest.no-sbom.invalid.json` | No SBOM reference (Sidged L0) |
| `module-manifest.signer-missing.invalid.json` | Signature without `signer`, so the Core cannot show who signed (Sidged L0) |
| `module-manifest.undeclared-egress-data.invalid.json` | Egress sends the data class `health`, which the manifest does not declare. Semantic check |
| `privacy-report.direct-but-says-relay.invalid.json` | No relay was used but the report claims the network identity was hidden by a relay |
| `privacy-report.p0-without-full-gateway.invalid.json` | P0 provider called anonymously without full gateway mode (Sidged L7) |
| `privacy-report.redaction-map-included.invalid.json` | Contains a redaction map. Redaction maps must not leave the device and are never part of a report (Sidged L7) |
| `privacy-report.retention-missing.invalid.json` | No retention declaration; the report must show it, even if `undeclared` (Sidged L7, section 13) |
| `privacy-report.unverified-claim-used.invalid.json` | Effective profile P2 although the claim was not verified. Unverified providers are P0 (Sidged L7, Sidged L7) |
| `provider-manifest.audit-older-than-two-years.invalid.json` | Audit valid for three years. Audits are renewed at least every two years (Sidged L7). Semantic check |
| `provider-manifest.claims-certification.invalid.json` | Claim basis `certification`. Before v1.0 only self-assessments exist (Sidged L7) |
| `provider-manifest.identified-linking-undeclared.invalid.json` | Identified mode offered without declaring how requests are linked (Sidged L7, section 4) |
| `provider-manifest.model-identity-without-envelope.invalid.json` | Model identity declared to travel in the envelope although the provider does not accept envelopes (Sidged L7) |
| `provider-manifest.p1-trains-on-requests.invalid.json` | Claims P1 but trains on runtime requests (Sidged L7) |
| `provider-manifest.p2-without-ohttp.invalid.json` | Claims P2 without an Oblivious HTTP gateway (Sidged L7) |
| `provider-manifest.p2-without-envelope.invalid.json` | Claims P2 without accepting the Sidged Envelope. Equivalent mappings are not accepted (Sidged L7) |
| `provider-manifest.p3-without-attestation.invalid.json` | Claims P3 without attestation endpoints, reference values, or retention evidence (Sidged L7, section 5) |
| `provider-manifest.retention-without-purpose.invalid.json` | Non-zero retention window without a stated purpose (abuse handling or legal duty, Sidged L7) |
| `refusal.free-text.invalid.json` | Free-text `detail` member. A refusal must not include content beyond codes and references (Sidged L6) |
| `refusal.unregistered-reason.invalid.json` | Reason `too-busy` is neither registered nor `x-` prefixed (registries/refusal-reasons.md) |
| `session-record.hides-c0.invalid.json` | The tier display leaves out the C0 hop of the session. The Core display must not hide a downgrade (Sidged L4). Semantic check |
| `session-record.report-mismatch.invalid.json` | The egress links a report for a different payload, so it has no matching privacy report (Sidged L7). Semantic check |
| `intent-catalog.required-slot-undeclared.invalid.json` | `required` names the slot `place`, which `properties` does not declare. Semantic check |
| `intent-catalog.missing-locale-ask.invalid.json` | The `time` slot has no `gsw` question although the catalog declares `gsw`. Semantic check |
| `linguist-envelope.missing-slot-without-clarification.invalid.json` | `time` is missing but `clarification_needed` is false and the route wakes Edge 1 |
| `linguist-envelope.residency-member.invalid.json` | The linguist adds `residency`. The Core supplies residency; the model never proposes it |
| `linguist-envelope.clarify-without-question.invalid.json` | `clarification_needed` is true but no question is given |
| `linguist-proposal.derived-member.invalid.json` | A compact proposal with `missing_slots`. The Core derives it; a v0.2 proposal carries no derived member (0017 L3a) |
| `linguist-proposal.residency-member.invalid.json` | A compact proposal with `residency`. The Core supplies residency; the model never proposes it |
| `linguist-proposal.follow-up-canonical.invalid.json` | A follow-up with `canonical_intent_en`. Follow-ups of a compact proposal are `intent` and `slots` only |
| `linguist-proposal.full-envelope.invalid.json` | A full v0.1 envelope is not a compact proposal (`v` must be `0.2`); it is checked against linguist-envelope.schema.json instead |
| `linguist-proposal.over-long-slot.invalid.json` | A slot value of 513 characters. Slot values are 1 to 512 characters |
| `linguist-proposal.null-intent-with-slots.invalid.json` | `intent` is null but slots are given. Without an intent there are no slots |
