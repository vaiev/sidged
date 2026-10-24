# Sidged JSON Schemas (v0.1)

> **Status: Draft, not for implementation. No certification program exists.** These schemas follow the drafts; where a schema and a draft disagree, the draft wins and the schema has a bug. Licensed under Apache-2.0 ([LICENSE-CODE](../../LICENSE-CODE)).

Machine-readable versions of the data structures defined in the drafts, written in [JSON Schema 2020-12](https://json-schema.org/draft/2020-12/schema). Examples are in [../examples](../examples), and the validator is in [../validate](../validate). Questions found while writing the schemas, how they were resolved in the drafts, and what remains open are listed in [OPEN-QUESTIONS.md](OPEN-QUESTIONS.md).

## Schemas and Draft Sections

| Schema | `$id` (under `https://sidged.com/spec/schemas/`) | Draft sections |
|---|---|---|
| [envelope.schema.json](envelope.schema.json) | `envelope.schema.json` | Sidged L6 (fields), A1 (forms), A3 (pairing, F5), A4 (F7 setup), A6 (`cap_token`), A7 (untrusted `data`), A9 (`idem_key`, `seq`, `expires`), A10 (`model_ref`), B1 and B5 (labels and proxy `provenance`); Sidged L7 (residency tags) |
| [capability-descriptor.schema.json](capability-descriptor.schema.json) | `capability-descriptor.schema.json` | SDG-L1 descriptor: effects, data classes, residency, cost, consequential. Not a grant |
| [capability-token.schema.json](capability-token.schema.json) | `capability-token.schema.json` | Sidged L2 (capabilities, short-lived, sender-bound, attenuation, chain), A7 (budgets); Sidged L2 (scoped, expiring, sender-bound tokens) |
| [module-manifest.schema.json](module-manifest.schema.json) | `module-manifest.schema.json` | Sidged L0 (signed manifest, permissions, data classes, egress, residency, resources, SBOM, weight hashes, legacy labels), 4 (capability descriptor, safe stop), 6 (permission manifest), 17 (SBOM formats); Sidged L6 (legacy methods B1 to B6) |
| [plan.schema.json](plan.schema.json) | `plan.schema.json` | SDG-L3 plan: calls, CEL expressions, bounded maps |
| [privacy-report.schema.json](privacy-report.schema.json) | `privacy-report.schema.json` | Sidged L7 (privacy report, full gateway mode, verifiable minimisation, P0 handling), 11 (retention in report, residency, log protection), 14 (model identity); Sidged L7 (retention window), 12 (downgrade) |
| [provider-manifest.schema.json](provider-manifest.schema.json) | `provider-manifest.schema.json` | Sidged L7 (manifest contents), 2 (anonymous mode, credentials, billing, identified mode), 3 (no training, retention), 4 (no tracking, relays, OHTTP), 5 (attestation), 6 (envelope, residency), 7 (model identity, transparency reports, announced changes), 10 (audit), 11 (profile requirements, self-assessment) |
| [refusal.schema.json](refusal.schema.json) | `refusal.schema.json` | Sidged L6 (refusal object, `sdg.refused`), A5 (refusal envelopes); Sidged L7 (residency refusals), 9 (refusal format); [registries/refusal-reasons.md](../registries/refusal-reasons.md) |
| [session-record.schema.json](session-record.schema.json) | `session-record.schema.json` | Sidged L7 (one privacy report per egress), 5 (effective tier display rendered and signed by the Core), 21 (R0 prototype label); carried as `data` of an envelope signed by the Core key |
| [intent-catalog.schema.json](intent-catalog.schema.json) | `intent-catalog.schema.json` | Companion linguist (Model -1) intent catalog: slots as JSON Schema, canonical English template, capabilities, data classes, route, localized clarification questions. Not a grant |
| [linguist-envelope.schema.json](linguist-envelope.schema.json) | `linguist-envelope.schema.json` | Companion linguist output: language, catalog intent, canonical English slots, missing slots, local clarification question. A proposal; the Core re-derives everything except `lang`, `intent`, and `slots` from the catalog |
| [linguist-proposal.schema.json](linguist-proposal.schema.json) | `linguist-proposal.schema.json` | Compact companion linguist output (v0.2, 0017 L3a): only `lang`, `intent`, `slots` and follow-ups. The Core derives the full linguist envelope from it |
| [common.schema.json](common.schema.json) | `common.schema.json` | Shared definitions: identifiers, timestamps, durations, digests, the signature block, residency tags (Sidged L7, TERMINOLOGY), data classes and intents (registries), the `ext` object (Sidged L6), profile tags (Sidged L5, Sidged L6, Sidged L7), trust labels (TERMINOLOGY) |

## Design Rules

- **Fail closed, with one extension point.** Unknown members are rejected (`additionalProperties` or `unevaluatedProperties` set to `false`), except inside the optional `ext` object, whose member names start with `x-` and which receivers ignore if not understood (Sidged L6).
- **Profiles are checked where the document states them.** The provider manifest carries a profile claim, so the schema checks that a P1, P2, or P3 claim states everything that profile requires. A claim is always a self-assessment (`basis: "self-assessment"`), never a certification. Envelopes carry no profile, so profile-dependent envelope rules (for example `attestation_ref` at C3) cannot be checked by the schema.
- **Structure here, semantics in the validator.** JSON Schema cannot compare values across members. spec/validate adds semantic checks: delegated capability tokens only narrow rights, lifetime, and budget, and keep the chain consistent; envelope `expires` is after `issued`; the envelope's token is bound to the sender and the recipient; module egress only uses declared data classes; provider audits are at most two years old; in a session record every egress has a matching report, and the tier display is signed by the Core key, shows every profile of the session, and is not higher than the effective tier.
- **Not checked at all:** signatures, key trust, revocation, replay, clocks, and residency enforcement. These need keys and runtime state.
- **Signatures.** Every signed object has a `sig` block with `alg`, `kid`, `canon` (`dcbor` or `jcs`), `value`, and for manifests `signer`. The signature covers the canonical encoding of the object with `sig` removed; `dcbor` is mandatory to implement (Sidged L6).
- **Versioning.** `v` is `MAJOR.MINOR`, and these schemas accept exactly `0.1`. A document using a later minor version is checked against that version's schemas (Sidged L6).
- **Registries.** Data classes, intents, and refusal reasons are restricted to [../registries](../registries/README.md) or `x-` private codes. The tests check that registries and schemas list the same codes.

## CBOR Encoding (non-normative note)

The JSON Schemas define the data model. A CBOR encoding follows the same data model, encoded as deterministic CBOR as defined in RFC 8949 section 4.2 (Core Deterministic Encoding Requirements), so that signatures over the canonical form are reproducible. Member names stay text strings, timestamps may be carried as CBOR tag 1 (epoch seconds), and binary values that JSON carries as base64url may be carried as CBOR byte strings. This note is non-normative; a normative CBOR profile, including the exact type mappings, is future work. Signatures already use deterministic CBOR (`canon: dcbor`) as the mandatory-to-implement encoding (Sidged L6).

## Validate

```sh
pip install -r spec/validate/requirements.txt
python spec/validate/validate.py                         # all examples
python spec/validate/validate.py my-envelope.json --schema envelope
python -m unittest discover -s spec/validate -v          # tests
```
