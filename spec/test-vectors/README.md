# Test Vectors

> **Status: Draft, not for implementation.** Shared conformance test vectors for the Sidged drafts, phase 1. Licensed under Apache-2.0 ([LICENSE-CODE](../../LICENSE-CODE)).

Each vector is a fixed input with an expected result, so that the validator in [../validate](../validate), the Python reference recorded in the [migration note](../../docs/analyse/02-SELFKIN-MIGRATION.md), and any other implementation can check themselves against the same files.

## Layout

| Path | Contents |
|---|---|
| `VERSION` | Suite version, the only place it is recorded |
| `vector.schema.json` | JSON Schema 2020-12 for every vector file |
| `keys/rfc8032-test-keys.json` | Ed25519 test keys copied from [RFC 8032, section 7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1). **TEST ONLY** |
| `resource-matching/` | Whether a right resource covers a requested resource (Sidged L2) |
| `tokens/` | Capability token lifetime, attenuation rules (a) to (f), budgets and constraints (Sidged L2) |
| `envelope/` | Envelope structure and token binding (Sidged L6/L2), and receive sequences (§A5, §A6, §A9) |
| `residency/` | Residency tag syntax and intersection (Sidged L7) |
| `signatures/` | RFC 8032 known answers, `jcs` signing input, signing, and verification (Sidged L6) |
| `intent/` | The intent linguist boundary: reply verification, intent plans, spoken times and durations (spec 0017) |
| `slice/` | Vertical slice: a session record in a Core-signed envelope, one privacy report per egress, and the Core-rendered effective tier display (Sidged L4/L7/L5) |

## Vector Format

A file holds `category`, `description`, and a list of `vectors`. Files do not record the suite version; it lives only in `VERSION`. Each vector has:

- `id`: stable and never reused, for example `token.narrowing.004`.
- `spec`: the rules it tests (document, version, section, profile tag).
- `operation`: what to run (below), with its `input`.
- `expected`: `{"result": "accept"}`, `{"result": "refuse", "reason": ...}`, or `{"value": ...}`. A `reason` is a code from [registries/refusal-reasons.md](../registries/refusal-reasons.md), or a list of acceptable codes where the drafts do not fix the order of checks. It is absent where the drafts do not fix a code; then any refusal passes.
- `status`: `normative` (follows from merged draft text) or `provisional` (an interim reading of an open question, described in `open_issue`). Provisional failures are reported but should not fail a run.
- Optional `requires` (features such as `EdDSA` or `jcs`; runners without them skip the vector) and `note` (for readers, never compared).

### Sequence Vectors

A vector with `"kind": "sequence"` has an initial `state` and ordered `steps` instead of `operation`, `input`, and `expected`. Each step has its own `operation`, `now` (the receiver's clock for that step), `input`, and `expected`, and sees the state left by the steps before it (seen nonces, executed `idem_key` values, usage counters). A step's `expected` has `result` (with an optional `reason`), `executed` (whether the requested action ran), or both; absent members are not compared. Steps are in time order. A runner that does not support every step skips the whole vector.

Each vector has one fault, so the expected result does not depend on check order. Signatures inside token and envelope inputs are placeholders, as in [examples/](../examples/); those operations do not check signatures. The `slice/` vectors are the exception: their signatures are real Ed25519 signatures over `jcs` with the test keys, so a runner can verify them.

## Operations

| Operation | Input | Output |
|---|---|---|
| `resource-covers` | `right`, `resource` (strings) | `value`: true if the right resource covers the resource |
| `capability-check` | `descriptor` | accept or refuse: SDG-L1 schema plus consequential and egress rules. No grants |
| `plan-check` | `plan`, `catalog`, optional `allow` | accept or refuse: SDG-L3 effects, labels, bounded map, approval, and cost. Runners without `cel` skip vectors that require it |
| `token-check` | `token` | accept or refuse: schema, lifetime (at most 1 hour, `exp` after `iat`, `nbf` before `exp`) and attenuation of every link. No clock, signatures, `cnf`, or trust anchors |
| `envelope-check` | `envelope` | accept or refuse: version, schema, `expires` after `issued`, the token as in `token-check`, and token binding (`sub`, `aud`, rights cover the instruction). No clock, signatures, replay, or session state |
| `residency-regions` | optional `tags` (missing or empty is the intersection identity; not egress permission), optional `owner_tags` (tag to list of regions), optional `provider_region` | `value`: sorted regions where the data may go (`CH` for Switzerland, `EU` for EU and EEA member states), `"any"` for explicit `unrestricted`, or refuse; optional `allowed` checks provider matching |
| `residency-destination` | optional `tags`, `destination` (`CH`, `EU`, `GLOBAL`, or an unregistered name) | accept or refuse: spec 0001 R8 v0.2 egress residency gate (missing or empty tags fail closed, `unrestricted` only alone, no CH/EU/CH-EU to GLOBAL) |
| `approval-binding` | `request` (0004 socket `request` JSON, optional `scope`, `scope_digest`), `line` (answer) | `value`: `{approved, standing}` (spec 0004 R9b) |
| `egress-check` | `route`, `provider`, `task_type`, `destination`, `tags`, `read_classes` (Core read log), `approval` (standing approval: `valid`, `standing`, `used`, `scope`, `scope_digest` = SHA-256 hex of canonical JSON of `scope`, optional `revoked`), optional `subscription`, `payload`, optional `max_payload_bytes`, `detector_version`, `local_only`, `export`; `model_claim` is ignored | accept or refuse: spec 0007 §5.1 to 5.3 |
| `residency-tag-syntax` | `tag` | `value`: true if the tag is well-formed |
| `ed25519-sign` | `key` (name in the key file), `message_hex` | `value`: signature as hex |
| `jcs-signing-input` | `object` | `value`: RFC 8785 canonical JSON of the object without `sig`, as a string |
| `sign` | `object`, `key`, `canon` | `value`: the resulting `sig.value` (unpadded base64url) |
| `verify` | `object`, `public_key` (name in the key file) | accept or refuse with `bad-signature`. Whether the key belongs to the signer is out of scope |
| `did-key` | `public_key_hex` or `did` | `value`: the Ed25519 `did:key`, or the public key hex when resolving |
| `jwk-thumbprint` | `public_key_hex` | `value`: RFC 7638 unpadded base64url thumbprint of the OKP JWK |
| `holder-bind` | `sub`, optional `kid`, optional `jkt` | accept when `kid` is that holder's Ed25519 `did:key` and `jkt`, if present, is its thumbprint |
| `token-chain` | `token` | accept when every link, including the token, has a valid EdDSA `jcs` signature by `iss` and a bound holder |
| `session-check` | `envelope`, `core_kid`, `public_key` (name in the key file of the Core key) | accept or refuse: the envelope as in `envelope-check`, signed by the Core key, carrying a session record (`schemas/session-record.schema.json`) whose core is the sender; every egress has a report with the same payload digest; the tier display is for this session, signed by the Core key, shows every runtime, hop, and provider profile of the session, and is not higher than their lowest tier; an R0 session shows `prototype`. Runners with `EdDSA` and `jcs` also verify the envelope and display signatures against `public_key`; the token signature is by `rfc8032-test-3` (owner) |
| `dcbor-encode` | `value` (JSON value) | `value`: the `dcbor` v0.1 bytes as hex (spec 0012 §2), or refuse `malformed` for floats and non-NFC text |
| `record-digest` | `record` | `value`: `{digest, dcbor_hex}`: SHA-256 unpadded base64url over the `dcbor` bytes of the record without `sig`, and those bytes |
| `dcbor-decode` | `hex` | `value`: the decoded JSON value, or refuse `malformed` when the bytes are not exactly dcbor v0.1 (spec 0012 R4) |
| `record-check` | `record`, `trusted_core_keys` (names in the key file) | accept or refuse: spec 0012 §3 members, class grammar, `kid` equal to `signer`, `signer` a trusted Core key, and an Ed25519 `dcbor` signature by it |
| `record-derive` | `inputs` (array of `{class, tags}`) | `value`: `{class, tags, regions}` for a derived Record (spec 0012 R10), or refuse `data-class-forbidden` |
| `record-resource` | `class` | `value`: the SDG-L2 resource of the class (spec 0012 R9), or refuse `malformed` |
| `record-retention` | `record`, `now` | `value`: `live` or `expired` (spec 0012 R8) |
| `plan-digest` | `plan` | `value`: `{digest, dcbor_hex}` of the plan (spec 0013 R2), or refuse `malformed` (float) |
| `stored-plan-signing-input` | `stored` | `value`: hex of the `dcbor` bytes of the stored plan without `sig` |
| `stored-plan-check` | `stored`, `catalog`, `owner_key` (name in the key file of the configured owner key), `now` | accept or refuse: spec 0013 R3-R6 (owner binding and Ed25519 `dcbor` signature, digests, lifetime, not-before, expiry) |
| `flow-check` | `plan`, `catalog`, `policies` (Cedar sources) | accept or refuse `data-class-forbidden` (spec 0013 §4). The runner derives labels, `sensitive` and each egress step's destination itself. Requires `cedar` |
| `linguist-verify` | optional `utterance`, `reply` (the model's JSON object) or `reply_text` (its raw text) | `value`: `{envelope, corrections}`, the envelope the Core keeps (0017 L2 to L7) and the correction codes in order; or refuse. Catalog: `runtime/sidged-cli/assets/intent-catalog.json`. Requires `intent` |
| `intent-plan` | `utterance`, `reply`, optional `plan` (a planner's SDG-L3 plan; absent: the intent's catalog plan) | `value`: `{verdict: "accept", plan_digest}` or `{verdict: "refuse", stage}` with stage `envelope`, `intent`, `bound`, `catalog`, `grounding`, `schema`, `structure`, `verifier` or `flow` (0017 PL1 to PL5; default capability catalog, `default-flow`). Requires `intent` and `cedar` |
| `time-resolve` | `text`, `now` (RFC 3339 UTC), `tz` (IANA zone) | `value`: the instant as RFC 3339 with the zone's offset, or `null` when the words are refused (0017 X6). Requires `intent` |
| `duration-read` | `text` | `value`: seconds, or `null` when refused (0017 X6). Requires `intent` |
| `receive` (sequence steps) | `envelope`; state `receiver` (its identity), optional `seen_nonces` | accept or refuse, and `executed`. Everything `envelope-check` covers, plus `aud` against the receiver, `expires` against `now`, replayed nonces, `idem_key` at most once, and usage counting. Signatures, sender identity, pairing, residency, `cnf`, root issuer trust, and local policy are assumed to pass; the requested action has a local handler |

## Keys

The only keys are the Ed25519 test keys published in [RFC 8032, section 7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1) (TEST 1, 2, and 3), copied unchanged. They are public, **for tests only**, and must never be used to sign anything real. Ed25519 signatures are deterministic, so `sign` vectors have exact expected values. [../.gitleaks.toml](../../.gitleaks.toml) allows these files in secret scans.

`dcbor` signatures on Records are covered by `records/` (spec 0012), generated by `tools/gen_dcbor_vectors.py`. Not yet covered: signatures on delegated token chains.

## Running

```sh
pip install -r spec/validate/requirements.txt
python -m unittest discover -s spec/validate -v   # includes the vectors
python spec/validate/test_vectors.py --summary    # pass, fail, and skip per file
```

The validator runs `resource-covers`, `token-check`, `envelope-check`, `residency-destination`, `egress-check`, `approval-binding`, `residency-tag-syntax`, and `session-check` (key binding by `kid`, no signature verification), comparing accept or refuse only because it has no refusal codes (except `egress-check`, which also compares the reason), and skips the rest, including `receive` sequences and every vector that lists `requires`. It does check that every envelope a `receive` step expects to be accepted is a valid envelope. Other implementations can read the files directly: validate each file against `vector.schema.json`, run the operations they support, and compare results.

## Status and Versioning

Phase 1 covers rules already in the drafts, and the slice covers the rules it adds to Sidged L5: 373 vectors, 369 normative and 4 provisional. `scripts/spec-coverage.py` lists which numbered rules have a vector.

| Category | Normative | Provisional |
|---|---|---|
| Resource matching | 19 | 0 |
| Tokens | 44 | 0 |
| Envelope (single) | 26 | 0 |
| Envelope (receive sequences) | 4 | 4 (repeated `idem_key` answer, usage counting) |
| Residency | 46 | 0 |
| Signatures | 26 | 0 |
| Slice (session record and tier display) | 19 | 0 |
| Capability descriptor | 5 | 0 |
| Plan | 16 | 0 |
| Records and `dcbor` (spec 0012) | 58 | 0 |
| Stored plans and flow policy (spec 0013) | 23 | 0 |
| Egress model calls (spec 0007 §5) | 35 | 0 |
| Approval binding (spec 0004 R9b) | 7 | 0 |
| Intent linguist, intent plans, times and durations (spec 0017) | 41 | 0 |

Resource matching and the two binding vectors that depend on it are normative under SDG-L2 R9 (`docs/specs/0002-grant.md`): a `/*` prefix does not cover an empty remainder, `.`, `..`, or percent-encoding. `open_issue` says in one sentence what is still open. Receive sequences about how a repeated `idem_key` is answered and how usage is counted are provisional; replay, expiry, audience, and at-most-once execution are normative. Later phases add `dcbor` and chain signatures, root issuers and `cnf`, and more stateful receiver checks such as sequence windows, clock skew, nonce retention, and chain-wide budget counting.

The current suite version is `0.13.1`. Suite `0.3.0` is the Sidged identifier rename of suite `0.2.0`: the same vectors, with `sdg.*` intents, `application/vnd.sidged.*` media types, and layer ids `L0` to `L8` in `spec.doc`. Accept and refuse outcomes are unchanged. Real Ed25519 signatures over JCS were recomputed for the renamed payloads. Section numbers inside `spec.section` still cite the source-draft section; the crosswalk is in the migration note. `VERSION` is its only source, and a test checks that this sentence matches it, so a version bump changes `VERSION` and this line and nothing else. The suite follows semantic versioning: patch for new vectors, minor for new operations or fields, major for changed expectations. A vector whose expectation changes gets a new `id`; old ids are never reused. [examples/](../examples/) stay as readable whole documents; vectors are minimal checks with expected results and do not refer to example files.

`residency-destination`: input `tags` (optional), `destination` (`CH`, `EU`, `GLOBAL`, or unknown), and optional `owner_tags`; expected `result` (`accept` or `refuse`) with refusal `reason`. R8a to R8e govern egress separately from region-set intersection. All normative vectors are in `residency/destination.json`.
