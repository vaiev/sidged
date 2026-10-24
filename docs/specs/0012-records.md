# 0012 – Records and deterministic CBOR (SDG-L0)

> **Status:** Draft v0.1 for roadmap phase 17. R1–R11 primitives and the offline audited Record store are implemented in `runtime/sidged-record`. Vectors in `spec/test-vectors/records/`.
> **Date:** 2026-10-15
> **Spec:** SDG-L0 Core Objects: Record, `dcbor` encoding
> **Basis:** [VISION.md](../vision/VISION.md) section 5 (invariants 2, 3, 5, 7, 9), [0000-architektur.md](0000-architektur.md) SDG-L0 and the Record primitive, [0002-grant.md](0002-grant.md), [0007-egress.md](0007-egress.md), [0011-agent-bundle.md](0011-agent-bundle.md).

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in BCP 14 (RFC 2119 and RFC 8174) when they appear in capitals.

A Record replaces the file as the unit of user data. It is a typed value with a data class, provenance, residency, and retention, signed by the Core that wrote it. This spec also fixes the deterministic CBOR (`dcbor`) profile that SDG-L0 names as mandatory to implement, because a Record is the first object that is stored and signed in it. Plans use the same profile ([0013](0013-cbor-plans-ifc.md)).

## 1. Scope

This spec defines the Record document, its canonical bytes, its digest, its signature, the store checks, and retention. It does not define a query language, sync, encryption at rest, or the legacy file view.

## 2. Deterministic CBOR profile (`dcbor` v0.1)

`dcbor` encodes the JSON data model (null, booleans, integers, text strings, arrays, maps with text keys) as CBOR (RFC 8949). The rules are the core deterministic encoding of RFC 8949 section 4.2.1, narrowed so JSON and CBOR describe the same tree.

**R1.** An encoder MUST use definite lengths and the shortest argument form for every integer and length. Map entries MUST be sorted by the bytewise lexicographic order of their encoded keys. Duplicate keys MUST NOT appear. *Rationale: one tree, one byte string. Signatures and digests compare bytes.*

**R2.** Map keys MUST be text strings. Text MUST be valid UTF-8 in Unicode Normalization Form C. Integers MUST be in the range −2^63 to 2^64−1 (encoder refuses with `malformed` outside it). Integers beyond ±2^53 are not portable through JSON inputs; test vectors stay inside that range except the out-of-range refusal. *Rationale: text keys keep the JSON mapping one-to-one. NFC removes the second spelling of the same text (`Zürich` with a combining diaeresis is refused, not normalised).*

**R3.** Floating-point values, byte strings, tags, `undefined`, and simple values other than `false`, `true`, and `null` MUST NOT appear in a v0.1 object. A decoder MUST refuse them with `malformed`. Money and other decimals stay decimal strings, as in SDG-L3 R14. *Rationale: floats have several encodings and lose exactness. v0.1 has no use for them.*

**R4.** A decoder MUST refuse with `malformed` input that is not exactly the `dcbor` encoding of the tree it decodes to (re-encode and compare): non-shortest arguments, indefinite lengths, unsorted or duplicate keys, non-text keys, floats (including half floats), tags, byte strings, and trailing bytes. Vectors `dcbor.decode.*`. *Rationale: a lenient decoder lets two byte strings carry one signature's meaning.*

The vectors `dcbor.encode.*` fix the bytes for the base cases (`null` = `f6`, `23` = `17`, `24` = `1818`, `-1` = `20`, `{"b":1,"a":2,"aa":3}` = `a361610261620162616103`).

## 3. The Record

| Member | Required | Meaning |
|---|---|---|
| `v` | yes | `"0.1"`. |
| `type` | yes | Media type of `content`, for example `application/vnd.sidged.note+json`. |
| `class` | yes | Exactly one class. Grammar: one or more segments `[a-z0-9][a-z0-9-]*` joined by `.`; no `/`, `%`, or empty segment. The root segment MUST be registered in `spec/registries/data-classes.md` or start with `x-` (owner-defined, as the registry allows). |
| `owner` | yes | The owner's `did:key`. |
| `provenance` | yes | `source` (capability id, `did:key`, or `urn:sidged:import:*`), `created` (RFC 3339 UTC, `Z`), `derived_from` (array of Record digests, MAY be empty), `plan` (digest of the stored plan whose step wrote it, or `null`). |
| `residency` | yes | `tags`: array of tags from `spec/registries/residency.md`. Missing or empty tags fail closed at egress (0001 R8a); "no limit" is the single tag `unrestricted` (0001 R8b). |
| `retention` | yes | `until` (RFC 3339 UTC, or `null` for owner-managed) and `on_expiry` (`delete` or `tombstone`). |
| `content` | yes | Any `dcbor` v0.1 value. |
| `sig` | yes | The existing signature object (`common.schema.json`): `alg` `EdDSA`, `kid`, `canon` `dcbor`, `value`, `signer`. |

**R5.** `sig` MUST be an Ed25519 signature over the `dcbor` bytes of the Record with the `sig` member removed. `canon` MUST be `dcbor`. `kid` MUST equal `signer`. `signer` MUST be a key in the store's configured set of trusted Core keys (the local Core key, plus owner-paired Cores); the trust anchor is that configuration, never a member of the Record. Because `kid` and `signer` sit outside the signed bytes, both checks are mandatory. A Record that fails any of them MUST be refused with `bad-signature`. Vectors: `record.check.002` (relabelled), `.013` (valid signature by `rfc8032-test-2`, not trusted), `.014` (`kid` ≠ `signer`). *Rationale: same signing-input rule as SDG-L2 tokens, with the other L0 encoding. A relabelled class (vector `record.check.002`) breaks the signature.*

**R6.** A Record missing a required member, with a class that breaks the grammar or has an unregistered non-`x-` root, an `on_expiry` other than `delete` or `tombstone`, or an unsupported `v`, MUST be refused (`malformed`, `unsupported-version`). A residency tag that is not registered MUST be refused with `residency-unknown-tag`. *Rationale: invariant 3. A Record without class, provenance, residency, and retention cannot be checked by the flow policy or the gateway.*

**R7.** The Record digest MUST be SHA-256, unpadded base64url, over the `dcbor` bytes of the Record without `sig`. It is the Record's identifier (`urn:sidged:record:<digest>`) and the value used in `derived_from` and in agent bundles (0011 R5). *Rationale: content addressing. Re-signing does not change the identity; changing any member does.*

## 4. Store rules

**R8.** A Record is `expired` when `retention.until` is not `null` and `now` is greater than or equal to `until`, compared as instants. In v0.1 timestamps are `YYYY-MM-DDTHH:MM:SSZ` without fractional seconds. `now` MUST be the Core's own clock; a caller-supplied time is for test harnesses only and MUST NOT be accepted in production. The store MUST NOT return the `content` of an expired Record. With `delete` it MUST remove the Record; with `tombstone` it MUST keep only `{digest, class, provenance, retention}` and the audit entry. *Rationale: retention is enforced by the Core, not by convention. The boundary instant counts as expired (vector `record.retention.002`).*

**R9.** The SDG-L2 resource of a class is `urn:sidged:record:` followed by the class with every `.` replaced by `/` (`health.records.notes` → `urn:sidged:record:health/records/notes`). Grants cover it under SDG-L2 R9 only: `urn:sidged:record:health/*` covers every `health` subclass and not `health` itself or `healthx`. Read, write, delete, retention change, and import of a Record are each an effect that MUST be covered by a grant on that resource with the matching action (`read`, `write`, `delete`, `retain`, `import`). A Record read by a plan step carries its `class` as that step's label (SDG-L3 R10). Vectors `record.resource.*` and `record.coverage.*`. *Rationale: invariant 2, with no second prefix-matching rule beside L2.*

**R10.** The inputs of a derived Record are what the Core recorded the writing step as reading (its SDG-L3 labels and the digests of the Records it read), never a list supplied by the writer. The store MUST set `provenance.derived_from` from that record and MUST resolve every digest in it. Class: if one input class covers all input classes (equal, or a `.`-boundary ancestor), the derived Record MUST carry it; otherwise the write MUST be refused with `data-class-forbidden` until multi-class Records exist, unless the step's capability declares a declassifying output that the flow policy allows ([0013](0013-cbor-plans-ifc.md) §4). Residency (0001 R8 v0.2): if any input has missing or empty tags, the derived `tags` MUST be empty, so the Record fails closed at egress. If every input is `unrestricted`, the derived tags are `["unrestricted"]`. Otherwise the derived `tags` MUST be the union of the inputs' restricting tags, with `unrestricted` dropped (0001 R8e), so the allowed regions are the intersection of the inputs' regions. An empty region set means nowhere, never "any" (`CH` + `EU` → nowhere). Vectors `record.derive.*`. *Rationale: labels and residency must not be laundered through storage.*

**R11.** Every write, read, delete, retention change, import, expiry, and refusal MUST append an entry to the audit log with the Record digest (invariant 9). The entry MUST be appended before content is returned and before a write, delete, or tombstone is committed. If the append fails, the operation MUST be refused and nothing committed (fail closed). A refusal of input that does not decode MUST be logged with the SHA-256 of the raw bytes, because it has no Record digest. The store MUST work with no network (invariant 7). Egress of `content` goes through the Privacy Gateway with a privacy report (invariant 5).

## 5. Conformance

`spec/test-vectors/records/records.json` (generated by `spec/test-vectors/tools/gen_dcbor_vectors.py`, `--check` verifies the files are current). Operations: `dcbor-encode`, `dcbor-decode`, `record-digest`, `record-check`, `record-retention`, `record-derive`, `record-resource`, and `resource-covers` (see the test-vector README). Signatures are real Ed25519 over `dcbor` with the RFC 8032 test keys (`rfc8032-test-1` is the only trusted Core key; `rfc8032-test-2` is an untrusted signer). The generator recomputes every expectation with its reference functions before it writes or checks a file. The structural validator runs the `resource-covers` vectors and skips the rest; `sidged-core` runs them in phase 17. The proposed 0013 depends on this spec and merges after it.

## 6. Out of scope

- Encryption at rest, sync between devices, and Records in L6 envelopes.
- Queries, indexes, and the legacy file-system view.
- Multiple classes per Record and declassification capabilities (named in 0013, specified later).
- Floats and byte strings in `dcbor` (a later minor version MAY add them).
