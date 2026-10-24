# 0011 – Agent bundle

> **Status:** Stub. Direction from vision section 7 (2026-10-15). Not a layer, and not a conformance target until the roadmap phase that implements it says so.
> **Date:** 2026-10-15
> **Spec:** Agent bundle (cross-cutting; not SDG-L0–L8)
> **Basis:** [VISION.md](../vision/VISION.md) section 7, the seven primitives in [0000-architektur.md](0000-architektur.md), and [0009-models.md](0009-models.md).

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in BCP 14 (RFC 2119 and RFC 8174) when they appear in capitals.

Today's agent is a text prompt, a harness, and guidelines. A Sidged agent is a bundle of objects the Core already knows, and the Core verifies it before anything in it runs. Sidged, as the user's personal AI, learns and understands the user. That learning stays outside the security boundary. The nine invariants stay as they are in the vision. This stub names the manifest and the checks. It does not add a schema, a crate, or a second agent protocol.

## 1. The bundle

**R1.** An agent that runs inside Sidged MUST be a bundle of five members: an Identity, one or more Grants, one or more Plans, zero or more Modules, and zero or more Records. *Rationale: vision section 7. Those are L0 primitives. The bundle is how they travel as one agent. Views stay generated per task (SDG-L4). They are not a sixth member.*

**R2.** A text prompt, a harness configuration, or a guideline document MUST NOT be an agent and MUST NOT authorize an effect. The Core MAY store such text as a Record. It remains data. *Rationale: invariant 3. The wrapper bubble is the habit of treating those files as the product. Authority is the verified bundle.*

## 2. Manifest

The manifest is one document. v0.1 is canonical JSON (JCS, RFC 8785) when signed. Deterministic CBOR (`dcbor`) is the other L0 encoding of the same tree. A v0.1 checker MAY reject a CBOR manifest it does not implement.

| Member | Required | Meaning |
|---|---|---|
| `v` | yes | Schema version. v0.1 is `"0.1"`. |
| `id` | yes | Agent identifier, `urn:sidged:agent:` plus the same character set as a capability id. |
| `identity` | yes | The agent Identity. On the owner's devices this is `did:key`. At an enterprise boundary it MAY be OAuth/WIMSE. The role is Agent. |
| `grants` | yes | One or more capability tokens (SDG-L2). Each entry is the token's digest. |
| `plans` | yes | One or more plans (SDG-L3). Each entry is the plan's digest. |
| `modules` | yes | Module manifests already defined by `spec/schemas/module-manifest.schema.json`. The array MAY be empty. Each entry is that manifest's digest. WASM bytes stay with the module. |
| `records` | yes | Records with data class, provenance, residency, and retention. The array MAY be empty. Each entry is the record's digest. |
| `personal_model` | no | A proposer only. See section 4. |
| `sig` | yes | Signature object already used on tokens and module manifests: `alg`, `kid`, `canon`, `value`, `signer`. |

**R3.** A consumer MUST reject a manifest whose `v` it does not implement. *Rationale: an unknown bundle is not verified.*

**R4.** `sig` MUST be an Ed25519 signature over the JCS bytes of this manifest. `canon` for v0.1 MUST be `jcs`. `signer` MUST be present. The signature object is the one module manifests already carry (`alg`, `kid`, `canon`, `value`, `signer`). The implementing phase copies the signing-input rule from SDG-L2 rather than inventing a second layout. *Rationale: L0 owns canonical bytes and signatures. A bundle that invents an encoding would split the trust boundary.*

**R5.** Every digest MUST be SHA-256, unpadded base64url, over the canonical bytes of that member. *Rationale: the same digest shape the privacy report already uses. The Core compares bytes, not names.*

## 3. How the Core verifies

**R6.** The Core MUST verify the bundle before it runs a plan step, calls a module, or treats a record in the bundle as the agent's data. Failure at any step MUST refuse the bundle. *Rationale: invariant 3. A bundle from a model, a tool, the web, or a peer is data until these checks pass.*

The order is:

1. Signature and signer. The Core resolves `signer` to a key the owner trusts, or to the owner's own `did:key`. A bad signature or an unknown signer refuses the bundle.
2. Each digest matches the bytes of that member. A missing member or a mismatch refuses the bundle.
3. `identity` is an Agent identity as in the manifest table. It is not ambient root and it is not the owner.
4. Each grant is checked under SDG-L2: holder binding, expiry, attenuation, and the owner's Cedar policy. The bundle signature does not replace that check. A token MUST NOT override a Cedar denial.
5. Each plan passes the SDG-L3 verifier before any step runs. The bundle does not skip effect, label, cost, or approval-flag checks.
6. Each module carries its own signed module manifest. The grants it requires are covered by the bundle's grants and are not wider. Its code runs only as a WASM component, with at most the rights of the task (invariant 6).
7. Each record carries class, provenance, residency, and retention. A read still needs a grant. Egress still goes through the Privacy Gateway with a privacy report (invariant 5).
8. A consequential step still waits for human approval on the Trusted UI channel (invariant 4). A bundle MUST NOT contain a pre-granted approval.
9. The Core appends an audit record for the verification and for every later effect and denial, with a cryptographic provenance chain (invariant 9).

**R7.** A bundle MUST NOT weaken invariants 1–9. A member that asks for ambient authority, for code outside the WASM sandbox, for egress around the gateway, or for the model to decide, MUST make the Core refuse the bundle. *Rationale: vision section 7. The ambition is large. The invariants are the limit.*

## 4. The learned personal model

**R8.** The model that learns the user and proposes on their behalf MUST stay outside the security boundary. The bundle MAY name it with `personal_model`: a module of kind `model` (weights identified by hash, as the module manifest already requires) and the adaptation Records that hold what it has learned. Those members propose plans and preferences. They MUST NOT sign the bundle's grants, MUST NOT satisfy a Trusted UI approval, and MUST NOT widen a grant when a learning update writes a Record. *Rationale: invariant 1, and vision section 6. Understanding the user is the product. It is not the decision. The router/personal role in `0009-models.md` is this proposer. An agent bundle points at it. It does not become a second Core.*

**R9.** Learning MUST work in local mode, with no network. A learning update that leaves the device MUST go through the Privacy Gateway. *Rationale: invariants 7 and 5. A personal model that only exists as a remote API is egress, not the on-device role.*

**R10.** Sidged as the user's personal AI is the runtime that holds these bundles and this model. It is not a harness around one prompt. *Rationale: section 7. The wrapper dissolves because authority is the verified bundle and understanding is the proposer.*

## 5. Out of scope

- A JSON Schema and test vectors. They arrive with the phase that implements the check. Until then this table is the direction.
- Runtime code. Phase 11 adds none. A full check waits on grant-gated execution, the module host, records, and signed stored plans.
- A new agent protocol. Foreign agents that are not this bundle attach through A2A (SDG-L6).
- Views, the Trusted UI channel, and the plan grammar. Those stay in SDG-L4, SDG-L5, and SDG-L3.
- Choosing model weights. `0009-models.md` leaves that open.
