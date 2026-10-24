# 0013 – Stored plans in dcbor, owner signatures, and the Cedar flow policy (SDG-L3)

> **Status:** Draft v0.1. Implemented in `runtime/sidged-verify` (`dcbor.rs`, `stored.rs`, `flow.rs`). Vectors in `spec/test-vectors/plan/dcbor-signed.json` and `spec/test-vectors/plan-check/plan.flow.json`.
> **Date:** 2026-10-15
> **Spec:** SDG-L3 Plan (extension of [0003-plan.md](0003-plan.md))
> **Basis:** [VISION.md](../vision/VISION.md) section 5 (invariants 1–5, 9), [0000-architektur.md](0000-architektur.md) plan language and SDG-L0, [0003-plan.md](0003-plan.md) R10–R11 and §7, [0002-grant.md](0002-grant.md), [0007-egress.md](0007-egress.md), [0011-agent-bundle.md](0011-agent-bundle.md), [0012-records.md](0012-records.md).

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in BCP 14 (RFC 2119 and RFC 8174) when they appear in capitals.

0003 left three things to phase 18: the `dcbor` form of a plan, signature verification of a stored plan, and a Cedar flow policy that replaces `DenySensitive`. This spec defines all three. The plan tree, the verifier rules R1–R14 of 0003, and the JSON interchange form are unchanged.

## 1. Scope

A stored plan is a verified plan that the owner signed so it can run again later, as a tool or inside an agent bundle (0011 R1), without the model proposing it again. Signing does not replace verification, grants, or approval.

## 2. Plan digest

**R1.** The `dcbor` form of a plan MUST be the `dcbor` v0.1 encoding ([0012](0012-records.md) §2) of the same tree as the JSON form. A plan containing a float MUST be refused with `malformed`. *Rationale: one tree, two L0 encodings. Budgets are decimal strings already.*

**R2.** The plan digest MUST be SHA-256, unpadded base64url, over the `dcbor` bytes of the plan. *Rationale: the digest shape of 0011 R5 and 0012 R7. A bundle's `plans` entry is this digest.*

## 3. Stored plan

| Member | Required | Meaning |
|---|---|---|
| `v` | yes | `"0.1"`. |
| `kind` | yes | `"sdg.plan.stored"`. |
| `plan` | yes | The plan tree (0003 §1). |
| `plan_digest` | yes | R2 digest of `plan`. |
| `catalog_digest` | yes | SHA-256, unpadded base64url, over the `dcbor` bytes of the array of catalog descriptors the plan references, sorted by `id`. Unrelated catalog entries and catalog order do not change it. |
| `owner` | yes | The owner's `did:key`. |
| `issued`, `expires` | yes | RFC 3339 UTC. |
| `flow_policy` | yes | `"default"`, or the policy-set digest: SHA-256, unpadded base64url, over the `dcbor` bytes of the array `[{id, source}]` of the owner's policies (§4), sorted by `@id`, `source` as the exact Cedar text. |
| `sig` | yes | Existing signature object: `alg` `EdDSA`, `kid`, `canon` `dcbor`, `value`, `signer`. |

**R3.** A Core MUST refuse a stored plan with an unsupported `v` or `kind` (`unsupported-version`), a missing member, or `plan_digest` that does not match `plan` (`malformed`). *Rationale: the digest is what the bundle and the audit log name.*

**R4.** The Core's trust anchor is its provisioned owner key (set when the device or bundle is paired with the owner), never a member of the object. `owner`, `sig.kid`, and `sig.signer` MUST all equal the `did:key` of that provisioned key, and `sig` MUST be an Ed25519 signature by it over the `dcbor` bytes of the stored plan without `sig`. Anything else, including a self-consistent plan whose `owner`, `kid`, and `signer` name another key (the Core's own, a model's, an attacker's), MUST be refused with `bad-signature`. *Rationale: invariant 1 and 3. Only the owner turns a proposal into a reusable tool. Vectors `plan.signed.004` and `.009`.*

**R5.** `issued` MUST be before `expires`, and `expires − issued` MUST NOT exceed 365 days (`malformed`). At `now < issued` the plan MUST be refused (`malformed`, not yet valid). At `now ≥ expires` it MUST be refused with `expired`. Instants are compared, and `now` is the Core's own clock. *Rationale: stored authority ages out. The boundary counts as expired.*

**R6.** Before each run the Core MUST re-run the full 0003 verifier on `plan` against the current catalog and the current flow policy. If the digest of the current referenced descriptors differs from `catalog_digest`, or the digest of the current policy set differs from `flow_policy`, the Core MUST refuse (`malformed`) until the owner re-signs. *Rationale: a capability that gained an effect or lost `consequential` after signing must not inherit the owner's earlier consent.*

**R7.** A valid stored plan MUST NOT satisfy approval (invariant 4), MUST NOT stand in for a grant (invariant 2), and MUST be logged with its digest at every run (invariant 9). Steps with `approval: true` still wait on Trusted UI. *Rationale: the signature proves the owner chose this plan. It does not prove the owner approves this instance.*

## 4. Flow policy in Cedar (replaces `DenySensitive`)

The 0003 hook `FlowPolicy::allow_egress(class, capability)` becomes a Cedar authorization request evaluated by the same Cedar engine `sidged-grant` uses.

| Request part | Value |
|---|---|
| principal | `Sidged::Owner::"<owner did>"` |
| action | `Sidged::Action::"flow"` |
| resource | `Sidged::Capability::"<egress capability id>"` |
| context | `class` (string, the label), `sensitive` (bool), `destination` (string), `step` (step id), `plan` (plan digest) |

**R8.** For every egress step and every label that reaches it (0003 R10–R11), the verifier MUST evaluate one request with that step's destination. Two `message.send` steps are two requests (vector `plan.flow.009`). The Core MUST derive every context value itself, never take it from a caller, a model, or the plan's prose: `class` from the 0003 label computation; `sensitive` as `true` exactly when the class equals `health.records` or `secrets` or starts with one of them followed by `.` (the rule in `sidged-verify`, so `health.recordsx` is not sensitive, vector `plan.flow.010`); `destination` from the step's literal `to` argument, or `""` when `to` is not a literal. The flow is allowed only when Cedar returns Allow for every request. *Rationale: Cedar is default-deny and forbid-overrides-permit. Both are the properties `DenySensitive` had.*

**R9.** The built-in default policy set MUST be exactly:

```cedar
@id("default-flow")
permit (principal, action == Sidged::Action::"flow", resource)
unless { context.sensitive };
```

With the default set, the verifier's decisions MUST equal those of `DenySensitive` on the existing 0003 vectors. *Rationale: phase 18 changes the mechanism, not the outcome. `plan/verify.json` stays green.*

**R10.** The owner MAY add `permit` and `forbid` policies, signed through Trusted UI, never by a model or a bundle. A `forbid` MUST win over any `permit`. A `secrets` class MUST NOT be allowed to reach egress even by a matching owner `permit` and no `forbid` (vector `plan.flow.005`); a later spec MAY add a secret-release list, and v0.1 has none. A `forbid` beats a matching `permit` on any class (vector `plan.flow.006`). An empty policy set MUST deny every flow. *Rationale: invariant 1 and the registry rule that `secrets` never leaves the device.*

**R11.** A refusal MUST use `data-class-forbidden` and MUST name the class, capability, and the Cedar policy ids that decided (`default-flow` or the owner's ids) in the audit entry. *Rationale: invariant 9. The owner can see why a flow was blocked.*

## 5. Conformance

`spec/test-vectors/plan/dcbor-signed.json`, generated by `spec/test-vectors/tools/gen_dcbor_vectors.py` (`--check`). Operations: `plan-digest`, `stored-plan-signing-input`, `stored-plan-check` (`stored`, `catalog`, `owner_key`, `now`), and `flow-check` (`plan`, `catalog`, `policies` as Cedar sources; the runner derives labels, `sensitive`, and destinations; `requires: ["cedar"]`). Signatures are real Ed25519 over `dcbor`. In the vectors the provisioned owner key is `rfc8032-test-3` and the Core key is `rfc8032-test-1`. The generator evaluates every R3–R6 check for each `stored-plan-check` vector and asserts that exactly one fails (one fault per vector). R7 and R11 have no vectors; phase 18 MUST cover them with implementation tests (approval still required, no grant substitution, digest logged per run, deciding policy ids in the audit entry).

## 6. Out of scope

- Declassifying capabilities and multi-class labels.
- Delegating stored plans to peers (SDG-L6) and plan revocation lists.
- The Trusted UI format for signing owner policies (v0.1 says only that it goes through Trusted UI).
- A Cedar schema file for `Sidged::*` entities (phase 18 implementation ships it next to the grant schema).
