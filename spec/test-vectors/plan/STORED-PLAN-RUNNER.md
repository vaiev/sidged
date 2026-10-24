The Rust runner is `stored_plan_runner.rs`, included by `sidged-verify` so its
injected vector clock stays private. Run from the repository root:

```sh
cd runtime && cargo test -p sidged-verify stored::vectors
```

It executes all 13 vectors for `plan-digest`, `stored-plan-signing-input`, and
`stored-plan-check` in `dcbor-signed.json`, comparing exact bytes, digests,
decisions, and refusal codes. The dCBOR implementation is `sidged-record`'s
codec. Unknown operations or changes to the executed/skipped counts fail.

Exactly these vectors are skipped by this runner:

| Vector | Reason |
| --- | --- |
| `plan.flow.001` | `flow-check`, requires Cedar flow evaluation (0013 R8-R11), outside this R3-R7 implementation. |
| `plan.flow.002` | Same: default sensitive-flow denial. |
| `plan.flow.003` | Same: owner permit and destination. |
| `plan.flow.004` | Same: destination mismatch. |
| `plan.flow.005` | Same: secrets cannot be released. |
| `plan.flow.006` | Same: forbid overrides permit. |
| `plan.flow.007` | Same: empty policy set, secrets. |
| `plan.flow.008` | Same: empty policy set, non-sensitive class. |
| `plan.flow.009` | Same: separate request per egress step. |
| `plan.flow.010` | Same: sensitive-class dot boundary. |

The spec labels these flow vectors v0.1; they are not reclassified as v1.1.
This library retains the existing `FlowPolicy` hook. A Core supplying an owner
policy must supply its current digest and matching evaluator together; a digest
alone does not implement Cedar semantics.

Additional implementation tests cover missing fields, signature metadata,
re-signed owner mismatches, nonzero UTC offsets, fractional UTC instants,
the exact 365-day lifetime boundary, invalid dates,
catalog ordering/unrelated entries, policy drift, static re-verification, and R7:
approval remains in the verification summary, stored authority is rejected as a
grant, and `check_for_run` sends exactly one structured `AuditEvent` to the sink
on every call, including refusals. Events contain the accept/refuse decision,
refusal code, computed plan digest when encodable, provisioned owner, and
presented kid, catalog digest and flow policy (untrusted on refusal). Sink failure
prevents acceptance; a refused plan retains its original refusal code even if
logging fails. Tests cover bad signatures, expired and future plans, catalog and
policy drift, static-verifier refusal, malformed input, and sink failure on both
acceptance and refusal paths. The executor must still enforce grants and
Trusted UI per instance. `CheckedPlan` conveys neither permission.

There is no stored-plan execution path added to `sidged run`: 0003 §7 leaves
stored-plan signature verification outside the v0.1 CLI contract. Consumers of
the new library must use `check_for_run` before each stored-plan execution;
`check` is authentication/verification only and does not execute anything.
