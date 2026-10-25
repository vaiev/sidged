# 0002 – Grant (VKR-L2)

> **Status:** Draft v0.1. The structural rules below are implemented in `spec/validate` and in `runtime/vaikor-grant`.
> **Date:** 2026-10-14
> **Spec:** VKR-L2 Grant
> **Basis:** [0000-architektur.md](0000-architektur.md) (Grant row, E6, E7) and [0001-capability.md](0001-capability.md). A capability describes an action. A grant is what allows one holder to perform it.

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in BCP 14 (RFC 2119 and RFC 8174) when they appear in capitals.

There is no effect without a grant. A grant is a capability token: a short-lived, holder-bound list of rights and a budget, which delegation can only narrow.

## 1. Token

The JSON shape is [capability-token.schema.json](../../spec/schemas/capability-token.schema.json). Version `v` is `"0.1"`.

| Member | Role |
|---|---|
| `iss` | Who minted this link. On a delegated token, the parent holder. |
| `sub` | Holder. Only this party may present the token. |
| `aud` | The single audience that may accept it. |
| `iat`, `exp` | Lifetime. Optional `nbf`. |
| `cnf` | Proof-of-possession confirmation (`jkt` and/or `kid`). |
| `rights` | Actions on resources, with optional constraints. |
| `budget` | Optional caps on messages, compute units, and money. |
| `chain` | Parent links, root first, each link without its own nested `chain`. Empty on a root token. At most 16 links. |

**R1.** A consumer MUST reject a token whose `v` it does not implement. *Rationale: an unknown token shape is not a grant.*

**R2.** `chain` MUST list parents from the root to the immediate parent, and MUST contain at most 16 links. *Rationale: the receiver checks every hop. An unbounded chain is an attack.*

## 2. Expiry

**R3.** For every link, including the token itself, `exp` MUST be later than `iat`, and `exp - iat` MUST be at most one hour. *Rationale: a stolen token dies quickly. Owner policy MAY set a shorter maximum.*

**R4.** When `nbf` is present it MUST be earlier than `exp`. *Rationale: a token that is never valid is not a grant.*

**R5.** A receiver that has a clock MUST refuse a link whose `exp` is not after that clock, whose `nbf` is after that clock, or whose `iat` is more than 30 seconds after that clock. *Rationale: a future `iat` would stretch the one-hour bound. The shared test vectors do not carry a clock, so `capability-check` in the suite does not apply R5. `vaikor-grant` applies R5 when the caller passes `now`.*

## 3. Holder binding

**R6.** Every link MUST include `cnf` with at least one of `jkt` or `kid`. *Rationale: a token without confirmation is a bearer token.*

**R7.** A presentation MUST name the holder, and that holder MUST equal `sub`. *Rationale: the token is for one party.*

**R8.** Before accepting a token at a trust boundary, the receiver MUST verify each link's signature and MUST verify that `cnf.jkt`, when present, is the RFC 7638 thumbprint of the holder key, and that `cnf.kid`, when present, names that holder. *Rationale: E7. Possession is cryptographic. The hosted runtime resolves an Ed25519 `did:key` (`cnf.kid` must equal `sub`) and checks `cnf.jkt` as the SHA-256 thumbprint of that key's OKP JWK. Each link's `sig.kid` must equal `iss` and the Ed25519 signature must cover the JCS signing input.*

## 4. Resource matching

A right resource covers a requested resource by the following rule. This is the normative reading of the vectors in `spec/test-vectors/resource-matching/coverage.json` and `spec/test-vectors/envelope-binding/`.

**R9.** Coverage:

1. Equal strings cover each other, including a resource that itself ends in `/*`.
2. Otherwise the right covers the resource only when the right ends in `/*` and the resource begins with that right without the final `*`.
3. The remainder after that prefix MUST be non-empty.
4. The remainder MUST NOT contain `%`.
5. Splitting the remainder on `/` MUST NOT produce an empty segment, `.`, or `..`.
6. A right that does not end in `/*` covers only itself. A `*` that is not the two-character suffix `/*` is literal.

*Rationale: `/*` is one prefix wildcard, not a glob and not a path normaliser. `urn:x:a/*` covers `urn:x:a/b` and `urn:x:a/b/c`. It does not cover `urn:x:a`, `urn:x:ab`, `urn:x:a/`, `urn:x:a//b`, `urn:x:a/./b`, or `urn:x:a/../b`. Percent-encoding is rejected rather than decoded, so `%2e%2e` and `%2F` cannot escape the prefix after a later decode. Case is not folded.*

## 5. Attenuation

Let the sequence be the `chain` links followed by the token. For each link after the first, the previous link is the parent.

**R10.** The child's `iss` MUST equal the parent's `sub`. *Rationale: only the holder can delegate. This is rule (a).*

**R11.** The child's `aud` MUST equal the parent's `aud`. *Rationale: delegation cannot retarget the audience. Rule (b).*

**R12.** The child's `exp` MUST NOT be later than the parent's `exp`. *Rationale: delegation cannot extend lifetime. Rule (c).*

**R13.** Every child right MUST be covered by at least one parent right. Coverage means the same `action`, the parent resource covers the child resource under R9, and the child constraints narrow the parent constraints. *Rationale: rights only shrink. Rule (d).*

**R14.** Constraint narrowing: if the parent sets `max_uses`, the child MUST set `max_uses` no higher. If the parent sets `max_amount`, the child MUST set the same currency and an amount no higher, compared as exact decimals. If the parent sets `data_classes`, the child's set MUST be a subset. Dropping a parent constraint is widening. *Rationale: a missing cap is unlimited.*

**R15.** If the parent sets `budget.messages`, `budget.compute_units`, or `budget.money`, the child MUST set that same field no higher. Money uses the same exact decimal comparison. Dropping a parent budget field is widening. *Rationale: rule (e). A delegated token cannot spend more than it was given.*

**R16.** Rule (f) is R2: the chain has at most 16 links. *Rationale: the bound is part of attenuation, not only a schema limit.*

## 6. Using a token

**R17.** An instruction is covered only when some right on the token itself (not only on an ancestor) has the same `action` and a resource that covers `instructions.resource` under R9. An instruction with no `resource` is not covered. *Rationale: the leaf grant is what the holder actually has. `envelope.binding.009` asks for `.../private` under a right for `.../work`. `envelope.binding.010` omits `resource`. Both are refused.*

**R18.** A covered instruction is still refused when the owner's policy does not permit it. The policy language is Cedar (E6). The authorisation request has principal equal to `sub`, action equal to the instruction action, resource equal to the instruction resource, and context that includes `aud` and the data classes. A token MUST NOT override a policy denial. *Rationale: the owner can be stricter than any token. The token cannot be looser.*

**R19.** A receiver that is configured with trusted root issuers MUST refuse a token whose root `iss` is not in that set. The root `iss` is the token's `iss` when `chain` is empty, and the first chain link's `iss` otherwise. An empty set MUST refuse every token. *Rationale: signature checks prove the issuer named in the token signed it. They do not prove the receiver trusts that issuer. Without this list any Ed25519 `did:key` is ambient authority.*

**R20.** When the leaf token sets `budget.messages` or `budget.compute_units`, each step that is about to run MUST decrement that field by one before the effect. When it sets `budget.money`, a metered step MUST decrement that amount by the capability cost times the step's `bound` (1 for a call). A step that does not fit MUST be refused, and the remaining budget MUST stay unchanged. A budget field the token omitted is not a cap. *Rationale: attenuation only compares parent and child. Without a decrement the leaf budget is a label, and a one-message grant can still send twice.*

**R21.** A leaf right's `constraints.max_uses` caps uses across executions, not just within one run. Before each effect and before requesting human approval, the Core MUST check that a covering leaf right has at least the step's `bound` uses remaining (1 for a call, 0 for a map with bound 0). If several rights cover the action and resource, the Core MUST select the first covering right in leaf order that fits; a right without `max_uses` is uncapped. If none fits, the step MUST be refused with a logged `grant denied` decision, without spending any uses. The Core MUST derive prior spends from the verified, signed hash-chained audit log keyed by issuer and token id plus leaf right index, and durably append a spend reservation before the effect. A reservation remains spent if execution crashes after it is written; refusing approval MUST NOT spend uses. Concurrent writers MUST be serialized or refused. An effectful execution without a writable log target and signing key MUST fail closed; only verification and explicit dry runs may omit the log. The default chain is `$XDG_STATE_HOME/vaikor/audit.log`, falling back to `~/.local/state/vaikor/audit.log`, independent of the working directory, and the Core reports the resolved path on stderr. Operators MUST retain the same chain across runs; choosing a new log, deleting it, or restoring an older valid prefix is outside the protection of a local hash chain without an external checkpoint. *Rationale: a use cap checked only at delegation or reset per run still allows unlimited calls. Durable reservations conservatively preserve the cap across crashes.*

A zero bound costs zero uses in the grant accounting API; the current plan verifier separately requires map bounds from 1 to 32. Per-step uses and R20 budget fit checks precede approval. This hosted runtime retains sequential execution: a later refusal can follow earlier effects; whole-plan preflight is not a guarantee of this rule.

`vaikor-grant` exposes this as a `PolicyHook`. `PermitAll` is the test double. `CedarEvaluator` parses Cedar with `cedar-policy` and implements `PolicyHook`. The request context is `audience` (the token `aud`), `data_classes`, and `residency`. A parse or evaluation error is a denial.

Non-normative sketch, not a grammar:

```
permit(principal, action, resource)
when { context.audience == "did:example:calendar" };
```

## 6a. Grants on a single node (draft, lead decision 2026-10-23, ROADMAP 11f)

**R22.** *Caveats are enforced at use.* A right covers a step only when, besides R17, every constraint it carries holds for that step: the step's capability data classes are a subset of `constraints.data_classes` when set, the step's cost times its `bound` is at most `constraints.max_amount` when set (same currency, else refused), and R21 uses remain. The right that covers the step is the one whose uses and budget are reserved. *Rationale: a constraint that only narrows delegation is a label; the leaf holder could still use the right for any data class or amount.*

**R23.** *Owner mandate.* At node initialisation the owner key signs a **mandate** (`vkr.mandate/v0`): the owner `did:key`, the node's executor `did:key`, the node audience, the rights the owner allows (action, resource, constraints as in §1), a budget per period, and `exp` at most 30 days after `iat`. A mandate is not a token and confers nothing by itself; it bounds what the executor may issue. Renewing or widening a mandate is an owner action through Trusted UI with user verification; a model, a bundle or a generated view MUST NOT issue, renew or widen one. *Rationale: R3 keeps every token at one hour, and from v0.4 the owner key sits in hardware behind a user-presence prompt (WP 15); signing a mandate once per period keeps that prompt rare without stretching any token's lifetime.*

**R24.** *Per-task token under the mandate.* For each verified plan the executor key issues a root token (R3: at most one hour, `sub` and `cnf` naming the executor key) whose rights are narrowed to the plan's capabilities. On a node, the executor `did:key` is a trusted root issuer (R19) only for tokens that a valid, unexpired owner mandate covers: every right is covered by a mandate right under R9 with constraints at least as narrow (§5), and the token's budget fits what the mandate's period has left, counted by the Core's ledger. A token outside its mandate MUST be refused. *Rationale: a compromised task holds at most its own plan's rights for one hour, and a compromised executor key is still capped by what the owner signed.*

**R25.** *Authenticated presenter.* The engine accepts a token only from a presenter that proves possession of the holder key: a signature by the key `cnf` names over the plan digest and a fresh nonce from the Core. On the node the executor key signs; a CLI caller supplies the holder key. A token presented without proof MUST be refused. *Rationale: R8 binds a token to a key, but only proof of possession binds it to the presenter; without it a token file is a bearer token.*

**R26.** *One engine.* Every entry point that can cause an effect (`vaikor run`, `vaikor task`, the companion, swarm workers) MUST execute through the same engine, which runs the verifier on the representation it executes and applies R17-R25, 0004 R9 and 0005 R5a (audit before effect) to every step. *Rationale: a rule enforced on one entry point and skipped on another is not enforced.*

## 7. Conformance

- Resource and envelope vectors in `spec/test-vectors` are normative for R9 and R17, including the nine that were provisional.
- `runtime/vaikor-grant` implements R3, R4, R6, R7, R9, R10 through R20, with R5 when `now` is supplied. Ed25519 and JCS cover the signature vectors. `cedar-policy` evaluates R18. R19 applies when the caller passes the trusted root set. An empty set refuses every token. R20 is `spend_step`.
- R8 holder binding (`did:key` and `cnf.jkt`) and capability-token chain signatures are implemented for Ed25519 `did:key` issuers. Envelope JCS signatures are what the `sign` and `verify` vectors check.

## 8. Out of scope

- The capability descriptor (VKR-L1) and the MCP binding.
- The plan verifier and data-flow labels (VKR-L3).
- Trusted UI copy and the VAIEV design tokens (VKR-L4).
- Envelope transport, replay, and bindings (VKR-L6), except the instruction check in R17. `dcbor` is an L0 canonical encoding. This layer does not define it, and L6 does not define it either. Token signatures in this layer are JCS and Ed25519.
- Issuer keys that are not Ed25519 `did:key` values. `did:example` placeholders in the examples are not resolvable.


### Runtime ledger follow-ups

Every live execution, including a capability with no effects, requires the signed ledger; dry runs remain non-persistent. Guard startup MUST follow this order: resolve local mode, open and exclusively lock the signed ledger, validate the real planner destination URL/host against its provider and region using gateway checks, verify the grant and durably reserve use and budget under R20–R21 (decision `reserve`), persist planner intent (`attempt`), then invoke the planner. The same lock remains held through execution. Missing keys and open, lock, or append failures refuse planning. Destination denials leave usage and budget unchanged. A started planner attempt consumes one use even if it fails, and a durable reservation remains spent after a crash. Budgets are enforced on every guard step, including steps without effects. `reserve` is not human approval and does not prompt for it; whether planner egress without human approval is acceptable remains an open owner decision.

R21 accounting also charges each ancestor's covering right, keyed by that link's issuer, signed token id, and right index. Fresh children therefore share ancestor caps. R20 budgets are replayed across executions for every link, with the original monetary unit price recorded in each signed reservation. Old reservations without a price refuse replay for money-limited grants rather than assume zero cost. Partial reservation writes conservatively consume the accounts already written, without permitting an effect.

Replay and verification use the locked file handle, so a path swap cannot substitute another file during replay. This does not detect truncation, rollback to a valid prefix, or selecting a fresh ledger. Those require an external anchored head/checkpoint. A future Core-owned ledger configuration must remove per-invocation path selection from agent-controlled inputs; until then operators must protect ledger paths and CLI configuration. This local prototype does not claim protection against an actor able to replace its state.

Execution remains sequential, with no whole-plan preflight. A later denial may follow earlier allowed effects; callers must not treat a plan as an atomic transaction.
