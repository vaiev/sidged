# 0017 – Intent Catalog, Companion Linguist, Morphing Canvas and Browser Verifier

> **Status:** Draft v0.1. Implemented in `v0.2.0`: `runtime/sidged-cli/src/linguist.rs`, `local-training/` (Model -1), `companion/sidged-companion-core`, `companion/sidged-companion-app`, `site/sidged-wasm`.
> **Date:** 2026-10-20
> **Basis:** [VISION.md](../vision/VISION.md) section 5 (invariants 1–9), [0001-capability.md](0001-capability.md), [0003-plan.md](0003-plan.md), [0004-view.md](0004-view.md), [0009-models.md](0009-models.md), [0013-cbor-plans-ifc.md](0013-cbor-plans-ifc.md), [0016-companion-swiyu-iso27090.md](0016-companion-swiyu-iso27090.md).
> **Schemas:** [`intent-catalog.schema.json`](../../spec/schemas/intent-catalog.schema.json), [`linguist-envelope.schema.json`](../../spec/schemas/linguist-envelope.schema.json); UI catalog [`ui/a2ui-catalog.v4.json`](../../ui/a2ui-catalog.v4.json).

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in BCP 14 (RFC 2119 and RFC 8174) when they appear in capitals.

This draft fixes the path from an utterance to a checked intent and from a checked intent or capability to a rendered surface. Models propose; every step that decides is deterministic Core code driven by schemas. There is no fixed app view, no per-intent code path and no per-product widget.

---

## 1. Intent catalog

An intent catalog lists generic user intents. Each intent declares its slots as a closed JSON Schema object, a canonical English template, the capabilities it needs, its data classes, its route and one clarification question per slot and locale.

- **I1.** A catalog MUST validate against `intent-catalog.schema.json` and the cross-member rules of `spec/validate` (unique intents, every required slot declared, every template placeholder declared, every localized text present for every declared locale).
- **I2.** Slot order is the order of `slots_schema.properties`; the Core asks for missing required slots in the order of `slots_schema.required`.
- **I3.** `route` is `edge-local` (Edge 1 plans and runs) or `swarm-worker` (Edge 1 plans, swarm workers run steps). A catalog grants nothing: capabilities still need grants (0002) and plans still need the verifier (0003, 0013).
- **I4.** Locales are BCP 47 tags without script. `gsw` is Swiss German; `de` is Standard German, including Swiss Standard German.
- **I5.** The catalog a Core uses is part of its build (`runtime/sidged-cli/assets/intent-catalog.json`) and of the model's training data. A catalog change MUST be followed by retraining or by re-evaluation of the deployed linguist on the held-out split.

## 2. Linguist envelope (Model -1)

The companion linguist reads one utterance plus the rendered catalog and proposes one envelope (`linguist-envelope.schema.json`).

- **L1.** The prompt is `SYSTEM_PROMPT` plus `Catalog:\n<one line per intent>\nUtterance: <text>`, byte-identical in every implementation (pinned by `runtime/sidged-cli/tests/fixtures/linguist-prompt.json`). A catalog line names the intent, title, route, data classes, template, and each slot with `*` for required and its description.
- **L2.** The Core MUST keep only `lang`, `intent` and `slots` from a proposal and MUST derive every other member from the catalog:
  - `missing_slots` = required slots not in `slots`, in catalog order;
  - `clarification_needed` = `intent` is null or `missing_slots` is not empty;
  - `clarification_question_local` = the catalog `x-ask` of the first missing slot in `lang`, or `unknown_intent_ask` when `intent` is null;
  - `canonical_intent_en` = the template with given slots filled, missing slots as `<slot>`, and given optional slots not in the template appended as `(slot: value; ...)`;
  - `suggested_route` = `clarify` when clarification is needed, else the intent's route;
  - `required_data_classes` = the intent's data classes.
- **L3.** A proposal with any member outside the envelope (for example `residency`, `approval`, `grant`), a missing member, a non-object `slots`, or a `lang` outside the catalog locales MUST be refused. The one optional member is `then` (§2c); a `then` that is not an array of at most two `{intent, slots}` objects MUST be refused.
- **L3a.** *Compact proposal (lead decision 2026-10-23, ROADMAP 13e B).* A proposal with `v` `"0.2"` carries only `v`, `lang`, `intent`, `missing`, `slots` and the optional `then`, in this order; the Core derives the full envelope (L2) from it. `missing` lists the intent's required slots the utterance does not give, in catalog order (empty for intent null); it is the model's commitment before it writes slots, not a derived member: the Core still derives `missing_slots` itself, drops a slot the proposal lists in `missing` and also gives (correction `slot-declared-missing`), and records a disagreement with its own derivation as `missing-corrected`. Follow-ups in `then` carry only `intent` and `slots`. Any other member MUST be refused as in L3. Proposals with `v` `"0.1"` (the full envelope) remain accepted, so a deployed model keeps working until it is retrained. *Rationale: L2 already discards every other member; generating them costs a small model tokens, latency and format errors for nothing. `missing` stays because without it a small model invents values for absent required slots (blind v1, run 10: 6 to 15 % of missing-slot utterances against 0 to 1 % with the full envelope), and it costs a few tokens.*
- **L3b.** *Declared output form (lead decision 2026-10-23, ROADMAP 13e).* A served linguist GGUF MAY carry the string metadata key `sidged.linguist.output` with the value `"compact"` (L3a) or `"full"` (v0.1); absent means `"full"`. The key sits inside the weights, so the SHA-256 that identifies them (0011 R8) covers it. A runtime that bundles or serves weights MUST set `model.output` from it, and MUST refuse any other value or type (the model is not started). The key is not a security boundary: the Core checks every reply as in L3 to L7, whatever form it was asked for.
- **L8.** *Constrained decoding.* A runtime that serves the linguist SHOULD constrain decoding with a JSON Schema the Core generates from the catalog: `lang` one of the locales, `intent` a catalog id or null, `slots` only that intent's declared slots as strings of 1 to 512 characters, with one branch per subset of the intent's required slots for `missing` in which the slots named there are absent and every other required slot is present, `then` only declared compositions (§2c) with their slots. The schema is an efficiency and robustness measure, not a security boundary: the Core checks every proposal as in L3 to L7, constrained or not.
- **L4.** An unknown intent MUST become `intent: null`. A slot not declared by the intent, an empty slot, a slot longer than 512 characters, or a slot with a control character MUST be dropped. Every such change and every disagreement between the proposal and the derivation MUST be reported as a correction; the proposal is never trusted.
- **L5.** A clarification-needed envelope MUST NOT wake Edge 1 or any planner. A complete envelope enters planning with residency supplied by the Core (`to_canonical_intent`), never by the linguist.
- **L7.** A slot marked `x-verbatim` in the catalog takes its value from the utterance (a name, a file or folder, a language name, the text of a note). When the utterance is known, the Core MUST drop such a value if it does not occur in the utterance (ignoring case and spacing) and report `slot-ungrounded:<slot>`; the slot then counts as missing. Translated slots (topics, durations) cannot be checked this way; time slots are verbatim and resolved by X6.
- **L6.** Slot values are proposals. A runtime MUST show the canonical intent and the slot values on a surface before a consequential step is planned, and every consequential step still needs Trusted UI approval (0004 R9). Value hallucination is a known model failure (section 6).

## 2b. Intent plans

An intent MAY declare a plan in the catalog: SDG-L3 steps whose arguments are `{"slot": name}` (a verified slot),
`{"intent": "canonical"}` (the canonical English intent) or `{"ref": step}` (an earlier step's result). The Core
instantiates it into a plain SDG-L3 plan (`{"lit": value}` / `{"ref": step}`); an optional slot the utterance did not give
is left out. Implemented in `runtime/sidged-cli/src/intent_plan.rs`.

- **PL1.** Only a complete, Core-verified intent is planned; a clarification-needed envelope is refused.
- **PL2.** Every step MUST use a capability the intent names (bound) and the capability catalog describes.
- **PL3.** Every literal MUST be a verified slot value or the canonical intent (grounding). This also binds plans a
  planner model proposes (`check_plan`, WP 11d).
- **PL4.** Every literal MUST satisfy its property in the capability `input_schema`; arguments outside the schema are
  refused and required arguments MUST be present (a `ref` counts as present).
- **PL5.** The plan then passes the SDG-L3 verifier (structure, budgets, approval for every consequential step) and the
  owner's Cedar flow policy; a refusal names its stage, step and deciding policies. A new workspace starts with the
  specified `default-flow` policy (0013 §4).

### Running a plan on the node

- **X1.** Each step's arguments are resolved (`lit`, or an earlier output for `ref`) and MUST satisfy the capability
  `input_schema` before the executor runs; the output MUST satisfy `output_schema`.
- **X2.** A consequential step runs only after the approval channel grants it; a node without a Trusted UI channel
  denies it. There is no automatic approval.
- **X3.** A capability without a backend on the node refuses; the run stops and later steps are skipped.
- **X4.** The owner's files are under `<workspace>/files/`; executors cannot reach the node's keys, logs or records.
- **X5.** Every step outcome is audited, and the run's record holds exactly the step outcomes (status, reason, executor
  output); no content is produced by the Core itself.
- **X6.** Times and durations are read by the node, not by the model. A time slot is verbatim (L7); the node resolves it from a published lexicon (en, de, gsw) in its IANA time zone (daylight saving time included) to an instant after now, and records both the words and the instant. Words the lexicon does not cover, a named day whose time has passed, or a clock time without a time zone MUST be refused, never guessed. A duration is read the same way from its lexicon.

## 2c. Compositions (owner decision roenu, 2026-10-22)

One utterance can ask for two or three things in a row ("Fass protokoll.docx zäme und schick's em Marco"). The linguist
proposes the first intent as before and the rest in `then`, in the order said. A catalog declares which intents may
follow which and how the result of the first flows into the next. The Core chains the declared plans; no model plans
a composition (a planner model for undeclared compositions is later work, WP 11d B).

```json
"compositions": [
  {"first": "task.summarize", "then": "messaging.send", "satisfies": ["topic"], "replaces": {"draft": "summary"}}
]
```

- **K1.** `then` holds at most two follow-ups, each `{intent, slots}`. Each follow-up is verified like the first intent
  (L4, L7: unknown intents, undeclared, empty, oversized, control-character and ungrounded slots are dropped and
  reported with the prefix `then[i].`).
- **K2.** Each adjacent pair (the first intent and `then[0]`, `then[0]` and `then[1]`) MUST be declared in the catalog's
  `compositions`. An undeclared pair, or a follow-up whose intent is null, drops that follow-up and every later one and
  is reported as `composition-undeclared`; the first intent stays as proposed.
- **K3.** `satisfies` names required slots of the follow-up that the earlier result provides; they are not missing.
  Every other required slot of every follow-up counts: the envelope needs clarification when the first intent or any
  follow-up misses a slot, and the question asks for the first missing slot in that order.
- **K4.** The Core instantiates the first plan (§2b), then each follow-up's plan with its step ids prefixed `t1_` or
  `t2_`. A step named as a key in `replaces` is not instantiated; every `{"ref"}` to it refers to the named step of the
  previous plan instead.
- **K5.** The chained plan passes the same checks as a single plan (PL2–PL5), with the union of the intents'
  capabilities as the bound and the union of their verified slot values and canonical intents as the grounding. Every
  consequential step still needs Trusted UI approval.
- **K6.** A catalog with `compositions` MUST name only catalog intents, satisfy only required slots of `then`, and
  replace only steps of `then`'s plan with steps of `first`'s plan. The linguist prompt lists the declared
  compositions, so a catalog change is a retraining event (I5).

## 3. Morphing canvas (`@vaiev/ui` v4 surfaces)

A surface is a JSON document `{v: "4.0", kind, source, nodes}` whose nodes reference primitives of `ui/a2ui-catalog.v4.json`.

- **C1.** Every primitive declares `props_schema` (JSON Schema), its child range, the `--vv-*` tokens it uses and its `binds`. A Core MUST validate every surface against the catalog before a webview receives it: unknown primitives, unknown node members, props that fail their schema, child counts outside the range, more than `max_nodes` nodes or a depth beyond `max_depth` are refused.
- **C2.** The validator MUST refuse a schema keyword it does not enforce (fail closed). The v0.2 subset is `type`, `enum`, `const`, `required`, `properties`, `additionalProperties`, `items`, `minItems`, `maxItems`, `minLength`, `maxLength`, `pattern`, `minimum`, `maximum`, `minProperties`, `maxProperties`; annotations are ignored.
- **C3.** Which primitive renders data is decided by `binds` in catalog order: the first primitive whose `shape` pattern matches the data's JSON Schema (`type`, `items`, `required` subset), or whose `mime_prefix` matches an artifact media type. No capability or intent name selects a primitive.
- **C4.** Surface kinds: `input` (capability `input_schema` as a form), `output` (capability result bound by `output_schema` or by the value's shape; a complete intent; a signed-record `ResultSurface`), `clarification` (missing intent slots, labelled with the catalog question).
- **C5.** No primitive renders or triggers a consequential confirmation. Approval, the residency indicator and the kill switch belong to the Core-owned Trusted UI outside every surface (0004).
- **C6.** Design: the canvas uses `@vaiev/ui` v4 with the Sidged theme (accent Sodium, dark only; `ui/vaiev-ui/`). Content is flat and tonal; navigation and floating controls form one glass layer; touch targets are 48 px; safe areas are respected.

## 4. Companion IPC

- **P1.** The webview of a companion node may call exactly one command (`companion`) that dispatches an allowlist: `catalog.describe`, `node.status`, `node.init`, `intent.list`, `intent.run`, `linguist.prompt`, `linguist.run`, `linguist.verify`, `surface.capability_input`, `surface.capability_output`, `surface.input_submit`, `surface.clarification_submit`.
- **P2.** No allowlisted command approves, signs, pairs or sends, and none confirms a consequential step. `surface.input_submit` validates values against the capability `input_schema` and returns a `pending-plan` invocation. `intent.run` runs a complete, Core-verified intent's catalog plan on the node under X1–X5; its consequential steps are denied, because the webview is not a Trusted UI (invariant 4). A complete intent's surface shows the plan the Core would run (`StepTimeline`, owner-gate marks) or the planning refusal.
- **P3.** `node.init` is the only writing command. It creates the node's workspace (owner and edge identities, default flow policy, SDG-L1 capability catalog, record store, audit log) once, returns only public identifiers, and MUST refuse when a node exists.
- **P5.** `linguist.run` sends the rendered prompt to the node's local model endpoint (`model.endpoint` in the workspace `config.json`; `unix:<path>` with the model uid by default, 0004 R9d) through the runtime's `LocalModel` client and returns the Core-verified envelope with its corrections and the next surface. The endpoint is node configuration, so `linguist.run` refuses before the node exists. The call does not need local mode: an `AF_UNIX` endpoint with the peer-uid check is not egress (0004 R9d); TCP loopback is refused outside local mode.
- **P4.** The webview CSP MUST restrict `connect-src` to the IPC origin; the canvas uses safe DOM APIs only (no HTML injection, no eval, no browser storage, no dialogs). `scripts/tests/companion_ui_check.sh` enforces this.

## 5. Browser verifier (sidged.com)

- **W1.** The playground module is built from the pure verification crates (`sidged-verify`, `sidged-record` without its file-backed store, `sidged-grant`) for `wasm32-unknown-unknown` and MUST have no imports: it cannot reach the network, a clock, files or randomness.
- **W2.** ABI: `sdg_alloc(len) -> ptr`, `sdg_free(ptr, len)`, `sdg_call(op_ptr, op_len, in_ptr, in_len) -> u64` with JSON in and out, the result packed as `ptr << 32 | len`. Operations: `about`, `plan.verify`, `flow.check`, `record.verify`, `dcbor.encode`, `dcbor.decode`, `did.resolve`. Malformed input yields a `refuse` verdict, never a trap.
- **W3.** `plan.verify` runs the SDG-L3 structural verifier with flows delegated to the Cedar stage, then `check_plan_flows`; `secrets.*` never reaches egress, even under an owner permit (0013 R10). A refusal names its stage, reason, step, class and the deciding policies.
- **W4.** The site publishes every JSON Schema at its `$id`, the test vectors with only the public halves of the test keys, and a SHA-256 manifest. A build that publishes an RFC 8032 test seed MUST fail.

## 6. Measured state (v0.2.0) and known limits

- Model -1 (`lora-linguist-ch`, Qwen3-0.6B bf16 LoRA): on phrasings never trained on, valid JSON 100 %, accepted unchanged 95.4 %, effective (lang, intent, slots) 88.7 % (en 96 %, de 91 %, gsw 82 %).
- The model can invent a slot value (L6). Close intents (contacting someone, proposing a meeting) are confused. Some Bernese forms are misread.
- The companion's intent home works without the model (tiles and clarification forms). On the desktop node the intent bar asks Model -1 through `linguist.run` (GGUF q8_0, 639 MB, llama-server on a private AF_UNIX socket, about 1 to 1.5 s per utterance on CPU). Android has no on-device endpoint yet (roadmap WP 9b).

## 7. Open questions

1. *Resolved by L7:* verbatim slots (`x-verbatim`) must occur in the utterance.
2. Localized intent titles in the catalog (today only the questions are localized).
3. Whether a linguist envelope becomes a signed record when it enters planning (0012).
4. *Resolved by 0004 R9d (owner decision 2026-10-20):* an `AF_UNIX` model endpoint with the peer-uid check is not egress and may be used outside local mode, so a companion can run Model -1 and join its owner's swarm.
