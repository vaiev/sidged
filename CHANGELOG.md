# Changelog

All notable changes to Sidged. Versions follow Semantic Versioning; while the major version is 0, a minor version may
change interfaces. The plan ahead is in [docs/ROADMAP.md](docs/ROADMAP.md).

## Unreleased

The first public preview, `v0.3.0-preview.1`, is a snapshot of this section: v0.3 work in progress, pre-alpha,
interfaces will still change. The public history starts with that tag; earlier development happened in a private
repository. 0.3.0 itself follows when the v0.3.0 section of [docs/ROADMAP.md](docs/ROADMAP.md) is done.

### Security
- Workspace containment by directory handle (ROADMAP 11g): every workspace file operation resolves beneath one open `<workspace>/files` with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`, a symlinked or foreign-owned root is refused; timers and reminders change under a lock with atomic replace and ids that never repeat; `sidged task` records go through the record store; the swarm and signed-adapter prototypes and `sidged swarm measure` are behind the `sidged-cli` feature `experimental`.
- One execution engine (ROADMAP 11f, 0002 R25, R26): `sidged run`, `sidged guard`, `sidged task` and the companion run every step through `sidged-cli/src/engine.rs`; every presenter proves possession over the plan digest and a fresh Core nonce (`sidged run --holder-key`), an effectful run without a signed audit chain refuses before its first step, and the plan parser refuses members the plan schema does not allow (vector `plan.verify.021`, suite 0.13.1).
- No effect without a grant on `sidged task` and the companion (0002 §6a, ROADMAP 11f): `sidged init` signs a 30-day owner
  mandate and a grant policy; each plan runs under a one-hour task token inside it, every step authorised and reserved on
  the audit chain before its effect; renewal is `sidged mandate renew` on a terminal.
- One plan parser (ROADMAP 11f, 0003 R4a): `sidged run` and the node executor read plans with the verifier's parser
  (no default `expr`, no truncated `bound`); a `ref` names an output member with `field` and the executor passes exactly
  that value, never a guessed one. Vectors `plan.verify.017`–`019`, `intent.plan.012`–`013`; suite 0.13.0.
- Grant caveats are enforced at use (0002 R22): a right covers a step only when the step's data classes are within
  `constraints.data_classes` and its cost times its bound fits `constraints.max_amount`; the reserved right is one whose
  caveats hold. Before, both only narrowed delegations.
- Found by the new mutation fuzzers and fixed: the plan verifier accepted malformed money amounts (a budget `1x`),
  overflowed on an out-of-range map bound and added long amounts in quadratic time; the CEL parser
  (`cel-interpreter` 0.10) panicked on expressions that fail to parse at their start and every CEL parser overflowed
  the stack on deep bracket nesting (now `cel` 0.15 and 0003 R8a: at most 1024 characters and 4 bracket levels);
  `resolve_did_key` decoded any length in quadratic time (a 300 000-character `did:key` took 96 s; now refused above
  the 47 characters of an Ed25519 key). Vectors `plan.verify.010`–`015`; the Python reference had the money gap too.
- The Core's capability registry enforced only the egress and residency rules of 0001. It now refuses descriptors that
  break R1 (identifier), R3 to R5, R6 (effects), R7 (data classes), R9 (`delete`/`execute` need `consequential`), R10
  or R11, as R20 requires; a `metered` descriptor without `max` was loaded as costing 0 CHF. Vectors
  `capability.descriptor.006`–`022`, run by the Python reference and the Rust registry.
- Implicit flow through `map` (0003 R10): a `map` over health records that sent one fixed message per element was
  accepted by the verifier and the Python reference (only the Cedar stage refused it), although the number of messages
  reveals the number of records. The list's labels now reach every `map` step; vector `plan.verify.016`; property tests
  (`sidged-verify/tests/ifc_properties.rs`) check the verifier and the Cedar stage against a reference of the label
  rules in both directions (no leak accepted, no clean plan refused).
- Audit before effect (invariant 9, WP 11e): `sidged task` and the companion ran every step before they opened the
  audit chain; now the chain is verified first, each decision is appended before its effect and its outcome after, and
  a failed append stops the plan.

### Added
- WebAuthn approvals (0004 R9w, owner decision 2026-10-22, WP 16): on a single-user device a consequential step may be
  approved by a user-verified assertion of the enrolled platform credential; the challenge is the SHA-256 of the R9
  binding. `sidged-cli::webauthn` checks client data (type, challenge, origin), authenticator data (relying party, user
  present and verified, increasing counter) and the ES256 or EdDSA signature; the audit names `webauthn-uv`, the
  credential and the counter. Platform bridges follow.
- WebAuthn enrollment (0004 R9w Enrollment, WP 16): `sidged-cli::webauthn_enroll` checks a WebAuthn Level 3 JSON
  registration against a single-use challenge (client data, relying party, user present and verified, credential id,
  a strictly canonical ES256 or EdDSA COSE_Key matching `publicKey`; attestation `none`) and stores the one enrolled
  credential in a 0600 file written atomically; a second enrollment and a counter rollback are refused.
- Compositions (0017 §2c, owner decision 2026-10-22, WP 11d A): one utterance may chain up to three intents
  ("Fass protokoll.docx zäme und schick's em Marco"). The linguist proposes follow-ups in `then`; the catalog declares
  which pairs may follow each other, which slots the earlier result satisfies and which plan steps it replaces; the
  Core verifies each follow-up like the first intent, drops undeclared pairs and chains the declared plans (bound and
  grounding over all intents, every consequential step still approved). Catalog: summarize, translate or search, then
  send. The prompt lists the compositions (Rust and Python byte-identical), the training data has composition frames,
  vectors `intent.linguist.020`–`025` and `intent.plan.009`–`011`.
- Shared vectors for the intent boundary (`spec/test-vectors/intent/`, suite 0.12.0, 41 vectors): reply verification and
  derivation (0017 L2 to L7), intent plans (PL1 to PL5), spoken times across daylight saving time and durations (X6),
  run by `sidged-cli/tests/intent_vectors.rs`; `scripts/spec-coverage.py` reports which numbered rules have a vector.
- `scripts/repro-wasm.sh`: the browser verifier builds bit-for-bit from a git revision (fixed path, pinned toolchain,
  remapped paths) and prints its SHA-256 (WP 26).
- Deterministic mutation fuzzing without new dependencies (`runtime/fuzz/mutate.rs`, `SIDGED_FUZZ_ITERS`): the
  stored-plan parser, verifier and Cedar flow stage; dCBOR decode/encode and record checks; linguist replies through
  intent plans; spoken times and durations; capability tokens, `did:key` and RFC 3339 times; the companion's surface
  validator.
- Model -1 on the desktop node: `linguist.run` in the companion, an intent bar on the canvas,
  `scripts/serve-local-linguist.sh` and `setup-companion-toolchain.sh --with-llama` (llama.cpp v0.6.0, CPU).
- `sidged-cli::linguist`: `LinguistModel`, `LocalLinguist`, `IntentCatalog::understand`.
- Real execution on the node (`node_exec.rs`, 0017 X1–X5): executors for workspace read/write/find, notes, timers,
  reminders and local text generation; schema-checked inputs and outputs; consequential steps denied without a Trusted
  UI; honest refusals for capabilities without a backend; records hold the step outcomes.
- Intent plans (0017 §2b): every catalog intent declares an SDG-L3 plan; `intent_plan::plan_for_intent` instantiates it
  from verified slots and checks bound, grounding, input schemas, the verifier and Cedar (`check_plan` also for model plans).
- Durations in en, de and Swiss German (`assets/duration-lexicon.json`: Bernese, Basel and Zurich forms, ISO 8601)
  for `timer.start`.
- Model -1 on the phone (WP 9b): `scripts/build-android-linguist.sh` bundles llama-server for arm64 as
  `libllama_server.so`; the app starts it on a private Unix socket when weights are present, verifies their SHA-256 and
  writes `model.endpoint` and `model.digest` (accepted by the gateway config, 0011 R8); the canvas shows the intent
  bar once the model answers.
- Timers and reminders ring on the phone: the app schedules a local OS notification at the instant the executor
  returned (Android; the plugin is not exposed to the webview).
- `SECURITY.md` (private reports through GitHub) and `CONTRIBUTING.md` (DCO, invariants, checks); the README opens
  with an honest status.
- Spoken times (0017 X6): the reminder `time` slot is verbatim and the node resolves it (`sidged-cli::when`,
  `assets/time-lexicon.json`, en/de/gsw) in the device's IANA time zone, or refuses; `reminder.create` returns `due_at`.
  The canvas sends the device time zone with `node.init` and `intent.run`.
- Linguist data as a dialect tree: `local-training/dialect_lexicon.json` (forms per region), node-bearing frames in
  the phrasebook, round-robin coverage, per-region eval buckets, length-grouped batches; `chat_split.py` and
  `dialect_evidence.py` for owner-local data. Run 4: 92.4 % effective, Swiss German 91.2 % (run 2: 84.3 % / 78.2 % on
  the same eval v4). Run 5 copies reminder times verbatim: 91.4 % / 91.8 % on eval v5 (run 4: 88.9 % / 86.7 %).
  Run 6 (deployed, seed 42) also copies message topics and meeting timeframes and adds first-person negatives: 93.1 %
  on eval v6 (run 5: 83.2 %), 44/46 hand-written probes on the served q8_0 GGUF and 42/46 on the phone's Q4_K_M
  (run 5: 28/46); a second seed reached 88.8 % and 39/46. Run 8 (deployed, seed 7) adds composition frames: 92.5 %
  on eval v8 with 84.1 % on compositions (run 6: 82.7 % and 0.0 %), 47/50 probes on q8_0 and 46/50 on Q4_K_M; seed
  42 reached 91.3 % (compositions 93.6 %) and 46/50.
- Capability descriptors for every intent capability (`text.generate_local`, `calendar.free_slots`, `reminder.create`,
  `timer.start`, `device.control`, `notes.append`, `web.search`, `workspace.find`); `sidged-capability::schema` (moved
  from the companion); `sidged_verify::DeferToCedar`.
- A linguist GGUF declares its output form (0017 L3b, ROADMAP 13e): `sidged.linguist.output` (`compact` or `full`, absent means full) in the GGUF metadata, covered by the SHA-256 pin; the app and `serve-local-linguist.sh --workspace` set `model.output` from it and refuse any other value, `release_gate.sh` stamps each export from the run manifest and refuses a served form the GGUF does not declare (`sidged-cli::gguf`, `local-training/gguf_output_form.py`).

### Changed
- Model -1 release gate (13e part A): `sidged linguist-eval` scores replies through the runtime path; train, dev
  and blind split by paraphrase family with cross-split dedup and a manifest-pinned blind set; the gate runs on the
  served GGUF; seeds are set before LoRA init. The old `effective` metric counted Core-refused replies as right and
  remains for comparison only. The Model 0 and planner-think trainers moved to `local-training/experimental/`.
- Model -1 compact output (13e part B, 0017 L3a, L8): the Core accepts v0.2 proposals (`lang`, `intent`, `slots`,
  `then`) besides v0.1 envelopes; `model.output: "compact"` sends the compact prompt and a catalog JSON Schema as
  llama-server `response_format`; `make_dataset_linguist.py --format compact`, `linguist-eval --compact`.
- Model -1 gate (13e): an utterance German and Swiss German write the same counts in either language (`langs` in the
  meta sidecar, decided from the phrasebook; `annotate_langs.py` for the frozen blind), the strict number is reported
  as `lang_strict`; companion `linguist.prompt` follows `model.output`; `check_envelope` refuses over-long slots.
- README states implementation status honestly; an implementation status table and per-invariant status clauses
  say which entry point enforces what (grants and pre-effect audit in `sidged run`, not yet in `sidged task`), and the
  runtime, crate and companion READMEs drop the swarm queue, hybrid planning and other overclaims.
- **0004 R9d (owner decision):** an `AF_UNIX` model endpoint with the peer-uid check is not egress and may be used
  outside local mode; TCP loopback stays local-mode only. Local mode keeps its stricter profile.
- New workspaces start with the specified `default-flow` policy. The previous turnkey policy named a principal that never
  matches (`Sidged::Step::"any"`) and so refused every egress flow.
- `sidged task` asks Model -1 through the node's `model.endpoint` and plans only Core-verified catalog intents; it
  refuses without a configured model.

### Fixed
- Result badges report what happened ("Stopped: a consequential step needs Trusted UI approval") instead of what the
  plan intended; the ready surface and the intent tiles no longer promise swarm workers.
- The model translated reminder times on its own ("am füfi" became 08:00); times are now read by the node.
- Android: creating the node failed with "audit log is locked" (`File::try_lock` is unsupported there); the audit
  chain and record store lock with flock(2).
- Canvas: "Open the canvas" did nothing because the onboarding kept `display: grid` while hidden.
- Container CI scripts pass on rootless podman 4.9 and 5.x (ROADMAP 8.2); the workflow stays manual until a green run.

- CI never ran: no self-hosted runner is registered. Workflows run on GitHub-hosted `ubuntu-24.04` only (a public
  repository never runs fork pull requests on a self-hosted runner); the container workflow is manual until
  ROADMAP 8.2 is fixed.

### Removed
- `init` no longer enrolls two swarm worker edges with keys made on the same device and a self-approval
  (`FixedApproval { granted: true }`); an edge joins only by pairing a real device (WP 19).
- `adapter::normalize_companion_utterance`, the keyword rules that mapped utterances to intents.
- The v0.1 swarm work queue (`execute_swarm_work_queue`, `build_hybrid_or_local_plan_blueprint`, `PlanningMode`): a fixed
  blueprint whose steps were not executed, template artifact payloads, and a pretend hybrid cloud planning step.


## 0.2.0 — 2026-10-20

### Added
- **Intent catalog and companion linguist (Model -1).** A schema-driven catalog of generic intents
  (`runtime/sidged-cli/assets/intent-catalog.json`, `spec/schemas/intent-catalog.schema.json`) and the linguist
  envelope (`spec/schemas/linguist-envelope.schema.json`). `sidged-cli::linguist` keeps only language, intent and slots
  from a model proposal and re-derives everything else from the catalog; residency, approval and grant members refuse
  the proposal. Training and evaluation pipeline in `local-training/` (Qwen3-0.6B LoRA `lora-linguist-ch`): 88.7 %
  effective accuracy on phrasings never trained on (en 96 %, de 91 %, gsw 82 %).
- **Companion nodes.** `companion/sidged-companion-core` builds `@vaiev/ui` v4 surfaces from capability schemas, intent
  slots and signed-record result surfaces and validates each against `ui/a2ui-catalog.v4.json`;
  `companion/sidged-companion-app` is one Tauri v2 app for `sidged-desktop` and `sidged-android` with a single
  allowlisted IPC command, a glass onboarding that creates the local node, and an intent home.
- **sidged.com verifier and schema hub.** `site/sidged-wasm` compiles the pure verification crates to an import-free
  `wasm32-unknown-unknown` module; `scripts/build-sidged-site.sh` publishes the schemas at their `$id`, examples, test
  vectors (public test keys only) and the in-browser playground.
- **Design.** `ui/vaiev-ui/`: the `@vaiev/ui` v4 tokens, components and IBM Plex fonts with the Sidged theme (Sodium,
  dark only), shared by the companion and the site.
- **Specification 0017** (intent catalog, linguist, canvas, browser verifier) and the roadmap to 1.0.0.
- `scripts/setup-companion-toolchain.sh` (pinned, checksum-verified user-local JDK, Android SDK/NDK, tauri-cli) and
  `scripts/tests/companion_ui_check.sh`; Rust CI runs the companion core, canvas and WASM verifier checks.

### Changed
- `sidged init` writes an SDG-L1 capability catalog (`runtime/sidged-cli/assets/capability-catalog.json`) with input and
  output schemas and the registered effect `egress`. The previous catalog declared `network.egress` without data
  classes, which the verifier and the Cedar flow check do not treat as egress.
- `sidged-record` builds its file-backed store only off `wasm32`; `sidged-verify` exports its plan and catalog parsers.

### Known issues
- The container workflow fails on the self-hosted runner (temporary Containerfile not found by podman; base-digest
  self-test cannot inspect its fixture). Tracked as WP 8.2.
- The linguist can invent slot values; every consequential step still needs Trusted UI approval (0017 L6).

## 0.1.0 — 2026-10-20

First public release: SDG-L0..L8 drafts 0000–0016, schemas and test vectors, the runtime crates (verifier, grants,
records, gateway, swarm, turnkey CLI), the offline UI shell, local training for Model 0 and Model 1, and OCI, host and
VM packaging.
