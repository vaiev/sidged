# Vaikor roadmap: v0.2.0 to v1.0.0

> **Date:** 2026-10-20. **Status of this document:** plan, revised at every release.
> **North star:** [vision/VISION.md](vision/VISION.md). **Specifications:** [specs/](specs/).

Every release keeps the nine invariants and the contract suite green (`cargo test`/`clippy` for `runtime/`,
`companion/` and `site/`, `spec/validate`, `local-training/tests`, the shell checks under `scripts/`). A work package
(WP) is done when its exit criteria are met by tests, not by description.

## v0.2.0: intent, canvas and browser verifier (current)

| WP | Content | State |
|---|---|---|
| 6 | Model -1 companion linguist (`lora-linguist-ch`), intent catalog, linguist envelope, Core re-derivation ([0017](specs/0017-intent-linguist-canvas.md) §1–2) | done |
| 7 | `@vaiev/ui` v4 catalog, companion core (surfaces from schemas), Tauri v2 `vaikor-desktop` / `vaikor-android`, glass onboarding, intent home ([0017](specs/0017-intent-linguist-canvas.md) §3–4) | done |
| 8 | Import-free WASM verifier, vaikor.com schema hub and playground ([0017](specs/0017-intent-linguist-canvas.md) §5) | done |
| 8.1 | VKR-L1 workspace capability catalog (`"egress"`, data classes, schemas) | done |
| 8.2 | Container CI (`container.yml` is manual-only until this is fixed, then push, pull request and nightly again): podman loses the temporary Containerfile under `/tmp`; the base-digest self-test cannot inspect its fixture | scripts fixed (podman 4.9 and 5.x), triggers wait for a green manual run |
| 8.3 | Release: crate versions 0.2.0, changelog, tag | open |

## v0.3.0: from utterance to signed record on one node

| WP | Content | Exit criteria |
|---|---|---|
| 9 | Local model endpoint on the desktop node (0009, 0004 R9d): Model -1 GGUF q8_0 on llama-server behind a private AF_UNIX socket with peer-uid check; `linguist.run` and the intent bar | done: utterance to clarification or ready surface, no network, about 1 to 1.5 s per utterance on CPU |
| 9b | Model -1 on Android: in-process inference (q4_k_m) in the companion, no socket | built: bundled llama-server (`libllama_server.so`, pinned llama.cpp) on a private Unix socket in the app's data dir, weights by SHA-256, endpoint written once the server answers; desktop run of the same setup: ready in 0.75 s, 0.8 to 1.6 s per utterance. Measured on a Galaxy S25-class phone (2026-10-22, run 6 Q4_K_M): server ready 17 s after start including the one-time SHA-256 of the weights, then 1.2 to 1.7 s per utterance (about 65 tokens/s), all five test utterances right; the APK has no INTERNET permission and the canvas works without it. Open: notification test on the device; weights distribution (WP 25) |
| 9c | Rule for local mode vs. swarm on one companion (0017 open question 4) | done: 0004 R9d, `AF_UNIX` model endpoint is not egress; tests for both modes |
| 10 | Replace the keyword normalizer in `turnkey` (`normalize_companion_utterance`) with the linguist path; remove the hardcoded keyword rules | done: `vaikor task` uses catalog + Model -1 (`LinguistModel`, `IntentCatalog::understand`); tests use recorded model replies |
| 11a | Intent plans declared in the intent catalog (VKR-L3 with slot placeholders), instantiated by the Core from verified slots; plan literals grounded in slot values; capabilities bounded by the intent | done (0017 §2b, `intent_plan.rs`): all 12 catalog intents pass the verifier and `default-flow`; refusals carry stage and deciding policy. Wiring into execution follows in 11b/11c |
| 11b | Real execution: local capability executors (workspace, timer, reminder, local text generation) behind the adapter contract; capabilities without a backend (calendar, device, message transport) refuse honestly | done (`node_exec.rs`): inputs and outputs schema-checked, owner files under `files/`, keys unreachable; the record holds the step outcomes |
| 11c | Remove the v0.1 demo paths: fabricated artifact payloads (fixed recipient, placeholder code, canned text) and `FixedApproval { granted: true }` in `turnkey`; consequential steps wait for the Trusted UI or are denied | done: the swarm queue blueprint, its template artifacts and the pretend hybrid cloud planning are removed; `vaikor task` denies consequential steps without a Trusted UI and uses the real clock |
| 11d | Compositions (owner decision 2026-10-22: A first). A: catalog-declared compositions chained by the Core; B: a Model 1 planner for undeclared compositions with one verifier-guided repair round | A done (0017 §2c): Core, vectors, prompt, training data, canvas asks for and shows follow-ups; linguist run 8 (deployed, seed 7) 92.5 % on eval v8, compositions 84.1 % (seed 42: 93.6 %), all composition probes pass; open: phone APK with the run 8 weights. B: plans for held-out compositions pass the verifier on a held-out split |
| 12 | Slot grounding (0017 open question 1): verbatim slots must occur in the utterance | done: 0017 L7, `x-verbatim` in the catalog, invented values become clarifications (tests) |
| 13 | Linguist v2 data: dialect breadth (Bernese, Basel, Zurich forms), contact-vs-meeting and remind-vs-propose disambiguation, held-out eval refreshed | done: dialect tree (`dialect_lexicon.json`, one region per utterance, round-robin leaves), owner chats split into single utterances and used for negatives and form weights (local only), eval v4 with region buckets. Run 4 (deployed) 92.4 % effective, gsw 91.2 % (be 98.3, zh 89.2, bs 90.2) vs. run 2 84.3 % / 78.2 % on the same eval. Open: older frames without nodes (gen 79 %), slots filled that the utterance leaves open |
| 13b | Time slots: a Core-side parser for times instead of model canonicalization | done (0017 X6): `time` is verbatim, `vaikor-cli::when` resolves it from `time-lexicon.json` in the device's IANA zone (DST included) or refuses; run 5 copies times: eval v5 91.4 % effective, gsw 91.8 % (run 4: 88.9 % / 86.7 %) |
| 13d | Linguist stability: free topics translated unchecked ("wäg em Znacht am Friitig" → "the next weekend"), "mäud di bi X" and first-person statements unstable across runs; a fixed probe set evaluated on the deployed GGUF, more first-person hard negatives, several seeds, and a decision on verbatim topics | mostly done: run 6 (deployed, seed 42) 93.1 % on eval v6, probes 44/46 (95.7 %) on q8_0 but 42/46 on the phone's Q4_K_M; seed spread 4.3 points (seed 7: 88.8 %, 39/46), published in `local-training/README.md`. Open: questions about messages read as sends, Q4 under 95 % |
| 13c | Further dialect sources: Schweizerisches Idiotikon API (CC BY-SA 4.0, historical lemmas, attribution required) and regional dictionaries for word variants; licences checked before any form is committed | lexicon forms with recorded source |
| 14 | Reclassify `worker.fetch` as egress through the Privacy Gateway (URL leaves the device) with residency and approval | done: `egress`, `query.general`, consequential; search intents use `web.search` |
| 11e | Audit before effect (invariant 9; vaikor.com: "recorded before anything happens; if recording fails, nothing happens"). Found by the 2026-10-23 audit: `vaikor task` opens the audit chain after `run_plan` has acted | done (`node_exec::AuditSink`): tests show that a decision append failing at step N leaves step N and every later step without effect on disk, that a locked, corrupt or unwritable log refuses `vaikor task` and the companion before the first effect, and that each executed step's decision precedes its outcome in a log `verify_file` accepts |
| 11f | One checked execution path (invariant 2, 0002 §6a R22-R26): `vaikor task`, the companion and `vaikor run` execute through the same engine, which requires an authenticated principal, a verified grant with every caveat enforced (data classes, amounts, uses) and a durable reservation; one plan parser shared by verifier and executor | done: one engine (`vaikor-cli/src/engine.rs`) for `vaikor run`, `vaikor guard`, `vaikor task` and the companion; every presenter proves possession over the plan digest and a fresh Core nonce (R25, `vaikor run --holder-key`); an effectful run without a signed chain refuses before its first step; the parser refuses members the plan schema does not allow and the flow check reads the parsed plan. Tests per entry point show that a plan without a covering grant or a valid proof has no effect, and the verified representation is the executed one |
| 11g | Containment by directory capability: workspace files opened relative to an open directory handle (`openat2`/`cap-std`), not by pathname checks; timers, reminders and task records in transactional state (the record store) | done: `<workspace>/files` is one directory handle (no symlink, Core uid) and every workspace open is `openat2(RESOLVE_BENEATH \| RESOLVE_NO_SYMLINKS)` beneath it (`vaikor-cli/src/contained.rs`; chosen over `cap-std` for no new dependency, static musl and Android); timers and reminders under `flock` with atomic replace and random ids; task records imported into the record store, `latest-record.json` a pointer; swarm and signed-adapter prototypes behind the feature `experimental`. Tests: `..`, absolute, symlinked root, a symlink swapped in and a rename race never leave `files/`; concurrent writers lose no entry |
| 13e | Model release gate: frozen blind test set split by paraphrase family and source, normalised cross-split dedup, seeds set before LoRA init, the full benchmark run on each shipped GGUF through the Rust Core's acceptance rules; grammar-constrained decoding from the catalog and a smaller model output (intent, slots, follow-ups; the Core derives the rest) | part A done: `vaikor linguist-eval` scores through the runtime path, train/dev/blind by paraphrase family with cross-split dedup and a manifest-pinned blind set, the gate runs on the served GGUF, seeds set before LoRA init, Model 0/1 trainers archived as demos. First gate (blind v1, 564 records, served run 8 through the Core): q8_0 92.7 % semantic, 1.9 % invented slots, 3.4 % unintended actions, compositions 77.8 %; Q4_K_M 89.4 %, compositions 77.8 %. Run 9a (more composition frames): compositions 100 % / 97.2 % (seeds 7 / 42) but Q4_K_M 85.5 % / 83.2 %; run 8 stays deployed. Part B code done: the Core accepts compact v0.2 proposals (0017 L3a) and v0.1 envelopes, `model.output: "compact"` constrains decoding with a catalog JSON Schema (L8), `make_dataset_linguist.py --format compact`, `linguist-eval --compact`; the gate accepts either language for an utterance German and Swiss German write the same (decided from the phrasebook, `langs` in the meta sidecar) and reports the strict number too. Run 10 (compact, constrained, frozen blind v1):
- Replies take half the tokens.
- Unintended actions fall from 3.4 to 0.7 %.
- q8_0 scores 94.3 / 93.1 % (seeds 7 / 42).
- Q4_K_M scores 93.4 / 87.6 %. Seed 42 is the one dev selects, so run 8 stays deployed.

The compact form invents absent required slots (up to 14.9 % on Q4_K_M). 0017 L3a adds `missing` before `slots`, and the grammar enforces it (L8).

Run 11 (compact with `missing`, done in Core, data and grammar):
- q8_0 scores 94.9 / 91.8 % (seeds 7 / 42), and Q6_K 95.4 / 90.4 %.
- Q4_K_M scores 88.3 / 86.2 %. Invented values on missing-slot utterances go up to 22.9 %, because two held-out frames ("share the file", "ändere die Einstellung") read as giving a slot.
- Dev selects seed 42 at Q6_K: 90.4 % on blind, but 13.7 % invented on missing-slot utterances, so run 8 stays deployed.

Blind v2 is frozen: 651 records from 203 families, with fresh eval frames. Run 8 Q4_K_M scores 84.9 % on it. Run 12 adds bare-noun frames; seed 7 misses its pre-registered rule by one record.
The run 12 soup (average of both seeds) passes it at Q6_K: 90.6 %, 9 of 196 missing-slot inventions (run 8: 10), unintended actions 4.6 % (run 8: 5.5 %); with the Vaikor prompt after the rename 91.2 %. It is the release candidate.

Done: the companion learns the bundled model's output form from the GGUF key `vaikor.linguist.output` (0017 L3b), stamped by the release gate. On the phone (Galaxy S25 Ultra, 2026-10-24) an utterance takes about 1 s.

Open: a companion node created before 11f has no owner mandate, so every run is denied, and the phone has no terminal for `vaikor mandate renew`. |

### Known v0.1 demo paths (found 2026-10-20, removed by WP 11a–11c on the same day)

- The swarm work queue builds envelopes for its steps but does not execute them, while reporting the steps as
  completed.
- The artifact payloads it signs are templates (a fixed mail recipient, placeholder code, canned text), not results.
- `turnkey` approves with `FixedApproval { granted: true }`, which contradicts invariant 4.
- The plan is a fixed three-step blueprint for every intent, in a format that is not VKR-L3.

### Found on the phone (2026-10-20)

- Node creation failed on Android: `std::fs::File::try_lock` is not implemented there in Rust 1.89 (fixed: flock(2)).
- Timers and reminders are stored on the node but nothing rang (fixed on Android: local OS notifications at the
  executor's instant; desktop notifications open).
- `vaikor init` enrolled two swarm worker edges with `FixedApproval { granted: true }` (v0.1 turnkey; removed, a new
  node has no edges until WP 19 pairs a real device).
- The "swiyu" pairing path verifies only a `did:key` signature; `issuer_attestation` is not checked. Real passkey and
  SD-JWT VC verification belong to WP 19.

## v0.4.0: Trusted UI on the devices

| WP | Content | Exit criteria |
|---|---|---|
| 15 | Android: owner and approval keys in Android Keystore / StrongBox, user presence by BiometricPrompt for every `consequential` approval | key never leaves hardware; approval record carries the attestation |
| 16 | Trusted UI approval on single-user devices (owner decision 2026-10-22: WebAuthn user verification, 0004 R9w) | Core done: `vaikor-cli::webauthn` verifies assertions (ES256, EdDSA) against the enrolled credential with a challenge binding the R9 request; every binding, flag, origin, counter and key failure denies (tests). Core-side enrollment done: `vaikor-cli::webauthn_enroll` verifies a WebAuthn Level 3 registration (attestation `none`, strict COSE_Key decoding) against a single-use challenge and stores the one credential and its counter in a 0600 file (tests). Open: the platform bridges (Android Credential Manager with an asset-links relying party, Windows Hello via webauthn.dll, the phone as roaming authenticator for Linux), enrollment through Trusted UI, negative tests that the webview cannot reach the channel |
| 17 | Trusted UI bar outside the webview: approval pill, residency indicator, kill switch (0004, 0005) | kill switch stops a running queue; residency shown per step |
| 18 | Windows and macOS builds of `vaikor-desktop` (workspace bootstrap without Unix permission bits, OS key stores) | signed installers for three desktop OSes |

## v0.5.0: devices as one owner swarm

The v0.1 swarm and signed-adapter code (`swarm.rs`, `adapter.rs`) stays behind an `experimental` feature until this
release rebuilds it on the 11f execution path: today a "measurement" signs a caller-supplied digest and "cull and
replace" changes enrollment state only.

| WP | Content | Exit criteria |
|---|---|---|
| 19 | `mobile.camera.qr_scan` pairing (`vkr://pair/v0`, 0016 §2) phone ↔ desktop, passkey and `swiyu` SD-JWT VC presentation | pairing vectors; revocation on drift (0015) |
| 20 | Transports `local-direct`, `cloud-to-local-e2ee`, `local-to-web-to-local-e2ee`; minimal blind relay (0016 §2.2) with no access to keys or plaintext | relay sees ciphertext only (tested); CH hosting |
| 21 | Android as Trusted UI approver for a desktop Edge 1 (0004 R9) | approval round trip across devices |
| 22 | `mobile.share.intake` (Android share sheet → intent surface by media type) | share of text, URL and file opens the matching surface |

## v0.6.0: model ensemble and packages

| WP | Content | Exit criteria |
|---|---|---|
| 23 | Multi-LoRA serving: Model -1, 0 and 1 on one shared base in RAM | memory budget published per device class |
| 24 | `mobile.audio.ptt_utterance`: on-device speech to text into Model -1 | no audio leaves the device |
| 25 | Signed model and module packages: weights by hash (0011 R8), `vkr.bundle/v0` manifests (0014) published under vaikor.com `/bundles` | bundle verification in the browser verifier |
| 26 | Reproducible builds for runtime, companion and WASM module | two independent builds produce the same digests. *WASM module done 2026-10-21:* `scripts/repro-wasm.sh` builds from `git archive` at a fixed path with the pinned toolchain and path remapping; two clean builds give the same SHA-256 (cargo hashes path-dependency locations into symbols, so the path must be fixed). Open: runtime binaries, the companion apps, a second machine |

## v0.7.0 to v0.9.0: hardening

- Fuzzing of the dCBOR codec, the plan verifier, the linguist envelope parser and the surface validator; property tests for IFC. *Started 2026-10-21:* deterministic mutation fuzzers for all four plus tokens, `did:key` and spoken times run in every `cargo test` (four bug classes found and fixed, see the changelog); IFC property tests run against a reference of the label rules (they found the `map` implicit flow); open: coverage-guided fuzzing (cargo-fuzz on a nightly toolchain).
- External security review and a published threat model mapped to ISO/IEC 27090 (0016 §4).
- Accessibility audit of the canvas and the Trusted UI (WCAG 2.2 AA, both themes where offered, reduced motion and transparency).
- French locale for the intent catalog and the companion.
- Conformance suite v1: every normative rule of 0000–0017 has at least one vector; second implementation of the record and plan checks. *Measured since 2026-10-21* by `scripts/spec-coverage.py`: 43 of 234 numbered rules (18 %) have a shared vector; 0017 has 11 of 38 since the `intent/` vectors, 0013 has 9 of 11.
- Performance budgets: cold start, first surface, plan verification time, RAM per device class.

## v1.0.0: exit criteria

1. Specifications 0000–0017 promoted from Draft to Candidate; schemas at v1.0 with versioned `$id`s on vaikor.com.
2. All nine invariants covered by tests and by the conformance suite; all CI workflows green, including containers.
3. Signed releases: desktop (Linux, Windows, macOS) and Android; the companion embeds the Core in-process.
4. Trusted UI hardware-bound on every supported device; no path in which a model or webview approves a consequential step.
5. No hardcoded keyword or template path for user intents; intents, surfaces and capabilities are catalog- and schema-driven.
6. Published threat model, external review closed, reproducible builds.
