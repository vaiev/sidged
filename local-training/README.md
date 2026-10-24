# Local training (user PC only)

> The deployed model is **Model -1, the companion linguist** (section below). The UI generator (Model 0) and
> the planner-think experiment (Model 1) are demonstrations on a handful of templates; their trainers live in
> `experimental/` and nothing on the runtime path uses them.

Status: turnkey work package (f). Not part of the cargo workspace. Nothing here runs in CI except the stdlib
unit tests (`tests/`), `py_compile` and `bash -n`. No training was run while writing these files.

Target machine: NVIDIA RTX 5060 Ti 16 GB (Blackwell, sm_120), 64 GB RAM, Linux or WSL2. Blackwell needs CUDA
12.8 builds, so the setup installs **stable** PyTorch cu128 wheels (no nightly).

## What it trains

A small LoRA (bf16, r 32, alpha 64, no 4-bit) on **Qwen3-0.6B** (Apache-2.0, the v1 primary). Optional:
FunctionGemma-270M (Gemma Terms of Use, not Apache-2.0; the licence is recorded in the manifest). The model
learns to emit one JSON tool call against the v1 A2UI registry:

- components: `TaskList`, `CountdownWidget`, `NoteEditor`, `WebResult`, `CloudCallTrace`;
- routes: `local-ui`, `worker-tool`, `cloud:grok`.

The model only proposes. The Sidged Core checks grants, Cedar policy, residency, the Privacy Gateway and human
approval (0009 R1/R2, 0007 §5.1). Training data therefore carries no residency, approval or grant fields, no IP
literals and nothing the sdg.pii/1 detectors (0007 R12) match; `validate_dataset.py` refuses all of that.

## Steps

```
cd local-training
bash setup_gpu_cu128.sh                       # uses the hashed lock below
. .venv-sidged-train/bin/activate
python3 -I make_dataset.py --out data.jsonl   # deterministic; prints its SHA-256
python3 -I validate_dataset.py data.jsonl
python3 experimental/train_edge_llm.py --dataset data.jsonl --base-model Qwen/Qwen3-0.6B \
    --revision <40-hex commit of the model repo> --out out/ --i-approve-training \
    [--gguf-converter <your llama.cpp checkout>/convert_hf_to_gguf.py]
```

`experimental/train_edge_llm.py` refuses without `--i-approve-training`, without an interactive terminal, and unless you type
`TRAIN` (v1 spec: training only after explicit user approval, on the user PC only). It validates the dataset and
the revision before any download. Downloading the base model at that revision is the only network access it
causes. GGUF export runs only if you point it at your own llama.cpp checkout; nothing is cloned or built.

`out/manifest.json` (see `write_manifest.py`) records base model id, commit revision and licence, the dataset and
script SHA-256, the hyperparameters, the registry, and the GGUF SHA-256 (0011 R8: weights identified by hash).
Timing: none is claimed. Measure on your machine.

## Lock file

`requirements.in` contains the top-level pins. PyTorch 2.7.0 with CUDA 12.8 is the minimum
for Blackwell sm_120 and satisfies the torch <=2.7.0 constraint for `unsloth==2025.6.2`
and `unsloth_zoo==2025.6.1`. Its matching torchvision is 0.22.0. Torchaudio is unused;
bitsandbytes and xformers are installed as unsloth dependencies via the lock.
They are not explicitly requested as top-level pins.

The checked-in `requirements.lock` contains pinned versions and hashes. On a connected
machine with uv available, regenerate with this command from this directory:

```
uv pip compile --generate-hashes --python-version 3.12 --python-platform x86_64-manylinux_2_28 --index-strategy unsafe-best-match --extra-index-url https://download.pytorch.org/whl/cu128 requirements.in -o requirements.lock
```

Use Python 3.12 for this lock. Review the generated versions and hashes, then run the offline
contract tests from the repository root:

```
python3 -I -m unittest discover -s local-training/tests
```

Setup installs the generated lock with `pip install --require-hashes -r requirements.lock`
and the cu128 extra index.
Do not hand-write hashes or bypass hash checking.

## Not in this package

Copying the GGUF to a Sidged host: the local-mode model endpoint (`model.endpoint`, AF_UNIX + SO_PEERCRED) and
module packaging (0011, 0014) come first.

## Companion linguist (Model -1, `lora-linguist-ch`)

A second LoRA on the same **Qwen3-0.6B** base (bf16, r 16, alpha 32; the base weights are shared with Model 0 and
Model 1). It reads one utterance in English, German or Swiss German (`gsw`) plus the intent catalog and proposes
one linguist envelope (`spec/schemas/linguist-envelope.schema.json`): language, catalog intent, slot values in
canonical English, missing required slots, and a local clarification question.

Everything is driven by the runtime intent catalog `runtime/sidged-cli/assets/intent-catalog.json`
(`spec/schemas/intent-catalog.schema.json`): each intent declares its slots as JSON Schema, a canonical English
template, capabilities, data classes, a route and one clarification question per locale. Adding an intent to the
catalog changes the prompt; nothing in the code names an intent.

- `linguist.py`: prompt renderer and the Core derivation rules, byte-identical to `runtime/sidged-cli/src/linguist.rs`
  (both pinned by `runtime/sidged-cli/tests/fixtures/linguist-prompt.json`).
- `linguist_phrasebook.json`: synthetic surface forms only (frames with `{slot}` placeholders, value pools with a
  canonical English value). Which slots a frame names decides which required slots are missing, so clarification
  targets come from the schema. `eval_frames` are phrasings that never appear in training.
- `make_dataset_linguist.py`, `validate_dataset_linguist.py`: deterministic data and its validator. The prompt shows a
  shuffled catalog subset; sometimes the matching intent is left out and the target becomes `intent: null`.
- `train_companion_linguist.py`: trains, merges, evaluates and writes `out/qwen3-0.6b-linguist/manifest.json` and
  `eval_report.json`.

The model only proposes. The Core keeps `lang`, `intent` and `slots` after checking them against the catalog and
re-derives missing slots, the question, the canonical intent, the route and the data classes; an envelope with
`residency`, `approval` or `grant` members is refused.

### Release gate (ROADMAP 13e)

A release number measures the artifact that ships, judged by the code that runs:

- **Scoring through the Core.** `sidged linguist-eval` (Rust, in the shipped binary) runs every reply through the
  runtime path (`IntentCatalog::understand`: utterance check, full-catalog prompt, chat request, reply
  post-processing, `verify_proposal_for`). `core_bridge.py` calls it; Python renders no prompt and judges nothing
  itself. `eval_linguist.py` lists the metrics: `core_accepted`, `accepted_unchanged`, `semantic_ok`,
  `semantic_accuracy_accepted`, `invented_slots`, `unintended_actions`, `clarification_ok`. `legacy_effective` is
  the old metric, kept for comparison only: it counted a reply as right even when the Core refuses it (a test pins
  that case).
- **Splits by paraphrase family.** `make_dataset_linguist.py` writes train, dev and blind. A family (one phrasebook
  source text) never crosses splits; utterances are deduplicated across splits after case folding and stripping
  punctuation and spacing; dev and blind prompts show the whole catalog, as at runtime. Blind is built first, so it
  depends only on the phrasebook, the lexicon and the seed; its SHA-256 goes into the run manifest, and the gate
  refuses a blind file that does not match.
- **The served GGUF.** The gate queries llama-server through the runtime's own request (same decoding and token
  limit), for q8_0 and Q4_K_M separately: `python3 -I eval_linguist.py --data out/<run>/linguist_blind.jsonl
  --manifest out/<run>/manifest.json --gguf <model.gguf> --socket <llama-server socket>`.
- **Seeds.** `seeding.seed_everything` seeds Python, NumPy and Torch before the adapter exists; the manifest records
  the seeds and library versions. A data change is still judged on at least two seeds.
- **German or Swiss German.** Some utterances are written the same in both ("Such plan.odt in Documents"); the model
  cannot know which was meant. Each record's meta sidecar names the languages it may be in (`langs`, its own first):
  `make_dataset_linguist.record_langs` adds the other one when that language's frames of the same intent or
  composition (or its unmatched phrases), with the pool surfaces of the same canonical slots, the lexicon forms and
  the greetings and tails it adds, write the same normalised utterance. The decision uses only the phrasebook, the
  lexicon and the record; no model reply, no owner data. The gate accepts any listed language (`semantic`) and also
  reports the strict number with exactly the generated language (`lang_strict`); training targets keep one language.
  `annotate_langs.py <split.jsonl>` adds `langs` to an existing split's sidecar (the frozen blind) and leaves the
  split's bytes and SHA-256 unchanged.

First gate numbers (blind v1: 564 records, 36 compositions, 60 owner-chat negatives; served GGUF of run 8, seed 7,
judged by the Core):

| artifact | Core accepts | semantic | invented slots | unintended actions | compositions | clarification right |
|---|---|---|---|---|---|---|
| run 8 q8_0 | 100.0 % | 92.7 % | 1.9 % | 3.4 % | 77.8 % | 99.5 % |
| run 8 Q4_K_M | 100.0 % | 89.4 % | 2.7 % | 3.7 % | 77.8 % | 98.2 % |
| run 9a s7 q8_0 (more composition frames) | 100.0 % | 92.2 % | 1.8 % | 1.4 % | 100.0 % | 98.8 % |
| run 9a s7 Q4_K_M | 100.0 % | 85.5 % | 5.3 % | 1.8 % | 97.2 % | 97.7 % |
| run 9a s42 q8_0 | 100.0 % | 91.8 % | 2.1 % | 3.4 % | 97.2 % | 98.8 % |
| run 9a s42 Q4_K_M | 97.0 % | 83.2 % | 6.0 % | 3.5 % | 83.3 % | 93.4 % |
| run 10 s7 q8_0 (compact v0.2, constrained) | 100.0 % | 94.3 % (strict 93.1 %) | 2.7 % | 0.7 % | 97.2 % | 97.9 % |
| run 10 s7 Q4_K_M | 100.0 % | 93.4 % (strict 92.2 %) | 2.5 % | 0.9 % | 100.0 % | 98.2 % |
| run 10 s42 q8_0 | 100.0 % | 93.1 % (strict 91.7 %) | 3.0 % | 0.7 % | 100.0 % | 97.3 % |
| run 10 s42 Q4_K_M | 100.0 % | 87.6 % (strict 86.4 %) | 6.4 % | 1.4 % | 86.1 % | 95.7 % |
| run 11 s7 q8_0 (compact with `missing`) | 100.0 % | 94.9 % (strict 93.4 %) | 2.5 % | 0.5 % | 86.1 % | 98.6 % |
| run 11 s7 Q6_K | 100.0 % | 95.4 % (strict 94.0 %) | 2.7 % | 0.4 % | 94.4 % | 98.8 % |
| run 11 s7 Q5_K_M | 100.0 % | 92.9 % (strict 91.5 %) | 4.1 % | 0.7 % | 91.7 % | 98.2 % |
| run 11 s7 Q4_K_M | 100.0 % | 88.3 % (strict 87.4 %) | 8.0 % | 1.4 % | 94.4 % | 97.7 % |
| run 11 s42 q8_0 | 100.0 % | 91.8 % (strict 90.4 %) | 4.8 % | 0.5 % | 100.0 % | 97.9 % |
| run 11 s42 Q6_K | 100.0 % | 90.4 % (strict 89.0 %) | 4.8 % | 0.4 % | 100.0 % | 96.6 % |
| run 11 s42 Q5_K_M | 100.0 % | 88.3 % (strict 86.9 %) | 5.3 % | 0.4 % | 97.2 % | 95.2 % |
| run 11 s42 Q4_K_M | 100.0 % | 86.2 % (strict 84.8 %) | 8.9 % | 2.3 % | 94.4 % | 96.8 % |

Run 9a (more composition paraphrase families, same v0.1 output) lifts compositions on both seeds but loses on
Q4_K_M, the phone artifact, including 17 malformed replies for seed 42; run 8 stays deployed. About a quarter of the
remaining failures are language labels on strings that are identical in German and Swiss German ("Such plan.odt in
Documents"); the gate will accept either language for such strings. Next: the compact output with catalog-constrained
decoding (13e part B), then run 10.

Run 10 trains on the compact v0.2 proposal and is served with the catalog grammar. The run uses the same frozen blind
set (`--frozen-blind`; the manifest pins its digest), and train and dev never contain a blind utterance:
- Replies are half as long: 28 instead of 57 tokens, 213 instead of 487 ms of generation on the desktop GPU.
- Unintended actions fall from 3.4 to 0.7 %.
- q8_0 beats run 8 on both seeds.
- Q4_K_M depends on the seed: 93.4 % for seed 7 and 87.6 % for seed 42.

Choosing the seed on dev (Q4_K_M through the Core: seed 7 92.3 %, seed 42 94.0 %) picks seed 42, which is below run 8
on blind. Run 8 stays deployed.

The cause is visible per bucket. Without `missing_slots` and the clarification question, the compact form invents
values for absent required slots:
- missing-slot utterances: 6 to 8 % invented on q8_0 and up to 14.9 % on Q4_K_M;
- run 8: 0 % and 1.1 %.

0017 L3a therefore puts `missing` back as the model's commitment before it writes slots. The grammar then forbids the
slots it names and requires the other required ones (L8). That change comes before run 11.

The Q4_K_M gap is not quantisation precision. For run 8 on blind v1:
- Q5_K_M (444 MB) scores 89.5 %.
- Q4_K_M with q8_0 token embeddings (434 MB) scores 89.0 %.
- Q4_K_M with an importance matrix from 300 training records scores 87.1 %, with 6.4 % invented slots.

All three are at or below plain Q4_K_M (397 MB, 89.4 %). The phone keeps plain Q4_K_M, and the lever is constrained
decoding. (Run 11 differs: there Q6_K is clearly better than Q4_K_M, see above.)

Run 11 trains the compact form with `missing` (0017 L3a), on the same frozen blind set. It does not reach the phone:
- Dev (through the Core) selects seed 42 at Q6_K: 94.5 % against 94.0 % for seed 7. On blind that gives 90.4 %, but
  13.7 % of missing-slot utterances get an invented value (run 8: 1.1 %). Run 8 stays deployed.
- For this model precision matters. Seed 7 goes from 88.3 % (Q4_K_M, 379 MB) to 92.9 % (Q5_K_M, 424 MB) and 95.4 %
  (Q6_K, 473 MB). Run 8 did not gain from Q5_K_M.
- Most inventions come from two held-out frames with a bare category noun and both required slots absent: "share the
  file" / "Teile die Datei" becomes `item: "the attached document"`, and "ändere die Einstellung" becomes `device: "the
  thermostat"`. Training has only "share that", "ich möchte etwas teilen" and "ändere eine Einstellung" for this case.
  The model writes one name into `missing` and fills the other slot.
- Not the cause: the grammar's fixed order of `missing`. A grammar that accepted every order gave the same replies on
  blind and dev for both seeds, so it was not kept.
- Blind v1 clusters: 24 of its 175 missing-slot records come from the share-the-file frames and 14 from the setting
  frames. A seed that misreads one frame loses several points, and the dev/blind seed ranking flips. Blind v1 has
  now been read at failure level. The next model change should be judged on a blind v2 with eval frames written
  before training.

Blind v2 (`out/gate-v2/`, frozen 2026-10-23 before run 12; 651 records from 203 paraphrase families, at most 9 per
family) adds four eval frames per intent in English and German and two in Swiss German, written before any model saw
them (commit 328452d). Records in blind v2: missing-slot 196. Run 8 is served the same records in its v0.1 form
(`linguist_blind.full.jsonl`); 15 of them occur in run 8's older training data. Dev v2 is the other half of the
new eval frames.

| on blind v2 | semantic | invented (all) | invented (missing-slot) | unintended | dev v2 |
|---|---|---|---|---|---|
| run 8 Q4_K_M (deployed) | 84.9 % | 4.5 % | 5.1 % | 5.5 % | - |
| run 11 s7 Q6_K | 90.0 % | 2.1 % | 1.0 % | 1.5 % | 86.9 % |
| run 11 s7 Q4_K_M | 86.3 % | 6.6 % | 9.7 % | 4.6 % | 84.6 % |
| run 11 s42 Q6_K | 85.6 % | 4.8 % | 7.1 % | 3.7 % | 85.3 % |
| run 12 s7 Q6_K | 89.5 % | 4.9 % | 6.1 % | 3.8 % | 87.7 % |
| run 12 s7 Q4_K_M | 84.2 % | 8.1 % | 12.8 % | 5.8 % | 83.5 % |
| run 12 s42 Q6_K | 90.0 % | 4.0 % | 3.6 % | 3.7 % | 84.3 % |
| run 12 s42 Q4_K_M | 88.9 % | 4.3 % | 2.0 % | 4.0 % | 82.7 % |

Run 12 adds training frames where a bare category noun gives no value ("Teile das Bild", "Find the PDF"; commit
e562842). Its rule was fixed before training: choose the seed on dev v2 at Q6_K, and ship only if that seed beats run 8
Q4_K_M on blind v2 by at least 1 point, invents on missing-slot utterances at most 1 point more than run 8, and has no
more unintended actions.
- Dev selects seed 7 (87.7 % against 84.3 %).
- Seed 7 at Q6_K: semantic 89.5 % (+4.6) and unintended actions 3.8 % (run 8: 5.5 %) pass. Missing-slot invention is
  12 of 196 records (6.12 %), and the limit is 6.10 % (run 8: 10 of 196). Run 12 does not ship, by one record.
- The seeds differ more than the data change does: seed 42 gains on every number, seed 7 loses invention against
  run 11.
- On blind v2, dev and blind rank run 11's seeds the same way, unlike on blind v1.

Next (rule fixed before measuring, 2026-10-23): average the merged weights of the two seeds of a run (a "model soup"),
which removes the seed choice. The candidate is the run 12 soup. It ships under run 12's rule, read on blind v2 at
Q6_K. Blind v2 has now been read for runs 11 and 12, at aggregate level only.

The run 12 soup (`out/qwen3-0.6b-linguist-r12-soup`: the bf16 average of seed 7 and seed 42 merged weights) passes that
rule and is the release candidate:

| run 12 soup | semantic | invented (all) | invented (missing-slot) | unintended | compositions | dev v2 |
|---|---|---|---|---|---|---|
| Q6_K (473 MB) | 90.6 % (strict 90.3 %) | 5.2 % | 4.6 % (9 of 196) | 4.6 % | 100.0 % | 88.5 % |
| q8_0 | 90.6 % | 5.4 % | 7.1 % | 4.5 % | - | 88.6 % |
| Q4_K_M | 88.0 % | 7.2 % | 8.7 % | 5.8 % | - | 87.8 % |

Against run 8 Q4_K_M on blind v2 it gains 5.7 points (German 76.8 to 91.7 %, compositions 68.9 to 100 %). Overall
invented slots are higher (5.2 against 4.5 %): on new phrasings the model picks a wrong intent and fills that
intent's slots ("Buzz me … about X" as a message, "Pencil in Laura" as a message, "For my notes: …" as a summary).
Run 8 q8_0 scores 88.9 % on blind v2.

The companion now reads the form from the GGUF key `sidged.linguist.output` (0017 L3b). The soup files are stamped
`compact` with `gguf_output_form.py stamp`, which changed their digests (Q6_K `0fa313fbe60f5af8…`). The backup release
`models-2026-10-23-r12-soup` holds the unstamped files: stamping them again gives the same bytes. Q6_K latency on the
device: on a Galaxy S25 Ultra (debug APK, 2026-10-24) the owner measured about 1 s per utterance for four utterances
(run 6 with the full form: 1.2 to 1.7 s). Seen there: a dropped optional slot ("Timer für 5 Minute fürs zähnputze"
without `label`) and a lost recipient ("Schick das Bild a lea" asks for item and recipient).


Compositions fail on phrasings the training never saw ("check X and let Y know the results" collapses into one
message; "leite es an X" becomes `share.offer`). The blind unmatched phrases may overlap run 8's older training data,
so non-composition numbers are an upper bound for run 8.

The eval tables below (v4 to v8) use the legacy metric on splits that shared up to 23 normalised utterances with
training; they are history, not comparable with gate numbers.

### Swiss German as a tree

Swiss German frames may name dialect nodes (`<nicht>`, `<kannst_du>`, `<melde_dich>`, …) from
`dialect_lexicon.json`, which lists the forms per region: Bernese (`be`), Zurich (`zh`) and Basel (`bs`). One
utterance picks one region and realizes every node in it ("I schribe dr speter", "Ich schriib der spöter"),
so a single frame yields consistent regional variants and never a mix. Each (intent, language) cell walks its leaves
(frame × region) round-robin, so every frame and region is covered before any repeats; Swiss German cells get more
samples (`train_gsw_weight`). The eval report has a bucket per region (`region:be|zh|bs`, `gen` for frames without
nodes, `chat` for owner chat negatives).

Owner data stays local and only shapes weights and negatives:

```
# owner chat exports -> pseudonymous single utterances (owner/peer), PII and excluded terms dropped
python3 -I chat_split.py --out-dir out/chat --exclude-terms-file <terms> <chat exports>
# per-form evidence in SwissDial (CC BY-NC 4.0, local only) and the owner's chats; candidate forms
python3 -I dialect_evidence.py --out out/dialect/evidence.json --swissdial <sentences_ch_de_transcribed.json> \
    --chat out/chat/utterances.jsonl
```

`--dialect-profile out/dialect/evidence.json` weights each form by 1 + sqrt(occurrences), using the owner's chats for
the owner's region, so generated forms follow how the owner writes. The
committed lexicon is curated by hand; no corpus sentence reaches the repository or the training data.

```
python3 train_companion_linguist.py --i-approve-training \
    [--chat-negatives out/chat/utterances.txt --exclude-terms-file <terms>] [--dialect-profile out/dialect/evidence.json]
python3 train_companion_linguist.py --eval-only [same options, so the eval split is identical]
```

`--chat-negatives` optionally adds owner-supplied Swiss German chat lines as intent-null examples. They stay on the
training PC: the generated splits live in the ignored `out/` directory, and lines are dropped when an sdg.pii/1
detector matches, when they contain a request verb, or when they match a term from `--exclude-terms-file`.

GGUF for the node's local endpoint: `python <llama.cpp>/convert_hf_to_gguf.py out/qwen3-0.6b-linguist/merged --outtype q8_0
--outfile out/qwen3-0.6b-linguist/sidged-linguist-q8_0.gguf` (639 MB); see `companion/README.md` for serving it.
The GGUF declares the output form it was trained on (0017 L3b): `python3 -I gguf_output_form.py stamp --manifest
out/qwen3-0.6b-linguist/manifest.json <model.gguf>` writes `sidged.linguist.output` (`compact` for `target_format`
compact, else `full`) before the SHA-256 is taken; `release_gate.sh` stamps every export itself and refuses to gate a
GGUF whose key differs from the form of the blind split. The app and `serve-local-linguist.sh --workspace` set
`model.output` from the key.

Measured on the reference PC (RTX 5060 Ti), eval v4 (606 records, phrasings never trained on, full catalog, 60
owner chat negatives), effective = lang, intent and slots right:

| model | all | en | de | gsw | be | zh | bs | gen | train |
|---|---|---|---|---|---|---|---|---|---|
| run 2 (phrasebook of e30cec0) | 84.3 % | 91.7 % | 88.5 % | 78.2 % | 75.0 % | 75.4 % | 70.5 % | 77.1 % | 27 min, 2978 records |
| run 4 (dialect tree) | 92.4 % | 95.5 % | 91.7 % | 91.2 % | 98.3 % | 89.2 % | 90.2 % | 79.2 % | 25 min, 3888 records |

Eval v5 (same frames; reminder times are verbatim, 0017 X6), effective:

| model | all | en | de | gsw | be | zh | bs | gen | chat |
|---|---|---|---|---|---|---|---|---|---|
| run 4 (times translated by the model) | 88.9 % | 93.6 % | 88.5 % | 86.7 % | 90.0 % | 86.2 % | 85.7 % | 73.9 % | 95.0 % |
| run 5 (verbatim times) | 91.4 % | 92.9 % | 89.1 % | 91.8 % | 96.7 % | 90.8 % | 88.9 % | 82.6 % | 98.3 % |

Eval v6 (message topics and meeting timeframes are verbatim too; first-person hard negatives), effective, and the
hand-written probes (`linguist_probes.json`, 46 hard cases, `probe_linguist.py` against the served GGUF):

| model | all | en | de | gsw | be | zh | bs | gen | chat | probes q8_0 | probes Q4_K_M |
|---|---|---|---|---|---|---|---|---|---|---|---|
| run 5 (translated topics) | 83.2 % | 83.3 % | 81.4 % | 84.0 % | 84.6 % | 84.6 % | 74.6 % | 75.6 % | 98.3 % | 28/46 | |
| run 6, seed 7 | 88.8 % | 92.3 % | 86.5 % | 88.1 % | 87.7 % | 87.7 % | 80.9 % | 85.4 % | 98.3 % | 39/46 | |
| run 6, seed 42 | 93.1 % | 95.5 % | 94.2 % | 91.2 % | 89.2 % | 90.8 % | 90.5 % | 90.2 % | 95.0 % | 44/46 | 42/46 |

The two seeds of the same data differ by 4.3 points effective and 5 probes: one run says little, so a new data
change is judged on at least two seeds. The probes were written while the run 6 negatives were added, so they are
not a blind test. The phone weights (Q4_K_M, quantized from f16, 397 MB) lose two probes against q8_0 (0.9 s per
probe on the reference PC's CPU).

Eval v8 (669 records, adds 63 composition frames, 0017 §2c; the prompt lists the compositions) and 50 probes (four
compositions added), effective; run 8 trains on 4308 records (33 min):

| model | all | en | de | gsw | be | zh | bs | gen | chat | compositions | probes q8_0 | probes Q4_K_M |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| run 6, seed 42 (no composition frames) | 82.7 % | 85.6 % | 84.5 % | 80.1 % | 88.1 % | 85.9 % | 83.3 % | 51.4 % | 95.0 % | 0.0 % | 45/50 | |
| run 8, seed 42 | 91.3 % | 92.5 % | 90.8 % | 91.0 % | 91.0 % | 90.6 % | 90.0 % | 92.9 % | 90.0 % | 93.6 % | 46/50 | |
| run 8, seed 7 (deployed) | 92.5 % | 91.4 % | 93.7 % | 92.5 % | 95.5 % | 87.5 % | 90.0 % | 92.9 % | 96.7 % | 84.1 % | 47/50 | 46/50 |

Run 6 never proposes a follow-up (all three composition probes fail on `then`); both run 8 seeds pass them. Seed 7
is deployed for the higher overall and probe score; seed 42 is better on composition frames (93.6 % vs. 84.1 %) but
fails four first-person and reminder probes. Q4_K_M (quantized from f16, 397 MB, SHA-256 `ef5b9420…`) loses one probe
against q8_0, 0.95 s per probe on the reference PC's CPU.

Run 4 is accepted unchanged by the Core in 99.7 % of cases; greedy decoding ~17 generated tokens/s on the CPU,
about 1 to 1.5 s per utterance behind llama-server. Length-grouped batches made training about 30 % faster per
record. Caveat: the regional eval frames are new structures, but their dialect words come from the same lexicon as
training; `gen` (older eval frames without nodes) moved little. Known limits: the model can fill a slot the
utterance leaves open ("Teil d Datei" → "the file"); topics are copied since run 6, but a short topic can still be cut ("Velo id Reparatur bringe" → "Velo id
Reparatur", run 8 also on q8_0) or dropped; "Chasch di bi Anna mäude wäg morn?" is not recognized; questions about messages ("Hesch mini Nachricht gseh?") are read as a send. Times
are no longer translated (run 5): the node resolves the words (0017 X6). Neither reaches a
consequential step unconfirmed: the Core re-derives the envelope and every consequential step still needs Trusted UI
approval.
