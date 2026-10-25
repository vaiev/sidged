# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Companion linguist (Model -1, lora-linguist-ch) LoRA trainer and training-time check.

Trains a bf16 LoRA on Qwen/Qwen3-0.6B (the base shared with Model 0 and Model 1) so
that one English, German or Swiss German utterance plus the intent catalog becomes one
linguist envelope (spec/schemas/linguist-envelope.schema.json), or with --format compact the
compact proposal the Core derives it from (linguist-proposal.schema.json, 0017 L3a). Loss is on the
completion only. The prompt is the runtime prompt, rendered by the Rust Core
(core_bridge, `vaikor linguist-eval render-prompt`), wrapped in the Qwen3 chat template
with thinking disabled.

Data: make_dataset_linguist.write_splits() writes train, dev and blind (split by paraphrase
family, deduplicated across splits); --frozen-blind keeps an earlier blind split and keeps
its utterances out of train and dev. The manifest records each file's SHA-256. Python
random, NumPy and Torch (CUDA included) are seeded before the model and the adapter exist;
the seeds and library versions go into the manifest.

The check after training is a TRAINING-TIME CHECK: the merged bf16 Transformers weights on
the dev split, greedy, with the runtime's max_tokens, without the runtime's decoding grammar
(compact form). It is not the shipped artifact. Every
reply is judged by the Rust Core (eval_linguist, `vaikor linguist-eval score`). The release
gate is eval_linguist.py on the blind split against the served GGUF.

Usage (user PC with GPU, after explicit approval):
  python3 train_companion_linguist.py --i-approve-training \
      [--chat-negatives FILE --exclude-terms-file FILE] [--dialect-profile FILE] [--out out/qwen3-0.6b-linguist]
      [--format compact] [--frozen-blind out/gate-v1/linguist_blind.jsonl]
  python3 train_companion_linguist.py --eval-only [--out ...]
"""
import argparse
import json
import os
import pathlib
import random
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import core_bridge  # noqa: E402
import eval_linguist  # noqa: E402
import linguist  # noqa: E402
import make_dataset_linguist  # noqa: E402
import seeding  # noqa: E402
import write_manifest  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
HYPERPARAMETERS = {
    "precision": "bf16",
    "lora_r": 16,
    "lora_alpha": 32,
    "lora_dropout": 0.05,
    "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    "per_device_train_batch_size": 16,
    "gradient_accumulation_steps": 1,
    "num_train_epochs": 2,
    "warmup_steps": 0.05,
    "learning_rate": 2e-4,
    "weight_decay": 0.01,
    "lr_scheduler_type": "cosine",
    "optim": "adamw_torch",
    "seed": 42,
    "max_length": 1536,
    "enable_thinking": False,
    "completion_only_loss": True,
    "train_sampling_strategy": "group_by_length",
    "train_per_cell": 70,
    "train_gsw_weight": 2.0,
    "eval_per_cell": 12,
    "eval_gsw_weight": 1.5,
    "data_seed": 42,
    "chat_negatives_train": 250,
    "chat_negatives_eval": 60,
}


def build_splits(args, out, tag=""):
    """Write, validate and leak-check train, dev and blind; return {split: path}."""
    catalog = linguist.load_catalog()
    phrasebook = linguist.load_json(args.phrasebook)
    exclude = make_dataset_linguist.load_exclude_terms(args.exclude_terms_file)
    lexicon = make_dataset_linguist.load_lexicon(profile=args.dialect_profile)
    h = HYPERPARAMETERS
    negatives = {}
    if args.chat_negatives:
        ranges = make_dataset_linguist.chat_ranges(h["chat_negatives_train"], h["chat_negatives_eval"])
        negatives = {split: make_dataset_linguist.chat_negatives(args.chat_negatives, count, random.Random("chat"),
                                                                exclude, skip)
                     for split, (skip, count) in ranges.items()}
    sizes = {"train": (h["train_per_cell"], h["train_gsw_weight"]),
             "dev": (h["eval_per_cell"], h["eval_gsw_weight"]),
             "blind": (h["eval_per_cell"], h["eval_gsw_weight"])}
    written = make_dataset_linguist.write_splits(out, catalog, phrasebook, h["data_seed"], sizes, negatives, lexicon,
                                                 exclude, tag, args.format, args.frozen_blind)
    return {split: path for split, (path, _) in written.items()}


def chat_prompt(tokenizer, messages):
    return tokenizer.apply_chat_template(
        messages[:2], tokenize=False, add_generation_prompt=True,
        enable_thinking=HYPERPARAMETERS["enable_thinking"])


def train(args, paths, out):
    import torch
    from datasets import load_dataset
    from peft import LoraConfig, get_peft_model
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from trl import SFTConfig, SFTTrainer

    h = HYPERPARAMETERS
    # Before the model and the adapter exist: LoRA init and data order are reproducible.
    seeds = seeding.seed_everything(h["seed"])
    tokenizer = AutoTokenizer.from_pretrained(args.base_model, revision=args.revision)
    model = AutoModelForCausalLM.from_pretrained(
        args.base_model, revision=args.revision, dtype=torch.bfloat16, device_map="cuda")
    model = get_peft_model(model, LoraConfig(
        r=h["lora_r"], lora_alpha=h["lora_alpha"], lora_dropout=h["lora_dropout"],
        target_modules=h["target_modules"], bias="none", task_type="CAUSAL_LM"))
    model.print_trainable_parameters()

    def to_pair(example):
        messages = example["messages"]
        return {"prompt": chat_prompt(tokenizer, messages),
                "completion": messages[2]["content"] + tokenizer.eos_token}

    dataset = load_dataset("json", data_files=str(paths["train"]), split="train")
    dataset = dataset.map(to_pair, remove_columns=dataset.column_names)
    config = SFTConfig(
        output_dir=str(out / "checkpoints"),
        per_device_train_batch_size=h["per_device_train_batch_size"],
        gradient_accumulation_steps=h["gradient_accumulation_steps"],
        num_train_epochs=h["num_train_epochs"],
        warmup_steps=h["warmup_steps"],
        learning_rate=h["learning_rate"],
        weight_decay=h["weight_decay"],
        lr_scheduler_type=h["lr_scheduler_type"],
        optim=h["optim"],
        bf16=True,
        seed=h["seed"],
        max_length=h["max_length"],
        completion_only_loss=h["completion_only_loss"],
        train_sampling_strategy=h["train_sampling_strategy"],
        logging_steps=10,
        save_strategy="no",
        report_to="none",
    )
    started = time.time()
    SFTTrainer(model=model, processing_class=tokenizer, train_dataset=dataset, args=config).train()
    print(f"LoRA training finished in {time.time() - started:.1f}s", flush=True)
    model.save_pretrained(str(out / "lora_adapter"), safe_serialization=True)
    merged = model.merge_and_unload()
    merged.save_pretrained(str(out / "merged"), safe_serialization=True)
    tokenizer.save_pretrained(str(out / "merged"))
    return seeds


def generate(out, records, device="cuda"):
    """Greedy replies of the merged Transformers weights (training-time check, not the GGUF)."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    merged = out / "merged"
    tokenizer = AutoTokenizer.from_pretrained(str(merged), padding_side="left")
    model = AutoModelForCausalLM.from_pretrained(str(merged), dtype=torch.bfloat16).to(device).eval()
    # The runtime's decoding: greedy, the max_tokens of linguist::chat_request.
    request = core_bridge.render_prompts([("x", None)])[0]["request"]
    if request["temperature"] != 0:
        raise SystemExit("the runtime request is not greedy; update the training-time check")
    replies, generated, started = [], 0, time.time()
    batch = 32 if device == "cuda" else 1
    for index in range(0, len(records), batch):
        chunk = records[index:index + batch]
        inputs = tokenizer([chat_prompt(tokenizer, r["messages"]) for r in chunk],
                           return_tensors="pt", padding=True).to(device)
        with torch.no_grad():
            output = model.generate(**inputs, max_new_tokens=request["max_tokens"], do_sample=False,
                                    pad_token_id=tokenizer.pad_token_id)
        for row in output[:, inputs["input_ids"].shape[1]:]:
            generated += int((row != tokenizer.pad_token_id).sum())
            replies.append(tokenizer.decode(row, skip_special_tokens=True))
    seconds = time.time() - started
    return replies, {"seconds": round(seconds, 1), "tokens_per_second": round(generated / seconds, 1)}


def evaluate(path, out, device="cuda", limit=None):
    records, meta = eval_linguist.load_split(path)
    records, meta = (records[:limit], meta[:limit]) if limit else (records, meta)
    replies, timing = generate(out, records, device)
    results = eval_linguist.score_completions(records, replies)
    label = f"TRAINING-TIME CHECK: merged bf16 Transformers weights on {pathlib.Path(path).name}, {device}"
    report = eval_linguist.report(label, results, records, meta, device=device, record_count=len(records),
                                   **timing)
    print(f"  {device}: {timing['tokens_per_second']} generated tok/s over {timing['seconds']}s", flush=True)
    return report


def write_provenance(args, paths, out, reports, seeds):
    scripts = [HERE / name for name in ("linguist.py", "core_bridge.py", "make_dataset_linguist.py",
                                        "validate_dataset_linguist.py", "eval_linguist.py", "seeding.py",
                                        "train_companion_linguist.py", "linguist_phrasebook.json",
                                        "dialect_lexicon.json")]
    manifest = {
        "v": "0.1",
        "kind": "model-training-provenance",
        "model": "lora-linguist-ch",
        "role": "Model -1 companion linguist",
        "base_model": {"id": args.base_model, "revision": args.revision,
                       "licence": write_manifest.LICENCES[args.base_model]},
        "catalog": {"path": "runtime/vaikor-cli/assets/intent-catalog.json",
                    "digest": write_manifest.digest(linguist.CATALOG_PATH)},
        "prompt_renderer": {"path": "vaikor", "command": "vaikor linguist-eval render-prompt",
                            "digest": write_manifest.digest(core_bridge.vaikor_binary())},
        "datasets": write_manifest.split_digests(paths),
        "splits": {"family_key": "(kind, owner, language, source text)",
                   "dedup": "case folded, punctuation and symbols stripped, whitespace collapsed; "
                            "blind kept whole, dev minus blind, train minus dev and blind",
                   "release_gate": "blind",
                   "frozen_blind": write_manifest.digest(args.frozen_blind) if args.frozen_blind else None},
        "target_format": args.format,
        "chat_negatives": "owner-local corpus, filtered, not distributed" if args.chat_negatives else None,
        "dialect_profile": "owner-local evidence counts, not distributed" if args.dialect_profile else None,
        "scripts": [{"path": s.name, "digest": write_manifest.digest(s)} for s in scripts],
        "hyperparameters": HYPERPARAMETERS,
        "seeds": seeds,
        "library_versions": seeding.library_versions(),
        "evaluation": {name: {k: v for k, v in r.items() if k != "failures"} for name, r in reports.items()},
    }
    (out / "manifest.json").write_text(write_manifest.dumps(manifest), encoding="utf-8")
    (out / "eval_report.json").write_text(json.dumps(reports, indent=2, ensure_ascii=False) + "\n",
                                          encoding="utf-8")


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-model", default="Qwen/Qwen3-0.6B", choices=sorted(write_manifest.LICENCES))
    parser.add_argument("--revision", default="c1899de289a04d12100db370d81485cdf75e47ca")
    parser.add_argument("--out", type=pathlib.Path, default=HERE / "out" / "qwen3-0.6b-linguist")
    parser.add_argument("--phrasebook", default=str(linguist.PHRASEBOOK_PATH))
    parser.add_argument("--chat-negatives", help="owner chat lines (one per line); never committed")
    parser.add_argument("--exclude-terms-file", help="one regex term per line; required with --chat-negatives")
    parser.add_argument("--dialect-profile", help="local evidence report (dialect_evidence.py); never committed")
    parser.add_argument("--i-approve-training", action="store_true")
    parser.add_argument("--eval-only", action="store_true",
                        help="training-time check of an existing merged model on the dev split; keeps its manifest")
    parser.add_argument("--cpu-samples", type=int, default=12, help="dev records for the CPU latency check")
    parser.add_argument("--seed", type=int, help="training seed (LoRA init and order); the data splits keep theirs")
    parser.add_argument("--format", choices=make_dataset_linguist.FORMATS, default="full",
                        help="target form: full v0.1 envelope or compact v0.2 proposal (0017 L3a)")
    parser.add_argument("--frozen-blind", type=pathlib.Path,
                        help="an earlier blind split kept as the blind split; train and dev never contain it")
    args = parser.parse_args(argv)
    if args.chat_negatives and not args.exclude_terms_file:
        parser.error("--chat-negatives needs --exclude-terms-file")
    if not args.eval_only and not args.i_approve_training:
        raise SystemExit("refused: pass --i-approve-training to confirm local training on this PC")
    if args.seed is not None:
        HYPERPARAMETERS["seed"] = args.seed
    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
    args.out.mkdir(parents=True, exist_ok=True)
    if args.eval_only:
        paths = build_splits(args, args.out, ".eval-only")
    else:
        paths = build_splits(args, args.out)
        seeds = train(args, paths, args.out)
    reports = {"gpu": evaluate(paths["dev"], args.out)}
    if args.cpu_samples:
        reports["cpu"] = evaluate(paths["dev"], args.out, device="cpu", limit=args.cpu_samples)
    if args.eval_only:
        (args.out / "eval_report.eval-only.json").write_text(
            json.dumps(reports, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    else:
        write_provenance(args, paths, args.out, reports, seeds)
    print("release gate: serve the GGUF (scripts/serve-local-linguist.sh) and run eval_linguist.py on "
          f"{paths['blind']}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
