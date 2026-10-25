# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""LoRA fine-tune of the local UI generator on the user's PC (turnkey WP f).

Runs ONLY on the user's own machine after explicit approval (v1 spec L1 item 3:
"only after explicit user approval; local training on the user PC only"):
it needs --i-approve-training, an interactive terminal, and the typed word
TRAIN. It never runs in CI. Heavy imports (torch, unsloth, trl, datasets)
happen only after consent, so this file can be syntax-checked and unit-tested
without them.

The trained model only proposes JSON tool calls; the Vaikor Core verifies
every proposal (0009 R1/R2). No timing figures are claimed: measure your own.

Usage:
  python3 experimental/train_edge_llm.py --dataset data.jsonl --base-model Qwen/Qwen3-0.6B \\
      --revision <40-hex commit> --out out/ --i-approve-training \\
      [--gguf-converter <llama.cpp checkout>/convert_hf_to_gguf.py]
"""
import argparse
import os
import pathlib
import subprocess
import sys

# Archived in experimental/; the shared helpers live one directory up.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import seeding  # noqa: E402
import validate_dataset  # noqa: E402
import write_manifest  # noqa: E402

HYPERPARAMETERS = {
    "precision": "bf16",
    "load_in_4bit": False,
    "max_seq_length": 2048,
    "lora_r": 32,
    "lora_alpha": 64,
    "lora_dropout": 0.0,
    "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    "per_device_train_batch_size": 16,
    "gradient_accumulation_steps": 2,
    "warmup_steps": 15,
    "max_steps": 180,
    "learning_rate": 3e-4,
    "weight_decay": 0.01,
    "lr_scheduler_type": "cosine",
    "optim": "adamw_torch",
    "seed": 42,
    "enable_thinking": False,
    "gguf_outtype": "q8_0",
}


def require_consent(flag, ask, tty):
    """Refuse unless the flag is given, stdin is a terminal and TRAIN is typed."""
    if not flag:
        raise SystemExit("refused: pass --i-approve-training to confirm local training on this PC")
    if not tty:
        raise SystemExit("refused: training needs an interactive terminal for the confirmation")
    answer = ask("This trains a model on THIS computer with the GPU. Type TRAIN to continue: ")
    if answer.strip() != "TRAIN":
        raise SystemExit("refused: confirmation not given")


def train(args):
    # Imported only after consent.
    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
    import inspect
    import torch
    from datasets import load_dataset
    from trl import SFTConfig, SFTTrainer

    h = HYPERPARAMETERS
    # Before the model and the adapter exist: LoRA init and data order are reproducible.
    seeds = seeding.seed_everything(h["seed"])
    use_unsloth = False
    try:
        from unsloth import FastLanguageModel
        use_unsloth = True
    except ImportError:
        from peft import LoraConfig, get_peft_model
        from transformers import AutoModelForCausalLM, AutoTokenizer

    if use_unsloth:
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=args.base_model,
            revision=args.revision,
            max_seq_length=h["max_seq_length"],
            dtype=torch.bfloat16,
            load_in_4bit=h["load_in_4bit"],
        )
        model = FastLanguageModel.get_peft_model(
            model,
            r=h["lora_r"],
            lora_alpha=h["lora_alpha"],
            lora_dropout=h["lora_dropout"],
            target_modules=h["target_modules"],
            use_gradient_checkpointing="unsloth",
            random_state=h["seed"],
        )
    else:
        tokenizer = AutoTokenizer.from_pretrained(args.base_model, revision=args.revision)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        model = AutoModelForCausalLM.from_pretrained(
            args.base_model,
            revision=args.revision,
            dtype=torch.bfloat16,
            device_map="auto",
        )
        model.enable_input_require_grads()
        lora_cfg = LoraConfig(
            r=h["lora_r"],
            lora_alpha=h["lora_alpha"],
            lora_dropout=h["lora_dropout"],
            target_modules=h["target_modules"],
            bias="none",
            task_type="CAUSAL_LM",
        )
        model = get_peft_model(model, lora_cfg)

    def to_text(example):
        text = tokenizer.apply_chat_template(
            example["messages"], tokenize=False, enable_thinking=h["enable_thinking"])
        return {"text": text}

    dataset = load_dataset("json", data_files=str(args.dataset), split="train").map(to_text)
    out = pathlib.Path(args.out)
    sft_kwargs = dict(
        output_dir=str(out / "checkpoints"),
        dataset_text_field="text",
        per_device_train_batch_size=h["per_device_train_batch_size"],
        gradient_accumulation_steps=h["gradient_accumulation_steps"],
        warmup_steps=h["warmup_steps"],
        max_steps=h["max_steps"],
        learning_rate=h["learning_rate"],
        weight_decay=h["weight_decay"],
        lr_scheduler_type=h["lr_scheduler_type"],
        optim=h["optim"],
        bf16=True,
        seed=h["seed"],
        logging_steps=10,
        report_to="none",
    )
    sig = inspect.signature(SFTConfig.__init__).parameters
    if "max_seq_length" in sig:
        sft_kwargs["max_seq_length"] = h["max_seq_length"]
    elif "max_length" in sig:
        sft_kwargs["max_length"] = h["max_seq_length"]
    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=dataset,
        args=SFTConfig(**sft_kwargs),
    )
    trainer.train()
    merged = out / "merged"
    if use_unsloth:
        model.save_pretrained_merged(str(merged), tokenizer, save_method="merged_16bit")
    else:
        merged_model = model.merge_and_unload()
        merged_model.save_pretrained(str(merged), safe_serialization=True)
        tokenizer.save_pretrained(str(merged))
    return merged, seeds


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dataset", required=True, type=pathlib.Path)
    parser.add_argument("--base-model", required=True, choices=sorted(write_manifest.LICENCES))
    parser.add_argument("--revision", required=True, help="40-hex commit of the base model")
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--gguf-converter", type=pathlib.Path,
                        help="convert_hf_to_gguf.py from your own llama.cpp checkout")
    parser.add_argument("--i-approve-training", action="store_true")
    args = parser.parse_args(argv)

    errors = validate_dataset.check_file(args.dataset)
    if errors:
        for error in errors[:50]:
            print(error, file=sys.stderr)
        raise SystemExit(f"refused: dataset has {len(errors)} error(s)")
    # Fail on a bad revision or base model before any download.
    write_manifest.build(args.base_model, args.revision, args.dataset, [__file__], HYPERPARAMETERS)
    require_consent(args.i_approve_training, input, sys.stdin.isatty())

    args.out.mkdir(parents=True, exist_ok=True)
    merged, seeds = train(args)
    gguf = None
    if args.gguf_converter:
        gguf = args.out / f"vaikor-edge-{HYPERPARAMETERS['gguf_outtype']}.gguf"
        subprocess.run(
            [sys.executable, str(args.gguf_converter), str(merged),
             "--outtype", HYPERPARAMETERS["gguf_outtype"], "--outfile", str(gguf)],
            check=True,
        )
    here = pathlib.Path(__file__).resolve().parent
    manifest = write_manifest.build(
        args.base_model, args.revision, args.dataset,
        [here.parent / "make_dataset.py", here / "train_edge_llm.py"], HYPERPARAMETERS, gguf)
    manifest["seeds"] = seeds
    manifest["library_versions"] = seeding.library_versions()
    (args.out / "manifest.json").write_text(write_manifest.dumps(manifest))
    print(f"wrote {args.out / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
