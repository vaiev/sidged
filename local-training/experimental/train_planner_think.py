# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Bounded-Thinking VKR-L3 Plan Architect & Self-Repair LoRA trainer (Model 1).

Trains Qwen/Qwen3-0.6B with concise <think>...</think> traces (40-80 tokens)
followed by a strict VKR-L3 v0.1 JSON plan (call, expr, map, budget, approval)
or a self-repaired plan when given a deterministic verifier refusal
(e.g. data-class-forbidden or missing approval).

Designed so the resulting merged model or ~25 MB LoRA adapter runs fast even on
pure CPU (zero GPU required at inference time) while respecting all 9 Vaikor
security invariants.
"""
import argparse
import inspect
import json
import os
import pathlib
import random
import sys

# Archived in experimental/; the shared helpers live one directory up.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import seeding  # noqa: E402

SYSTEM_PROMPT = (
    "You are Vaikor Model 1 (Thinking Plan Architect). "
    "Reason briefly in <think>...</think> about capability effects, data_classes, "
    "Cedar flow rules (secrets and health.records cannot reach egress under default-flow), "
    "CEL expressions (no filter/map/all/exists macros), and consequential=true -> approval=true. "
    "Then output ONLY a valid VKR-L3 v0.1 JSON plan object with keys v, goal, and steps (and optional budget)."
)

TEMPLATES = [
    # 1. Calendar availability + approved message send (multi-step read -> expr -> egress)
    {
        "user": (
            "Goal: Propose a meeting slot next week to contact:bea\n"
            "Capabilities:\n"
            "- tag:vaikor.com,2026:capability:calendar.free_slots (effects=[read], data_classes=[calendar.availability], consequential=false, cost=free)\n"
            "- tag:vaikor.com,2026:capability:message.send (effects=[egress], data_classes=[communications.content], consequential=true, cost=free)"
        ),
        "think": (
            "1. Read free slots via tag:vaikor.com,2026:capability:calendar.free_slots (non-sensitive calendar.availability). "
            "2. Select slots with CEL expr free.slots (no macros). "
            "3. Send via tag:vaikor.com,2026:capability:message.send: effects=[egress], consequential=true requires approval=true. "
            "calendar.availability is non-sensitive so default-flow permits egress."
        ),
        "plan": {
            "v": "0.1",
            "goal": "Propose a meeting slot next week",
            "steps": [
                {
                    "id": "free",
                    "kind": "call",
                    "capability": "tag:vaikor.com,2026:capability:calendar.free_slots",
                    "args": {"range": {"lit": "next_week"}},
                },
                {
                    "id": "pick",
                    "kind": "expr",
                    "expr": "free.slots",
                },
                {
                    "id": "send",
                    "kind": "call",
                    "capability": "tag:vaikor.com,2026:capability:message.send",
                    "approval": True,
                    "args": {"to": {"lit": "contact:bea"}, "body": {"ref": "pick"}},
                },
            ],
        },
    },
    # 2. Public weather lookup + summary (metered with budget)
    {
        "user": (
            "Goal: Check Zurich weather and summarize\n"
            "Capabilities:\n"
            "- tag:vaikor.com,2026:capability:weather.lookup (effects=[egress], data_classes=[x-public.weather], consequential=true, cost=free)\n"
            "- tag:vaikor.com,2026:capability:model.complete (effects=[egress], data_classes=[x-public.weather], consequential=true, cost=0.01 CHF)"
        ),
        "think": (
            "1. Call tag:vaikor.com,2026:capability:weather.lookup with approval=true (consequential=true). "
            "2. Call tag:vaikor.com,2026:capability:model.complete referencing weather step with approval=true. "
            "3. model.complete is metered (0.01 CHF), so include budget.max = 0.02 CHF. "
            "x-public.weather is non-sensitive, permitted by default-flow."
        ),
        "plan": {
            "v": "0.1",
            "goal": "Check Zurich weather and summarize",
            "budget": {"max": {"amount": "0.02", "currency": "CHF"}},
            "steps": [
                {
                    "id": "wx",
                    "kind": "call",
                    "capability": "tag:vaikor.com,2026:capability:weather.lookup",
                    "approval": True,
                    "args": {"city": {"lit": "Zurich"}},
                },
                {
                    "id": "sum",
                    "kind": "call",
                    "capability": "tag:vaikor.com,2026:capability:model.complete",
                    "approval": True,
                    "args": {"prompt": {"ref": "wx"}},
                },
            ],
        },
    },
    # 3. Technocratic Self-Repair: sensitive health.records blocked from egress -> keep local!
    {
        "user": (
            "Goal: Summarize my health notes and share them\n"
            "Verifier Refusal: data-class-forbidden on step send1 (health.records.notes -> tag:vaikor.com,2026:capability:message.send)\n"
            "Capabilities:\n"
            "- tag:vaikor.com,2026:capability:notes.read (effects=[read], data_classes=[health.records.notes], consequential=false, cost=free)\n"
            "- tag:vaikor.com,2026:capability:notes.summarize_local (effects=[read], data_classes=[health.records.notes], consequential=false, cost=free)\n"
            "- tag:vaikor.com,2026:capability:message.send (effects=[egress], data_classes=[communications.content], consequential=true, cost=free)"
        ),
        "think": (
            "1. Verifier refused step send1 with data-class-forbidden because health.records.notes is sensitive and cannot reach egress capability tag:vaikor.com,2026:capability:message.send under default-flow. "
            "2. Repair plan by removing the egress step and only reading and summarizing locally via tag:vaikor.com,2026:capability:notes.summarize_local."
        ),
        "plan": {
            "v": "0.1",
            "goal": "Summarize health notes locally",
            "steps": [
                {
                    "id": "read",
                    "kind": "call",
                    "capability": "tag:vaikor.com,2026:capability:notes.read",
                    "args": {},
                },
                {
                    "id": "local_sum",
                    "kind": "call",
                    "capability": "tag:vaikor.com,2026:capability:notes.summarize_local",
                    "args": {"text": {"ref": "read"}},
                },
            ],
        },
    },
    # 4. Technocratic Self-Repair: secrets.token blocked from egress -> strip secret read!
    {
        "user": (
            "Goal: Send status update to contact:team\n"
            "Verifier Refusal: data-class-forbidden on step send1 (secrets.token -> tag:vaikor.com,2026:capability:message.send)\n"
            "Capabilities:\n"
            "- tag:vaikor.com,2026:capability:tasks.list (effects=[read], data_classes=[calendar.availability], consequential=false, cost=free)\n"
            "- tag:vaikor.com,2026:capability:message.send (effects=[egress], data_classes=[communications.content], consequential=true, cost=free)"
        ),
        "think": (
            "1. Spec 0013 R10 forbids secrets.* from ever reaching egress. "
            "2. Repair plan to read only tag:vaikor.com,2026:capability:tasks.list (non-sensitive calendar.availability) and send with approval=true."
        ),
        "plan": {
            "v": "0.1",
            "goal": "Send status update to team",
            "steps": [
                {
                    "id": "tasks",
                    "kind": "call",
                    "capability": "tag:vaikor.com,2026:capability:tasks.list",
                    "args": {"scope": {"lit": "today"}},
                },
                {
                    "id": "send1",
                    "kind": "call",
                    "capability": "tag:vaikor.com,2026:capability:message.send",
                    "approval": True,
                    "args": {"to": {"lit": "contact:team"}, "body": {"ref": "tasks"}},
                },
            ],
        },
    },
    # 5. Bounded Map step over prior list
    {
        "user": (
            "Goal: Fetch headlines for each feed item\n"
            "Capabilities:\n"
            "- tag:vaikor.com,2026:capability:feeds.list (effects=[read], data_classes=[public.web], consequential=false, cost=free)\n"
            "- tag:vaikor.com,2026:capability:worker.fetch (effects=[read], data_classes=[public.web], consequential=false, cost=free)"
        ),
        "think": (
            "1. Read feed list via tag:vaikor.com,2026:capability:feeds.list. "
            "2. Use a map step over feeds with bound=8 (1..32 allowed by 0003) and item=true argument."
        ),
        "plan": {
            "v": "0.1",
            "goal": "Fetch headlines for each feed item",
            "steps": [
                {
                    "id": "feeds",
                    "kind": "call",
                    "capability": "tag:vaikor.com,2026:capability:feeds.list",
                    "args": {},
                },
                {
                    "id": "fetch_each",
                    "kind": "map",
                    "over": {"ref": "feeds"},
                    "bound": 8,
                    "capability": "tag:vaikor.com,2026:capability:worker.fetch",
                    "args": {"url": {"item": True}},
                },
            ],
        },
    },
]


def build_dataset(out_path: pathlib.Path, per_template: int = 32, seed: int = 42):
    rng = random.Random(seed)
    records = []
    for tpl in TEMPLATES:
        for i in range(per_template):
            assistant = f"<think>\n{tpl['think']}\n</think>\n" + json.dumps(tpl["plan"], sort_keys=True)
            records.append(
                {
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": tpl["user"]},
                        {"role": "assistant", "content": assistant},
                    ]
                }
            )
    rng.shuffle(records)
    out_path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in records))
    return len(records)


def train_and_benchmark(base_model: str, revision: str, out_dir: pathlib.Path):
    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
    import time
    import torch
    from datasets import load_dataset
    from peft import LoraConfig, get_peft_model
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from trl import SFTConfig, SFTTrainer

    out_dir.mkdir(parents=True, exist_ok=True)
    data_path = out_dir / "planner_think_data.jsonl"
    n_rec = build_dataset(data_path, per_template=32, seed=42)
    print(f"Generated {n_rec} thinking-planner training records at {data_path}", flush=True)
    # Before the model and the adapter exist: LoRA init and data order are reproducible.
    seeds = seeding.seed_everything(42)
    (out_dir / "run.json").write_text(json.dumps(
        {"seeds": seeds, "library_versions": seeding.library_versions()}, indent=2, sort_keys=True) + "\n")

    tokenizer = AutoTokenizer.from_pretrained(base_model, revision=revision)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        revision=revision,
        dtype=torch.bfloat16,
        device_map="auto",
    )
    model.enable_input_require_grads()
    lora_cfg = LoraConfig(
        r=16,
        lora_alpha=32,
        lora_dropout=0.0,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora_cfg)

    def to_text(ex):
        # Preserve the explicit <think>...</think> + JSON structure in assistant content
        msgs = ex["messages"]
        text = (
            f"<|im_start|>system\n{msgs[0]['content']}<|im_end|>\n"
            f"<|im_start|>user\n{msgs[1]['content']}<|im_end|>\n"
            f"<|im_start|>assistant\n{msgs[2]['content']}<|im_end|>\n"
        )
        return {"text": text}

    ds = load_dataset("json", data_files=str(data_path), split="train").map(to_text)
    sft_kwargs = dict(
        output_dir=str(out_dir / "checkpoints"),
        dataset_text_field="text",
        per_device_train_batch_size=16,
        gradient_accumulation_steps=1,
        warmup_steps=5,
        max_steps=60,
        learning_rate=3e-4,
        weight_decay=0.01,
        lr_scheduler_type="cosine",
        optim="adamw_torch",
        bf16=True,
        seed=42,
        logging_steps=10,
        report_to="none",
    )
    sig = inspect.signature(SFTConfig.__init__).parameters
    if "max_seq_length" in sig:
        sft_kwargs["max_seq_length"] = 1024
    elif "max_length" in sig:
        sft_kwargs["max_length"] = 1024

    t0 = time.time()
    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=ds,
        args=SFTConfig(**sft_kwargs),
    )
    trainer.train()
    print(f"LoRA training finished in {time.time() - t0:.1f}s", flush=True)

    adapter_dir = out_dir / "lora_adapter"
    model.save_pretrained(str(adapter_dir), safe_serialization=True)
    merged_dir = out_dir / "merged"
    merged = model.merge_and_unload()
    merged.save_pretrained(str(merged_dir), safe_serialization=True)
    tokenizer.save_pretrained(str(merged_dir))

    # Pure CPU benchmark (proving zero-GPU feasibility!)
    print("=== Running Pure CPU Inference Benchmark (device='cpu', 0 GPU) ===", flush=True)
    cpu_model = AutoModelForCausalLM.from_pretrained(str(merged_dir), dtype=torch.bfloat16).to("cpu")
    cpu_model.eval()
    torch.set_num_threads(min(8, os.cpu_count() or 4))

    for idx, tpl in enumerate(TEMPLATES, 1):
        prompt = (
            f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n"
            f"<|im_start|>user\n{tpl['user']}<|im_end|>\n"
            f"<|im_start|>assistant\n"
        )
        inputs = tokenizer(prompt, return_tensors="pt").to("cpu")
        t_cpu = time.time()
        with torch.no_grad():
            out = cpu_model.generate(
                **inputs,
                max_new_tokens=220,
                do_sample=False,
                pad_token_id=tokenizer.eos_token_id,
            )
        dt_cpu = time.time() - t_cpu
        n_tok = out[0].shape[0] - inputs["input_ids"].shape[1]
        reply = tokenizer.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True).strip()
        has_think = "<think>" in reply and "</think>" in reply
        json_part = reply.split("</think>")[-1].strip() if "</think>" in reply else reply
        plan_obj = json.loads(json_part)
        assert plan_obj.get("v") == "0.1" and isinstance(plan_obj.get("steps"), list)
        print(
            f"  [CPU Case {idx}] has_think={has_think}, valid_vkr_l3_json=True, "
            f"steps={len(plan_obj['steps'])}, tokens={n_tok}, cpu_time={dt_cpu:.2f}s ({n_tok/dt_cpu:.1f} tok/s)",
            flush=True,
        )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-model", default="Qwen/Qwen3-0.6B")
    ap.add_argument("--revision", default="c1899de289a04d12100db370d81485cdf75e47ca")
    ap.add_argument("--out", type=pathlib.Path, default=pathlib.Path("local-training/out/qwen3-0.6b-planner-think"))
    args = ap.parse_args()
    train_and_benchmark(args.base_model, args.revision, args.out)


if __name__ == "__main__":
    main()
