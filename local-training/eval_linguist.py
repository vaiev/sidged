# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Model -1 release gate: evaluate the served linguist GGUF through the Rust Core. Stdlib only.

Every reply is judged by `sidged linguist-eval` (core_bridge), i.e. by the functions the
runtime runs: the prompt, the chat request (greedy, max_tokens and thinking off as at
runtime), the reply post-processing and verify_proposal_for. Python only counts.

Metrics per bucket (all, kind, lang, region), each a share of the bucket's n unless noted:
  core_accepted               the Core accepts the reply (corrected or not); the rest is refused,
                              counted per stage in refused (utterance, model, envelope, derive)
  accepted_unchanged          accepted without any correction
  semantic_accuracy_accepted  among accepted replies: what the Core keeps has the expected
                              lang, intent, follow-ups and exactly the expected slots
  semantic_ok                 accepted and semantically right (end to end); the language is right
                              when it is one of the record's langs (meta sidecar): an utterance
                              German and Swiss German write the same may be either
  semantic_ok_lang_strict     semantic_ok with exactly the language the record was generated in
                              (column lang_strict)
  invented_slots              the Core keeps a slot the utterance does not give
  unintended_actions          the Core would go on to plan an intent or slots nobody asked for
  clarification_ok            the Core asks back exactly when it should
  clarification_asked         share of clarification_needed_n where the Core asks back
  legacy_effective            OLD METRIC, comparison only: the raw reply's lang, intent, slots
                              and follow-ups equal the target, even when the Core refuses it

A split built with --format compact (0017 L3a) is served with the compact request (the
compact instruction and the catalog decoding schema, L8): --compact with --socket, or
model.output "compact" in the --config. The served form must be the split's form.

Usage (lead PC; llama-server started by scripts/serve-local-linguist.sh <model.gguf>):
  python3 -I eval_linguist.py --data out/qwen3-0.6b-linguist/linguist_blind.jsonl \\
      --manifest out/qwen3-0.6b-linguist/manifest.json --gguf <model.gguf> \\
      --socket $XDG_RUNTIME_DIR/sidged/linguist.sock [--compact] [--out report.json]
  python3 -I eval_linguist.py --data <split.jsonl> --completions <recorded.jsonl>   (re-score)
"""
import argparse
import collections
import functools
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import core_bridge  # noqa: E402
import linguist  # noqa: E402
import make_dataset_linguist  # noqa: E402
import write_manifest  # noqa: E402

RATES = ("core_accepted", "accepted_unchanged", "semantic_ok", "semantic_ok_lang_strict", "invented_slots",
         "unintended_actions", "clarification_ok", "legacy_effective")


def load_jsonl(path):
    return [json.loads(line) for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def load_split(path):
    """(records, meta) of a generated split; meta is {} per record without a sidecar."""
    records = load_jsonl(path)
    sidecar = make_dataset_linguist.meta_path(path)
    meta = load_jsonl(sidecar) if sidecar.exists() else [{} for _ in records]
    if len(meta) != len(records):
        raise SystemExit(f"{sidecar}: {len(meta)} rows for {len(records)} records")
    return records, meta


def utterance_of(record):
    return record["messages"][1]["content"].rsplit("\nUtterance: ", 1)[1]


def expected_of(record):
    return json.loads(record["messages"][2]["content"])


@functools.lru_cache(maxsize=1)
def _catalog():
    return linguist.load_catalog()


def case_kind(expected):
    if expected.get("then"):
        return "composition"
    if expected["intent"] is None:
        return "intent-null"
    if expected.get("v") == linguist.PROPOSAL_V:
        expected = linguist.derive_proposal(_catalog(), expected)
    return "missing-slot" if expected["missing_slots"] else "complete"


def split_form(records):
    """"compact" or "full": the form every target of a split is in (a mixed split is refused)."""
    forms = {"compact" if expected_of(r).get("v") == linguist.PROPOSAL_V else "full" for r in records}
    if len(forms) != 1:
        raise SystemExit(f"the split mixes target forms {sorted(forms)}; refused")
    return forms.pop()


def config_form(path):
    """The output form a node config selects (model.output, default full)."""
    model = json.loads(pathlib.Path(path).read_text(encoding="utf-8")).get("model")
    return model.get("output", "full") if isinstance(model, dict) else "full"


def gate_expected(record, meta=None):
    """The expectation the Core scores against: the target, with the sidecar's langs (the
    target's own language first) as the accepted languages when the sidecar has them."""
    expected = expected_of(record)
    langs = (meta or {}).get("langs")
    if langs is None:
        return expected
    if not isinstance(langs, list) or not langs or langs[0] != expected["lang"]:
        raise SystemExit(f"meta langs {langs!r} do not start with the target language {expected['lang']!r}")
    return dict(expected, lang=langs)


def score_completions(records, completions, meta=None):
    """Core verdicts for recorded replies (Transformers check or a saved run)."""
    if len(records) != len(completions):
        raise ValueError(f"{len(completions)} completions for {len(records)} records")
    meta = meta if meta is not None else [{} for _ in records]
    return core_bridge.score([{"utterance": utterance_of(r), "completion": c, "expected": gate_expected(r, m)}
                              for r, c, m in zip(records, completions, meta)])


def serve_records(records, socket=None, config=None, compact=False, meta=None):
    """Ask the served model (runtime request) and judge each reply through the Core."""
    meta = meta if meta is not None else [{} for _ in records]
    return core_bridge.serve([{"utterance": utterance_of(r), "expected": gate_expected(r, m)}
                              for r, m in zip(records, meta)],
                             socket=socket, config=config, compact=compact)


def _buckets(expected, meta):
    out = ["all", f"kind:{case_kind(expected)}", f"lang:{expected['lang']}"]
    return out + ([f"region:{meta['region']}"] if meta.get("region") else [])


def aggregate(results, records, meta):
    """{bucket: metrics} from per-row Core results."""
    counts = collections.defaultdict(collections.Counter)
    refused = collections.defaultdict(collections.Counter)
    for result, record, m in zip(results, records, meta):
        flags = {
            "core_accepted": result["core_accepts"],
            "accepted_unchanged": result["core_accepts"] and not result["corrections"],
            "semantic_ok": result["semantic_ok"],
            "semantic_ok_lang_strict": result["semantic_ok"] and result["lang_strict_ok"] is not False,
            "invented_slots": bool(result["invented_slots"]),
            "unintended_actions": result["unintended_action"],
            "clarification_ok": result["clarification_ok"],
            "legacy_effective": result["legacy_effective"],
            "clarification_needed_n": result["clarification_expected"],
            "clarification_asked": result["clarification_expected"] and result["clarification_ok"],
        }
        for bucket in _buckets(expected_of(record), m):
            counts[bucket]["n"] += 1
            counts[bucket].update(key for key, value in flags.items() if value)
            if not result["core_accepts"]:
                refused[bucket][result["refusal"]["stage"]] += 1
    metrics = {}
    for bucket, c in sorted(counts.items()):
        row = {"n": c["n"]}
        row.update({key: round(c[key] / c["n"], 4) for key in RATES})
        row["semantic_accuracy_accepted"] = (round(c["semantic_ok"] / c["core_accepted"], 4)
                                             if c["core_accepted"] else None)
        row["clarification_needed_n"] = c["clarification_needed_n"]
        row["clarification_asked"] = (round(c["clarification_asked"] / c["clarification_needed_n"], 4)
                                      if c["clarification_needed_n"] else None)
        row["refused"] = dict(sorted(refused[bucket].items()))
        metrics[bucket] = row
    return metrics


def failures(results, records, limit=40):
    """Rows that are not semantically right, with the Core's reason."""
    out = []
    for result, record in zip(results, records):
        if not result["semantic_ok"] and len(out) < limit:
            out.append({"utterance": utterance_of(record), "expected": expected_of(record),
                        "completion": result["completion"], "refusal": result["refusal"],
                        "corrections": result["corrections"], "invented_slots": result["invented_slots"],
                        "missing_slots": result["missing_slots"], "wrong_slots": result["wrong_slots"],
                        "extra_followups": result["extra_followups"]})
    return out


def _pct(value):
    return "  -   " if value is None else f"{value:6.1%}"


def print_metrics(metrics, label):
    print(f"=== {label} ===", flush=True)
    print(f"  {'bucket':<20} {'n':>4} {'accept':>7} {'sem|acc':>7} {'sem':>7} {'lang_strict':>11} {'invent':>7} "
          f"{'unint':>7} {'clar':>7} {'asked':>7} | legacy_effective (old, not Core-checked)")
    for bucket, m in metrics.items():
        print(f"  {bucket:<20} {m['n']:>4} {_pct(m['core_accepted'])} {_pct(m['semantic_accuracy_accepted'])} "
              f"{_pct(m['semantic_ok'])} {_pct(m['semantic_ok_lang_strict']):>11} {_pct(m['invented_slots'])} "
              f"{_pct(m['unintended_actions'])} "
              f"{_pct(m['clarification_ok'])} {_pct(m['clarification_asked'])} | {_pct(m['legacy_effective'])}"
              + (f"  refused {m['refused']}" if m["refused"] else ""), flush=True)


def report(label, results, records, meta, **extra):
    metrics = aggregate(results, records, meta)
    print_metrics(metrics, label)
    return {"label": label, **extra, "metrics": metrics, "failures": failures(results, records)}


def check_manifest(data, manifest_path):
    """The split file must be the one whose digest the run manifest recorded."""
    manifest = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
    name = pathlib.Path(data).name
    recorded = [d for d in manifest.get("datasets", {}).values() if d.get("path") == name]
    if not recorded:
        raise SystemExit(f"{manifest_path}: no dataset {name}")
    if recorded[0]["digest"] != write_manifest.digest(data):
        raise SystemExit(f"{data}: SHA-256 differs from {manifest_path}; refused")


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data", required=True, type=pathlib.Path, help="a generated split (blind for the gate)")
    parser.add_argument("--manifest", help="run manifest; the split's SHA-256 must match it")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--socket", help="llama-server AF_UNIX socket (served under this uid)")
    source.add_argument("--config", help="a node config.json with model.endpoint")
    source.add_argument("--completions", help="JSONL {\"completion\": ...} per record, to re-score a saved run")
    parser.add_argument("--compact", action="store_true",
                        help="with --socket: send the compact request (0017 L3a, L8); a --config uses model.output")
    parser.add_argument("--gguf", help="the served GGUF, to record its SHA-256 in the report")
    parser.add_argument("--out", help="report JSON")
    args = parser.parse_args(argv)
    if args.manifest:
        check_manifest(args.data, args.manifest)
    records, meta = load_split(args.data)
    if args.completions:
        completions = [row["completion"] for row in load_jsonl(args.completions)]
        results, label = score_completions(records, completions, meta), f"recorded completions on {args.data.name}"
    else:
        if args.compact and not args.socket:
            parser.error("--compact goes with --socket; a --config selects the form with model.output")
        served = config_form(args.config) if args.config else ("compact" if args.compact else "full")
        if served != split_form(records):
            raise SystemExit(f"{args.data}: a {split_form(records)} split served as {served}; refused")
        results = serve_records(records, socket=args.socket, config=args.config, compact=args.compact, meta=meta)
        label = f"served model on {args.data.name} (runtime request through the Core)"
    extra = {"data": {"path": args.data.name, "digest": write_manifest.digest(args.data)},
             "gguf": {"path": pathlib.Path(args.gguf).name, "digest": write_manifest.digest(args.gguf)}
             if args.gguf else None}
    result = report(label, results, records, meta, **extra)
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    broken = sum(1 for r in results if r["refusal"] and r["refusal"]["stage"] == "model")
    if broken:
        print(f"{broken} row(s) got no model reply (stage model): the run is not a valid benchmark", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
