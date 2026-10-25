# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Validate a companion linguist (Model -1) dataset. Stdlib only (plus the vaikor binary).

Each JSONL record is {"messages": [system, user, assistant]}. The system and user prompts
are exactly what the Rust Core renders for the record's utterance and catalog subset
(core_bridge.render_prompts, one batched call per form), and the assistant content is one
linguist envelope (v0.1) or compact proposal (v "0.2", 0017 L3a) that the Core accepts
unchanged (linguist.check_envelope, linguist.check_proposal) and whose intents are in the
shown subset. The system prompt must be the runtime instruction for that form. Residency, approval and grant keys are refused anywhere, as are IP
literals and every vkr.pii/1 detector (validate_dataset.detect).

Usage: python3 -I validate_dataset_linguist.py <data.jsonl>   (exit 1 on any error)
"""
import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import core_bridge  # noqa: E402
import linguist  # noqa: E402
import validate_dataset  # noqa: E402

MAX_BYTES = 64 * 1024 * 1024


def catalog_lines(catalog):
    """Each runtime catalog line (as the Core renders it) -> its intent id."""
    rendered = core_bridge.render_prompts([("x", [e["intent"]]) for e in catalog["intents"]])
    return {r["user"][len("Catalog:\n"):].split("\n", 1)[0]: e["intent"]
            for r, e in zip(rendered, catalog["intents"])}


def _shown(lines, user):
    """Intent ids of the catalog lines in a user prompt, or None if a line is not a catalog line."""
    if not user.startswith("Catalog:\n") or "\nUtterance: " not in user:
        return None, None
    head, utterance = user[len("Catalog:\n"):].rsplit("\nUtterance: ", 1)
    head = head.split("\nCompositions:\n", 1)[0]
    ids = [lines.get(line) for line in head.split("\n")]
    if None in ids or len(set(ids)) != len(ids):
        return None, utterance
    return ids, utterance


def _structure(record):
    if not isinstance(record, dict) or set(record) != {"messages"}:
        return "record keys must be exactly {'messages'}"
    messages = record["messages"]
    if (not isinstance(messages, list) or len(messages) != 3
            or [m.get("role") if isinstance(m, dict) else None for m in messages]
            != ["system", "user", "assistant"]):
        return "messages must be system, user, assistant roles in that order"
    if any(set(m) != {"role", "content"} or not isinstance(m["content"], str) for m in messages):
        return "each message has exactly role and a string content (keys)"
    return None


def is_compact(target):
    """Whether an assistant target is a compact proposal (v "0.2"); everything else is read as v0.1."""
    return isinstance(target, dict) and target.get("v") == linguist.PROPOSAL_V


def _target(record):
    try:
        return json.loads(record["messages"][2]["content"])
    except ValueError:
        return None


def check_records(catalog, records):
    """One list of errors per record (empty when the record is valid)."""
    lines = catalog_lines(catalog)
    parsed = {}
    for index, record in enumerate(records):
        if _structure(record) is None:
            parsed[index] = _shown(lines, record["messages"][1]["content"])
    # The prompt, compositions block included, must be exactly the one the Core renders.
    renderable = [i for i, (shown, utterance) in parsed.items()
                  if shown is not None and utterance.strip() and utterance == utterance.strip()]
    rendered = {}
    for compact in (False, True):
        batch = [i for i in renderable if is_compact(_target(records[i])) == compact]
        prompts = core_bridge.render_prompts([(parsed[i][1], parsed[i][0]) for i in batch], compact)
        rendered.update(zip(batch, prompts))
    return [_check(catalog, record, parsed.get(index), rendered.get(index)) for index, record in enumerate(records)]


def check_record(catalog, record):
    """Return a list of errors (empty when the record is valid)."""
    return check_records(catalog, [record])[0]


def _check(catalog, record, parsed, rendered):
    problem = _structure(record)
    if problem:
        return [problem]
    messages = record["messages"]
    errors = []
    shown, utterance = parsed
    if shown is not None and not utterance.strip():
        errors.append("empty utterance")
    elif rendered is None or rendered["user"] != messages[1]["content"]:
        errors.append("user prompt is not the runtime prompt for a catalog subset plus utterance")
        shown = None
    if rendered is not None and messages[0]["content"] != rendered["system"]:
        errors.append("system prompt is not the runtime system prompt")
    try:
        envelope = json.loads(messages[2]["content"])
    except ValueError:
        return errors + ["assistant content is not JSON"]
    if is_compact(envelope):
        if [k for k in envelope if k != "then"] != list(linguist.PROPOSAL_KEYS):
            errors.append("proposal keys must be exactly the compact proposal keys, in order")
        errors.extend(linguist.check_proposal(catalog, envelope))
    else:
        if isinstance(envelope, dict) and [k for k in envelope if k != "then"] != list(linguist.ENVELOPE_KEYS):
            errors.append("envelope keys must be exactly the linguist envelope keys, in order")
        errors.extend(linguist.check_envelope(catalog, envelope))
    if shown is not None and isinstance(envelope, dict):
        named = [envelope.get("intent")] + [f.get("intent") for f in envelope.get("then", []) if isinstance(f, dict)]
        for intent in named:
            if intent is not None and intent not in shown:
                errors.append(f"intent {intent!r} is not in the shown catalog")
    strings = [m["content"] for m in messages[:2]]
    validate_dataset._walk(envelope, "", errors, strings)
    for text in strings:
        for hit in validate_dataset.detect(text):
            errors.append(f"detector {hit} matches (no IP literals or personal data in training data)")
    return sorted(set(errors))


def check_file(catalog, path):
    path = pathlib.Path(path)
    if path.stat().st_size > MAX_BYTES:
        return [f"{path}: larger than {MAX_BYTES} bytes"]
    errors, records = [], []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                errors.append(f"line {number}: empty")
                continue
            try:
                records.append((number, json.loads(line)))
            except ValueError:
                errors.append(f"line {number}: not JSON")
    checked = check_records(catalog, [record for _, record in records])
    for (number, _), found in zip(records, checked):
        errors.extend(f"line {number}: {e}" for e in found)
    return sorted(errors, key=lambda e: int(e.split(":", 1)[0].split()[1]))


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("data")
    args = parser.parse_args(argv)
    errors = check_file(linguist.load_catalog(), args.data)
    for error in errors[:200]:
        print(error, file=sys.stderr)
    if errors:
        print(f"{len(errors)} error(s)", file=sys.stderr)
        return 1
    print("linguist dataset OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
