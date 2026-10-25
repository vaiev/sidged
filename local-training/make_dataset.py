# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Build the synthetic local-training dataset (turnkey WP f). Stdlib only.

Deterministic for a given seed: the same arguments give the same bytes. Only
the five v1 registry components and the ratified routes appear; no residency,
approval or grant fields (the Core supplies those), no IP literals, no
personal data. The model learns to *propose* a tool call; the Core decides.

Usage: python3 -I make_dataset.py --out data.jsonl [--seed 42] [--per-template 50]
"""
import argparse
import hashlib
import json
import pathlib
import random
import sys

SYSTEM_PROMPT = (
    "/no_think You are the Vaikor local UI generator. Reply with exactly one JSON object "
    '{"component": ..., "route": ..., "props": {...}} and nothing else. '
    "component is one of TaskList, CountdownWidget, NoteEditor, WebResult, CloudCallTrace. "
    "route is local-ui for TaskList, CountdownWidget and NoteEditor, worker-tool for WebResult, "
    "cloud:grok for CloudCallTrace. Your reply is a proposal: the Vaikor Core checks grants, "
    "policy, residency and approval. Never add fields for those."
)

TOPICS = ["den Umzug", "the release notes", "das Quartalsende", "a garden project",
          "die Steuererklärung", "the team offsite", "s Wuchenänd", "a bike repair"]
ITEMS = ["Liste machen", "call the landlord", "Kisten organisieren", "write a draft",
         "Termin abmachen", "check the budget", "Unterlagen sammeln", "send the summary",
         "Einkauf planen", "review open points"]
THINGS = ["Pause", "the oven", "Wäsche", "stand-up", "Tee", "the parking meter"]
NOTE_BODIES = ["Erste Ideen sammeln und morgen weiterschreiben.",
               "Open questions: scope, owner, next step.",
               "Kurz notiert, später ausformulieren.",
               "Keep it short; revisit after lunch."]
PAGES = ["docs/getting-started", "blog/winter-hiking", "news/local-events", "help/faq",
         "recipes/roesti", "guides/bike-maintenance"]
QUESTIONS = ["Explain how photosynthesis works in two sentences.",
             "Was ist der Unterschied zwischen Wetter und Klima?",
             "Summarise the rules of chess castling.",
             "Wie funktioniert ein Wärmepumpenboiler, einfach erklärt?"]


def _call(component, route, props):
    return json.dumps({"component": component, "route": route, "props": props},
                      ensure_ascii=False, sort_keys=True)


def _templates(rng):
    topic = rng.choice(TOPICS)
    count = rng.randint(2, 4)
    items = rng.sample(ITEMS, count)
    minutes = rng.choice([5, 10, 15, 20, 25, 30, 45])
    thing = rng.choice(THINGS)
    page = rng.choice(PAGES)
    question = rng.choice(QUESTIONS)
    body = rng.choice(NOTE_BODIES)
    return [
        (rng.choice([f"Plane mir {count} Aufgaben für {topic}.",
                     f"Make a task list with {count} items for {topic}."]),
         _call("TaskList", "local-ui", {"title": topic, "items": items})),
        (rng.choice([f"Erinnere mich in {minutes} Minuten an {thing}.",
                     f"Set a timer: {thing} in {minutes} minutes."]),
         _call("CountdownWidget", "local-ui", {"label": thing, "minutes": minutes})),
        (rng.choice([f"Schriib mer e Notiz zu {topic}.",
                     f"Open a note about {topic}."]),
         _call("NoteEditor", "local-ui", {"title": topic, "body": body})),
        (rng.choice([f"Hol mir den Inhalt von https://example.org/{page}.",
                     f"Fetch https://example.org/{page} with the worker."]),
         _call("WebResult", "worker-tool", {"url": f"https://example.org/{page}"})),
        (rng.choice([f"Frag Grok in der Cloud: {question}",
                     f"Ask Grok in the cloud: {question}"]),
         _call("CloudCallTrace", "cloud:grok", {"provider": "xai", "question": question})),
    ]


def build(seed=42, per_template=50):
    rng = random.Random(seed)
    records = []
    for _ in range(per_template):
        for user, assistant in _templates(rng):
            records.append({"messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user},
                {"role": "assistant", "content": assistant},
            ]})
    return records


def write(path, seed=42, per_template=50):
    """Write JSONL and return its SHA-256 (hex)."""
    data = "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n"
                   for r in build(seed, per_template)).encode("utf-8")
    pathlib.Path(path).write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--per-template", type=int, default=50)
    args = parser.parse_args(argv)
    if not 1 <= args.per_template <= 10000:
        parser.error("--per-template must be 1..10000")
    digest = write(args.out, args.seed, args.per_template)
    print(f"{args.out} sha256 {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
