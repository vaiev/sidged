# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Companion linguist (Model -1) contract shared by data, validation and evaluation. Stdlib only.

The linguist reads one utterance plus the intent catalog and proposes a
linguist envelope (spec/schemas/linguist-envelope.schema.json). Only lang,
intent and slots are its own judgement: everything else is derived from the
catalog with the same rules the Core applies (runtime/sidged-cli/src/linguist.rs);
derive_envelope() and derive_with_then() are pinned against the Rust rules by
runtime/sidged-cli/tests/fixtures/linguist-prompt.json. Prompts are not rendered
here: core_bridge.render_prompts() asks the Rust Core for the exact runtime prompt.

A model trained on the compact form (0017 L3a) proposes only v "0.2", lang, intent,
missing, slots and then (spec/schemas/linguist-proposal.schema.json); compact() and
derive_proposal() map between the two forms, check_proposal() applies the Core rules.
"""
import json
import pathlib
import re
import unicodedata

HERE = pathlib.Path(__file__).resolve().parent
CATALOG_PATH = HERE.parent / "runtime" / "sidged-cli" / "assets" / "intent-catalog.json"
PHRASEBOOK_PATH = HERE / "linguist_phrasebook.json"

ENVELOPE_KEYS = (
    "v", "lang", "intent", "slots", "missing_slots", "clarification_needed",
    "clarification_question_local", "canonical_intent_en", "suggested_route",
    "required_data_classes",
)
PROPOSAL_V = "0.2"
PROPOSAL_KEYS = ("v", "lang", "intent", "missing", "slots")
MAX_SLOT_CHARS = 512
CLARIFY = "clarify"
PLACEHOLDER = re.compile(r"\{([a-z][a-z0-9_]*)\}")


def load_json(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def load_catalog(path=CATALOG_PATH):
    return load_json(path)


def intents_by_id(catalog):
    return {entry["intent"]: entry for entry in catalog["intents"]}


def composition(catalog, first, then):
    return next((c for c in catalog.get("compositions", []) if c["first"] == first and c["then"] == then), None)


def canonical_text(entry, slots):
    """Fill the catalog template; a missing slot reads <slot>; optional extras follow in parentheses."""
    used = set(PLACEHOLDER.findall(entry["canonical_en"]))
    text = PLACEHOLDER.sub(lambda m: slots.get(m.group(1), f"<{m.group(1)}>"), entry["canonical_en"])
    extras = [f"{name}: {slots[name]}" for name in entry["slots_schema"]["properties"]
              if name in slots and name not in used]
    if extras:
        text += " (" + "; ".join(extras) + ")"
    return " ".join(text.split())


def derive_envelope(catalog, lang, intent, slots):
    """The envelope the Core accepts for (lang, intent, slots). Raises ValueError on unknown names."""
    if lang not in catalog["locales"]:
        raise ValueError(f"unknown locale {lang!r}")
    if intent is None:
        return dict(zip(ENVELOPE_KEYS, (
            "0.1", lang, None, {}, [], True, catalog["unknown_intent_ask"][lang], None, CLARIFY, [])))
    entry = intents_by_id(catalog).get(intent)
    if entry is None:
        raise ValueError(f"unknown intent {intent!r}")
    properties = entry["slots_schema"]["properties"]
    for name in slots:
        if name not in properties:
            raise ValueError(f"{intent}: unknown slot {name!r}")
    ordered = {name: slots[name] for name in properties if name in slots}
    missing = [name for name in entry["slots_schema"]["required"] if name not in ordered]
    question = properties[missing[0]]["x-ask"][lang] if missing else None
    return dict(zip(ENVELOPE_KEYS, (
        "0.1", lang, intent, ordered, missing, bool(missing), question,
        canonical_text(entry, ordered), CLARIFY if missing else entry["route"],
        list(entry["data_classes"]))))


FOLLOW_UP_KEYS = ("intent", "slots", "missing_slots", "canonical_intent_en")


def derive_with_then(catalog, lang, intent, slots, then=()):
    """derive_envelope plus the follow-ups of a declared composition (0017 §2c, K3)."""
    envelope = derive_envelope(catalog, lang, intent, slots)
    previous, follow_ups = intent, []
    for nxt, given in then:
        comp = composition(catalog, previous, nxt) if previous else None
        if comp is None:
            raise ValueError(f"composition {previous} -> {nxt} is not declared")
        entry = intents_by_id(catalog)[nxt]
        properties = entry["slots_schema"]["properties"]
        for name in given:
            if name not in properties:
                raise ValueError(f"{nxt}: unknown slot {name!r}")
        ordered = {name: given[name] for name in properties if name in given}
        missing = [n for n in entry["slots_schema"]["required"] if n not in ordered and n not in comp.get("satisfies", [])]
        if not envelope["missing_slots"] and all(not f["missing_slots"] for f in follow_ups) and missing:
            envelope["clarification_question_local"] = properties[missing[0]]["x-ask"][lang]
        if missing:
            envelope["clarification_needed"] = True
            envelope["suggested_route"] = CLARIFY
        for cls in entry["data_classes"]:
            if cls not in envelope["required_data_classes"]:
                envelope["required_data_classes"].append(cls)
        shown = dict(ordered)
        for slot in comp.get("satisfies", []):
            shown.setdefault(slot, "the previous result")
        follow_ups.append({"intent": nxt, "slots": ordered, "missing_slots": missing,
                           "canonical_intent_en": canonical_text(entry, shown)})
        previous = nxt
    if follow_ups:
        envelope["then"] = follow_ups
    return envelope


def dumps(envelope):
    """Compact JSON in key order (the order the model learns to generate in), for either form."""
    base = PROPOSAL_KEYS if envelope.get("v") == PROPOSAL_V else ENVELOPE_KEYS
    keys = base + (("then",) if envelope.get("then") else ())
    return json.dumps({key: envelope[key] for key in keys}, ensure_ascii=False, separators=(", ", ": "))


def grammar_order(catalog, intent, slots):
    """slots in the order the decoding grammar writes them (0017 L8): the required slots first, then
    the optional ones, each in catalog order (llama.cpp emits required members first)."""
    if intent is None:
        return dict(slots)
    schema = intents_by_id(catalog)[intent]["slots_schema"]
    names = list(schema["properties"])
    required = [n for n in names if n in schema.get("required", []) and n in slots]
    optional = [n for n in names if n not in schema.get("required", []) and n in slots]
    return {n: slots[n] for n in required + optional}


def compact(envelope, catalog):
    """The compact proposal (0017 L3a) with the content of a full envelope: v, lang, intent, missing
    (the required slots it does not give, committed before the slots), slots in grammar order, then."""
    proposal = {"v": PROPOSAL_V, "lang": envelope["lang"], "intent": envelope["intent"],
                "missing": list(envelope["missing_slots"]),
                "slots": grammar_order(catalog, envelope["intent"], envelope["slots"])}
    if envelope.get("then"):
        proposal["then"] = [{"intent": f["intent"], "slots": f["slots"]} for f in envelope["then"]]
    return proposal


def derive_proposal(catalog, proposal):
    """The envelope the Core derives from a compact proposal. Raises ValueError on unknown names."""
    then = [(f["intent"], f["slots"]) for f in proposal.get("then", [])]
    return derive_with_then(catalog, proposal["lang"], proposal["intent"], proposal["slots"], then)


def _bad_slots(slots):
    """Whether slots is not an object of non-empty strings of at most MAX_SLOT_CHARS without a
    control character: a value the Core would drop (0017 L4) is never a training target."""
    return not isinstance(slots, dict) or not all(
        isinstance(v, str) and v.strip() and len(v) <= MAX_SLOT_CHARS
        and not any(unicodedata.category(c) == "Cc" for c in v) for v in slots.values())


def check_proposal(catalog, proposal):
    """Problems of a compact proposal against the Core rules; empty means the Core accepts it unchanged."""
    if not isinstance(proposal, dict):
        return ["not a JSON object"]
    if set(proposal) - {"then"} != set(PROPOSAL_KEYS):
        return [f"keys must be exactly {', '.join(PROPOSAL_KEYS)} (and optionally then)"]
    if proposal["v"] != PROPOSAL_V:
        return [f"v must be {PROPOSAL_V!r}"]
    slots = proposal["slots"]
    if _bad_slots(slots):
        return [f"slots must map slot names to non-empty strings of at most {MAX_SLOT_CHARS} characters"]
    then = proposal.get("then", [])
    if "then" in proposal and (not isinstance(then, list) or not 1 <= len(then) <= 2
                               or not all(isinstance(f, dict) and set(f) == {"intent", "slots"} for f in then)):
        return ["then must be one or two follow-ups with exactly intent and slots"]
    for index, follow_up in enumerate(then):
        if not isinstance(follow_up["intent"], str):
            return [f"then[{index}].intent must be a catalog intent"]
        if _bad_slots(follow_up["slots"]):
            return [f"then[{index}].slots must map slot names to non-empty strings of at most "
                    f"{MAX_SLOT_CHARS} characters"]
    if proposal["intent"] is None and (slots or then):
        return ["intent null has no slots and no then"]
    missing = proposal["missing"]
    if not isinstance(missing, list) or not all(isinstance(n, str) for n in missing):
        return ["missing must be a list of slot names"]
    if set(missing) & set(slots):
        return ["a slot listed in missing is never given"]
    try:
        derived = derive_proposal(catalog, proposal)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        return [str(exc)]
    if missing != derived["missing_slots"]:
        return [f"missing must be {derived['missing_slots']} (the required slots not given, in catalog order)"]
    if list(slots) != list(grammar_order(catalog, proposal["intent"], slots)):
        return ["slots must come in grammar order: required first, then optional, each in catalog order"]
    return []


def check_envelope(catalog, envelope):
    """Problems of a proposed envelope against the Core rules; empty means the Core accepts it unchanged."""
    if not isinstance(envelope, dict):
        return ["not a JSON object"]
    if set(envelope) - {"then"} != set(ENVELOPE_KEYS):
        return [f"keys must be exactly {', '.join(ENVELOPE_KEYS)} (and optionally then)"]
    lang, intent, slots = envelope["lang"], envelope["intent"], envelope["slots"]
    if _bad_slots(slots):
        return [f"slots must map slot names to non-empty strings of at most {MAX_SLOT_CHARS} characters"]
    then = envelope.get("then", [])
    if "then" in envelope and (not isinstance(then, list) or not 1 <= len(then) <= 2
                               or not all(isinstance(f, dict) and set(f) <= set(FOLLOW_UP_KEYS) for f in then)):
        return ["then must be one or two follow-ups with intent and slots"]
    for index, follow_up in enumerate(then):
        if "slots" in follow_up and _bad_slots(follow_up["slots"]):
            return [f"then[{index}].slots must map slot names to non-empty strings of at most "
                    f"{MAX_SLOT_CHARS} characters"]
    try:
        expected = derive_with_then(catalog, lang, intent, slots, [(f["intent"], f["slots"]) for f in then])
    except (ValueError, TypeError, KeyError) as exc:
        return [str(exc)]
    keys = ENVELOPE_KEYS + (("then",) if "then" in envelope else ())
    return [f"{key}: expected {expected.get(key)!r}, got {envelope[key]!r}"
            for key in keys if envelope[key] != expected.get(key)]
