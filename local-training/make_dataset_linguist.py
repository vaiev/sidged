# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Build the companion linguist (Model -1) dataset from the intent catalog. Stdlib only (plus the vaikor binary).

Every target is derived from the runtime intent catalog by linguist.derive_envelope(),
so labels follow the Core rules by construction. The phrasebook only supplies surface
forms: frames with {slot} placeholders and value pools (canonical English plus en / de /
gsw surface forms). Which slots a frame names decides which required slots are missing,
so clarification cases come from the schema, not from hand-written answers. Every prompt
is rendered by the Rust Core (core_bridge.render_prompts), byte for byte the runtime prompt.
--format compact writes the compact v0.2 proposal (0017 L3a: v, lang, intent, slots, then)
as the target, under the compact instruction; the default full writes the v0.1 envelope.
Both forms hold the same records and the same content.

Three splits, by paraphrase family. A family is one phrasebook source text with all its
realizations (slot values, dialect regions, chat noise); its key is (kind, owner, language,
source text): kind frame, composition or unmatched; owner the intent id, "first>then" for
a composition, "-" for unmatched phrases. A family never crosses splits:
  train  the phrasebook's frames and 3 of 5 unmatched phrases per language;
  dev    half of the eval_frames of each (intent, language) cell and of each composition,
         1 of 5 unmatched phrases; for training-time checks on the merged weights;
  blind  the other half, 1 of 5 unmatched phrases; the release gate on the served GGUF,
         never looked at while training.
Eval frames and unmatched phrases are assigned in SHA-256 order of the family key (blind
first), so the assignment is fixed by the phrasebook alone. After generation, utterances are
deduplicated across splits in a normalised form (case folded, punctuation and symbols
stripped, whitespace collapsed): blind is kept whole, dev drops what blind holds, train
drops what dev or blind hold. The blind file therefore depends only on the phrasebook, the
seed and its own size, and its SHA-256 goes into the run manifest.

Each record's meta names the languages its utterance may be in ("langs", its own first):
German and Swiss German sometimes write the same string ("Such report.pdf in Documents"), and
record_langs() adds the other one when that language's frames (or unmatched phrases), pool
surfaces, lexicon forms and greetings can write the same normalised utterance for the same
target. The gate accepts any of them; targets keep their single generated language.

Train prompts show a shuffled subset of the catalog; sometimes the matching intent is left
out and the target becomes intent null, so the model learns to choose from the catalog it
is given. Dev and blind prompts always show the full catalog, as at runtime.

Swiss German is generated as a tree: a gsw frame or pool value may name dialect nodes
(<node>, dialect_lexicon.json). Each utterance picks one region (be, zh, bs) and realizes
every node in it, so one frame yields consistent Bernese, Zurich and Basel variants. Each
(intent, language) cell walks its leaves (frame x region) round-robin in a shuffled order,
so every frame and region is covered before any repeats; Swiss German cells get
--gsw-weight times more samples. An optional local evidence report (dialect_evidence.py,
--dialect-profile) weights each form by how often it occurs in the local corpora.

Optional owner-supplied chat lines (--chat-negatives, never committed) become extra
Swiss German intent-null examples after filtering: no vkr.pii/1 detector hit, no request
verb, no term from --exclude-terms-file. The filtered lines are shuffled once and cut
into consecutive ranges: train, then dev, then blind.

Usage: python3 -I make_dataset_linguist.py --out-dir DIR [--seed 42] [--per-cell 40]
       [--eval-per-cell 12] [--gsw-weight 1.0] [--eval-gsw-weight 1.0] [--dialect-profile FILE]
       [--format full|compact]
       [--chat-negatives FILE --exclude-terms-file FILE [--chat-negatives-count 250]
        [--eval-chat-negatives-count 60]]
"""
import argparse
import hashlib
import itertools
import json
import pathlib
import random
import re
import sys
import unicodedata

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import core_bridge  # noqa: E402
import linguist  # noqa: E402
import validate_dataset  # noqa: E402
import validate_dataset_linguist  # noqa: E402

LEXICON_PATH = pathlib.Path(__file__).resolve().parent / "dialect_lexicon.json"
NODE = re.compile(r"<([a-z][a-z0-9_]*)>")
REGIONS = ("be", "zh", "bs")
OUT_OF_CATALOG = 0.08
UNMATCHED_PER_CELL = 1.0
COMPOSITION_PER_CELL = 0.5
SPLITS = ("train", "dev", "blind")
FORMATS = ("full", "compact")
HELD_OUT = ("blind", "dev")
AMBIGUOUS = ("de", "gsw")  # languages whose generators can write the same string
UNMATCHED_SHARE = 5  # of every 5 unmatched phrases (hash order): 1 blind, 1 dev, 3 train
AFFIXES = {
    "en": {"prefix": ["Hey, ", "Hi, ", "Okay, "], "suffix": [" please", " thanks", "!", " :)"]},
    "de": {"prefix": ["Hallo, ", "Hey, ", "Du, "], "suffix": [" bitte", " danke", "!", " :)"]},
    "gsw": {"prefix": ["Hoi, ", "Du, ", "Sorry, ", "Hey "], "suffix": [" bitte", " merci", " ^^", " :)", " 🙏", " xD"]},
}
# Chat lines that ask for something are not safe intent-null examples.
REQUEST_STEMS = re.compile(
    r"schick|schrib|schriib|shrib|schreib|erinner|such|find|mach|stell|teil|übersetz|notier|timer|plan|"
    r"termin|organis|programm|lueg|säg|sag|frag|chasch|chönn|chöntsch|hol|bring|bstell|buech|spiel|lüt|"
    r"send|share|remind|search|translate|note|code|fass|recherch|hilf|hälf|tue|gib|nimm|kauf|chouf|posch",
    re.IGNORECASE)
GSW_MARKERS = {"isch", "bisch", "hesch", "het", "hei", "ig", "nid", "ni", "öppis", "scho", "gsi", "eifach",
               "aues", "haut", "auso", "gloub", "chunt", "gö", "gah", "wei", "wosch", "wotsch", "odr", "u", "ds",
               "dr", "mir", "dir", "nüt", "nume", "o", "ou", "hüt", "morn", "gseh", "chume", "bi", "hie"}
TOKEN = re.compile(r"[\wäöüÄÖÜ']+")


def load_lexicon(path=LEXICON_PATH, profile=None, owner_region="be"):
    """Dialect nodes with per-form weights: 1 + sqrt(evidence) when a profile is given."""
    lexicon = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    counts = json.loads(pathlib.Path(profile).read_text(encoding="utf-8"))["counts"] if profile else {}
    nodes = {}
    for name, entry in lexicon["nodes"].items():
        nodes[name] = {}
        for region in REGIONS:
            weights = []
            for form in entry[region]:
                seen = counts.get(name, {}).get(region, {}).get(form, {})
                n = seen.get(f"swissdial:{region}", 0)
                if region == owner_region:
                    n += seen.get("chat:owner", 0) + seen.get("chat:peer", 0)
                weights.append(1.0 + n ** 0.5)
            nodes[name][region] = (entry[region], weights)
    return nodes


def realize(text, region, lexicon, rng):
    """Replace every <node> with one of its forms in region (a sentence-initial form is capitalized).

    Region "gen" (a frame without nodes) realizes a node-bearing pool value in a random region.
    """
    if region == "gen":
        region = rng.choice(REGIONS)

    def pick(match):
        forms, weights = lexicon[match.group(1)][region]
        form = rng.choices(forms, weights)[0]
        return form[:1].upper() + form[1:] if match.start() == 0 else form
    return NODE.sub(pick, text)


def _surface(entry, lang, rng, region=None, lexicon=None):
    """(surface, canonical) for one pool entry; a plain string is verbatim everywhere.

    Without a canonical value the entry is verbatim, so the canonical value is the realized surface.
    """
    if isinstance(entry, str):
        return entry, entry
    surface = rng.choice(entry[lang])
    if region is not None:
        surface = realize(surface, region, lexicon, rng)
    return surface, entry.get("canonical", surface)


def leaves(frames, lang):
    """The (frame, region) leaves of one cell: a Swiss German frame with nodes has one leaf per
    region, one without nodes the single leaf "gen"; other languages have no region."""
    out = []
    for frame in frames:
        if lang != "gsw":
            out.append((frame, None))
        elif NODE.search(frame):
            out.extend((frame, region) for region in REGIONS)
        else:
            out.append((frame, "gen"))
    return out


def walk(cell_leaves, n, rng):
    """n leaves, round-robin over shuffled passes, so every leaf is used before any repeats."""
    order = []
    while len(order) < n:
        batch = list(cell_leaves)
        rng.shuffle(batch)
        order.extend(batch)
    return order[:n]


def _pool_entries(phrasebook, pool_names, lang):
    entries = []
    for name in pool_names:
        for entry in phrasebook["pools"][name]:
            if isinstance(entry, str) or lang in entry:
                entries.append(entry)
    return entries


def _augment(text, lang, starts_with_slot, rng):
    """Chat-style noise: lower-case start, dropped punctuation, greetings and tails."""
    if not starts_with_slot and rng.random() < 0.3:
        text = text[:1].lower() + text[1:]
    if rng.random() < 0.3:
        text = text.rstrip("?.!")
    if rng.random() < 0.15:
        prefix = rng.choice(AFFIXES[lang]["prefix"])
        text = prefix + (text[:1].lower() + text[1:] if not starts_with_slot else text)
    if rng.random() < 0.15:
        text += rng.choice(AFFIXES[lang]["suffix"])
    return text


def _shown_intents(catalog, target, rng, full):
    """Intent ids the prompt shows: all of them (dev, blind, runtime) or a shuffled subset (train)."""
    ids = [entry["intent"] for entry in catalog["intents"]]
    if full:
        return ids
    drop_target = target is not None and rng.random() < OUT_OF_CATALOG
    others = [i for i in ids if i != target]
    k = rng.randint(min(2, len(others)), len(others))
    shown = rng.sample(others, k)
    if target is not None and not drop_target:
        shown.append(target)
    rng.shuffle(shown)
    return shown


def family_key(kind, owner, lang, text):
    """The paraphrase family of one phrasebook source text."""
    return "\x1f".join((kind, owner, lang, text))


def _rank(key):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def held_out_split(keys):
    """Eval-frame families of one group -> "blind" or "dev", alternating in hash order (blind first)."""
    return {key: HELD_OUT[i % 2] for i, key in enumerate(sorted(keys, key=_rank))}


def unmatched_split(keys):
    """Unmatched-phrase families of one language -> "blind", "dev" or "train" (1:1:3 in hash order)."""
    return {key: ("blind", "dev", "train", "train", "train")[i % UNMATCHED_SHARE]
            for i, key in enumerate(sorted(keys, key=_rank))}


def split_frames(split, kind, owner, book):
    """{lang: frames of this split} for one intent (kind "frame") or composition.

    An intent's eval frames are divided per language; a composition's across its languages,
    since it has one eval frame per language.
    """
    if split == "train":
        return {lang: list(frames) for lang, frames in book["frames"].items()}
    evals = book["eval_frames"]
    groups = [evals] if kind == "composition" else [{lang: frames} for lang, frames in evals.items()]
    chosen = set()
    for group in groups:
        keys = {family_key(kind, owner, lang, f): (lang, f) for lang, frames in group.items() for f in frames}
        chosen |= {keys[key] for key, assigned in held_out_split(keys).items() if assigned == split}
    # Phrasebook order, so the walk does not depend on hash order.
    return {lang: [f for f in frames if (lang, f) in chosen] for lang, frames in evals.items()}


def split_unmatched(split, phrasebook, lang):
    phrases = phrasebook["unmatched"][lang]
    assigned = unmatched_split([family_key("unmatched", "-", lang, p) for p in phrases])
    return [p for p in phrases if assigned[family_key("unmatched", "-", lang, p)] == split]


def normalise(text):
    """Dedup form of an utterance: case folded, punctuation and symbols stripped, whitespace collapsed."""
    kept = "".join(c for c in text.casefold() if unicodedata.category(c)[0] not in "PS")
    return " ".join(kept.split())


def _pending(catalog, utterance, lang, intent, slots, shown, then=()):
    """One record before rendering; the Core renders the prompts in one batch per split."""
    target = intent if intent in shown else None
    envelope = linguist.derive_with_then(catalog, lang, target, slots if target else {}, then if target else ())
    return {"utterance": utterance, "lang": lang, "shown": shown, "envelope": envelope}


def render(pending, fmt="full"):
    """Records with the exact runtime prompt for fmt (one call to the Rust Core for all of them)."""
    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt!r}; known: {', '.join(FORMATS)}")
    compact = fmt == "compact"
    catalog = linguist.load_catalog() if compact else None
    prompts = core_bridge.render_prompts([(p["utterance"], p["shown"]) for p in pending], compact)
    for p, prompt in zip(pending, prompts):
        if prompt["utterance"] != p["utterance"]:
            raise ValueError(f"the runtime trims this utterance: {p['utterance']!r}")
    return [{"messages": [
        {"role": "system", "content": prompt["system"]},
        {"role": "user", "content": prompt["user"]},
        {"role": "assistant",
         "content": linguist.dumps(linguist.compact(p["envelope"], catalog) if compact else p["envelope"])},
    ]} for p, prompt in zip(pending, prompts)]


def load_exclude_terms(path):
    if path is None:
        return None
    terms = [line.strip() for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines()
             if line.strip() and not line.startswith("#")]
    return re.compile("|".join(terms), re.IGNORECASE) if terms else None


def chat_negatives(path, count, rng, exclude=None, skip=0):
    """Swiss German chat lines that ask for nothing, filtered and shuffled deterministically.

    skip selects a disjoint slice (a range of the shuffled lines), so splits never share a line.
    """
    keep = set()
    with pathlib.Path(path).open(encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = " ".join(line.split())
            if not 8 <= len(line) <= 120 or "://" in line or "@" in line or "#" in line:
                continue
            tokens = [t.lower() for t in TOKEN.findall(line)]
            if len(tokens) < 3 or not GSW_MARKERS.intersection(tokens):
                continue
            if REQUEST_STEMS.search(line) or validate_dataset.detect(line):
                continue
            if exclude is not None and exclude.search(line):
                continue
            keep.add(line)
    pool = sorted(keep)
    rng.shuffle(pool)
    return pool[skip:skip + count]


def chat_ranges(train_count, eval_count):
    """(skip, count) per split: consecutive ranges of the shuffled chat lines."""
    return {"train": (0, train_count), "dev": (train_count, eval_count),
            "blind": (train_count + eval_count, eval_count)}


def _fill(phrasebook, pools, frame, lang, region, lexicon, rng):
    """(utterance text, canonical slot values) for one frame."""
    slots, canon = {}, {}

    def fill(match):
        name = match.group(1)
        if name not in slots:
            surface, canonical = _surface(
                rng.choice(_pool_entries(phrasebook, pools[name], lang)), lang, rng, region, lexicon)
            slots[name], canon[name] = surface, canonical
        return slots[name]

    text = linguist.PLACEHOLDER.sub(fill, frame)
    if region is not None:
        text = realize(text, region, lexicon, rng)
    return text, canon


def build_pending(catalog, phrasebook, split="train", seed=42, per_cell=40, negatives=(), gsw_weight=1.0,
                  lexicon=None):
    """Unrendered records and their meta ({"region", "family"}) for one split, before cross-split dedup."""
    if split not in SPLITS:
        raise ValueError(f"unknown split {split!r}; known: {', '.join(SPLITS)}")
    rng = random.Random(f"{split}:{seed}")
    lexicon = lexicon if lexicon is not None else load_lexicon()
    full = split != "train"
    rows = []
    for entry in catalog["intents"]:
        intent = entry["intent"]
        book = phrasebook["intents"][intent]
        frames = split_frames(split, "frame", intent, book)
        for lang in catalog["locales"]:
            n = round(per_cell * (gsw_weight if lang == "gsw" else 1.0))
            for frame, region in walk(leaves(frames[lang], lang), n, rng) if frames[lang] else ():
                text, canon = _fill(phrasebook, book["pools"], frame, lang, region, lexicon, rng)
                utterance = _augment(text, lang, frame.startswith("{"), rng)
                shown = _shown_intents(catalog, intent, rng, full)
                rows.append((_pending(catalog, utterance, lang, intent, canon, shown),
                             {"region": region, "family": family_key("frame", intent, lang, frame)}))
    # 0017 §2c: one utterance, two intents; both are always shown so the composition is listed.
    for comp in phrasebook.get("compositions", []):
        owner = f"{comp['first']}>{comp['then']}"
        frames = split_frames(split, "composition", owner, comp)
        for lang in catalog["locales"]:
            n = round(per_cell * COMPOSITION_PER_CELL * (gsw_weight if lang == "gsw" else 1.0))
            for frame, region in walk(leaves(frames[lang], lang), n, rng) if frames[lang] else ():
                text, canon = _fill(phrasebook, comp["pools"], frame, lang, region, lexicon, rng)
                utterance = _augment(text, lang, frame.startswith("{"), rng)
                first = {k: v for k, v in canon.items() if k in comp["slots"]["first"]}
                then = {k: v for k, v in canon.items() if k in comp["slots"]["then"]}
                shown = _shown_intents(catalog, comp["first"], rng, full)
                if comp["first"] not in shown:
                    shown.append(comp["first"])
                if comp["then"] not in shown:
                    shown.insert(rng.randrange(len(shown) + 1), comp["then"])
                rows.append((_pending(catalog, utterance, lang, comp["first"], first, shown, [(comp["then"], then)]),
                             {"region": region, "family": family_key("composition", owner, lang, frame)}))
    unmatched_n = max(1, round(per_cell * UNMATCHED_PER_CELL))
    for lang in catalog["locales"]:
        phrases = split_unmatched(split, phrasebook, lang)
        n = round(unmatched_n * (gsw_weight if lang == "gsw" else 1.0))
        for phrase, region in walk(leaves(phrases, lang), n, rng) if phrases else ():
            text = realize(phrase, region, lexicon, rng) if region is not None else phrase
            utterance = _augment(text, lang, False, rng)
            rows.append((_pending(catalog, utterance, lang, None, {}, _shown_intents(catalog, None, rng, full)),
                         {"region": region, "family": family_key("unmatched", "-", lang, phrase)}))
    for line in negatives:
        rows.append((_pending(catalog, line, "gsw", None, {}, _shown_intents(catalog, None, rng, full)),
                     {"region": "chat", "family": family_key("chat", "-", "gsw", line)}))
    rows = drop_conflicts(rows)
    rng.shuffle(rows)
    return rows


def build(catalog, phrasebook, split="train", seed=42, per_cell=40, negatives=(), gsw_weight=1.0,
          lexicon=None, with_meta=False, fmt="full"):
    """Rendered records of one split on its own (no cross-split dedup; see build_splits)."""
    lexicon = lexicon if lexicon is not None else load_lexicon()
    rows = build_pending(catalog, phrasebook, split, seed, per_cell, negatives, gsw_weight, lexicon)
    records = render([p for p, _ in rows], fmt)
    if not with_meta:
        return records
    cache = {}
    return records, [dict(m, langs=record_langs(phrasebook, lexicon, p["utterance"], p["envelope"], cache))
                     for p, m in rows]


def load_frozen(catalog, path):
    """(pending, meta) of a frozen held-out split in either form: its utterances and targets only.

    The prompt is rendered again, as the gate asks the runtime anyway; it shows the whole catalog."""
    path = pathlib.Path(path)
    pending = []
    for line in path.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        target = json.loads(record["messages"][2]["content"])
        envelope = linguist.derive_proposal(catalog, target) if target["v"] == linguist.PROPOSAL_V else target
        pending.append({"utterance": _utterance(record), "lang": envelope["lang"], "shown": None,
                        "envelope": envelope})
    meta = [json.loads(line) for line in meta_path(path).read_text(encoding="utf-8").splitlines()]
    if len(meta) != len(pending):
        raise SystemExit(f"{path}: {len(pending)} records but {len(meta)} meta lines")
    return pending, meta


def build_splits(catalog, phrasebook, seed=42, sizes=None, negatives=None, lexicon=None, fmt="full",
                 frozen_blind=None):
    """{split: (records, meta)} for train, dev and blind, deduplicated across splits.

    sizes: {split: (per_cell, gsw_weight)}; negatives: {split: [chat lines]}. Blind is built
    and kept first, so it does not depend on the train or dev settings. frozen_blind: a blind
    split written earlier (either form); it is kept as the blind split, re-rendered in fmt, and
    train and dev never contain its utterances, whatever the phrasebook became since.
    """
    sizes = sizes or {"train": (40, 1.0), "dev": (12, 1.0), "blind": (12, 1.0)}
    negatives = negatives or {}
    lexicon = lexicon if lexicon is not None else load_lexicon()
    out, taken, cache = {}, set(), {}

    def with_langs(pending, meta):
        return [dict(m, langs=record_langs(phrasebook, lexicon, p["utterance"], p["envelope"], cache))
                for p, m in zip(pending, meta)]

    if frozen_blind is not None:
        pending, meta = load_frozen(catalog, frozen_blind)
        taken = {normalise(p["utterance"]) for p in pending}
        out["blind"] = (render(pending, fmt), with_langs(pending, meta))
    for split in ("blind", "dev", "train"):
        if split in out:
            continue
        per_cell, gsw_weight = sizes[split]
        rows = build_pending(catalog, phrasebook, split, seed, per_cell, negatives.get(split, ()), gsw_weight,
                             lexicon)
        rows = [(p, m) for p, m in rows if normalise(p["utterance"]) not in taken]
        taken |= {normalise(p["utterance"]) for p, _ in rows}
        pending = [p for p, _ in rows]
        out[split] = (render(pending, fmt), with_langs(pending, [m for _, m in rows]))
    return {split: out[split] for split in SPLITS}


def _realizations(text, region, lexicon):
    """Every text realize() can make of text in region (None: verbatim)."""
    if region is None:
        return [text]
    parts = NODE.split(text)
    options = [[part] if i % 2 == 0 else lexicon[part][region][0] for i, part in enumerate(parts)]
    return ["".join(choice) for choice in itertools.product(*options)]


def _slot_options(phrasebook, pools, lang, regions, lexicon, want):
    """Surfaces _fill can give one slot in lang whose canonical value is want."""
    out = set()
    for entry in _pool_entries(phrasebook, pools, lang):
        if isinstance(entry, str):
            if entry == want:
                out.add(entry)
            continue
        for surface in entry[lang]:
            for region in regions:
                out.update(r for r in _realizations(surface, region, lexicon)
                           if entry.get("canonical", r) == want)
    return out


def _frame_texts(phrasebook, pools, frame, lang, region, lexicon, want):
    """Normalised texts _fill can make of one frame leaf whose canonical slots are exactly want."""
    names = linguist.PLACEHOLDER.findall(frame)
    if set(names) != set(want):
        return set()
    # A frame without nodes ("gen") realizes each pool value in a region of its own.
    regions = REGIONS if region == "gen" else (region,)
    options = {}
    for name in dict.fromkeys(names):
        options[name] = sorted(_slot_options(phrasebook, pools[name], lang, regions, lexicon, want[name]))
        if not options[name]:
            return set()
    texts = set()
    order = list(options)
    for values in itertools.product(*(options[name] for name in order)):
        chosen = dict(zip(order, values))
        filled = linguist.PLACEHOLDER.sub(lambda m: chosen[m.group(1)], frame)
        literal_region = None if region == "gen" else region
        texts.update(normalise(t) for t in _realizations(filled, literal_region, lexicon))
    return texts


def _target_texts(phrasebook, lexicon, lang, target):
    """Normalised texts (affixes aside) the lang generator can write for target (intent, slots, then)."""
    if target["intent"] is None:
        return {normalise(t) for phrase, region in leaves(phrasebook["unmatched"][lang], lang)
                for t in _realizations(phrase, None if region == "gen" else region, lexicon)}
    if target.get("then"):
        comp = next((c for c in phrasebook.get("compositions", []) if c["first"] == target["intent"]
                     and [c["then"]] == [f["intent"] for f in target["then"]]), None)
        if comp is None:
            return set()
        book = comp
        want = dict(target["slots"])
        for name, value in target["then"][0]["slots"].items():
            if want.setdefault(name, value) != value:
                return set()
    else:
        book = phrasebook["intents"].get(target["intent"])
        if book is None:
            return set()
        want = dict(target["slots"])
    frames = book["frames"].get(lang, []) + book.get("eval_frames", {}).get(lang, [])
    texts = set()
    for frame, region in leaves(frames, lang):
        texts |= _frame_texts(phrasebook, book["pools"], frame, lang, region, lexicon, want)
    return texts


def _written_by(texts, lang, utterance):
    """Whether utterance, normalised, is one of texts with an optional greeting and tail of lang."""
    norm = normalise(utterance)
    prefixes = {normalise(a) for a in AFFIXES[lang]["prefix"]} | {""}
    suffixes = {normalise(a) for a in AFFIXES[lang]["suffix"]} | {""}
    for prefix in prefixes:
        if prefix and not norm.startswith(prefix + " "):
            continue
        rest = norm[len(prefix):].strip()
        for suffix in suffixes:
            if suffix and not rest.endswith(" " + suffix):
                continue
            if (rest[:-len(suffix)].strip() if suffix else rest) in texts:
                return True
    return False


def record_langs(phrasebook, lexicon, utterance, target, cache=None):
    """The languages an utterance may be in for its target: its own first, then any other of
    AMBIGUOUS whose generator writes the same normalised string for the same target (intent,
    slots, follow-ups) from that language's frames (or unmatched phrases) and its lexicon forms."""
    langs = [target["lang"]]
    if target["lang"] not in AMBIGUOUS:
        return langs
    cache = {} if cache is None else cache
    for other in AMBIGUOUS:
        if other == target["lang"]:
            continue
        key = (other, json.dumps([target["intent"], target["slots"],
                                  [[f["intent"], f["slots"]] for f in target.get("then", [])]], sort_keys=True))
        if key not in cache:
            cache[key] = _target_texts(phrasebook, lexicon, other, target)
        if _written_by(cache[key], other, utterance):
            langs.append(other)
    return langs


def annotate(phrasebook, lexicon, records):
    """record_langs of every rendered record (either target form)."""
    cache = {}
    return [record_langs(phrasebook, lexicon, _utterance(r), json.loads(r["messages"][2]["content"]), cache)
            for r in records]


def _utterance(record):
    return record["messages"][1]["content"].rsplit("\nUtterance: ", 1)[1]


def drop_conflicts(rows):
    """Drop utterances that carry two different targets (e.g. the same words in two languages)."""
    seen = {}
    for pending, _ in rows:
        seen.setdefault(pending["utterance"], set()).add(pending["lang"])
    return [(p, m) for p, m in rows if len(seen[p["utterance"]]) == 1]


def write(path, records):
    """Write JSONL and return its SHA-256 (hex)."""
    data = "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in records).encode("utf-8")
    pathlib.Path(path).write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def meta_path(path):
    """Sidecar with one {"region", "family", "langs"} per record of a split."""
    path = pathlib.Path(path)
    return path.with_name(path.stem + ".meta.jsonl")


def write_splits(out_dir, catalog, phrasebook, seed, sizes, negatives=None, lexicon=None, exclude=None, tag="",
                 fmt="full", frozen_blind=None):
    """Build, write, validate and leak-check train, dev and blind; {split: (path, sha256 hex)}."""
    built = build_splits(catalog, phrasebook, seed, sizes, negatives, lexicon, fmt, frozen_blind)
    written = {}
    for split, (records, meta) in built.items():
        path = pathlib.Path(out_dir) / f"linguist_{split}{tag}.jsonl"
        digest = write(path, records)
        meta_path(path).write_text("".join(json.dumps(m, ensure_ascii=False) + "\n" for m in meta),
                                   encoding="utf-8")
        errors = validate_dataset_linguist.check_file(catalog, path)
        if errors:
            raise SystemExit(f"{path}: {len(errors)} validation error(s), first: {errors[0]}")
        if exclude is not None and exclude.search(path.read_text(encoding="utf-8")):
            raise SystemExit(f"{path}: an excluded term reached the data; refused")
        chat = sum(1 for m in meta if m["region"] == "chat")
        print(f"{split}: {len(records)} records ({chat} chat negatives) sha256 {digest}", flush=True)
        written[split] = (path, digest)
    return written


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out-dir", required=True, type=pathlib.Path)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--per-cell", type=int, default=40, help="train samples per intent and language")
    parser.add_argument("--eval-per-cell", type=int, default=12, help="dev and blind samples per intent and language")
    parser.add_argument("--gsw-weight", type=float, default=1.0, help="train sample factor for Swiss German cells")
    parser.add_argument("--eval-gsw-weight", type=float, default=1.0, help="dev and blind factor for Swiss German")
    parser.add_argument("--dialect-profile", help="local evidence report (dialect_evidence.py); never committed")
    parser.add_argument("--chat-negatives", help="owner chat lines (one per line); never committed")
    parser.add_argument("--chat-negatives-count", type=int, default=250, help="train chat lines")
    parser.add_argument("--eval-chat-negatives-count", type=int, default=60, help="chat lines for dev and for blind")
    parser.add_argument("--exclude-terms-file", help="one regex term per line; matching chat lines are dropped")
    parser.add_argument("--format", choices=FORMATS, default="full",
                        help="target form: full v0.1 envelope (default) or compact v0.2 proposal (0017 L3a)")
    parser.add_argument("--frozen-blind", type=pathlib.Path,
                        help="keep this earlier blind split (either form) and keep its utterances out of train and dev")
    args = parser.parse_args(argv)
    for per_cell in (args.per_cell, args.eval_per_cell):
        if not 1 <= per_cell <= 10000:
            parser.error("--per-cell and --eval-per-cell must be 1..10000")
    for weight in (args.gsw_weight, args.eval_gsw_weight):
        if not 0.5 <= weight <= 4:
            parser.error("--gsw-weight and --eval-gsw-weight must be 0.5..4")
    if args.chat_negatives and not args.exclude_terms_file:
        parser.error("--chat-negatives needs --exclude-terms-file")
    exclude = load_exclude_terms(args.exclude_terms_file)
    negatives = {}
    if args.chat_negatives:
        for split, (skip, count) in chat_ranges(args.chat_negatives_count, args.eval_chat_negatives_count).items():
            negatives[split] = chat_negatives(args.chat_negatives, count, random.Random("chat"), exclude, skip)
    sizes = {"train": (args.per_cell, args.gsw_weight), "dev": (args.eval_per_cell, args.eval_gsw_weight),
             "blind": (args.eval_per_cell, args.eval_gsw_weight)}
    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_splits(args.out_dir, linguist.load_catalog(), linguist.load_json(linguist.PHRASEBOOK_PATH), args.seed,
                 sizes, negatives, load_lexicon(profile=args.dialect_profile), exclude, fmt=args.format,
                 frozen_blind=args.frozen_blind)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
