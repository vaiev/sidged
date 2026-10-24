# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Check the dialect lexicon against local corpora and propose missing forms. Stdlib only.

For every node form it counts whole-word occurrences in each corpus given:
  --swissdial FILE   SwissDial sentences_ch_de_transcribed.json (columns de, ch_be, ch_zh, ch_bs)
  --chat FILE        utterances.jsonl from chat_split.py (counted per speaker: owner, peer)
For single-word Standard German references it also lists candidate regional forms: words
that occur in the regional SwissDial sentence clearly more often when the German sentence
holds the reference word than overall (lift), not yet in the node.

The corpora stay local and their licences differ (SwissDial is CC BY-NC 4.0); the report
goes to an ignored directory and only counts and single words reach it. The committed
lexicon is curated by hand from it.

Usage: python3 -I dialect_evidence.py --out out/dialect/evidence.json [--swissdial F] [--chat F]
"""
import argparse
import collections
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
LEXICON_PATH = HERE / "dialect_lexicon.json"
WORD = re.compile(r"[\wäöüÄÖÜéèàÿ']+")
REGIONS = ("be", "zh", "bs")


def words(text):
    return [w.lower() for w in WORD.findall(text)]


def form_pattern(form):
    return re.compile(r"(?<![\wäöü])" + re.escape(form.lower()) + r"(?![\wäöü])")


def count_forms(lexicon, corpora):
    """{node: {region: {form: {corpus: count}}}}"""
    report = {}
    for node, entry in lexicon["nodes"].items():
        report[node] = {}
        for region in REGIONS:
            report[node][region] = {}
            for form in entry[region]:
                pattern = form_pattern(form)
                report[node][region][form] = {
                    name: sum(1 for text in texts if pattern.search(text)) for name, texts in corpora.items()}
    return report


def candidates(lexicon, swissdial, top=5, min_hits=5):
    """Regional words that co-occur with single-word German references (by lift)."""
    overall = {r: collections.Counter() for r in REGIONS}
    for row in swissdial:
        for r in REGIONS:
            overall[r].update(set(words(row.get(f"ch_{r}", ""))))
    total = len(swissdial) or 1
    out = {}
    for node, entry in lexicon["nodes"].items():
        refs = [d.lower() for d in entry["de"] if " " not in d]
        if not refs:
            continue
        rows = [row for row in swissdial if set(words(row["de"])) & set(refs)]
        if len(rows) < min_hits:
            continue
        out[node] = {}
        for r in REGIONS:
            hits = collections.Counter()
            for row in rows:
                hits.update(set(words(row.get(f"ch_{r}", ""))))
            known = {f.lower() for f in entry[r]}
            scored = []
            for word, n in hits.items():
                if n < min_hits or word in known:
                    continue
                lift = (n / len(rows)) / (overall[r][word] / total)
                if lift >= 3:
                    scored.append((round(lift, 1), n, word))
            out[node][r] = [w for _, _, w in sorted(scored, reverse=True)[:top]]
    return out


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    parser.add_argument("--lexicon", default=str(LEXICON_PATH))
    parser.add_argument("--swissdial")
    parser.add_argument("--chat")
    args = parser.parse_args(argv)
    lexicon = json.loads(pathlib.Path(args.lexicon).read_text(encoding="utf-8"))
    corpora, swissdial = {}, []
    if args.swissdial:
        swissdial = json.loads(pathlib.Path(args.swissdial).read_text(encoding="utf-8"))
        for r in REGIONS:
            corpora[f"swissdial:{r}"] = [row.get(f"ch_{r}", "").lower() for row in swissdial]
    if args.chat:
        rows = [json.loads(line) for line in pathlib.Path(args.chat).read_text(encoding="utf-8").splitlines()]
        for speaker in ("owner", "peer"):
            corpora[f"chat:{speaker}"] = [r["text"].lower() for r in rows if r["speaker"] == speaker and r["gsw"]]
    report = {"counts": count_forms(lexicon, corpora), "candidates": candidates(lexicon, swissdial),
              "corpus_sizes": {k: len(v) for k, v in corpora.items()}}
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    unseen = [f"{n}/{r}/{f}" for n, regions in report["counts"].items() for r, forms in regions.items()
              for f, c in forms.items() if not any(c.values())]
    print(f"{args.out}: {len(unseen)} forms without evidence: {', '.join(unseen)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
