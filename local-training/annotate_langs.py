# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Write the languages each record of an existing split may be in (ROADMAP 13e). Stdlib only.

Some utterances are spelled the same in German and Swiss German ("Such report.pdf in Documents"):
the model cannot know which one was meant, so the gate accepts either. Which records those are
is decided by make_dataset_linguist.record_langs() from the phrasebook, the lexicon and each
record's own utterance and target, never from a model reply or owner data. This rewrites only the
split's .meta.jsonl sidecar, giving every line a "langs" member (the record's own language first);
the split file itself, and so its SHA-256, is left as it is. A sidecar whose line count differs
from the split's record count is refused.

Usage: python3 -I annotate_langs.py <split.jsonl>
"""
import argparse
import collections
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import linguist  # noqa: E402
import make_dataset_linguist  # noqa: E402


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("split", type=pathlib.Path, help="a generated split, e.g. the frozen linguist_blind.jsonl")
    args = parser.parse_args(argv)
    records = [json.loads(line) for line in args.split.read_text(encoding="utf-8").splitlines()]
    sidecar = make_dataset_linguist.meta_path(args.split)
    if not sidecar.exists():
        raise SystemExit(f"{sidecar}: no meta sidecar; refused")
    meta = [json.loads(line) for line in sidecar.read_text(encoding="utf-8").splitlines()]
    if len(meta) != len(records):
        raise SystemExit(f"{sidecar}: {len(meta)} meta lines for {len(records)} records; refused")
    langs = make_dataset_linguist.annotate(linguist.load_json(linguist.PHRASEBOOK_PATH),
                                           make_dataset_linguist.load_lexicon(), records)
    sidecar.write_text("".join(json.dumps(dict(m, langs=ls), ensure_ascii=False) + "\n"
                               for m, ls in zip(meta, langs)), encoding="utf-8")
    counts = collections.Counter("/".join(ls) for ls in langs if len(ls) > 1)
    print(f"{sidecar}: {len(records)} records, {sum(counts.values())} in more than one language "
          f"{dict(sorted(counts.items()))}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
