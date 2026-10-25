# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Split owner chat exports into single utterances for local use. Stdlib only.

Input: chat exports in the "dd.mm.yy, HH:MM - Sender: text" form, one file per chat.
Output (under --out-dir, which must be git-ignored; nothing here is ever committed):
  utterances.jsonl  {"chat": <8 hex>, "speaker": "owner"|"peer", "gsw": bool, "text": ...}
  utterances.txt    the Swiss German utterances, one per line (input for --chat-negatives)
  stats.json        counts only

Names never leave this script: the owner is the sender who appears in the most chats, every
other sender is "peer", and a chat is named by a hash of its file name. A message is split
into lines and sentences; a part is dropped if it holds a URL, an @ or #, a media or deletion
placeholder, an vkr.pii/1 detector hit or a term from --exclude-terms-file.

Usage: python3 -I chat_split.py --out-dir out/chat --exclude-terms-file FILE CHAT.txt [...]
"""
import argparse
import collections
import hashlib
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import make_dataset_linguist  # noqa: E402
import validate_dataset  # noqa: E402

HEADER = re.compile(r"^\d{1,2}\.\d{1,2}\.\d{2,4}, \d{1,2}:\d{2} - ([^:\n]{1,80}?): (.*)$")
SYSTEM = re.compile(r"^\d{1,2}\.\d{1,2}\.\d{2,4}, \d{1,2}:\d{2} - ")
SENTENCE = re.compile(r"(?<=[.!?])\s+")
PLACEHOLDERS = ("<medien ausgeschlossen>", "<media omitted>", "nachricht wurde gelöscht",
                "this message was deleted", "du hast diese nachricht gelöscht", "<anhang:",
                "(datei angehängt)", "nachricht wurde bearbeitet", "<diese nachricht wurde bearbeitet>",
                "null", "standort:", "live-standort")
MIN_CHARS, MAX_CHARS = 3, 160


def messages(path):
    """(sender, text) for each message; continuation lines belong to the message above."""
    current = None
    with pathlib.Path(path).open(encoding="utf-8", errors="ignore") as handle:
        for raw in handle:
            line = raw.rstrip("\n").lstrip("‎﻿")
            match = HEADER.match(line)
            if match:
                if current:
                    yield current
                current = [match.group(1).strip("‎ "), match.group(2)]
            elif SYSTEM.match(line):
                if current:
                    yield current
                current = None
            elif current is not None:
                current[1] += "\n" + line
    if current:
        yield current


def parts(text):
    for line in text.split("\n"):
        for part in SENTENCE.split(line.strip()):
            part = " ".join(part.split())
            if MIN_CHARS <= len(part) <= MAX_CHARS:
                yield part


def keep(part, exclude):
    low = part.lower()
    if "://" in low or "www." in low or "@" in part or "#" in part:
        return False
    if any(p in low for p in PLACEHOLDERS):
        return False
    if validate_dataset.detect(part):
        return False
    return exclude is None or not exclude.search(part)


def is_gsw(part):
    tokens = {t.lower() for t in make_dataset_linguist.TOKEN.findall(part)}
    return bool(make_dataset_linguist.GSW_MARKERS.intersection(tokens))


def split_chats(paths, exclude):
    per_chat = {p: list(messages(p)) for p in paths}
    chats_by_sender = collections.Counter()
    volume = collections.Counter()
    for msgs in per_chat.values():
        senders = {s for s, _ in msgs}
        chats_by_sender.update(senders)
        volume.update(s for s, _ in msgs)
    owner = max(chats_by_sender, key=lambda s: (chats_by_sender[s], volume[s])) if chats_by_sender else None
    rows, stats = [], collections.Counter()
    for path, msgs in per_chat.items():
        chat = hashlib.sha256(pathlib.Path(path).name.encode()).hexdigest()[:8]
        for sender, text in msgs:
            stats["messages"] += 1
            speaker = "owner" if sender == owner else "peer"
            for part in parts(text):
                if not keep(part, exclude):
                    stats["dropped"] += 1
                    continue
                gsw = is_gsw(part)
                stats[f"{speaker}:{'gsw' if gsw else 'other'}"] += 1
                rows.append({"chat": chat, "speaker": speaker, "gsw": gsw, "text": part})
    stats["owner_chats"] = chats_by_sender[owner] if owner else 0
    stats["chats"] = len(paths)
    return rows, dict(stats)


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--exclude-terms-file", required=True)
    parser.add_argument("chats", nargs="+")
    args = parser.parse_args(argv)
    out = pathlib.Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    rows, stats = split_chats(args.chats, make_dataset_linguist.load_exclude_terms(args.exclude_terms_file))
    with (out / "utterances.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    seen, lines = set(), []
    for row in rows:
        if row["gsw"] and row["text"] not in seen:
            seen.add(row["text"])
            lines.append(row["text"])
    (out / "utterances.txt").write_text("".join(t + "\n" for t in lines), encoding="utf-8")
    (out / "stats.json").write_text(json.dumps(stats, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(stats, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
