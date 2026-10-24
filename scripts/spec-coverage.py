#!/usr/bin/env python3
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Which normative rules of docs/specs have a shared test vector (v1.0 conformance criterion).

    python3 -I scripts/spec-coverage.py [--missing] [--json]

A rule is a bold id at the start of a paragraph or list item (`**R9.**`, `- **L7.**`). A vector
covers it when its `spec` entry names the rule's document and section: `{"doc": "L3",
"section": "R7"}` for 0003 (or `"doc": "0017"`), or a section prefixed with the spec number
(`"0013 R2"`); ranges (`R3-R6`) cover each rule in between. Rules are covered by vectors only; unit tests do not count,
because a second implementation cannot run them. Stdlib only.
"""
import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPECS = ROOT / "docs" / "specs"
VECTORS = ROOT / "spec" / "test-vectors"
# Layer codes the vectors use, by spec number.
LAYERS = {"L0": "0012", "L1": "0001", "L2": "0002", "L3": "0003", "L4": "0004", "L5": "0005",
          "L6": "0006", "L7": "0007"}
RULE = re.compile(r"^(?:- )?\*\*([A-Z]{1,3})(\d+)([a-z]?)\.\*\*", re.M)
SECTION = re.compile(r"^(?:(\d{4}) )?([A-Z]{1,3})(\d+)([a-z]?)(?:\s*(?:-|to)\s*(?:[A-Z]{1,3})?(\d+))?$")


def rules():
    found = {}
    for path in sorted(SPECS.glob("0*.md")):
        number = path.name[:4]
        ids = []
        for prefix, digits, suffix in RULE.findall(path.read_text(encoding="utf-8")):
            rule = f"{prefix}{digits}{suffix}"
            if rule not in ids:
                ids.append(rule)
        found[number] = (path.name, ids)
    return found


def covered():
    hits = {}
    for path in sorted(VECTORS.rglob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            continue
        vectors = data.get("vectors", []) if isinstance(data, dict) else []
        for vector in vectors:
            for ref in vector.get("spec", []):
                doc = str(ref.get("doc"))
                number = LAYERS.get(doc) or (doc if re.fullmatch(r"\d{4}", doc) else None)
                match = SECTION.match(str(ref.get("section", "")).strip())
                if not number or not match:
                    continue
                spec, prefix, first, suffix, last = match.groups()
                spec = spec or number
                end = int(last) if last else int(first)
                for n in range(int(first), end + 1):
                    rule = f"{prefix}{n}{suffix if n == int(first) else ''}"
                    hits.setdefault((spec, rule), []).append(vector.get("id", path.name))
    return hits


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--missing", action="store_true", help="list the rules without a vector")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    all_rules, hits = rules(), covered()
    report, total, with_vector = [], 0, 0
    for number, (name, ids) in all_rules.items():
        have = [r for r in ids if (number, r) in hits]
        total += len(ids)
        with_vector += len(have)
        report.append({"spec": name, "rules": len(ids), "covered": len(have),
                       "missing": [r for r in ids if r not in have]})
    if args.json:
        print(json.dumps({"rules": total, "covered": with_vector, "specs": report}, indent=1))
        return 0
    width = max(len(r["spec"]) for r in report)
    for row in report:
        if not row["rules"]:
            line = "no numbered rules"
        else:
            line = f"{row['covered']:>3}/{row['rules']:<3}"
            if args.missing and row["missing"]:
                line += "  missing: " + " ".join(row["missing"])
        print(f"{row['spec']:<{width}}  {line}")
    print(f"{'total':<{width}}  {with_vector:>3}/{total:<3} ({with_vector / max(total, 1):.0%})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
