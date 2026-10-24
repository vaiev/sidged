# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Run the hand-written probes against a served linguist GGUF through the Rust Core. Stdlib only.

Sends each probe of linguist_probes.json to the llama-server endpoint with the runtime's
request (`sidged linguist-eval serve`: full-catalog prompt, chat_request, reply
post-processing, verify_proposal_for), so this measures the model as deployed. A probe
passes when the Core accepts the reply and what it keeps has the probe's intent, exactly
the probe's slots (values compared case-insensitively) and exactly its follow-ups: an
unnamed slot or an extra follow-up fails the probe.

Usage: python3 -I probe_linguist.py --socket $XDG_RUNTIME_DIR/sidged/linguist.sock [--out report.json]
"""
import argparse
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import core_bridge  # noqa: E402

PROBES_PATH = pathlib.Path(__file__).resolve().parent / "linguist_probes.json"


def expected(probe):
    """The Core-level expectation of one probe (no lang: probes do not name one)."""
    out = {"intent": probe["intent"], "slots": probe.get("slots", {})}
    if probe.get("then"):
        out["then"] = [{"intent": f["intent"], "slots": f.get("slots", {})} for f in probe["then"]]
    return out


def verdict(result):
    """(ok, why) from one Core result."""
    if not result["core_accepts"]:
        return False, f"refused at {result['refusal']['stage']}: {result['refusal']['reason']}"
    if result["semantic_ok"] and result["clarification_ok"]:
        return True, ""
    why = []
    if not result["intent_ok"]:
        why.append(f"intent {result['kept']['intent']}"
                   + "".join(f" then {f['intent']}" for f in result["kept"].get("then", [])))
    if not result["clarification_ok"]:
        why.append("asks back" if result["kept"].get("clarification_needed") else "does not ask back")
    for key in ("invented_slots", "missing_slots", "wrong_slots", "extra_followups", "missing_followups"):
        if result[key]:
            why.append(f"{key} {', '.join(result[key])}")
    return False, "; ".join(why)


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--socket", help="llama-server AF_UNIX socket (served under this uid)")
    source.add_argument("--config", help="a node config.json with model.endpoint")
    parser.add_argument("--probes", default=str(PROBES_PATH))
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    probes = json.loads(pathlib.Path(args.probes).read_text(encoding="utf-8"))["probes"]
    started = time.time()
    results = core_bridge.serve([{"utterance": p["u"], "expected": expected(p)} for p in probes],
                                socket=args.socket, config=args.config)
    rows = []
    for probe, result in zip(probes, results):
        ok, why = verdict(result)
        rows.append({"u": probe["u"], "ok": ok, "why": why, "reply": result["completion"]})
        print(f"{'ok  ' if ok else 'FAIL'} {probe['u']}" + (f"  ({why})" if why else ""), flush=True)
    passed = sum(r["ok"] for r in rows)
    seconds = time.time() - started
    print(f"probes: {passed}/{len(rows)} ({passed / len(rows):.1%}), {seconds / len(rows):.2f} s per probe")
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps({"passed": passed, "total": len(rows), "results": rows},
                                                     ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    broken = sum(1 for r in results if r["refusal"] and r["refusal"]["stage"] == "model")
    if broken:
        print(f"{broken} probe(s) got no model reply (stage model)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
