# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""The Rust Core as the single source of linguist prompts and verdicts. Stdlib only.

Calls `vaikor linguist-eval` (runtime/vaikor-cli/src/linguist_eval.rs), the shipped binary:
  render-prompt  utterance (+ catalog subset) -> the exact runtime prompt and chat request
  score          recorded completion -> the runtime verdict and what the Core keeps
  serve          utterance -> the reply of the running llama-server endpoint, scored the same way
Nothing here renders a prompt or decides acceptance in Python. compact=True selects the
compact output (0017 L3a, L8): the compact instruction and the catalog decoding schema,
as `model.output: "compact"` does at runtime (`--compact`).

The binary is $VAIKOR_BIN when set (the cargo test of vaikor-guard passes its own build),
otherwise `cargo build -p vaikor-guard --bin vaikor` in runtime/ (debug profile).
"""
import functools
import json
import os
import pathlib
import subprocess

HERE = pathlib.Path(__file__).resolve().parent
RUNTIME_MANIFEST = HERE.parent / "runtime" / "Cargo.toml"


class CoreError(RuntimeError):
    """The Core command failed or refused an input row (a malformed row is never skipped)."""


@functools.lru_cache(maxsize=1)
def vaikor_binary():
    path = os.environ.get("VAIKOR_BIN")
    if path:
        if not os.access(path, os.X_OK):
            raise CoreError(f"VAIKOR_BIN={path} is not an executable")
        return path
    build = subprocess.run(
        ["cargo", "build", "--quiet", "--locked", "--manifest-path", str(RUNTIME_MANIFEST),
         "-p", "vaikor-guard", "--bin", "vaikor", "--message-format=json"],
        capture_output=True, text=True, check=False)
    if build.returncode != 0:
        raise CoreError(f"cargo build of vaikor failed:\n{build.stderr[-4000:]}")
    for line in build.stdout.splitlines():
        message = json.loads(line)
        if (message.get("reason") == "compiler-artifact" and message.get("executable")
                and message["target"]["name"] == "vaikor"):
            return message["executable"]
    raise CoreError("cargo build did not report the vaikor executable")


def run(mode, rows, *args, timeout=None):
    """One JSON result per row, in order; raises CoreError on any failed row."""
    data = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    proc = subprocess.run([vaikor_binary(), "linguist-eval", mode, *args], input=data, capture_output=True,
                          text=True, encoding="utf-8", check=False, timeout=timeout)
    results = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    errors = [r["error"] for r in results if "error" in r]
    if proc.returncode != 0 or errors or len(results) != len(rows):
        detail = errors[0] if errors else proc.stderr.strip()
        raise CoreError(f"vaikor linguist-eval {mode}: exit {proc.returncode}, "
                        f"{len(errors)} bad row(s): {detail}")
    return results


def render_prompts(items, compact=False):
    """[(utterance, intent_ids or None)] -> [{"utterance", "system", "user", "request"}] (runtime prompt)."""
    rows = [{"utterance": u} if ids is None else {"utterance": u, "intent_ids": list(ids)} for u, ids in items]
    return run("render-prompt", rows, *(["--compact"] if compact else [])) if rows else []


def render_prompt(utterance, intent_ids=None, compact=False):
    """(system, user) for one utterance, as the runtime renders it."""
    out = render_prompts([(utterance, intent_ids)], compact)[0]
    return out["system"], out["user"]


def score(rows):
    """Rows {utterance, completion, expected} -> per-row runtime verdict and comparison."""
    return run("score", rows) if rows else []


def serve(rows, socket=None, config=None, compact=False):
    """Rows {utterance, expected}: ask the served model through the runtime request, then score.

    With a socket, compact selects the form; a config decides it with its model.output."""
    if (socket is None) == (config is None):
        raise ValueError("give exactly one of socket or config")
    if config is not None and compact:
        raise ValueError("a config selects the output form with model.output")
    endpoint = ["--socket", str(socket)] if socket is not None else ["--config", str(config)]
    return run("serve", rows, *endpoint, *(["--compact"] if compact else [])) if rows else []
