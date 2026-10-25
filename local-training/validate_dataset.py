# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Validate a local-training dataset (turnkey WP f). Stdlib only.

Each JSONL record is {"messages": [system, user, assistant]}; the assistant
content is one JSON tool call {"component", "route", "props"} against the v1
A2UI registry (5 components) and the ratified routes local-ui, worker-tool,
cloud:grok. The model only proposes; residency, approvals and grants come from
the Core (0001 R8, 0009 R1/R2), so such fields are refused anywhere. IP
literals and every vkr.pii/1 detector (0007 R12) are refused in all text.

Usage: python3 -I validate_dataset.py <data.jsonl>   (exit 1 on any error)
"""
import json
import pathlib
import re
import sys
import unicodedata

COMPONENTS = {"TaskList", "CountdownWidget", "NoteEditor", "WebResult", "CloudCallTrace"}
ROUTES = {"local-ui", "worker-tool", "cloud:grok"}
# The route each component may propose (the Core still decides).
ROUTE_FOR = {
    "TaskList": "local-ui",
    "CountdownWidget": "local-ui",
    "NoteEditor": "local-ui",
    "WebResult": "worker-tool",
    "CloudCallTrace": "cloud:grok",
}
FORBIDDEN_KEYS = {
    "residency", "approval", "approved", "approve", "grant", "grants", "capability_token",
    "token", "signature", "sig", "consent", "trusted", "trusted_ui", "anonymized",
}
MAX_BYTES = 64 * 1024 * 1024

_I = re.IGNORECASE
DETECTORS = [
    ("email", re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", _I)),
    ("phone", re.compile(r"\+?\d[\d ().-]{7,}\d", _I)),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b", _I)),
    ("ch-ahv", re.compile(r"\b756[.\s]?\d{4}[.\s]?\d{4}[.\s]?\d{2}\b", _I)),
    ("card", re.compile(r"\d(?:[ -]?\d){12,}", _I)),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", _I)),
    ("secret", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{16,}|\bgh[pousr]_[A-Za-z0-9]{20,}"
        r"|\bAKIA[0-9A-Z]{16}\b|\bxox[abpr]-[A-Za-z0-9-]{10,}", _I)),
]
# Not part of vkr.pii/1: IPv6 literals (the training data names no hosts).
IPV6 = re.compile(r"(?<![0-9a-f:])(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])|"
                  r"(?<![0-9a-f:])[0-9a-f]{0,4}::[0-9a-f]{0,4}(?![0-9a-f:])", _I)


def _luhn(digits):
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def detect(text):
    """vkr.pii/1 detector ids (plus ipv6) that match the NFKC text."""
    text = unicodedata.normalize("NFKC", text)
    hits = []
    for name, pattern in DETECTORS:
        if name == "phone":
            hit = any(sum(c.isdigit() for c in m.group()) >= 9 for m in pattern.finditer(text))
        elif name == "card":
            hit = any(13 <= len(d) <= 19 and _luhn(d)
                      for d in ([int(c) for c in m.group() if c.isdigit()] for m in pattern.finditer(text)))
        else:
            hit = pattern.search(text) is not None
        if hit:
            hits.append(name)
    if IPV6.search(text):
        hits.append("ipv6")
    return hits


def _walk(value, path, errors, strings):
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_KEYS:
                errors.append(f"forbidden key {path}{key} (the Core supplies it, not the model)")
            strings.append(str(key))
            _walk(item, f"{path}{key}.", errors, strings)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk(item, f"{path}{index}.", errors, strings)
    elif isinstance(value, str):
        strings.append(value)


def check_record(record):
    """Return a list of errors (empty when the record is valid)."""
    errors = []
    if not isinstance(record, dict) or set(record) != {"messages"}:
        return ["record keys must be exactly {'messages'}"]
    messages = record["messages"]
    if (not isinstance(messages, list) or len(messages) != 3
            or [m.get("role") if isinstance(m, dict) else None for m in messages]
            != ["system", "user", "assistant"]):
        return ["messages must be system, user, assistant roles in that order"]
    strings = []
    for message in messages:
        if set(message) != {"role", "content"} or not isinstance(message["content"], str):
            errors.append("each message has exactly role and a string content (keys)")
            return errors
        strings.append(message["content"])
    try:
        call = json.loads(messages[2]["content"])
    except ValueError:
        return ["assistant content is not JSON"]
    if not isinstance(call, dict) or set(call) != {"component", "route", "props"}:
        errors.append("tool call keys must be exactly component, route, props")
        _walk(call, "", errors, strings)
    else:
        component, route, props = call["component"], call["route"], call["props"]
        if component not in COMPONENTS:
            errors.append(f"component {component!r} is not in the v1 registry")
        if route not in ROUTES:
            errors.append(f"route {route!r} is not a ratified route")
        elif component in ROUTE_FOR and ROUTE_FOR[component] != route:
            errors.append(f"route {route!r} is not the route for component {component}")
        if not isinstance(props, dict):
            errors.append("props must be an object")
        _walk(call, "", errors, strings)
    for text in strings:
        for hit in detect(text):
            errors.append(f"detector {hit} matches (no IP literals or personal data in training data)")
    return sorted(set(errors))


def check_file(path):
    path = pathlib.Path(path)
    if path.stat().st_size > MAX_BYTES:
        return [f"{path}: larger than {MAX_BYTES} bytes"]
    errors = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                errors.append(f"line {number}: empty")
                continue
            try:
                record = json.loads(line)
            except ValueError:
                errors.append(f"line {number}: not JSON")
                continue
            errors.extend(f"line {number}: {e}" for e in check_record(record))
    return errors


def main(argv):
    if len(argv) != 2:
        print("usage: validate_dataset.py <data.jsonl>", file=sys.stderr)
        return 2
    errors = check_file(argv[1])
    for error in errors[:200]:
        print(error, file=sys.stderr)
    if errors:
        print(f"{len(errors)} error(s)", file=sys.stderr)
        return 1
    print("dataset OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
