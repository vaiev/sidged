#!/usr/bin/env python3
# Copyright 2026 The Selfkin Standards contributors
# Copyright 2026 VAIEV
# Provenance: adapted from https://github.com/selfkin/standards (see NOTICE).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Validate Sidged JSON documents against the v0.1 JSON Schemas.

Two layers of checks:

1. Structural checks with JSON Schema 2020-12 (schemas/*.schema.json).
2. Semantic checks that JSON Schema cannot express, for example that a
   delegated capability token only narrows its parent (Sidged L2).

The validator does not check signatures, clocks, revocation, or replay.
Those depend on keys and receiver state and belong to a runtime.

Usage:
  python spec/validate/validate.py                 # check every example
  python spec/validate/validate.py FILE --schema envelope
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

REPO = Path(__file__).resolve().parents[2]
SPEC = REPO / "spec"
SCHEMA_DIR = SPEC / "schemas"
EXAMPLE_DIR = SPEC / "examples"
ID_PREFIX = "https://sidged.com/spec/schemas/"
SCHEMA_NAMES = (
    "envelope",
    "capability-descriptor",
    "capability-token",
    "plan",
    "module-manifest",
    "privacy-report",
    "provider-manifest",
    "refusal",
    "session-record",
    "intent-catalog",
    "linguist-envelope",
    "linguist-proposal",
)
SESSION_RECORD_TYPE = "application/vnd.sidged.session-record+json"  # Sidged L7
MAX_TOKEN_LIFETIME = timedelta(hours=1)  # Sidged L2


# ---------------------------------------------------------------- loading


def load_json(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_schemas(schema_dir: Path = SCHEMA_DIR) -> dict[str, dict]:
    """Return all schemas keyed by short name (file name without suffix)."""
    schemas = {}
    for path in sorted(schema_dir.glob("*.schema.json")):
        schemas[path.name[: -len(".schema.json")]] = load_json(path)
    return schemas


def build_registry(schemas: dict[str, dict]) -> Registry:
    resources = []
    for name, schema in schemas.items():
        schema_id = schema.get("$id") if isinstance(schema, dict) else None
        if not isinstance(schema_id, str) or not schema_id:
            raise ValueError(f"{name}: schema has no $id, run check_schema_files for details")
        resources.append((schema_id, Resource.from_contents(schema, default_specification=DRAFT202012)))
    return Registry().with_resources(resources)


def make_validator(name: str, schemas: dict[str, dict], registry: Registry) -> Draft202012Validator:
    return Draft202012Validator(schemas[name], registry=registry, format_checker=FormatChecker())


def check_schema_files(schemas: dict[str, dict]) -> list[str]:
    """Meta-validate every schema and check the repository conventions."""
    problems = []
    for name, schema in schemas.items():
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:  # noqa: BLE001 - report any metaschema error
            problems.append(f"{name}: not a valid 2020-12 schema: {exc}")
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            problems.append(f"{name}: $schema must be JSON Schema 2020-12")
        if schema.get("$id") != f"{ID_PREFIX}{name}.schema.json":
            problems.append(f"{name}: $id must be {ID_PREFIX}{name}.schema.json")
        for key in ("title", "description"):
            if not schema.get(key):
                problems.append(f"{name}: missing {key}")
    for name in SCHEMA_NAMES:
        if name not in schemas:
            problems.append(f"missing schema: {name}")
    return problems


# ---------------------------------------------------------------- helpers


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


MONEY_AMOUNT = re.compile(r"[0-9]+(\.[0-9]+)?")
MONEY_CURRENCY = re.compile(r"[A-Z]{3}")


def is_money(money) -> bool:
    """True for a common.schema.json money object (decimal amount string, ISO 4217 code)."""
    return (isinstance(money, dict) and isinstance(money.get("amount"), str)
            and MONEY_AMOUNT.fullmatch(money["amount"]) is not None
            and isinstance(money.get("currency"), str) and MONEY_CURRENCY.fullmatch(money["currency"]) is not None)


def decimal(value: str) -> Decimal:
    """Exact decimal for money amounts (common.schema.json money.amount is a decimal string).

    Python's Decimal also reads "-1", "1e3", "NaN" and "Infinity"; those are not money amounts.
    """
    if not isinstance(value, str) or MONEY_AMOUNT.fullmatch(value) is None:
        raise ValueError(f"not a money amount: {value!r}")
    return Decimal(value)


def resource_covers(parent: str, child: str) -> bool:
    """True if the parent resource covers the child resource (SDG-L2 R9).

    A trailing ``/*`` is one prefix wildcard. The remainder must be non-empty
    and must not contain ``%`` or an empty, ``.``, or ``..`` segment.
    """
    if parent == child:
        return True
    if not parent.endswith("/*") or not child.startswith(parent[:-1]):
        return False
    rest = child[len(parent) - 1 :]
    if not rest or "%" in rest:
        return False
    return all(segment not in ("", ".", "..") for segment in rest.split("/"))


def right_covered(child: dict, parent: dict) -> bool:
    if child["action"] != parent["action"]:
        return False
    if not resource_covers(parent["resource"], child["resource"]):
        return False
    pc = parent.get("constraints", {})
    cc = child.get("constraints", {})
    if "max_amount" in pc:
        if "max_amount" not in cc:
            return False
        if cc["max_amount"]["currency"] != pc["max_amount"]["currency"]:
            return False
        if decimal(cc["max_amount"]["amount"]) > decimal(pc["max_amount"]["amount"]):
            return False
    if "max_uses" in pc and ("max_uses" not in cc or cc["max_uses"] > pc["max_uses"]):
        return False
    if "data_classes" in pc:
        if "data_classes" not in cc or not set(cc["data_classes"]) <= set(pc["data_classes"]):
            return False
    return True


def budget_problems(child: dict, parent: dict) -> list[str]:
    problems = []
    pb = parent.get("budget", {})
    cb = child.get("budget", {})
    for key in ("messages", "compute_units"):
        if key in pb and (key not in cb or cb[key] > pb[key]):
            problems.append(f"budget.{key} widens the parent budget")
    if "money" in pb:
        cm = cb.get("money")
        if cm is None or cm["currency"] != pb["money"]["currency"] or decimal(cm["amount"]) > decimal(pb["money"]["amount"]):
            problems.append("budget.money widens or drops the parent budget")
    return problems


# ---------------------------------------------------------------- semantic checks


CONSEQUENTIAL_EFFECTS = frozenset({"delete", "execute", "egress"})


def check_capability_descriptor(descriptor: dict) -> list[str]:
    """Effect and cost rules for a capability descriptor (SDG-L1 R9, R10)."""
    problems = []
    effects = descriptor.get("effects", [])
    if "egress" in effects and not descriptor.get("data_classes"):
        problems.append("egress requires at least one data class")
    if "egress" in effects and not descriptor.get("residency", {}).get("tags"):
        problems.append("egress requires residency with at least one tag; missing or empty tags fail closed (SDG-L1 R8a)")
    tags = descriptor.get("residency", {}).get("tags", [])
    if "unrestricted" in tags and len(tags) > 1:
        problems.append("unrestricted must be the only residency tag (SDG-L1 R8b)")
    if CONSEQUENTIAL_EFFECTS.intersection(effects) and descriptor.get("consequential") is not True:
        problems.append("consequential must be true when effects include delete, execute, or egress")
    for key in ("input_schema", "output_schema"):
        schema = descriptor.get(key)
        if isinstance(schema, dict) and "type" in schema and schema["type"] != "object":
            problems.append(f"{key}.type must be object when present")
    return problems


PLACEHOLDER = re.compile(r"\{([a-z][a-z0-9_]*)\}")


def check_intent_catalog(catalog: dict) -> list[str]:
    """Cross-member rules for the intent catalog: unique intents, declared slots, every locale."""
    problems = []
    locales = catalog.get("locales", [])

    def complete(texts: dict, where: str) -> None:
        for locale in locales:
            if locale not in texts:
                problems.append(f"{where} has no text for locale {locale}")
        for locale in texts:
            if locale not in locales:
                problems.append(f"{where} uses undeclared locale {locale}")

    complete(catalog.get("unknown_intent_ask", {}), "unknown_intent_ask")
    seen = set()
    for entry in catalog.get("intents", []):
        name = entry.get("intent")
        if name in seen:
            problems.append(f"duplicate intent {name}")
        seen.add(name)
        slots = entry.get("slots_schema", {}).get("properties", {})
        for slot in entry.get("slots_schema", {}).get("required", []):
            if slot not in slots:
                problems.append(f"{name}: required slot {slot} is not declared")
        for slot in PLACEHOLDER.findall(entry.get("canonical_en", "")):
            if slot not in slots:
                problems.append(f"{name}: canonical_en names undeclared slot {slot}")
        for slot, definition in slots.items():
            complete(definition.get("x-ask", {}), f"{name}.{slot}.x-ask")
        earlier = set()
        for step in entry.get("plan", {}).get("steps", []):
            sid = step.get("id")
            if sid in earlier:
                problems.append(f"{name}: plan step id {sid} is repeated")
            if step.get("capability") not in entry.get("capabilities", []):
                problems.append(f"{name}: plan step {sid} uses {step.get('capability')}, which the intent does not name")
            for arg, value in step.get("args", {}).items():
                if "slot" in value and value["slot"] not in slots:
                    problems.append(f"{name}: plan step {sid} argument {arg} names undeclared slot {value['slot']}")
                if "ref" in value and value["ref"] not in earlier:
                    problems.append(f"{name}: plan step {sid} argument {arg} refers to {value['ref']}, which is not an earlier step")
            earlier.add(sid)
    # 0017 K6: compositions name catalog intents, required slots of `then`, and plan steps.
    by_id = {entry.get("intent"): entry for entry in catalog.get("intents", [])}
    pairs = set()
    for comp in catalog.get("compositions", []):
        first, then = by_id.get(comp.get("first")), by_id.get(comp.get("then"))
        pair = f"composition {comp.get('first')} -> {comp.get('then')}"
        if first is None or then is None:
            problems.append(f"{pair} names an unknown intent")
            continue
        if (comp["first"], comp["then"]) in pairs:
            problems.append(f"{pair} is declared twice")
        pairs.add((comp["first"], comp["then"]))
        for slot in comp.get("satisfies", []):
            if slot not in then.get("slots_schema", {}).get("required", []):
                problems.append(f"{pair} satisfies {slot}, not a required slot of {comp['then']}")
        steps = lambda entry: {step.get("id") for step in entry.get("plan", {}).get("steps", [])}
        for replaced, by in comp.get("replaces", {}).items():
            if replaced not in steps(then) or by not in steps(first):
                problems.append(f"{pair} replaces {replaced} by {by}, not plan steps")
    return problems


def check_linguist_envelope(envelope: dict) -> list[str]:
    """Consistency of a linguist envelope that JSON Schema cannot express."""
    problems = []
    given = set(envelope.get("slots", {}))
    missing = envelope.get("missing_slots", [])
    for slot in missing:
        if slot in given:
            problems.append(f"slot {slot} is both given and missing")
    if missing and envelope.get("clarification_needed") is not True:
        problems.append("missing slots require clarification_needed: true")
    canonical = envelope.get("canonical_intent_en") or ""
    for slot in PLACEHOLDER.findall(canonical):
        problems.append(f"canonical_intent_en keeps the unfilled placeholder {{{slot}}}")
    return problems


RESIDENCY_DESTINATIONS = {"CH": {"CH"}, "EU": {"EU"}, "CH-EU": {"CH", "EU"}}
DESTINATION_CLASSES = {"CH", "EU", "GLOBAL"}


def residency_destination(tags, destination: str) -> list[str]:
    """Egress residency gate (SDG-L1 R8 v0.2). Returns problems; empty means allowed."""
    if destination not in DESTINATION_CLASSES:
        return ["unregistered destination"]
    if not tags:
        return ["missing or empty residency tags fail closed (R8a)"]
    if "unrestricted" in tags:
        return [] if len(tags) == 1 else ["unrestricted must be the only tag (R8b)"]
    unknown = [t for t in tags if t not in RESIDENCY_DESTINATIONS]
    if unknown:
        return [f"tag {t} not allowed without an owner mapping (R8, R8d)" for t in unknown]
    allowed = set.intersection(*(RESIDENCY_DESTINATIONS[t] for t in tags))
    return [] if destination in allowed else [f"residency {sorted(tags)} does not allow {destination} (R8c)"]


# Spec 0007 §5.1-5.3 (SDG-L7): Core-checked egress for model calls.
PII_V1 = {
    "email": r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",
    "iban": r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b",
    "ch-ahv": r"\b756[.\s]?\d{4}[.\s]?\d{4}[.\s]?\d{2}\b",
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "secret": r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{16,}|\bgh[pousr]_[A-Za-z0-9]{20,}|\bAKIA[0-9A-Z]{16}\b|\bxox[abpr]-[A-Za-z0-9-]{10,}",
}
DEFAULT_LOCAL_ONLY = {"health", "biometric", "adaptation", "secrets"}
DEFAULT_EXPORT = {"query", "documents.text"}


def _class_in(cls: str, names) -> bool:
    return any(cls == n or cls.startswith(n + ".") for n in names)


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def pii_detect(payload: str) -> list[str]:
    """Detector set sdg.pii/1 (0007 R12). Returns matched detector ids, never the text."""
    import re as _re, unicodedata
    text = unicodedata.normalize("NFKC", payload)
    hits = [i for i, pat in PII_V1.items() if _re.search(pat, text, _re.IGNORECASE)]
    for m in _re.finditer(r"\+?\d[\d ().-]{7,}\d", text):
        if len(_re.sub(r"\D", "", m.group())) >= 9:
            hits.append("phone")
            break
    for m in _re.finditer(r"\d(?:[ -]?\d){12,18}", text):
        if _luhn(_re.sub(r"\D", "", m.group())):
            hits.append("card")
            break
    return sorted(set(hits))


def egress_check(data: dict) -> tuple[str, str | None]:
    """0007 R7-R13 decision for one model call. Returns (result, reason)."""
    if data.get("route") == "local":
        return ("accept", None)  # R7: grant and audit still apply, no approval
    if data.get("detector_version", "sdg.pii/1") != "sdg.pii/1":
        return ("refuse", "policy-denied")  # R12a
    approval = data.get("approval")  # Core's approval Record state for (provider, task_type)
    if not approval or not approval.get("valid") or approval.get("revoked"):
        return ("refuse", "approval-required")  # R8, R8r
    scope = approval.get("scope")
    if not approval.get("standing") or not isinstance(scope, dict) or scope.get("standing") is not True:
        return ("refuse", "approval-required")  # R8s: a plain step approval never becomes standing
    import hashlib as _h, json as _j
    digest = _h.sha256(_j.dumps(scope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    if approval.get("scope_digest") != digest or scope.get("provider") != data.get("provider") or scope.get("task_type") != data.get("task_type"):
        return ("refuse", "approval-required")  # R8s
    if approval.get("used", 0) + 1 > scope.get("limit", {}).get("calls", 0):
        return ("refuse", "approval-required")  # R8b
    sub = data.get("subscription")
    if sub and sub.get("used", 0) + data.get("cost", 1) > sub.get("limit", 0):
        return ("refuse", "budget-exceeded")  # R10b
    classes = data.get("read_classes")  # from the Core's step read log, never the model
    if not classes or any(not c for c in classes):
        return ("refuse", "data-class-forbidden")
    local_only = set(data.get("local_only", DEFAULT_LOCAL_ONLY))
    export = set(data.get("export", DEFAULT_EXPORT))
    if any(_class_in(c, local_only) for c in classes) or not all(_class_in(c, export) for c in classes):
        return ("refuse", "data-class-forbidden")  # R9, R11 A
    if residency_destination(data.get("tags"), data["destination"]):
        return ("refuse", "residency-unsupported")  # R11 B
    if len(data["payload"].encode()) > data.get("max_payload_bytes", 32768):
        return ("refuse", "policy-denied")  # R11 C
    if pii_detect(data["payload"]):
        return ("refuse", "data-class-forbidden")  # R11 D
    return ("accept", None)


def approval_binding(request: dict, line: str) -> dict:
    """0004 R9/R9b: result of one approval answer for a pending request."""
    import hashlib as _h, json as _j
    parts = line.split()
    fields = [request["step"], request["capability"], request["args_digest"], request["nonce"], request["plan_digest"]]
    if len(parts) < 7 or parts[0] != "approve" or parts[2:7] != fields:
        return {"approved": False, "standing": False}
    scope = request.get("scope")
    if not isinstance(scope, dict) or scope.get("standing") is not True:
        return {"approved": True, "standing": False}
    digest = _h.sha256(_j.dumps(scope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    standing = request.get("scope_digest") == digest and len(parts) == 8 and parts[7] == digest
    return {"approved": True, "standing": standing}


def check_token(token: dict, where: str = "token") -> list[str]:
    """Attenuation and lifetime checks for a Sidged capability token (Sidged L2)."""
    problems = []
    links = list(token.get("chain", [])) + [token]
    for index, link in enumerate(links):
        label = where if index == len(links) - 1 else f"{where}.chain[{index}]"
        if parse_time(link["exp"]) <= parse_time(link["iat"]):
            problems.append(f"{label}: exp must be later than iat")
        elif parse_time(link["exp"]) - parse_time(link["iat"]) > MAX_TOKEN_LIFETIME:
            problems.append(f"{label}: lifetime exceeds the 1 hour maximum (Sidged L2)")
        if "nbf" in link and parse_time(link["nbf"]) >= parse_time(link["exp"]):
            problems.append(f"{label}: nbf must be earlier than exp")
    for index in range(1, len(links)):
        parent, child = links[index - 1], links[index]
        label = where if index == len(links) - 1 else f"{where}.chain[{index}]"
        if child["iss"] != parent["sub"]:
            problems.append(f"{label}: iss must equal the parent's sub (holder delegates)")
        if child["aud"] != parent["aud"]:
            problems.append(f"{label}: aud must equal the parent's aud (audience cannot change on delegation)")
        if parse_time(child["exp"]) > parse_time(parent["exp"]):
            problems.append(f"{label}: exp is later than the parent's exp (lifetime widened)")
        for right in child["rights"]:
            if not any(right_covered(right, p) for p in parent["rights"]):
                problems.append(f"{label}: right {right['action']} on {right['resource']} is not covered by the parent (rights widened)")
        problems.extend(f"{label}: {p}" for p in budget_problems(child, parent))
    return problems


def check_envelope(env: dict) -> list[str]:
    problems = []
    if parse_time(env["expires"]) <= parse_time(env["issued"]):
        problems.append("expires must be later than issued")
    token = env.get("cap_token")
    if isinstance(token, dict) and "rights" in token:
        problems.extend(check_token(token, "cap_token"))
        if token["aud"] != env["aud"]:
            problems.append("cap_token.aud must equal the envelope aud")
        if token["sub"] != env["sender_agent"]:
            problems.append("cap_token.sub must equal sender_agent (token is sender-bound)")
        instr = env.get("instructions")
        if instr:
            resource = instr.get("resource")
            covered = isinstance(resource, str) and any(
                r.get("action") == instr.get("action") and resource_covers(r.get("resource", ""), resource)
                for r in token["rights"]
            )
            if not covered:
                problems.append("instructions are not covered by a cap_token right")
    return problems


def check_module_manifest(manifest: dict) -> list[str]:
    problems = []
    declared = set(manifest["data_classes"])
    for index, dest in enumerate(manifest["egress"]):
        extra = set(dest["data_classes"]) - declared
        if extra:
            problems.append(f"egress[{index}] sends undeclared data classes: {sorted(extra)}")
    if manifest["egress"] and manifest.get("resources", {}).get("network") is False:
        problems.append("egress is declared but resources.network is false")
    return problems


def check_provider_manifest(manifest: dict) -> list[str]:
    problems = []
    audit = manifest.get("transparency", {}).get("audit")
    if audit:
        issued = parse_time(audit["issued"])
        until = parse_time(audit["valid_until"])
        if until <= issued:
            problems.append("audit.valid_until must be later than audit.issued")
        if until > issued + timedelta(days=731):
            problems.append("audit must be renewed at least every two years (Sidged L7)")
    return problems


def check_privacy_report(report: dict) -> list[str]:
    problems = []
    overlap = set(report["sent"]["fields"]) & set(report["redacted"]["fields"])
    if overlap:
        problems.append(f"fields listed as both sent and redacted: {sorted(overlap)}")
    return problems


def profile_tier(profile: str) -> int:
    """Tier of a runtime, communication, or provider profile tag: R0 to R3, C0 to C3, P0 to P3."""
    return int(profile[1])


def session_profiles(record: dict) -> set[str]:
    profiles = {record["runtime_profile"]}
    profiles.update(hop["profile"] for hop in record["hops"])
    profiles.update(egress["provider_profile"] for egress in record["egress"])
    return profiles


def check_session_record(record: dict) -> list[str]:
    """Report links and the effective tier display (Sidged L4, section 13, section 21)."""
    problems = []
    for index, egress in enumerate(record["egress"]):
        if egress["report"]["payload_digest"] != egress["payload_digest"]:
            problems.append(f"egress[{index}]: the report's payload_digest does not match the egress (no matching report)")
    display = record["tier_display"]
    if display["session"] != record["session"]:
        problems.append("tier_display.session is not this session")
    if display["sig"]["kid"] != record["core"]["kid"]:
        problems.append("tier_display is not signed by the Core key")
    if "signer" in display["sig"] and display["sig"]["signer"] != record["core"]["agent"]:
        problems.append("tier_display signer is not the Core")
    profiles = session_profiles(record)
    hidden = profiles - set(display["shows"])
    if hidden:
        problems.append(f"tier_display hides profiles of the session: {sorted(hidden)}")
    extra = set(display["shows"]) - profiles
    if extra:
        problems.append(f"tier_display shows profiles the session does not have: {sorted(extra)}")
    effective = min(profile_tier(p) for p in profiles)
    if display["tier"] > effective:
        problems.append(f"tier_display.tier {display['tier']} is higher than the effective tier {effective}")
    if record["runtime_profile"] == "R0" and "prototype" not in display["labels"]:
        problems.append("an R0 runtime must show the prototype label")
    return problems


def check_session(envelope: dict, core_kid: str, schemas: dict[str, dict], registry: Registry) -> list[str]:
    """A session record as received: a valid envelope signed by the Core key, carrying a valid session record.

    Checks key binding (kid), not cryptography: like the rest of the validator it does not verify signatures.
    """
    problems = validate_document(envelope, "envelope", schemas, registry)
    if problems:
        return problems
    if envelope.get("payload_type") != SESSION_RECORD_TYPE:
        return [f"payload_type must be {SESSION_RECORD_TYPE}"]
    if envelope["sig"]["kid"] != core_kid:
        problems.append("envelope is not signed by the Core key")
    record = envelope["data"]
    problems.extend(f"data: {p}" for p in validate_document(record, "session-record", schemas, registry))
    if problems:
        return problems
    if record["core"]["kid"] != core_kid:
        problems.append("data.core.kid is not the Core key")
    if record["core"]["agent"] != envelope["sender_agent"]:
        problems.append("data.core.agent is not the envelope sender")
    if record["session"] != envelope["session"]:
        problems.append("data.session is not the envelope session")
    return problems


CEL_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
CEL_WORDS = {
    "true", "false", "null", "in",
    "size", "has", "matches", "startsWith", "endsWith", "contains",
    "int", "uint", "double", "string", "bool", "bytes", "duration", "timestamp", "type", "dyn",
}
MACRO = re.compile(r"\.(filter|map|all|exists|exists_one)\s*\(")
SENSITIVE = ("health.records", "secrets")


def _sensitive(name: str) -> bool:
    return any(name == root or name.startswith(root + ".") for root in SENSITIVE)


def _bracket_depth(expr: str) -> int:
    """Deepest bracket nesting, string literals included (0003 R8a)."""
    depth = deepest = 0
    for char in expr:
        if char in "([{":
            depth += 1
            deepest = max(deepest, depth)
        elif char in ")]}":
            depth = max(depth - 1, 0)
    return deepest


def _expr_vars(expr: str) -> list[str]:
    found = []
    for match in CEL_IDENT.finditer(expr):
        if match.start() > 0 and expr[match.start() - 1] == ".":
            continue
        name = match.group(0)
        if name in CEL_WORDS:
            continue
        found.append(name)
    return found


def _arg_labels(arg: dict, labels: dict[str, set[str]], *, item: set[str] | None,
                members: dict[str, set[str]] | None = None) -> tuple[set[str], list[str]]:
    problems = []
    if "lit" in arg:
        return set(), problems
    if "ref" in arg:
        ref = arg["ref"]
        if ref not in labels:
            problems.append(f"ref {ref} is not an earlier step")
            return set(), problems
        # SDG-L3 R4a: a member keeps the producer's labels and must be declared by its output_schema.
        if "field" in arg and members is not None and arg["field"] not in members.get(ref, set()):
            problems.append(f"ref {ref} has no declared output member {arg['field']}")
        return set(labels[ref]), problems
    if arg.get("item") is True:
        if item is None:
            problems.append("item is only valid inside a map")
            return set(), problems
        return set(item), problems
    problems.append("argument is not lit, ref, or item")
    return set(), problems


def _args_labels(args: dict, labels: dict[str, set[str]], *, item: set[str] | None,
                 members: dict[str, set[str]] | None = None) -> tuple[set[str], list[str]]:
    acc: set[str] = set()
    problems: list[str] = []
    for arg in args.values():
        got, extra = _arg_labels(arg, labels, item=item, members=members)
        acc |= got
        problems.extend(extra)
    return acc, problems


def check_plan(plan: dict) -> list[str]:
    """Graph rules that do not need a capability catalog (SDG-L3 R2, R4, R5, R9)."""
    problems = []
    steps = plan.get("steps")
    if not isinstance(steps, list):
        return ["steps must be a list"]
    seen: set[str] = set()
    labels: dict[str, set[str]] = {}
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            problems.append(f"steps[{index}] is not an object")
            continue
        step_id = step.get("id")
        if not isinstance(step_id, str) or step_id in seen:
            problems.append(f"steps[{index}] id is missing or duplicated")
            continue
        seen.add(step_id)
        kind = step.get("kind")
        if kind == "expr":
            expr = step.get("expr", "")
            if not isinstance(expr, str) or MACRO.search(expr):
                problems.append(f"{step_id}: comprehension macros are not in plan v0")
                labels[step_id] = set()
                continue
            if len(expr) > 1024 or _bracket_depth(expr) > 4:
                problems.append(f"{step_id}: expression exceeds the R8a bounds")
                labels[step_id] = set()
                continue
            for name in _expr_vars(expr):
                if name not in labels:
                    problems.append(f"{step_id}: {name} is not an earlier step")
            labels[step_id] = set()
        elif kind == "call":
            _, extra = _args_labels(step.get("args") or {}, labels, item=None)
            problems.extend(f"{step_id}: {item}" for item in extra)
            labels[step_id] = set()
        elif kind == "map":
            bound = step.get("bound")
            if not isinstance(bound, int) or isinstance(bound, bool) or not 1 <= bound <= 32:
                problems.append(f"{step_id}: map bound must be an integer from 1 to 32")
            over = step.get("over")
            if not isinstance(over, dict) or "ref" not in over or "field" in over:
                problems.append(f"{step_id}: map over must be a ref to a whole output")
            else:
                _arg_labels(over, labels, item=None)
                if over["ref"] not in labels:
                    problems.append(f"{step_id}: map over is not an earlier step")
            _, extra = _args_labels(step.get("args") or {}, labels, item=set())
            problems.extend(f"{step_id}: {item}" for item in extra)
            labels[step_id] = set()
        else:
            problems.append(f"{step_id}: unknown kind")
            labels[step_id] = set()
    return problems


def check_plan_run(document: dict) -> list[str]:
    """Full plan-check: structure, effects, labels, approval, and cost."""
    plan = document.get("plan")
    catalog = {item["id"]: item for item in document.get("catalog", []) if isinstance(item, dict) and "id" in item}
    allow = {(item.get("class"), item.get("capability")) for item in document.get("allow", []) if isinstance(item, dict)}
    if not isinstance(plan, dict):
        return ["plan must be an object"]
    problems = check_plan(plan)
    if problems:
        return problems
    labels: dict[str, set[str]] = {}
    # R4a: output members each earlier step declares; an expr or a map declares none.
    members: dict[str, set[str]] = {}
    total = Decimal(0)
    currency = None
    metered = False
    for step in plan["steps"]:
        step_id = step["id"]
        kind = step["kind"]
        if kind == "expr":
            acc: set[str] = set()
            for name in _expr_vars(step["expr"]):
                acc |= labels.get(name, set())
            labels[step_id] = acc
            continue
        cap_id = step["capability"]
        cap = catalog.get(cap_id)
        if cap is None:
            return [f"{step_id}: unknown capability {cap_id}"]
        item_labels = None
        if kind == "map":
            item_labels = labels.get(step["over"]["ref"], set())
        arg_labels, extra = _args_labels(step.get("args") or {}, labels, item=item_labels, members=members)
        if extra:
            return [f"{step_id}: {item}" for item in extra]
        if item_labels is not None:
            # 0003 R10: the number of repetitions depends on the list (implicit flow).
            arg_labels |= item_labels
        effects = set(cap.get("effects") or [])
        cap_classes = set(cap.get("data_classes") or [])
        if "egress" in effects:
            for name in arg_labels | cap_classes:
                if _sensitive(name) and (name, cap_id) not in allow:
                    problems.append(f"{step_id}: {name} reaches egress capability {cap_id}")
        if cap.get("consequential") is True and step.get("approval") is not True:
            problems.append(f"{step_id}: consequential capability requires approval")
        labels[step_id] = arg_labels | cap_classes
        if kind == "call":
            output = cap.get("output_schema")
            properties = output.get("properties") if isinstance(output, dict) else None
            members[step_id] = set(properties) if isinstance(properties, dict) else set()
        cost = cap.get("cost") or {"class": "free"}
        amount = Decimal(0)
        if cost.get("class") == "metered":
            metered = True
            if not is_money(cost.get("max")):
                return [f"{step_id}: cost max of {cap_id} is not a decimal amount and currency"]
            amount = decimal(cost["max"]["amount"])
            step_currency = cost["max"]["currency"]
            currency = currency or step_currency
            if step_currency != currency:
                problems.append(f"{step_id}: cost currency {step_currency} does not match {currency}")
        if kind == "map":
            amount *= step["bound"]
        total += amount
    if metered:
        budget = (plan.get("budget") or {}).get("max")
        if not budget:
            problems.append("metered plan requires budget.max")
        elif not is_money(budget):
            problems.append("budget.max is not a decimal amount and currency")
        else:
            if budget["currency"] != currency:
                problems.append("budget currency does not match capability costs")
            elif total > decimal(budget["amount"]):
                problems.append(f"maximum cost {total} exceeds budget {budget['amount']}")
    return problems


SEMANTIC = {
    "envelope": check_envelope,
    "capability-descriptor": check_capability_descriptor,
    "plan": check_plan,
    "capability-token": check_token,
    "module-manifest": check_module_manifest,
    "provider-manifest": check_provider_manifest,
    "privacy-report": check_privacy_report,
    "refusal": lambda document: [],
    "session-record": check_session_record,
    "intent-catalog": check_intent_catalog,
    "linguist-envelope": check_linguist_envelope,
    "linguist-proposal": lambda document: [],
}


# ---------------------------------------------------------------- validation


def validate_document(document, name: str, schemas: dict[str, dict], registry: Registry) -> list[str]:
    """Return a list of problems; empty means the document is valid."""
    validator = make_validator(name, schemas, registry)
    problems = []
    for error in sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path)):
        location = "/".join(str(p) for p in error.absolute_path) or "(root)"
        message = error.message
        if len(message) > 200:
            message = f"failed '{error.validator}' check at {'/'.join(str(p) for p in error.absolute_schema_path)}"
        problems.append(f"{location}: {message}")
    if not problems:
        try:
            problems.extend(SEMANTIC[name](document))
        except ValueError as exc:  # for example a timestamp that matches the pattern but is not a real date
            problems.append(f"(semantic): {exc}")
    return problems


def schema_for_example(path: Path) -> str:
    matches = [n for n in SCHEMA_NAMES if path.name.startswith(n + ".")]
    if not matches:
        raise ValueError(f"{path.name}: file name must start with a schema name")
    return max(matches, key=len)


def example_files(example_dir: Path = EXAMPLE_DIR) -> list[Path]:
    return sorted(example_dir.glob("*.json"))


def load_checked() -> tuple[dict[str, dict], Registry]:
    """Load the schemas and build the registry, failing with a clear message."""
    schemas = load_schemas()
    problems = check_schema_files(schemas)
    if problems:
        raise SystemExit("schema problems:\n" + "\n".join(f"SCHEMA  {p}" for p in problems))
    return schemas, build_registry(schemas)


def run_examples(verbose: bool = True) -> int:
    schemas, registry = load_checked()
    failures: list[str] = []
    files = example_files()
    if not files:
        failures.append("no examples found")
    for path in files:
        name = schema_for_example(path)
        expect_valid = not path.name.endswith(".invalid.json")
        problems = validate_document(load_json(path), name, schemas, registry)
        ok = (not problems) == expect_valid
        status = "ok  " if ok else "FAIL"
        expectation = "valid" if expect_valid else "invalid"
        if verbose or not ok:
            print(f"{status}  {path.relative_to(REPO)} (expected {expectation}, schema {name})")
            for problem in problems if (verbose and not expect_valid) or not ok else []:
                print(f"        - {problem}")
        if not ok:
            failures.append(str(path))
    print(f"\n{len(files)} examples checked, {len(failures)} failure(s)")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("files", nargs="*", type=Path, help="JSON files to validate (default: all examples)")
    parser.add_argument("--schema", choices=SCHEMA_NAMES, help="schema to use for FILES (default: from file name)")
    parser.add_argument("-q", "--quiet", action="store_true", help="only print failures")
    args = parser.parse_args(argv)
    if not args.files:
        return run_examples(verbose=not args.quiet)
    schemas, registry = load_checked()
    status = 0
    for path in args.files:
        try:
            name = args.schema or schema_for_example(path)
            document = load_json(path)
        except (OSError, ValueError) as exc:  # unreadable file, bad JSON, or unknown file name
            print(f"ERROR   {path}: {exc}")
            status |= 2
            continue
        problems = validate_document(document, name, schemas, registry)
        print(f"{'valid  ' if not problems else 'INVALID'} {path} ({name})")
        for problem in problems:
            print(f"        - {problem}")
        status |= 1 if problems else 0
    return status


if __name__ == "__main__":
    sys.exit(main())
