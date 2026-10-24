#!/usr/bin/env python3
"""Reproducible generator for the dcbor, record (SDG-L0, spec 0012) and signed-plan
(SDG-L3, spec 0013) test vectors.

Deterministic: the same inputs and the RFC 8032 test keys always give the same bytes,
digests and Ed25519 signatures. Requires only `cryptography` (spec/validate/requirements.txt).

    python spec/test-vectors/tools/gen_dcbor_vectors.py          # rewrite the vector files
    python spec/test-vectors/tools/gen_dcbor_vectors.py --check  # fail if files are stale

TEST KEYS ONLY. Never sign anything real with them.
"""
import argparse, base64, hashlib, json, sys, unicodedata
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
KEYS = {k["name"]: k for k in json.loads((ROOT / "keys/rfc8032-test-keys.json").read_text())["keys"]}


class DcborError(ValueError):
    pass


# ---------------------------------------------------------------- dcbor (L0)
def _head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise DcborError("integer-out-of-range")


def dcbor(v):
    """Encode the JSON data model as deterministic CBOR (spec 0012 section 2)."""
    if v is None:
        return b"\xf6"
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if isinstance(v, int):
        if not -(1 << 63) <= v < (1 << 64):
            raise DcborError("integer-out-of-range")
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, float):
        raise DcborError("float-not-allowed")
    if isinstance(v, str):
        if unicodedata.normalize("NFC", v) != v:
            raise DcborError("not-nfc")
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(dcbor(x) for x in v)
    if isinstance(v, dict):
        items = []
        for k, x in v.items():
            if not isinstance(k, str):
                raise DcborError("non-text-key")
            items.append((dcbor(k), dcbor(x)))
        items.sort(key=lambda kv: kv[0])  # bytewise lexicographic order of encoded keys
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    raise DcborError("unsupported-type")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def digest(obj):
    """SHA-256, unpadded base64url, over dcbor of the object without `sig`."""
    return b64u(hashlib.sha256(dcbor(strip_sig(obj))).digest())


def strip_sig(obj):
    return {k: v for k, v in obj.items() if k != "sig"}


def did_key(pub_hex):
    raw = bytes.fromhex("ed01") + bytes.fromhex(pub_hex)
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n, out = int.from_bytes(raw, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    return "did:key:z" + "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def sign(obj, key_name):
    k = KEYS[key_name]
    did = did_key(k["public_key_hex"])
    body = strip_sig(obj)
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(k["secret_key_hex"]))
    value = b64u(sk.sign(dcbor(body)))
    return {**body, "sig": {"alg": "EdDSA", "kid": did, "canon": "dcbor", "value": value, "signer": did}}


def verify(obj, key_name):
    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(KEYS[key_name]["public_key_hex"]))
    raw = base64.urlsafe_b64decode(obj["sig"]["value"] + "==")
    try:
        pk.verify(raw, dcbor(strip_sig(obj)))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- helpers
def vec(vid, doc, section, op, inp, expected, requires=None, note=None):
    sections = section if isinstance(section, list) else [section]
    v = {"id": vid, "spec": [{"doc": doc, "version": "0.1", "section": s} for s in sections], "operation": op}
    if requires:
        v["requires"] = requires
    v["input"] = inp
    v["expected"] = expected
    v["status"] = "normative"
    if note:
        v["note"] = note
    return v


def ok(value=None, **kw):
    if kw:
        return {"value": {"digest": value, **kw}}
    return {"result": "accept"} if value is None else {"value": value}


# Refusal codes come from spec/registries (no new codes); the finer cause goes in `note`.
REASON = {"float-not-allowed": "malformed", "not-nfc": "malformed", "missing-class": "malformed",
          "missing-retention": "malformed", "missing-provenance": "malformed", "bad-residency": "residency-unknown-tag",
          "bad-retention": "malformed", "digest-mismatch": "malformed", "catalog-mismatch": "malformed",
          "lifetime-too-long": "malformed", "flow-denied": "data-class-forbidden",
          "integer-out-of-range": "malformed", "not-deterministic": "malformed", "indefinite-or-reserved": "malformed",
          "duplicate-key": "malformed", "float-or-simple": "malformed", "bytes-or-tag": "malformed", "non-text-key": "malformed",
          "truncated": "malformed", "bad-class": "malformed", "kid-not-signer": "bad-signature", "untrusted-signer": "bad-signature", "not-yet-valid": "malformed"}


def refuse(reason):
    return {"result": "refuse", "reason": REASON.get(reason, reason)}


CORE, OWNER = "rfc8032-test-1", "rfc8032-test-3"
CORE_DID, OWNER_DID = did_key(KEYS[CORE]["public_key_hex"]), did_key(KEYS[OWNER]["public_key_hex"])


# ---------------------------------------------------------------- strict dcbor decoder (0012 R4)
def dcbor_decode(data):
    """Decode bytes and refuse anything that is not exactly dcbor v0.1 (re-encode and compare)."""
    pos = 0

    def arg(ai):
        nonlocal pos
        if ai < 24:
            return ai
        if ai in (24, 25, 26, 27):
            size = 1 << (ai - 24)
            if pos + size > len(data):
                raise DcborError("truncated")
            n = int.from_bytes(data[pos:pos + size], "big")
            pos += size
            return n
        raise DcborError("indefinite-or-reserved")

    def item():
        nonlocal pos
        if pos >= len(data):
            raise DcborError("truncated")
        ib = data[pos]; pos += 1
        major, ai = ib >> 5, ib & 31
        if major == 7:
            return {20: False, 21: True, 22: None}.get(ai) if ai in (20, 21, 22) else (_ for _ in ()).throw(DcborError("float-or-simple"))
        if major in (2, 6):
            raise DcborError("bytes-or-tag")
        n = arg(ai)
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if major == 3:
            s = data[pos:pos + n]; pos += n
            return s.decode("utf-8")
        if major == 4:
            return [item() for _ in range(n)]
        out = {}
        for _ in range(n):
            k = item()
            if not isinstance(k, str):
                raise DcborError("non-text-key")
            if k in out:
                raise DcborError("duplicate-key")
            out[k] = item()
        return out

    try:
        value = item()
    except (UnicodeDecodeError, IndexError):
        raise DcborError("malformed")
    if pos != len(data) or dcbor(value) != data:
        raise DcborError("not-deterministic")
    return value


# ---------------------------------------------------------------- records (0012)
CLASS_ROOTS = {"identity", "contacts", "communications", "calendar", "location", "health", "biometric", "finance",
               "documents", "media", "home", "device", "query", "usage", "adaptation", "memory", "secrets"}
TAG_REGIONS = {"CH": {"CH"}, "EU": {"EU"}, "CH-EU": {"CH", "EU"}}
SEG = __import__("re").compile(r"^[a-z0-9][a-z0-9-]*$")


def class_ok(c):
    if not isinstance(c, str) or not c:
        return False
    segs = c.split(".")
    if not all(SEG.match(s) for s in segs):
        return False
    return segs[0] in CLASS_ROOTS or segs[0].startswith("x-")


def class_resource(c):
    """0012 R9: urn:sidged:record:<class with '.' -> '/'>."""
    if not class_ok(c):
        raise DcborError("malformed")
    return "urn:sidged:record:" + c.replace(".", "/")


def covers(parent, child):
    return child == parent or child.startswith(parent + ".")


def derive(inputs, declassify=False):
    """0012 R10: covering class of the inputs and union of residency tags."""
    classes = [i["class"] for i in inputs]
    top = [c for c in classes if all(covers(c, o) for o in classes)]
    if not top and not declassify:
        raise DcborError("data-class-forbidden")
    if any(not i["tags"] for i in inputs):
        return {"class": top[0] if top else None, "tags": [], "regions": []}  # fail closed (0001 R8a)
    tags = sorted({t for i in inputs for t in i["tags"] if t != "unrestricted"})
    if not tags:
        return {"class": top[0] if top else None, "tags": ["unrestricted"], "regions": "any"}
    regions = sorted(set.intersection(*(TAG_REGIONS[t] for t in tags)))
    return {"class": top[0] if top else None, "tags": tags, "regions": regions}


def record_check(rec, trusted):
    """Reference for record-check. Returns None (accept) or a fine cause."""
    req = ["v", "type", "class", "owner", "provenance", "residency", "retention", "content", "sig"]
    if rec.get("v") != "0.1":
        return "unsupported-version"
    if any(k not in rec for k in req):
        return "missing-" + next(k for k in req if k not in rec)
    if not class_ok(rec["class"]):
        return "bad-class"
    p = rec["provenance"]
    if any(k not in p for k in ("source", "created", "derived_from", "plan")):
        return "missing-provenance"
    if any(t not in TAG_REGIONS and not __import__("re").match(r"^x-[a-z0-9-]{1,62}$", t) for t in rec["residency"]["tags"]):
        return "bad-residency"
    if rec["retention"].get("on_expiry") not in ("delete", "tombstone"):
        return "bad-retention"
    sig = rec["sig"]
    if sig.get("canon") != "dcbor" or sig.get("alg") != "EdDSA":
        return "bad-signature"
    if sig.get("kid") != sig.get("signer"):
        return "kid-not-signer"
    names = [n for n in trusted if did_key(KEYS[n]["public_key_hex"]) == sig.get("signer")]
    if not names:
        return "untrusted-signer"
    return None if verify(rec, names[0]) else "bad-signature"


def retention_state(rec, now):
    from datetime import datetime
    u = rec["retention"]["until"]
    if u is None:
        return "live"
    t = lambda s: datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
    return "expired" if t(now) >= t(u) else "live"


def base_record():
    return {
        "v": "0.1",
        "type": "application/vnd.sidged.note+json",
        "class": "health.records.notes",
        "owner": OWNER_DID,
        "provenance": {"source": "urn:sidged:capability:notes.write", "created": "2026-10-15T08:00:00Z",
                       "derived_from": [], "plan": None},
        "residency": {"tags": ["CH"]},
        "retention": {"until": "2027-10-15T08:00:00Z", "on_expiry": "delete"},
        "content": {"text": "Physio Tuesday 14:00"},
    }


TRUSTED = [CORE]


def records_vectors():
    v = []
    enc = [("null", None), ("true", True), ("int-23", 23), ("int-24", 24), ("int-neg-1", -1),
           ("int-65536", 65536), ("text", "Zürich"), ("array", [1, "a"]),
           ("map-key-order", {"b": 1, "a": 2, "aa": 3})]
    for i, (name, val) in enumerate(enc, 1):
        v.append(vec(f"dcbor.encode.{i:03d}", "L0", "0012 §2", "dcbor-encode", {"value": val},
                     ok(value=dcbor(val).hex()), ["dcbor"], name))
    n = len(enc)
    for name, val, why in [("float", 1.5, "float-not-allowed"), ("not-nfc", "Zu\u0308rich", "not-nfc"),
                           ("int-2^64", 1 << 64, "integer-out-of-range"), ("not-nfc-key", {"Zu\u0308": 1}, "not-nfc")]:
        n += 1
        v.append(vec(f"dcbor.encode.{n:03d}", "L0", "0012 R2-R3", "dcbor-encode", {"value": val}, refuse(why), ["dcbor"], f"{name}: {why}"))
    dec = [("a2616101616202", {"a": 1, "b": 2}, None, "canonical map"),
           ("1817", None, "not-deterministic", "non-shortest int 23"),
           ("a2616201616102", None, "not-deterministic", "unsorted map keys"),
           ("9f01ff", None, "indefinite-or-reserved", "indefinite-length array"),
           ("a2616101616102", None, "duplicate-key", "duplicate key a"),
           ("f93c00", None, "float-or-simple", "half float 1.0"),
           ("c060", None, "bytes-or-tag", "tag 0"),
           ("4101", None, "bytes-or-tag", "byte string"),
           ("a10101", None, "non-text-key", "integer map key"),
           ("0102", None, "not-deterministic", "trailing bytes")]
    for i, (hx, val, why, note) in enumerate(dec, 1):
        v.append(vec(f"dcbor.decode.{i:03d}", "L0", "0012 R4", "dcbor-decode", {"hex": hx},
                     ok(value=val) if why is None else refuse(why), ["dcbor"], note if why is None else f"{why}: {note}"))

    rec = sign(base_record(), CORE)
    v.append(vec("record.digest.001", "L0", "0012 R7", "record-digest", {"record": rec},
                 ok(value=digest(rec), dcbor_hex=dcbor(strip_sig(rec)).hex()), ["dcbor"],
                 "digest ignores sig; sha256 b64url over dcbor"))
    checks = [(rec, None, "signed by the trusted Core key")]
    bad = json.loads(json.dumps(rec)); bad["class"] = "calendar.availability"
    checks.append((bad, "bad-signature", "class relabelled after signing"))
    for mut, why in [
        (lambda r: r.pop("class"), "missing-class"),
        (lambda r: r.pop("retention"), "missing-retention"),
        (lambda r: r["provenance"].pop("source"), "missing-provenance"),
        (lambda r: r["residency"].update(tags=["Not A Tag!"]), "bad-residency"),
        (lambda r: r["retention"].update(on_expiry="archive"), "bad-retention"),
        (lambda r: r.update(v="0.2"), "unsupported-version"),
        (lambda r: r.update({"class": "healthx.notes"}), "bad-class"),
        (lambda r: r.update({"class": "health/records"}), "bad-class"),
        (lambda r: r.update({"class": "health..notes"}), "bad-class"),
    ]:
        r = base_record(); mut(r); checks.append((sign(r, CORE), why, why))
    xr = base_record(); xr["class"] = "x-acme.notes"
    checks.append((sign(xr, CORE), None, "x- class roots are accepted (data-class registry)"))
    checks.append((sign(base_record(), "rfc8032-test-2"), "untrusted-signer",
                   "valid signature by rfc8032-test-2, which is not a trusted Core key"))
    kd = sign(base_record(), CORE); kd["sig"]["kid"] = did_key(KEYS["rfc8032-test-2"]["public_key_hex"])
    checks.append((kd, "kid-not-signer", "kid differs from signer (both outside the signed bytes)"))
    for i, (r, why, note) in enumerate(checks, 1):
        v.append(vec(f"record.check.{i:03d}", "L0", "0012 §3", "record-check",
                     {"record": r, "trusted_core_keys": TRUSTED},
                     ok() if why is None else refuse(why), ["dcbor", "EdDSA"], note))
    for i, (now, state) in enumerate([("2027-10-15T07:59:59Z", "live"), ("2027-10-15T08:00:00Z", "expired"),
                                      ("2028-01-01T00:00:00Z", "expired")], 1):
        v.append(vec(f"record.retention.{i:03d}", "L0", "0012 R8", "record-retention",
                     {"record": rec, "now": now}, ok(value=state)))
    keep = base_record(); keep["retention"] = {"until": None, "on_expiry": "delete"}
    v.append(vec("record.retention.004", "L0", "0012 R8", "record-retention",
                 {"record": sign(keep, CORE), "now": "2099-01-01T00:00:00Z"}, ok(value="live"), None, "until null = owner-managed"))
    # Ids are stable: 001 and 004 were retired in suite 0.10.0 when 0001 R8 v0.2 made empty tags fail closed.
    der = [
        (2, [("health.records.notes", ["CH"]), ("health.records.notes", ["EU"])], {"class": "health.records.notes", "tags": ["CH", "EU"], "regions": []}, "CH + EU -> nowhere, never any"),
        (3, [("health.records.notes", ["CH"]), ("health.records.notes", ["CH-EU"])], {"class": "health.records.notes", "tags": ["CH", "CH-EU"], "regions": ["CH"]}, "CH + CH-EU -> CH"),
        (5, [("health.records", []), ("finance.payments", [])], None, "no common covering class"),
        (6, [("health.records.notes", []), ("health.records.labs", [])], None, "siblings have no covering input class"),
        (7, [("health.records.notes", ["CH"]), ("health.records.notes", ["unrestricted"])], {"class": "health.records.notes", "tags": ["CH"], "regions": ["CH"]}, "CH + unrestricted -> CH (0001 R8e)"),
        (8, [("health.records", ["unrestricted"]), ("health.records.notes", ["unrestricted"])], {"class": "health.records", "tags": ["unrestricted"], "regions": "any"}, "covering class; all unrestricted stays unrestricted"),
        (9, [("health.records.notes", ["CH"]), ("health.records.notes", [])], {"class": "health.records.notes", "tags": [], "regions": []}, "CH + empty tags -> empty, fails closed (0001 R8a)"),
    ]
    for i, ins, exp, note in der:
        v.append(vec(f"record.derive.{i:03d}", "L0", "0012 R10", "record-derive",
                     {"inputs": [{"class": c, "tags": t} for c, t in ins]},
                     ok(value=exp) if exp else refuse("data-class-forbidden"), None, note))
    for i, (c, exp) in enumerate([("health.records.notes", "urn:sidged:record:health/records/notes"),
                                  ("x-acme", "urn:sidged:record:x-acme"), ("health/records", None), ("healthx", None)], 1):
        v.append(vec(f"record.resource.{i:03d}", "L0", "0012 R9", "record-resource", {"class": c},
                     ok(value=exp) if exp else refuse("malformed"), None, None if exp else "bad class grammar or root"))
    for i, (right, res, exp) in enumerate([
            ("urn:sidged:record:health/*", "urn:sidged:record:health/records/notes", True),
            ("urn:sidged:record:health/records/*", "urn:sidged:record:health/records/notes", True),
            ("urn:sidged:record:health/*", "urn:sidged:record:health", False),
            ("urn:sidged:record:health/*", "urn:sidged:record:healthx/notes", False),
            ("urn:sidged:record:health/records", "urn:sidged:record:health/records/notes", False)], 1):
        v.append(vec(f"record.coverage.{i:03d}", "L2", "R9", "resource-covers", {"right": right, "resource": res},
                     ok(value=exp), None, "record class resources under SDG-L2 R9 (0012 R9)"))
    return {"category": "records", "description": "Deterministic CBOR encoding and decoding and typed Records (spec 0012, SDG-L0). Real Ed25519 signatures over dcbor with the RFC 8032 test keys; generated and self-checked by tools/gen_dcbor_vectors.py.", "vectors": v}


def selfcheck_records(f):
    """Recompute every records expectation with the reference functions above."""
    for x in f["vectors"]:
        op, inp, exp = x["operation"], x["input"], x["expected"]
        try:
            if op == "dcbor-encode":
                got = {"value": dcbor(inp["value"]).hex()}
            elif op == "dcbor-decode":
                got = {"value": dcbor_decode(bytes.fromhex(inp["hex"]))}
            elif op == "record-check":
                cause = record_check(inp["record"], inp["trusted_core_keys"])
                got = {"result": "accept"} if cause is None else refuse(cause)
            elif op == "record-retention":
                got = {"value": retention_state(inp["record"], inp["now"])}
            elif op == "record-derive":
                got = {"value": derive(inp["inputs"])}
            elif op == "record-resource":
                got = {"value": class_resource(inp["class"])}
            elif op == "record-digest":
                r = inp["record"]
                got = {"value": {"digest": digest(r), "dcbor_hex": dcbor(strip_sig(r)).hex()}}
            elif op == "resource-covers":
                r, s = inp["right"], inp["resource"]
                got = {"value": s == r or (r.endswith("/*") and s.startswith(r[:-1]) and len(s) > len(r) - 1)}
            else:
                continue
        except DcborError as e:
            got = refuse(str(e))
        if got != exp:
            raise SystemExit(f"self-check failed: {x['id']}: expected {exp}, got {got}")


# ---------------------------------------------------------------- signed plans (0013)
SEND = "urn:sidged:capability:message.send"
CATALOG = [
    {"id": "urn:sidged:capability:calendar.free_slots", "effects": ["read"], "data_classes": ["calendar.availability"], "consequential": False, "cost": {"class": "free"}},
    {"id": SEND, "effects": ["egress"], "data_classes": ["communications.content"], "consequential": True, "cost": {"class": "free"}},
]
PLAN = {"v": "0.1", "goal": "Propose a time", "budget": {"max": {"amount": "0.01", "currency": "CHF"}}, "steps": [
    {"id": "free", "kind": "call", "capability": "urn:sidged:capability:calendar.free_slots", "args": {"range": {"lit": "next_week"}}},
    {"id": "pick", "kind": "expr", "expr": "free.slots"},
    {"id": "send", "kind": "call", "capability": SEND, "approval": True,
     "args": {"to": {"lit": "contact:bea"}, "body": {"ref": "pick"}}}]}


def is_sensitive(c):
    """Same rule as runtime/sidged-verify/src/plan.rs `sensitive` (exact name or '.' boundary)."""
    return any(c == r or c.startswith(r + ".") for r in ("health.records", "secrets"))


def catalog_digest(catalog, plan):
    """0013 R6: dcbor of the descriptors the plan references, sorted by id."""
    used = {s["capability"] for s in plan["steps"] if "capability" in s}
    return b64u(hashlib.sha256(dcbor(sorted((c for c in catalog if c["id"] in used), key=lambda c: c["id"]))).digest())


def policy_digest(policies):
    """0013 R6: dcbor of [{id, source}] sorted by @id."""
    import re
    items = sorted(({"id": re.search(r'@id\("([^"]+)"\)', p).group(1), "source": p} for p in policies), key=lambda x: x["id"])
    return b64u(hashlib.sha256(dcbor(items)).digest())


def stored_plan(plan=PLAN, catalog=CATALOG, **over):
    sp = {"v": "0.1", "kind": "sdg.plan.stored", "plan": plan, "plan_digest": digest(plan),
          "catalog_digest": catalog_digest(catalog, plan), "owner": OWNER_DID,
          "issued": "2026-10-15T08:00:00Z", "expires": "2027-01-15T08:00:00Z", "flow_policy": "default"}
    sp.update(over)
    return sp


DEFAULT_POLICY = ('@id("default-flow")\npermit (principal, action == Sidged::Action::"flow", resource)\n'
                  'unless { context.sensitive };')


def permit(pid, cls, dest):
    return (f'@id("{pid}")\npermit (principal, action == Sidged::Action::"flow", resource == Sidged::Capability::"{SEND}")\n'
            f'when {{ context.class == "{cls}" && context.destination == "{dest}" }};')


def forbid(pid, cond):
    return f'@id("{pid}")\nforbid (principal, action == Sidged::Action::"flow", resource)\nwhen {{ {cond} }};'


def flow_plan(cls, dests):
    """A plan that reads one class and sends it to each destination (one egress step per destination)."""
    cat = [{"id": "urn:sidged:capability:notes.read", "effects": ["read"], "data_classes": [cls], "consequential": False, "cost": {"class": "free"}},
           CATALOG[1]]
    steps = [{"id": "read", "kind": "call", "capability": "urn:sidged:capability:notes.read", "args": {}}]
    for i, d in enumerate(dests, 1):
        steps.append({"id": f"send{i}", "kind": "call", "capability": SEND, "approval": True,
                      "args": {"to": {"lit": d}, "body": {"ref": "read"}}})
    return {"v": "0.1", "goal": "Share notes", "steps": steps}, cat


def plan_vectors():
    v = []
    v.append(vec("plan.dcbor.001", "L3", "0013 R2", "plan-digest", {"plan": PLAN},
                 ok(value=digest(PLAN), dcbor_hex=dcbor(PLAN).hex()), ["dcbor"]))
    fl = json.loads(json.dumps(PLAN)); fl["steps"][0]["args"]["range"] = {"lit": 1.5}
    v.append(vec("plan.dcbor.002", "L3", "0013 R1", "plan-digest", {"plan": fl}, refuse("float-not-allowed"), ["dcbor"], "float in a plan"))
    sp = sign(stored_plan(), OWNER)
    ctx = {"catalog": CATALOG, "owner_key": OWNER, "now": "2026-11-01T00:00:00Z"}
    v.append(vec("plan.signed.001", "L3", "0013 R3-R6", "stored-plan-check", {"stored": sp, **ctx},
                 ok(), ["dcbor", "EdDSA"], "owner-signed stored plan"))
    v.append(vec("plan.signed.002", "L3", "0013 R4", "stored-plan-signing-input", {"stored": sp},
                 ok(value=dcbor(strip_sig(sp)).hex()), ["dcbor"]))
    t = json.loads(json.dumps(sp)); t["plan"]["goal"] = "Propose a time to everyone"; t["plan_digest"] = digest(t["plan"])
    cat2 = json.loads(json.dumps(CATALOG)); cat2[1]["effects"] = ["egress", "write"]
    cases = [
        (t, {}, "bad-signature", "goal changed and plan_digest recomputed after signing; only the signature fails"),
        (sign(stored_plan(), CORE), {}, "bad-signature", "signed by the Core key, owner member still the owner"),
        (sp, {"now": "2027-01-15T08:00:00Z"}, "expired", "now == expires"),
        (sign(stored_plan(plan_digest="AAAA"), OWNER), {}, "digest-mismatch", None),
        (sp, {"catalog": cat2}, "catalog-mismatch", "message.send gained an effect; plan still verifies"),
        (sign(stored_plan(expires="2027-10-16T08:00:00Z"), OWNER), {}, "lifetime-too-long", "366 days"),
        (sign(stored_plan(owner=CORE_DID), CORE), {}, "bad-signature", "self-consistent owner/kid/signer = Core DID; configured owner key is rfc8032-test-3"),
        (sign(stored_plan(issued="2026-12-01T00:00:00Z"), OWNER), {}, "not-yet-valid", "issued after now"),
        (sign(stored_plan(kind="sdg.plan"), OWNER), {}, "unsupported-version", "unknown kind"),
    ]
    # The rule each fault breaks, in case order.
    rules = ['R4', 'R4', 'R5', 'R3', 'R6', 'R5', 'R4', 'R5', 'R3']
    for i, ((s, over, why, note), rule) in enumerate(zip(cases, rules), 3):
        v.append(vec(f"plan.signed.{i:03d}", "L3", ["0013 §3", f"0013 {rule}"], "stored-plan-check", {"stored": s, **ctx, **over},
                     refuse(why), ["dcbor", "EdDSA"], f"{why}: {note}" if note else why))
    owner_permit = permit("owner-allow-1", "health.records.notes", "contact:dr-meier")
    flows = [
        ("calendar.availability", ["contact:bea"], [DEFAULT_POLICY], True, "non-sensitive, default set"),
        ("health.records.notes", ["contact:bea"], [DEFAULT_POLICY], False, "sensitive, default set"),
        ("health.records.notes", ["contact:dr-meier"], [DEFAULT_POLICY, owner_permit], True, "owner permit matches destination"),
        ("health.records.notes", ["contact:bea"], [DEFAULT_POLICY, owner_permit], False, "owner permit is for another destination"),
        ("secrets.token", ["contact:dr-meier"], [DEFAULT_POLICY, permit("owner-allow-2", "secrets.token", "contact:dr-meier")], False,
         "R10 secrets rule: matching owner permit, no forbid, still refused"),
        ("health.records.notes", ["contact:dr-meier"], [DEFAULT_POLICY, owner_permit,
          forbid("owner-forbid-1", 'context.class == "health.records.notes" && context.destination == "contact:dr-meier"')], False,
         "forbid overrides a matching permit on a non-secrets class"),
        ("secrets", ["contact:bea"], [], False, "empty set denies"),
        ("calendar.availability", ["contact:bea"], [], False, "empty set denies non-sensitive too"),
        ("health.records.notes", ["contact:dr-meier", "contact:bea"], [DEFAULT_POLICY, owner_permit], False,
         "R8: one request per egress step; send1 allowed, send2 refused"),
        ("health.recordsx", ["contact:bea"], [DEFAULT_POLICY], True, "dot boundary: health.recordsx is not sensitive (plan.rs)"),
    ]
    flow_rules = ['R9', 'R9', 'R10', 'R8', 'R10', 'R10', 'R10', 'R10', 'R8', 'R8']
    for i, ((cls, dests, pols, allow, note), rule) in enumerate(zip(flows, flow_rules), 1):
        assert is_sensitive(cls) == cls.startswith(("health.records.", "secrets.")) or cls in ("health.records", "secrets")
        plan, cat = flow_plan(cls, dests)
        v.append(vec(f"plan.flow.{i:03d}", "L3", ["0013 §4", f"0013 {rule}"], "flow-check",
                     {"plan": plan, "catalog": cat, "policies": pols},
                     ok() if allow else refuse("flow-denied"), ["cedar"], note))
    return {"category": "plan", "description": "dcbor plan digests, owner-signed stored plans and the Cedar flow policy (spec 0013, SDG-L3). Real Ed25519 signatures over dcbor with the RFC 8032 test keys; generated by tools/gen_dcbor_vectors.py.", "vectors": v}


def stored_plan_faults(sp, catalog, owner_key, now):
    """Every 0013 R3-R6 check that fails (the suite rule is one fault per vector)."""
    from datetime import datetime
    t = lambda s: datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
    f = []
    if sp.get("v") != "0.1" or sp.get("kind") != "sdg.plan.stored":
        f.append("unsupported-version")
    if sp.get("plan_digest") != digest(sp["plan"]):
        f.append("digest-mismatch")
    owner_did = did_key(KEYS[owner_key]["public_key_hex"])
    s = sp["sig"]
    if not (sp["owner"] == owner_did and s["kid"] == s["signer"] == owner_did and verify(sp, owner_key)):
        f.append("bad-signature")
    life = (t(sp["expires"]) - t(sp["issued"])).total_seconds()
    if life <= 0 or life > 365 * 86400:
        f.append("lifetime-too-long")
    if t(now) < t(sp["issued"]):
        f.append("not-yet-valid")
    if t(now) >= t(sp["expires"]):
        f.append("expired")
    if sp["catalog_digest"] != catalog_digest(catalog, sp["plan"]):
        f.append("catalog-mismatch")
    return f


def selfcheck_plans(data):
    for x in data["vectors"]:
        if x["operation"] != "stored-plan-check":
            continue
        i = x["input"]
        f = stored_plan_faults(i["stored"], i["catalog"], i["owner_key"], i["now"])
        exp = x["expected"]
        want = [] if exp.get("result") == "accept" else [k for k in f if REASON.get(k, k) == exp["reason"]]
        if (exp.get("result") == "accept" and f) or (exp.get("result") == "refuse" and len(f) != 1) or (f and not want):
            raise SystemExit(f"self-check failed: {x['id']}: faults {f}, expected {exp}")


OUTPUTS = {"records/records.json": records_vectors, "plan/dcbor-signed.json": plan_vectors}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--only", choices=list(OUTPUTS))
    a = ap.parse_args()
    stale = []
    for rel, fn in OUTPUTS.items():
        if a.only and rel != a.only:
            continue
        data = fn()
        if data["category"] == "records":
            selfcheck_records(data)
        else:
            selfcheck_plans(data)
        text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
        p = ROOT / rel
        if a.check:
            if not p.exists() or p.read_text(encoding="utf-8") != text:
                stale.append(rel)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
            print("wrote", rel)
    if stale:
        sys.exit("stale: " + ", ".join(stale))


if __name__ == "__main__":
    main()
