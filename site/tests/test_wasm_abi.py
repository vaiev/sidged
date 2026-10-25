# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""ABI test for the built verifier module (site/target/.../vaikor_wasm.wasm).

Drives the exports exactly as site/playground/playground.js does (vkr_alloc, vkr_call
with a packed ptr<<32|len result, vkr_free) and runs every published vector the
playground offers. Needs the optional `wasmtime` package and a release wasm build;
skips otherwise. Run after `bash scripts/build-vaikor-site.sh`:
    python3 -m unittest discover -s site/tests
"""
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
WASM = ROOT / "site/target/wasm32-unknown-unknown/release/vaikor_wasm.wasm"
VECTORS = ROOT / "spec/test-vectors"

try:
    import wasmtime
except ImportError:  # optional dev dependency
    wasmtime = None


def did_key(public_hex):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    raw = b"\xed\x01" + bytes.fromhex(public_hex)
    n, text = int.from_bytes(raw, "big"), ""
    while n:
        n, r = divmod(n, 58)
        text = alphabet[r] + text
    return "did:key:z" + text


@unittest.skipIf(wasmtime is None or not WASM.exists(), "needs wasmtime and a release wasm build")
class AbiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        engine = wasmtime.Engine()
        cls.store = wasmtime.Store(engine)
        module = wasmtime.Module.from_file(engine, str(WASM))
        if module.imports:
            raise AssertionError(f"verifier imports {len(module.imports)} item(s)")
        instance = wasmtime.Instance(cls.store, module, [])
        cls.ex = instance.exports(cls.store)
        cls.memory = cls.ex["memory"]

    def call(self, op, data):
        store, ex, mem = self.store, self.ex, self.memory
        buffers = []
        for raw in (op.encode(), json.dumps(data).encode()):
            ptr = ex["vkr_alloc"](store, len(raw))
            mem.write(store, raw, ptr)
            buffers.append((ptr, len(raw)))
        packed = ex["vkr_call"](store, *buffers[0], *buffers[1]) & 0xFFFFFFFFFFFFFFFF
        for ptr, size in buffers:
            ex["vkr_free"](store, ptr, size)
        ptr, size = packed >> 32, packed & 0xFFFFFFFF
        text = bytes(mem.read(store, ptr, ptr + size)).decode()
        ex["vkr_free"](store, ptr, size)
        return json.loads(text)

    def test_about_lists_the_operations(self):
        about = self.call("about", {})
        self.assertIn("plan.verify", about["operations"])
        self.assertIn("default-flow", about["default_flow_policy"])

    def test_every_playground_vector_matches_its_published_expectation(self):
        keys = {}
        for path in (VECTORS / "keys").glob("*.json"):
            for key in json.loads(path.read_text())["keys"]:
                keys[key["name"]] = did_key(key["public_key_hex"])
        shapes = {
            "plan-check": ("plan.verify", lambda i: {"plan": i["plan"], "catalog": i["catalog"]}),
            "flow-check": ("flow.check", lambda i: i),
            "record-check": ("record.verify", lambda i: {
                "record": i["record"], "trusted_dids": [keys.get(n, n) for n in i["trusted_core_keys"]]}),
            "dcbor-encode": ("dcbor.encode", lambda i: {"value": i["value"]}),
            "dcbor-decode": ("dcbor.decode", lambda i: {"hex": i["hex"]}),
        }
        ran = 0
        for name in ("plan/verify.json", "plan/dcbor-signed.json", "records/records.json"):
            for vector in json.loads((VECTORS / name).read_text())["vectors"]:
                shape = shapes.get(vector.get("operation"))
                if not shape or "allow" in vector["input"]:
                    continue
                op, build = shape
                out = self.call(op, build(vector["input"]))
                expected = vector["expected"]
                with self.subTest(vector=vector["id"]):
                    if "result" in expected:
                        self.assertEqual(out.get("verdict"), expected["result"], out)
                    elif op == "dcbor.encode":
                        self.assertEqual(out.get("hex"), expected["value"], out)
                    elif op == "dcbor.decode":
                        self.assertEqual(out.get("value"), expected["value"], out)
                ran += 1
        self.assertGreater(ran, 40)

    def test_malformed_input_is_a_verdict_not_a_trap(self):
        self.assertEqual(self.call("plan.verify", {"plan": 1})["verdict"], "refuse")
        self.assertEqual(self.call("does.not.exist", {})["stage"], "operation")


if __name__ == "__main__":
    unittest.main()
