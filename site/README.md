# vaikor.com (WP 8): schema hub and WASM verifier playground

`bash scripts/build-vaikor-site.sh [out-dir]` writes a static site (default `dist/site`, ignored by git) that any
static host can serve:

| Path | Contents |
|---|---|
| `/playground/` | Verifier playground. Lists the published test vectors (plan structure, Cedar information flow, signed records, dCBOR), lets a visitor edit the input and runs the check in the browser |
| `/wasm/vaikor_wasm.wasm` | [`vaikor-wasm`](vaikor-wasm/): `vaikor-verify` (VKR-L3 verifier, `CedarFlowPolicy`), `vaikor-record` (dCBOR, signed records, artifact surfaces) and `vaikor-grant` (`did:key`) for `wasm32-unknown-unknown` |
| `/spec/schemas/*.schema.json` | Every JSON Schema at its `$id` (`https://vaikor.com/spec/schemas/...`) |
| `/spec/examples/`, `/spec/test-vectors/`, `/spec/catalogs/` | Examples, the test vector suite (keys reduced to their public halves), the intent catalog and the `@vaiev/ui` v4 catalog |
| `/spec/index.json` | Every published spec file with its SHA-256 |
| `/_headers` | CSP (`script-src 'self' 'wasm-unsafe-eval'`, `connect-src 'self'`) and content types for hosts that read it |

The build fails closed: the WASM module must have **no imports** (it cannot reach the network, a clock, files or
randomness, so it can only check), and `scripts/check-no-test-keys.py` must find no RFC 8032 test seed in the output.
`vaikor-record` builds without its file-backed `store` on `wasm32`, so no file lock or audit-chain code is in the module.

The module has a small C ABI instead of wasm-bindgen: `vkr_alloc`, `vkr_free`, and
`vkr_call(op, input) -> ptr << 32 | len` with JSON in and out. `site/tests/test_wasm_abi.py` drives it like the
playground does (optional `wasmtime` package) and checks every vector the playground offers.

Not yet here: signed `vkr.bundle/v0` manifests (0014) and the blind E2EE relay (`wss://relay.vaikor.com`, 0016 §2.2).
