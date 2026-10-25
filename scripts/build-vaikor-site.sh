#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
# build-vaikor-site.sh: static vaikor.com (WP 8): schema hub + WASM verifier playground.
#
#   bash scripts/build-vaikor-site.sh [out-dir]      (default: dist/site)
#
# Output (plain static files, any host):
#   /                          hub index
#   /playground/               verifier playground (runs only in the browser)
#   /wasm/vaikor_wasm.wasm     pure verification crates for wasm32-unknown-unknown
#   /spec/schemas/*.schema.json   resolvable at their $id (https://vaikor.com/spec/schemas/...)
#   /spec/examples/, /spec/test-vectors/, /spec/catalogs/, /spec/index.json (sha-256 manifest)
# Fail-closed: the WASM module must import nothing, and no RFC 8032 test seed may be
# published (only the public halves of the test keys are written).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/dist/site}
case $out in /*) ;; *) out=$PWD/$out ;; esac

cargo build --manifest-path "$root/site/Cargo.toml" --release --target wasm32-unknown-unknown --locked
wasm=$root/site/target/wasm32-unknown-unknown/release/vaikor_wasm.wasm

rm -rf "$out"
mkdir -p "$out"/{wasm,assets/tokens,assets/fonts,playground,spec/schemas,spec/examples,spec/catalogs,spec/test-vectors}
cp "$wasm" "$out/wasm/vaikor_wasm.wasm"
cp "$root"/spec/schemas/*.json "$out/spec/schemas/"
cp "$root"/spec/examples/*.json "$out/spec/examples/"
(cd "$root/spec/test-vectors" && find . -type f \( -name '*.json' -o -name VERSION -o -name '*.md' \) \
  ! -path './keys/*' -exec cp --parents {} "$out/spec/test-vectors/" \;)
cp "$root/runtime/vaikor-cli/assets/intent-catalog.json" "$out/spec/catalogs/intent-catalog.json"
cp "$root/ui/a2ui-catalog.v4.json" "$out/spec/catalogs/a2ui-catalog.v4.json"
# @vaiev/ui v4 and the Vaikor theme, the same files and paths vaikor.com serves.
cp "$root"/ui/vaiev-ui/tokens/*.css "$out/assets/tokens/"
cp "$root"/ui/vaiev-ui/fonts/* "$out/assets/fonts/"
cp "$root/ui/vaiev-ui/vaikor-theme.css" "$out/assets/vaikor-theme.css"
cat > "$out/assets/site.css" <<'CSS'
/* vaikor.com index pages on @vaiev/ui v4 + the Vaikor theme. */
.site { max-width: 960px; margin: 0 auto; padding: var(--vv-space-12) var(--vv-layout-margin); display: grid; gap: var(--vv-space-4); }
.site a { color: var(--vv-color-primary); }
.site ul { display: grid; gap: var(--vv-space-2); padding-left: 1.25em; }
CSS
cp "$root"/site/playground/* "$out/playground/"

python3 -I - "$root" "$out" <<'EOF'
import hashlib, html, json, pathlib, sys

root, out = map(pathlib.Path, sys.argv[1:3])

def leb(b, i):
    r = s = 0
    while True:
        x = b[i]; i += 1; r |= (x & 0x7F) << s; s += 7
        if x < 0x80:
            return r, i

# 1. The verifier module must not import anything from the page.
data = (out / "wasm/vaikor_wasm.wasm").read_bytes()
assert data[:4] == b"\0asm", "not a wasm module"
i = 8
while i < len(data):
    section = data[i]; size, i = leb(data, i + 1)
    if section == 2:
        count, _ = leb(data, i)
        if count:
            sys.exit(f"FAIL: vaikor_wasm.wasm has {count} import(s); the verifier must be import-free")
    i += size

# 2. Public halves of the test keys, so record vectors can name trusted signers.
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def did_key(public_hex):
    raw = b"\xed\x01" + bytes.fromhex(public_hex)
    n, text = int.from_bytes(raw, "big"), ""
    while n:
        n, r = divmod(n, 58); text = B58[r] + text
    return "did:key:z" + "1" * (len(raw) - len(raw.lstrip(b"\0"))) + text
keys = []
for path in sorted((root / "spec/test-vectors/keys").glob("*.json")):
    for key in json.loads(path.read_text())["keys"]:
        keys.append({"name": key["name"], "public_key_hex": key["public_key_hex"],
                     "did": did_key(key["public_key_hex"])})
pub = out / "spec/test-vectors/keys/public-keys.json"
pub.parent.mkdir(parents=True, exist_ok=True)
pub.write_text(json.dumps({"note": "Public halves of the RFC 8032 test keys. TEST ONLY.", "keys": keys}, indent=2) + "\n")

# 3. Manifest of everything under /spec, with the schema $id each file answers.
files = []
for path in sorted((out / "spec").rglob("*")):
    if path.is_file():
        entry = {"path": "/" + path.relative_to(out).as_posix(), "bytes": path.stat().st_size,
                 "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        if path.name.endswith(".schema.json"):
            entry["id"] = json.loads(path.read_text()).get("$id")
        files.append(entry)
version = (root / "spec/test-vectors/VERSION").read_text().strip()
(out / "spec/index.json").write_text(json.dumps({"test_vectors_version": version, "files": files}, indent=2) + "\n")

# 4. Plain HTML indexes (no script).
def page(title, body):
    return ("<!doctype html>\n<html lang=\"en\" data-theme=\"dark\">\n<head>\n<meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            f"<title>{html.escape(title)}</title>\n"
            "<link rel=\"stylesheet\" href=\"/assets/tokens/tokens.css\">\n<link rel=\"stylesheet\" href=\"/assets/tokens/fonts.css\">\n"
            "<link rel=\"stylesheet\" href=\"/assets/tokens/components.css\">\n<link rel=\"stylesheet\" href=\"/assets/vaikor-theme.css\">\n"
            "<link rel=\"stylesheet\" href=\"/assets/site.css\">\n</head>\n"
            f"<body class=\"site\">\n{body}\n</body>\n</html>\n")
schemas = [f for f in files if f.get("id")]
rows = "\n".join(f"<li><a href=\"{html.escape(f['path'])}\">{html.escape(f['path'].rsplit('/', 1)[1])}</a></li>" for f in schemas)
(out / "spec/index.html").write_text(page("Vaikor specifications", (
    "<h1>Vaikor schemas and vectors</h1>\n<p>Draft, not for implementation. Every file with its SHA-256 is listed in "
    f"<a href=\"/spec/index.json\">index.json</a>. Test vector suite {html.escape(version)}.</p>\n"
    f"<h2>JSON Schemas</h2>\n<ul>\n{rows}\n</ul>\n"
    "<h2>More</h2>\n<ul>\n<li><a href=\"/spec/examples/\">examples/</a></li>\n<li><a href=\"/spec/test-vectors/\">test-vectors/</a></li>\n"
    "<li><a href=\"/spec/catalogs/intent-catalog.json\">intent catalog</a></li>\n"
    "<li><a href=\"/spec/catalogs/a2ui-catalog.v4.json\">@vaiev/ui v4 catalog</a></li>\n</ul>")))
(out / "index.html").write_text(page("Vaikor: Personal Edge Intelligence OS", (
    "<h1>Vaikor</h1>\n<p>A personal edge intelligence OS: models propose, a verifying Core decides, and every result is a "
    "signed record the owner keeps.</p>\n<ul>\n<li><a href=\"/playground/\">Verifier playground</a>: the Core's plan verifier, "
    "Cedar information-flow policy and record checks, running in your browser.</li>\n"
    "<li><a href=\"/spec/\">Schemas, examples and test vectors</a></li>\n</ul>")))
print(f"site: {len(files)} spec files, {len(schemas)} schemas, {len(keys)} public test keys, wasm {len(data)} bytes")
EOF

cat > "$out/_headers" <<'EOF'
/*
  Content-Security-Policy: default-src 'self'; font-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
/wasm/*
  Content-Type: application/wasm
/assets/fonts/*
  Cache-Control: public, max-age=31536000, immutable
/spec/schemas/*
  Content-Type: application/schema+json
  Access-Control-Allow-Origin: *
EOF

python3 -I "$root/scripts/check-no-test-keys.py" "$out"
echo "vaikor.com site built in $out"
