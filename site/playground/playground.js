// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//
// Verifier playground. Loads the published test vectors and the WASM verifier from this
// origin, then runs every check locally. Safe DOM APIs only (textContent), no storage.
(function () {
  "use strict";

  const $ = function (id) { return document.getElementById(id); };
  const status = $("status");
  const vectorSelect = $("vector");
  const opSelect = $("op");
  const input = $("input");

  // Spec vector operation -> WASM operation and input shape. Vectors of other
  // operations are listed by the spec, not by the playground.
  const OPERATIONS = {
    "plan-check": {
      op: "plan.verify",
      accepts: function (v) { return !v.input.allow; },
      input: function (v) { return { plan: v.input.plan, catalog: v.input.catalog }; }
    },
    "flow-check": { op: "flow.check", input: function (v) { return v.input; } },
    "record-check": {
      op: "record.verify",
      input: function (v, keys) {
        return {
          record: v.input.record,
          trusted_dids: (v.input.trusted_core_keys || []).map(function (name) {
            return keys[name] || name;
          })
        };
      }
    },
    "dcbor-encode": { op: "dcbor.encode", input: function (v) { return { value: v.input.value }; } },
    "dcbor-decode": { op: "dcbor.decode", input: function (v) { return { hex: v.input.hex }; } }
  };
  const VECTOR_FILES = ["plan/verify.json", "plan/dcbor-signed.json", "records/records.json"];

  let wasm = null;
  let entries = [];

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function call(op, data) {
    const ex = wasm.exports;
    const enc = new TextEncoder();
    const opBytes = enc.encode(op);
    const inBytes = enc.encode(JSON.stringify(data));
    const opPtr = ex.sdg_alloc(opBytes.length);
    new Uint8Array(ex.memory.buffer, opPtr, opBytes.length).set(opBytes);
    const inPtr = ex.sdg_alloc(inBytes.length);
    new Uint8Array(ex.memory.buffer, inPtr, inBytes.length).set(inBytes);
    const packed = BigInt.asUintN(64, ex.sdg_call(opPtr, opBytes.length, inPtr, inBytes.length));
    ex.sdg_free(opPtr, opBytes.length);
    ex.sdg_free(inPtr, inBytes.length);
    const ptr = Number(packed >> 32n);
    const len = Number(packed & 0xffffffffn);
    const text = new TextDecoder().decode(new Uint8Array(ex.memory.buffer, ptr, len).slice());
    ex.sdg_free(ptr, len);
    return JSON.parse(text);
  }

  function renderSurface(surface) {
    const box = $("surface");
    box.replaceChildren();
    if (!surface || !surface.props || !Array.isArray(surface.props.primitives)) return;
    surface.props.primitives.forEach(function (p) {
      const card = el("div", "vv-card vv-card--high pg-prim");
      card.appendChild(el("p", "vv-overline", p.primitive));
      if (p.title) card.appendChild(el("h3", "vv-title", p.title));
      if (p.label) card.appendChild(el("span", "vv-chip vv-chip--primary", p.label));
      if (p.subtitle) card.appendChild(el("p", "vv-muted", p.subtitle));
      if (p.body) card.appendChild(el("p", "", p.body));
      if (Array.isArray(p.residency)) card.appendChild(el("p", "vv-small vv-muted", p.residency.join(", ")));
      box.appendChild(card);
    });
  }

  function run() {
    let data;
    try {
      data = JSON.parse(input.value);
    } catch (e) {
      $("verdict").textContent = "Input is not JSON: " + e.message;
      $("verdict").className = "vv-note vv-note--error";
      return;
    }
    const out = call(opSelect.value, data);
    const verdict = out.verdict || (out.hex !== undefined || out.value !== undefined || out.public_key_hex ? "value" : "");
    const parts = [verdict.toUpperCase()];
    if (out.stage) parts.push("stage " + out.stage);
    if (out.reason && typeof out.reason === "string") parts.push(out.reason);
    if (out.class) parts.push(out.class + " → " + out.capability);
    if (Array.isArray(out.deciding_policies) && out.deciding_policies.length) {
      parts.push("decided by " + out.deciding_policies.join(", "));
    }
    $("verdict").textContent = parts.join(" · ");
    $("verdict").className = "vv-note " + (verdict === "accept" ? "vv-note--success" : verdict === "refuse" ? "vv-note--error" : "");
    $("output").textContent = JSON.stringify(out, null, 2);
    renderSurface(out.surface);
  }

  function choose() {
    const entry = entries[Number(vectorSelect.value)];
    if (!entry) return;
    opSelect.value = entry.op;
    input.value = JSON.stringify(entry.input, null, 2);
    const exp = entry.vector.expected || {};
    $("expected").textContent = "Published expectation: " +
      (exp.result || (exp.value !== undefined ? "value" : "?")) + (exp.reason ? " (" + exp.reason + ")" : "");
    $("verdict").textContent = "";
    $("output").textContent = "";
    $("surface").replaceChildren();
  }

  function loadJson(path) {
    return fetch(path, { credentials: "omit" }).then(function (r) {
      if (!r.ok) throw new Error(path + ": " + r.status);
      return r.json();
    });
  }

  Promise.all([
    WebAssembly.instantiateStreaming(fetch("../wasm/sidged_wasm.wasm", { credentials: "omit" }), {}),
    loadJson("../spec/test-vectors/keys/public-keys.json"),
    Promise.all(VECTOR_FILES.map(function (f) { return loadJson("../spec/test-vectors/" + f); }))
  ]).then(function (loaded) {
    wasm = loaded[0].instance;
    const keys = {};
    (loaded[1].keys || []).forEach(function (k) { keys[k.name] = k.did; });
    const about = call("about", {});
    about.operations.filter(function (o) { return o !== "about"; }).forEach(function (o) {
      opSelect.appendChild(el("option", "", o));
    });
    loaded[2].forEach(function (file) {
      file.vectors.forEach(function (v) {
        const spec = OPERATIONS[v.operation];
        if (!spec || (spec.accepts && !spec.accepts(v))) return;
        entries.push({ vector: v, op: spec.op, input: spec.input(v, keys) });
        vectorSelect.appendChild(el("option", "", v.id + (v.note ? " · " + v.note : "")));
        vectorSelect.lastChild.value = String(entries.length - 1);
      });
    });
    status.textContent = "Verifier " + about.version + " loaded · " + entries.length + " vectors · runs locally.";
    choose();
  }).catch(function (e) {
    status.textContent = "Could not load the verifier: " + e.message;
  });

  vectorSelect.addEventListener("change", choose);
  $("run").addEventListener("click", function () { if (wasm) run(); });
})();
