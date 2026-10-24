// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//
// Morphing intent canvas. Renders @vaiev/ui v4 surface documents produced and validated
// by the Rust companion core; it never builds a surface itself. Safe DOM APIs only
// (createElement + textContent), no network, no storage. The only channel is the single
// `companion` IPC command, which the core restricts to its allowlist.
(function () {
  "use strict";

  const invoke = window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke;
  const canvas = document.getElementById("canvas");
  const picker = document.getElementById("capability");
  const nodeChip = document.getElementById("node");

  function call(command, args) {
    if (!invoke) {
      return Promise.reject(new Error("companion IPC is not available"));
    }
    return invoke("companion", { command: command, args: args || {} });
  }

  // The device's IANA time zone; the node resolves spoken clock times in it.
  function deviceZone() {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || undefined;
    } catch (e) {
      return undefined;
    }
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function str(value, fallback) {
    return typeof value === "string" ? value : fallback;
  }

  function note(kind, message) {
    return el("p", "vv-note vv-note--" + kind, message);
  }

  function showError(message) {
    canvas.replaceChildren(note("error", message));
  }

  // One renderer per catalog primitive; an unknown primitive is refused, not guessed.
  const render = {
    IntentHeader: function (p) {
      const box = el("section", "canvas__head");
      box.appendChild(el("p", "vv-overline", str(p.status, "")));
      box.appendChild(el("h1", "vv-headline", str(p.title, "")));
      if (p.subtitle) box.appendChild(el("p", "vv-body vv-muted", p.subtitle));
      if (p.lang) box.lang = p.lang;
      return box;
    },
    FlowBadge: function (p) {
      const box = el("div", "chips");
      box.appendChild(el("span", "vv-chip vv-chip--primary", str(p.label, "")));
      (p.residency || []).forEach(function (tag) { box.appendChild(el("span", "vv-chip vv-chip--outlined", tag)); });
      (p.data_classes || []).forEach(function (dc) { box.appendChild(el("span", "vv-chip vv-chip--outlined", dc)); });
      return box;
    },
    ArtifactCard: function (p) {
      const card = el("article", "vv-card");
      card.appendChild(el("p", "vv-overline", str(p.artifact_type, "")));
      card.appendChild(el("h2", "vv-title", str(p.title, "")));
      if (p.subtitle) card.appendChild(el("p", "vv-body vv-muted", p.subtitle));
      if (p.body) card.appendChild(el("p", "vv-body", p.body));
      if (Array.isArray(p.files)) {
        const list = el("ul", "files");
        p.files.forEach(function (f) { list.appendChild(el("li", "", str(f.path, ""))); });
        card.appendChild(list);
      }
      if (p.consequential_capability) {
        card.appendChild(note("warning", "A follow-up action (" + p.consequential_capability + ") needs Trusted UI confirmation; this canvas never approves it."));
      }
      card.appendChild(el("p", "vv-small vv-muted", "record " + str(p.record_id, "")));
      return card;
    },
    StepTimeline: function (p) {
      const list = el("ol", "timeline");
      (p.steps || []).forEach(function (s) {
        const item = el("li", "is-" + str(s.status, "pending"));
        item.appendChild(el("code", "", str(s.step_id, "")));
        item.appendChild(el("span", "vv-body", str(s.label, "")));
        item.appendChild(el("span", "vv-small vv-muted", str(s.status, "") + (s.worker_id ? " · " + s.worker_id : "")));
        list.appendChild(item);
      });
      return list;
    },
    DataTable: function (p) {
      const wrap = el("div", "vv-card table-wrap");
      const table = el("table", "table");
      if (p.caption) table.appendChild(el("caption", "vv-small vv-muted", p.caption));
      const head = el("tr");
      (p.columns || []).forEach(function (c) { head.appendChild(el("th", "", str(c.label, ""))); });
      const thead = el("thead");
      thead.appendChild(head);
      table.appendChild(thead);
      const body = el("tbody");
      (p.rows || []).forEach(function (row) {
        const tr = el("tr");
        (p.columns || []).forEach(function (c) {
          const v = row[c.key];
          tr.appendChild(el("td", "", v === undefined || v === null ? "" : v));
        });
        body.appendChild(tr);
      });
      table.appendChild(body);
      wrap.appendChild(table);
      return wrap;
    },
    FormSurface: function (p, context) {
      const form = el("form", "vv-card form");
      const readonly = p.mode === "readonly";
      const inputs = [];
      (p.fields || []).forEach(function (f, index) {
        const id = "f" + index + "-" + f.name;
        const row = el("div", "vv-field");
        const label = el("label", "", f.label + (f.required && !readonly ? " *" : ""));
        label.htmlFor = id;
        row.appendChild(label);
        let input;
        if (f.kind === "choice" || f.kind === "boolean") {
          input = el("select");
          const options = f.kind === "boolean" ? ["true", "false"] : (f.options || []);
          if (!f.required || f.kind === "boolean") input.appendChild(el("option", "", ""));
          options.forEach(function (o) { input.appendChild(el("option", "", o)); });
        } else {
          input = el(f.kind === "json" ? "textarea" : "input");
          if (f.kind === "number" || f.kind === "integer") {
            input.type = "number";
            input.inputMode = f.kind === "integer" ? "numeric" : "decimal";
          }
        }
        input.id = id;
        input.name = f.name;
        if (f.value !== undefined) input.value = typeof f.value === "string" ? f.value : JSON.stringify(f.value);
        if (readonly) {
          input.readOnly = true;
          input.disabled = true;
        }
        row.appendChild(input);
        if (f.description) row.appendChild(el("p", "vv-field__help", f.description));
        form.appendChild(row);
        inputs.push({ field: f, input: input });
      });
      if (!readonly && context && context.onSubmit) {
        const submit = el("button", "vv-btn vv-btn--block", str(p.submit_label, "Continue"));
        submit.type = "submit";
        form.appendChild(submit);
        form.addEventListener("submit", function (event) {
          event.preventDefault();
          context.onSubmit(collect(inputs));
        });
      }
      return form;
    },
    SplitPane: function (p, context, children) {
      const pane = el("div", "split split--" + str(p.orientation, "horizontal"));
      children.forEach(function (child) { pane.appendChild(child); });
      return pane;
    }
  };

  function collect(inputs) {
    const values = {};
    inputs.forEach(function (entry) {
      const f = entry.field;
      const raw = entry.input.value;
      if (raw === "") return;
      if (f.kind === "number") values[f.name] = Number(raw);
      else if (f.kind === "integer") values[f.name] = parseInt(raw, 10);
      else if (f.kind === "boolean") values[f.name] = raw === "true";
      else if (f.kind === "text-list") values[f.name] = raw.split(",").map(function (s) { return s.trim(); }).filter(Boolean);
      else if (f.kind === "json") {
        try { values[f.name] = JSON.parse(raw); } catch (e) { values[f.name] = raw; }
      } else values[f.name] = raw;
    });
    return values;
  }

  function renderNode(node, context) {
    const renderer = render[node.primitive];
    if (!renderer) throw new Error("unknown primitive " + node.primitive);
    const children = (node.children || []).map(function (c) { return renderNode(c, context); });
    const out = renderer(node.props || {}, context, children);
    out.dataset.primitive = node.primitive;
    return out;
  }

  function show(surface, context) {
    try {
      const nodes = surface.nodes.map(function (n) { return renderNode(n, context); });
      canvas.replaceChildren.apply(canvas, nodes);
      canvas.dataset.kind = surface.kind;
      window.scrollTo(0, 0);
    } catch (e) {
      showError(String(e.message || e));
    }
  }

  function openCapability(id) {
    call("surface.capability_input", { capability: id }).then(function (surface) {
      let result = null;
      show(surface, {
        onSubmit: function (values) {
          if (result) result.remove();
          call("surface.input_submit", { capability: id, values: values }).then(function (pending) {
            result = note("success", "Handed to the planner as " + pending.status + ". Nothing has run yet.");
            canvas.appendChild(result);
            result.scrollIntoView({ block: "nearest" });
          }, function (err) {
            result = note("error", String(err));
            canvas.appendChild(result);
            result.scrollIntoView({ block: "nearest" });
          });
        }
      });
    }, function (err) { showError(String(err)); });
  }

  // ---------- Intents: the catalog decides what can be asked, the Core derives the rest ----------

  const lang = (function () {
    const tag = (navigator.language || "en").toLowerCase();
    if (tag.indexOf("gsw") === 0) return "gsw";
    return tag.indexOf("de") === 0 ? "de" : "en";
  })();

  // `language` is the one Model -1 detected; follow-up questions stay in it.
  // `then` carries the follow-ups of a composition ([{intent, slots}], spec 0017 §2c).
  function startIntent(intent, slots, language, then) {
    call("surface.clarification_submit", { lang: language || lang, intent: intent, slots: slots || {}, then: then || [], answers: {} })
      .then(function (out) { showIntentResult(out, intent); }, function (err) { showError(String(err)); });
  }

  // A linguist or clarification result: ask for what is missing, keeping what is known.
  function showIntentResult(out, intent) {
    const envelope = out.envelope || {};
    const known = envelope.slots || {};
    const target = intent || envelope.intent;
    const then = (envelope.then || []).map(function (f) {
      return { intent: f.intent, slots: Object.assign({}, f.slots || {}) };
    });
    const ready = out.surface && out.surface.kind === "output";
    show(out.surface, ready ? null : {
      onSubmit: function (values) {
        const slots = {};
        Object.keys(known).forEach(function (k) { slots[k] = known[k]; });
        Object.keys(values).forEach(function (k) {
          // A follow-up field is named then.<i>.<slot>.
          const m = /^then\.(\d)\.(.+)$/.exec(k);
          if (m && then[Number(m[1])]) then[Number(m[1])].slots[m[2]] = String(values[k]);
          else slots[k] = String(values[k]);
        });
        if (target) {
          startIntent(target, slots, envelope.lang, then);
        } else if (values.utterance) {
          askModel(String(values.utterance));
        }
      }
    });
    if (ready && out.plan_refusal) {
      canvas.appendChild(note("error", "The Core refuses to plan this: " + out.plan_refusal));
    } else if (ready && out.runnable) {
      const run = el("button", "vv-btn vv-btn--block", "Run on this node");
      run.type = "button";
      run.addEventListener("click", function () {
        run.disabled = true;
        run.textContent = "Running…";
        call("intent.run", { lang: envelope.lang, intent: target, slots: known, then: then, timezone: deviceZone() }).then(showRun, function (err) {
          run.disabled = false;
          run.textContent = "Run on this node";
          canvas.appendChild(note("error", String(err)));
        });
      });
      canvas.appendChild(run);
      canvas.appendChild(el("p", "vv-small vv-muted",
        "Steps marked for the owner gate need the Trusted UI; this canvas never approves them."));
    } else if (ready) {
      canvas.appendChild(note("success", "Ready for the planner (" + envelope.suggested_route + ")."));
    }
  }

  // The run's record as a surface, and what each step did.
  function showRun(out) {
    const summary = out.summary || {};
    if (out.surface) show(out.surface, null);
    (summary.steps || []).forEach(function (step) {
      if (step.status === "completed") return;
      const kind = step.status === "skipped" ? "warning" : "error";
      canvas.appendChild(note(kind, step.id + " · " + step.status + (step.reason ? ": " + step.reason : "")));
    });
    canvas.appendChild(note(summary.steps_executed ? "success" : "warning",
      summary.steps_executed + " of " + (summary.steps || []).length + " steps ran on this node. The signed record is in the node's record store."));
  }

  function askModel(utterance) {
    canvas.replaceChildren(el("p", "vv-body vv-muted", "Model -1 reads this on this node…"));
    call("linguist.run", { utterance: utterance }).then(function (out) {
      showIntentResult(out, null);
      if (out.corrections && out.corrections.length) {
        canvas.appendChild(el("p", "vv-small vv-muted", "The Core corrected the model's proposal: " + out.corrections.join(", ")));
      }
    }, function (err) { showError(String(err)); });
  }

  function waitForModel(grid, tries) {
    if (tries <= 0) return;
    setTimeout(function () {
      if (!canvas.contains(grid)) return;
      call("node.status", {}).then(function (next) {
        if (!canvas.contains(grid)) return;
        if (next && next.model) showHome(next); else waitForModel(grid, tries - 1);
      }, function () { waitForModel(grid, tries - 1); });
    }, 3000);
  }

  function showHome(status) {
    call("intent.list", {}).then(function (listed) {
      const head = el("section", "canvas__head");
      head.appendChild(el("p", "vv-overline", status && status.initialized ? "This node" : "Canvas"));
      head.appendChild(el("h1", "vv-headline", "What should happen?"));
      head.appendChild(el("p", "vv-body vv-muted",
        "Say it in English, German or Swiss German, or pick an intent. Sidged asks only for what is missing, then hands a checked intent to the planner."));
      const parts = [head];
      if (status && status.model) {
        const bar = el("form", "askbar vv-glass");
        const label = el("label", "vv-sr-only", "What should happen?");
        label.htmlFor = "ask";
        const input = el("input", "askbar__input");
        input.id = "ask";
        input.name = "utterance";
        input.autocomplete = "off";
        input.placeholder = "Erinner mi morn am achti a …";
        input.maxLength = 1000;
        const go = el("button", "vv-btn", "Ask");
        go.type = "submit";
        bar.append(label, input, go);
        bar.addEventListener("submit", function (event) {
          event.preventDefault();
          if (input.value.trim()) askModel(input.value.trim());
        });
        parts.push(bar);
      }
      const grid = el("div", "intents");
      (listed.intents || []).forEach(function (entry) {
        const tile = el("button", "intent vv-state");
        tile.type = "button";
        tile.appendChild(el("span", "vv-overline", "this node"));
        tile.appendChild(el("span", "vv-title intent__title", entry.title));
        const meta = el("span", "intent__meta");
        (entry.data_classes || []).slice(0, 2).forEach(function (dc) { meta.appendChild(el("span", "vv-chip vv-chip--outlined", dc)); });
        tile.appendChild(meta);
        tile.addEventListener("click", function () { startIntent(entry.intent, {}); });
        grid.appendChild(tile);
      });
      parts.push(grid);
      canvas.replaceChildren.apply(canvas, parts);
      // The on-device model starts in the background; show the intent bar once it answers.
      if (status && status.initialized && !status.model) waitForModel(grid, 40);
      canvas.dataset.kind = "home";
    }, function (err) { showError(String(err)); });
  }

  // ---------- Onboarding: one glass card on the stage ----------

  const onboarding = document.getElementById("onboarding");
  const onboardingBody = document.getElementById("onboarding-body");

  function step(index, build) {
    const dots = onboarding.querySelectorAll(".onboarding__steps span");
    dots.forEach(function (dot, i) { dot.classList.toggle("is-active", i === index); });
    const body = el("div", "onboarding__step");
    build(body);
    onboardingBody.replaceChildren(body);
    // Keyboard users land on the action; touch users get no focus ring from a programmatic focus.
    const focus = body.querySelector("button");
    if (focus && !window.matchMedia("(pointer: coarse)").matches) focus.focus();
  }

  function shortDid(did) {
    const text = String(did || "");
    return text.length > 28 ? text.slice(0, 18) + "…" + text.slice(-6) : text;
  }

  function runOnboarding(done) {
    onboarding.hidden = false;
    document.body.classList.add("is-onboarding");
    step(0, function (b) {
      b.appendChild(el("p", "vv-overline onboarding__over", "Personal edge OS"));
      const claim = el("h1", "onboarding__claim");
      claim.id = "onboarding-title";
      claim.appendChild(el("span", "onboarding__line onboarding__line--1", "The model proposes."));
      claim.appendChild(el("span", "onboarding__line onboarding__line--2", "The core decides."));
      b.appendChild(claim);
      b.appendChild(el("p", "onboarding__lede",
        "This device becomes a node of your own edge OS. Every plan is checked before anything runs, and every result is a signed record you keep."));
      const next = el("button", "vv-btn vv-btn--block", "Set up this device");
      next.type = "button";
      next.addEventListener("click", function () { createStep(done); });
      b.appendChild(next);
    });
  }

  function createStep(done) {
    step(1, function (b) {
      b.appendChild(el("p", "vv-overline onboarding__over", "Step 2 of 3 · Local node"));
      b.appendChild(el("h2", "onboarding__title", "Create your node"));
      const list = el("ul", "onboarding__list");
      [
        "An owner identity for this device (did:key).",
        "A default information-flow policy: sensitive data leaves only with your permit, secrets never.",
        "A local record store and a signed audit log."
      ].forEach(function (text) { list.appendChild(el("li", "", text)); });
      b.appendChild(list);
      b.appendChild(el("p", "onboarding__fine",
        "Keys stay in this app's private storage. Hardware-backed keys (Android Keystore, OS credential gate) come in a later release."));
      const create = el("button", "vv-btn vv-btn--block", "Create node");
      create.type = "button";
      create.addEventListener("click", function () {
        create.disabled = true;
        create.textContent = "Creating…";
        call("node.init", { timezone: deviceZone() }).then(function (status) { readyStep(status, done); }, function (err) {
          create.disabled = false;
          create.textContent = "Create node";
          b.appendChild(note("error", String(err)));
        });
      });
      b.appendChild(create);
    });
  }

  function readyStep(status, done) {
    step(2, function (b) {
      b.appendChild(el("p", "vv-overline onboarding__over", "Step 3 of 3 · Ready"));
      b.appendChild(el("h2", "onboarding__title", "This device is a Sidged node"));
      const id = el("div", "onboarding__id");
      id.appendChild(el("span", "onboarding__fine", "Owner"));
      id.appendChild(el("code", "", shortDid(status.owner_did)));
      b.appendChild(id);
      const chips = el("div", "chips");
      ["default-flow policy", "local first", "signed audit log"].forEach(function (t) {
        chips.appendChild(el("span", "vv-chip vv-glass--on-stage onboarding__chip", t));
      });
      b.appendChild(chips);
      const open = el("button", "vv-btn vv-btn--block", "Open the canvas");
      open.type = "button";
      open.addEventListener("click", function () {
        onboarding.hidden = true;
        document.body.classList.remove("is-onboarding");
        done(status);
      });
      b.appendChild(open);
    });
  }

  // ---------- Shell ----------

  function updateNode(status) {
    if (status && status.initialized) {
      nodeChip.textContent = shortDid(status.owner_did);
      nodeChip.title = status.owner_did;
    } else {
      nodeChip.textContent = "not set up";
    }
  }

  function loadTools() {
    call("catalog.describe", {}).then(function (described) {
      const ids = described.capabilities || [];
      picker.replaceChildren();
      ids.forEach(function (id) { picker.appendChild(el("option", "", id)); });
      const has = ids.length > 0;
      picker.hidden = !has;
      document.getElementById("open").hidden = !has;
    }, function () {});
  }

  document.getElementById("open").addEventListener("click", function () {
    if (picker.value) openCapability(picker.value);
  });
  document.getElementById("home").addEventListener("click", function () {
    call("node.status", {}).then(showHome, function () { showHome(null); });
  });

  call("node.status", {}).then(function (status) {
    updateNode(status);
    loadTools();
    if (!status.initialized && status.can_initialize) {
      runOnboarding(function (created) { updateNode(created); loadTools(); showHome(created); });
    } else {
      showHome(status);
    }
  }, function (err) { showError(String(err)); });
})();
