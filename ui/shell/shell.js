// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//
// Vaikor offline shell. No network access of any kind (CSP connect-src
// 'none'), no storage, no generated identities. The only data binding is a
// local audit log file the user picks; its lines are listed as text and are
// NOT verified here (that is `vaikor log verify`).
"use strict";

(function () {
  const MAX_BYTES = 5 * 1024 * 1024;
  const MAX_ENTRIES = 2000;

  // Tabs.
  const tabs = Array.from(document.querySelectorAll('[role="tab"]'));
  function select(tab) {
    for (const other of tabs) {
      const selected = other === tab;
      other.setAttribute("aria-selected", String(selected));
      other.tabIndex = selected ? 0 : -1;
      document.getElementById(other.getAttribute("aria-controls")).hidden = !selected;
    }
    tab.focus();
  }
  tabs.forEach(function (tab, index) {
    tab.addEventListener("click", function () { select(tab); });
    tab.addEventListener("keydown", function (event) {
      if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
        const step = event.key === "ArrowRight" ? 1 : tabs.length - 1;
        select(tabs[(index + step) % tabs.length]);
        event.preventDefault();
      }
    });
  });

  // Theme (not stored).
  document.getElementById("theme").addEventListener("click", function () {
    const body = document.body;
    body.dataset.theme = body.dataset.theme === "dark" ? "light" : "dark";
  });

  // Audit log file: "<prev> <signature> <json>" per line (vaikor-log).
  const input = document.getElementById("log-file");
  const status = document.getElementById("log-status");
  const list = document.getElementById("log-entries");
  document.getElementById("open-log").addEventListener("click", function () {
    input.click();
  });

  function field(value) {
    return typeof value === "string" && value.length > 0 ? value : "-";
  }

  function entry(line, number) {
    const item = document.createElement("li");
    item.className = "vv-audit-entry";
    const first = line.indexOf(" ");
    const second = first < 0 ? -1 : line.indexOf(" ", first + 1);
    let event = null;
    if (second > 0) {
      try {
        event = JSON.parse(line.slice(second + 1));
      } catch (error) {
        event = null;
      }
    }
    if (event === null || typeof event !== "object" || Array.isArray(event)) {
      item.textContent = "line " + number + ": not an audit entry";
      return item;
    }
    if (event.decision === "deny") {
      item.classList.add("vv-audit-entry--deny");
    }
    item.textContent = [
      field(event.at),
      field(event.decision),
      field(event.step),
      field(event.capability),
      "actor " + field(event.actor),
    ].join("  ");
    return item;
  }

  input.addEventListener("change", function () {
    list.replaceChildren();
    const file = input.files && input.files[0];
    if (!file) {
      status.textContent = "No file opened.";
      return;
    }
    if (file.size > MAX_BYTES) {
      status.textContent = "File is larger than 5 MiB; not read.";
      return;
    }
    const reader = new FileReader();
    reader.addEventListener("load", function () {
      const lines = String(reader.result).split("\n").filter(function (l) { return l.length > 0; });
      const shown = lines.slice(-MAX_ENTRIES);
      const offset = lines.length - shown.length;
      shown.forEach(function (line, i) { list.appendChild(entry(line, offset + i + 1)); });
      status.textContent = lines.length + " lines read from " + file.name +
        (offset > 0 ? " (last " + shown.length + " shown)" : "") +
        ". Not verified here.";
    });
    reader.addEventListener("error", function () {
      status.textContent = "The file could not be read.";
    });
    reader.readAsText(file);
  });

  // Core A2UI surface file renderer (TaskList, CountdownWidget, NoteEditor, WebResult, CloudCallTrace, ResultSurface + atomic @vaiev/ui primitives).
  const viewInput = document.getElementById("view-file");
  const openViewBtn = document.getElementById("open-view");
  const surfaceStatus = document.getElementById("surface-status");
  const surfaceContent = document.getElementById("surface-content");
  const countdownEl = document.querySelector(".vv-countdown");
  const ALLOWED_COMPONENTS = [
    "TaskList",
    "CountdownWidget",
    "NoteEditor",
    "WebResult",
    "CloudCallTrace",
    "ResultSurface",
    "IntentHeader",
    "ArtifactCard",
    "StepTimeline",
    "FlowBadge"
  ];

  function renderPrimitiveNode(prim) {
    const box = document.createElement("div");
    box.className = "vv-card";
    const kind = typeof prim.primitive === "string" ? prim.primitive : (typeof prim.component === "string" ? prim.component : "Primitive");
    const overline = document.createElement("p");
    overline.className = "vv-overline";
    overline.textContent = kind;
    box.appendChild(overline);

    if (kind === "IntentHeader") {
      const h = document.createElement("h2");
      h.textContent = typeof prim.title === "string" ? prim.title : "Intent";
      box.appendChild(h);
      const meta = document.createElement("p");
      meta.className = "vv-muted";
      const workers = typeof prim.active_workers === "number" ? prim.active_workers : 0;
      const st = typeof prim.status === "string" ? prim.status : "active";
      meta.textContent = "Status: " + st + " · Active workers: " + String(workers);
      box.appendChild(meta);
    } else if (kind === "FlowBadge") {
      const badge = document.createElement("span");
      badge.className = "vv-chip vv-chip--primary vv-mono";
      const label = typeof prim.label === "string" ? prim.label : "100% Local Processing";
      const res = Array.isArray(prim.residency) ? " [" + prim.residency.join(",") + "]" : "";
      badge.textContent = label + res;
      box.appendChild(badge);
    } else if (kind === "ArtifactCard") {
      const h = document.createElement("h2");
      h.textContent = typeof prim.title === "string" ? prim.title : "Artifact";
      box.appendChild(h);
      if (typeof prim.subtitle === "string" && prim.subtitle.length > 0) {
        const sub = document.createElement("p");
        sub.className = "vv-muted";
        sub.textContent = prim.subtitle;
        box.appendChild(sub);
      }
      if (typeof prim.body === "string" && prim.body.length > 0) {
        const bodyP = document.createElement("p");
        bodyP.textContent = prim.body;
        box.appendChild(bodyP);
      }
      if (Array.isArray(prim.files)) {
        const ul = document.createElement("ul");
        ul.className = "vv-audit-list";
        prim.files.slice(0, 20).forEach(function (f) {
          const li = document.createElement("li");
          li.className = "vv-audit-entry";
          li.textContent = (f && typeof f.path === "string" ? f.path : "file") +
            (f && typeof f.diff === "string" ? " · " + f.diff : "");
          ul.appendChild(li);
        });
        box.appendChild(ul);
      }
      if (prim.consequential_action && typeof prim.consequential_action === "object") {
        const note = document.createElement("p");
        note.className = "vv-note";
        const cap = typeof prim.consequential_action.capability === "string" ? prim.consequential_action.capability : "";
        const hint = typeof prim.consequential_action.gate_hint === "string" ? prim.consequential_action.gate_hint : "";
        note.textContent = cap + (hint ? " — " + hint : "");
        box.appendChild(note);
      }
    } else if (kind === "StepTimeline" && Array.isArray(prim.steps)) {
      const ul = document.createElement("ul");
      ul.className = "vv-audit-list";
      prim.steps.slice(0, 50).forEach(function (step) {
        const li = document.createElement("li");
        li.className = "vv-audit-entry";
        const sid = step && typeof step.step_id === "string" ? step.step_id : "-";
        const lbl = step && typeof step.label === "string" ? step.label : "-";
        const st = step && typeof step.status === "string" ? step.status : "done";
        const wk = step && typeof step.worker_id === "string" ? " [" + step.worker_id + "]" : "";
        li.textContent = sid + ": " + lbl + " · " + st + wk;
        ul.appendChild(li);
      });
      box.appendChild(ul);
    }
    return box;
  }

  if (openViewBtn && viewInput) {
    openViewBtn.addEventListener("click", function () {
      viewInput.click();
    });
    viewInput.addEventListener("change", function () {
      surfaceContent.replaceChildren();
      const file = viewInput.files && viewInput.files[0];
      if (!file) {
        surfaceStatus.textContent = "No view yet. Views appear here only from the Core.";
        return;
      }
      if (file.size > MAX_BYTES) {
        surfaceStatus.textContent = "View file is larger than 5 MiB; not read.";
        return;
      }
      const reader = new FileReader();
      reader.addEventListener("load", function () {
        let doc = null;
        try {
          doc = JSON.parse(String(reader.result));
        } catch (err) {
          doc = null;
        }
        if (!doc || typeof doc !== "object" || Array.isArray(doc) || ALLOWED_COMPONENTS.indexOf(doc.component) < 0) {
          surfaceStatus.textContent = "Refused: not a valid v1 A2UI component.";
          return;
        }
        const props = doc.props && typeof doc.props === "object" && !Array.isArray(doc.props) ? doc.props : {};
        surfaceStatus.textContent = doc.component + (typeof doc.route === "string" ? " · " + doc.route : "");

        if (doc.component === "ResultSurface" && Array.isArray(props.primitives)) {
          props.primitives.slice(0, 20).forEach(function (prim) {
            if (prim && typeof prim === "object" && !Array.isArray(prim)) {
              surfaceContent.appendChild(renderPrimitiveNode(prim));
            }
          });
          return;
        }
        if (["IntentHeader", "ArtifactCard", "StepTimeline", "FlowBadge"].indexOf(doc.component) >= 0) {
          const single = Object.assign({ primitive: doc.component }, props);
          surfaceContent.appendChild(renderPrimitiveNode(single));
          return;
        }

        const card = document.createElement("div");
        card.className = "vv-card";
        const heading = document.createElement("h2");
        heading.textContent = typeof props.title === "string" ? props.title : doc.component;
        card.appendChild(heading);

        if (doc.component === "TaskList" && Array.isArray(props.items)) {
          const ul = document.createElement("ul");
          ul.className = "vv-audit-list";
          props.items.slice(0, 50).forEach(function (entryText) {
            const li = document.createElement("li");
            li.className = "vv-audit-entry";
            li.textContent = String(entryText);
            ul.appendChild(li);
          });
          card.appendChild(ul);
        } else if (doc.component === "CountdownWidget") {
          const label = typeof props.label === "string" ? props.label : "timer";
          const mins = typeof props.minutes === "number" ? String(props.minutes) + " min" : "active";
          if (countdownEl) {
            countdownEl.textContent = label + " · " + mins;
          }
          const p = document.createElement("p");
          p.className = "vv-muted";
          p.textContent = label + " (" + mins + ")";
          card.appendChild(p);
        } else {
          Object.keys(props).forEach(function (k) {
            if (k === "title") { return; }
            const p = document.createElement("p");
            p.className = "vv-muted";
            p.textContent = k + ": " + String(props[k]);
            card.appendChild(p);
          });
        }
        surfaceContent.appendChild(card);
      });
      reader.readAsText(file);
    });
  }
})();

