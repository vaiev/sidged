# Sidged – Vision (briefing from roenu, 2026-10-15, binding)

> English translation of the binding briefing of 2026-10-15. This file is the north star. Accepted decisions stay in [0000-architektur.md](../specs/0000-architektur.md).

## 1. Three-layer system architecture

In the long run it runs on every target device (VPS, container, PC, smartphone, embedded) in place of classic desktop environments, app stores, package managers, and file systems.

3. AI interface – generated UI per task/person (view) + fixed Trusted UI elements of the Core
2. AI runtime – Rust core (policy, grants, verifier, privacy gateway, log) + router model + WASM modules + memory (records)
1. Kernel – Linux (drivers, scheduler, isolation)

- Kernel: Linux stays for drivers, scheduling, and isolation; the classic userland goes away.
- AI runtime: a small local router/personal model learns preferences and proposes plans; only the deterministic Core checks rights, data flows, and policies before execution.
- AI interface: views are generated declaratively (A2UI-compatible) per task, device, and person; security-critical approvals go through the Core-controlled Trusted UI channel. Visually under VAIEV: "content is flat, controls float", token system `--vv-*`, sub-brands fill their own palette.

## 2. Seven basic building blocks (L0)

| Block | Replaces | Function |
|---|---|---|
| Identity | User accounts, UIDs | Cryptographic identity (`did:key` for one's own devices, OAuth/WIMSE at company boundaries) for Owner, Device, Agent, Service |
| Capability | Apps, syscalls, IPC | Typed capability, including effects, data classes, cost, residency, and a consequential marking |
| Grant | File rights, permissions | Attenuable object-capability token + Cedar: who, what, how often, for how long |
| Plan | Scripts, small apps, workflows | Declarative, statically checkable program of capability calls and data flows |
| View | Windows, UI toolkits | Declarative UI per task, with no foreign code, + unbreakable Trusted UI |
| Record | File system, app databases | Typed record with data class, provenance, residency tag, and retention period |
| Module | Packages, userland drivers, libraries | Signed, isolated WASM component (WASI 0.3) with a manifest (capabilities offered, grants required) |

Two communication paths: local typed calls in the WASM Component Model, with no signature overhead; across trust boundaries (another device, a foreign agent, an external provider) a signed message envelope.

## 3. Three-level execution model

- Core in Rust: written and audited by people, minimal dependencies, `no_std` where possible.
- Modules in WASM/WASI 0.3: computation never in the Core, strict sandbox.
- Plans in a declarative plan language of their own (USP): a canonical JSON/CBOR tree, CEL for expressions, Cedar for policies; guaranteed termination (no general recursion, only a bounded `map`, fixed time and cost budgets); a static verifier plus IFC, in the manner of eBPF: before start it proves the capabilities called, the maximum cost, and the data-class flows (for example `health.records`) – it prevents exfiltration through prompt injection, independent of the model.

## 4. Layer model L0–L8 (adoptable individually, option C via bindings)

- L0 Core Objects: the 7 building blocks, canonical JSON / `dcbor`, signatures
- L1 Capability: descriptors, including the official MCP binding (an MCP server is checkable via annotation)
- L2 Grant: tokens with attenuation, delegation, budgets, Cedar
- L3 Plan: plan language v0, static verifier, effect and data-flow analysis
- L4 View: A2UI binding + a Trusted UI channel of its own
- L5 Core Contract: kill switch, human approvals, audit log, offline, adaptation, accessibility
- L6 Exchange: a mesh of its own (CBOR over QUIC/Noise), A2A binding, MLS for groups, legacy bridges
- L7 Egress and Provider: Privacy Gateway, machine-readable privacy reports, provider profiles P0–P3, OHTTP
- L8 Native System: direct boot (kernel → runtime → interface), A/B image updates, a Wayland compositor of its own (for example Smithay) in the Core for unforgeable Trusted UI

## 5. Nine security invariants

1. The model is never the security boundary (the model proposes, the Core decides).
2. No effect without a valid grant (no ambient authority).
3. All external inputs (model, tool, web, peer) are data until the verifier has checked them.
4. Consequential steps always require human approval through Trusted UI.
5. Every egress goes through the Privacy Gateway, including a privacy report.
6. Generated code runs only in the WASM sandbox, with at most the rights of the task that generated it.
7. Full offline capability in local mode.
8. Minimal Core: everything else is an isolated module.
9. A gapless audit log of every effect, with a cryptographic provenance chain.

## 6. Addition from roenu (2026-10-15, 02:21)

- Sidged is an OS for edge devices: it runs directly on the host (for example a VPS, or bare metal) in place of Android/iOS, and likewise in a VM and as an OCI container. Hence Linux kernel → AI runtime → interface.
- The goal is new, or optimal, interfaces for communication, data processing, hardware calls, and the like. All of it is security first.
- Example: the user wants to send Ben a message and edit a photo first. The UI is generated directly for that task, and the communication follows. Incoming messages and tasks work the same way (a UI is generated per incoming item). This holds for many tasks.
- On-device model ensemble (roles; the choice of models is still open):
  - a small edge embedding model, for example EmbeddingGemma 2 (`google/embeddinggemma-2`, about 271 million parameters, multimodal for text, image, audio, and video, 768 dimensions, task prompts; fine-tunable via sentence-transformers), for intent routing, memory/record search, and capability matching
  - a router/personal model (plan proposals, preferences)
  - a builder model (produces views, plans, and WASM modules on demand)
  - further specialist models as needed
- All models stay outside the security boundary (invariant 1): they propose, and the Core verifies.

## 7. Core thesis: the wrapper dissolves (roenu, 2026-10-15, binding)

Today's agents are a text prompt, a harness, and guidelines. Sidged replaces that shape.

- Each agent is a Sidged-native bundle: Identity, Grants, Plans, Modules, and Records. The Core verifies the bundle before it runs. A prompt, a harness, or a guideline is not the agent, and it is not authority.
- Sidged is the user's personal AI. It learns them and understands them. That learning dissolves the wrapper bubble. The product is the runtime and the verified bundle, not a chat window wrapped around a model and held together by instructions.
- The aim is the whole of today's agent layer. The nine invariants in section 5 stay intact. The personal model proposes. The Core decides. Learning does not grant a right, skip an approval, or leave the device except through the Privacy Gateway.
