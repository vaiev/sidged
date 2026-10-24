# 0000 – Architecture Decisions

> **Status:** Accepted.
> **Date:** 2026-10-14
> **Revision:** 2026-10-20. Updated crate list (`runtime/`, 12 crates), specification index (`0000`–`0017`), and implementation status to match `v0.1.0` and the binding vision in [VISION.md](../vision/VISION.md).
> **North star:** [VISION.md](../vision/VISION.md).

Sidged (<https://sidged.com>) is the **Personal Edge Intelligence Operating System and Runtime**. The stack is the Linux kernel, the AI runtime, and the generative AI interface. The open standard uses the namespace `urn:sidged:` and the prefix `sdg.*`.

## Vision and scope

Sidged is the OS. The stack is the Linux kernel, the AI runtime, and the AI interface (a generated GUI or a terminal). Native is the target: that stack is the system on the device (E9, SDG-L8). Hosted is the stepping stone while the same runtime runs on an existing Linux host, VM, or OCI container.

Sidged defines its own standards so personal AIs talk to each other. That path is peer-to-peer between owners' runtimes and sits in SDG-L6: mesh and signed envelopes at the trust boundary. Systems outside Sidged attach through the same layer's bindings: legacy apps and services (methods 1–5), people via email and messaging, and MCP/A2A (E1, E8). An agent that runs inside Sidged is a bundle of Identity, Grants, Plans, Modules, and Records, verified by the Core ([0011-agent-bundle.md](0011-agent-bundle.md)). A2A stays the binding for an agent that is not that bundle.

The interface is generated for the intent in front of the owner. A checked plan (SDG-L3) names the capabilities (SDG-L1) the intent needs. The view (SDG-L4) is the GUI or terminal for that intent. Trusted UI elements stay owned by the Core (SDG-L4, SDG-L5). Effects still require a grant (SDG-L2).

| Intent | Surface the runtime generates | Mapping |
|---|---|---|
| Send a photo | A GUI to drop or pick the photo and edit the message | Plan: the send. Capability: photo and message. View: that GUI. A consequential send still passes through Trusted UI. |
| Browse | A browser-like view | Plan: the browsing task. Capability: fetch and navigation. View: the browser-like surface. |

The same pattern covers further intents: the runtime builds the surface for the task, and the Core keeps the trusted controls.

## Stack

```
┌──────────────────────────────────────────────────────────┐
│ AI interface   A2UI views, generated per intent          │
│                (GUI or terminal)                         │
│                + Trusted UI owned by the Core            │
├──────────────────────────────────────────────────────────┤
│ AI runtime     Core (policy, grants, verifier, gateway,  │
│                log) + router model + WASM modules        │
│                + records + planner                       │
├──────────────────────────────────────────────────────────┤
│ Linux kernel   drivers, scheduler, isolation             │
└──────────────────────────────────────────────────────────┘
```

Communication and agent behaviour are part of the runtime.

## Nomenclature

Layer specifications use the identifiers SDG-L0 through SDG-L8. Short names L0–L8 in this file mean the same layers.

| Spec | File | Layers |
|---|---|---|
| SDG-L0 + SDG-L1 | `docs/specs/0001-capability.md` | Core objects and the capability descriptor, including the MCP binding |
| SDG-L2 | `docs/specs/0002-grant.md` | Grants |
| SDG-L3 | `docs/specs/0003-plan.md` | Plan language and verifier |
| SDG-L4 | `docs/specs/0004-view.md` | Views and Trusted UI |
| SDG-L5 | `docs/specs/0005-core.md` | Core contract |
| SDG-L6 | `docs/specs/0006-exchange.md` | Exchange, peer-to-peer, legacy, MCP/A2A bindings |
| SDG-L7 | `docs/specs/0007-egress.md` | Egress, privacy gateway, providers |
| SDG-L8 | `docs/specs/0008-native.md` | Native system |
| Model ensemble | `docs/specs/0009-models.md` | On-device ensemble. Not a layer |
| Deployment targets | `docs/specs/0010-deployment.md` | Bare metal, VPS host, VM, OCI container. Not a layer |
| Agent bundle | `docs/specs/0011-agent-bundle.md` | Identity, Grants, Plans, Modules, Records. Not a layer |
| SDG-L0 Records | `docs/specs/0012-records.md` | Record object, `dcbor` profile, and signed artifact surfaces |
| SDG-L3 stored plans | `docs/specs/0013-cbor-plans-ifc.md` | `dcbor` plans, owner-signed stored plans, Cedar flow policy |
| Bundle package | `docs/specs/0014-bundle-package.md` | Distributable `sdg.bundle/v0` package installed into a 0011 bundle. Not a layer |
| SDG-L6 Owner Swarm | `docs/specs/0015-swarm.md` | Multi-edge swarm (`S1–S16`), drift auto-revocation, technocratic worker culling |
| Companion & ISO 27090 | `docs/specs/0016-companion-swiyu-iso27090.md` | Cross-platform companion, QR/Passkey/`swiyu` pairing, `@vaiev/ui` v4, ISO/IEC 27090 |
| Intent, linguist & canvas | `docs/specs/0017-intent-linguist-canvas.md` | Intent catalog, companion linguist (Model -1), morphing canvas surfaces, companion IPC, browser verifier |

`docs/specs/0000-architektur.md` is this decision record. Adoption order stays L1 (with L0), then L2, L3, L4/L5, L7, L6, L8 (E3). `0009` and `0010` record vision section 6. `0011` records vision section 7. They do not insert a layer into that order. Each layer spec is at most about 15 pages, in English, with BCP 14 terms.

| Layer | What it specifies |
|---|---|
| **SDG-L0 Core Objects** | The seven primitives. Canonical JSON and deterministic CBOR. Signatures. |
| **SDG-L1 Capability** | Descriptor: input and output schema, effects, data classes, residency, cost, consequential. MCP binding, written so it can be proposed as an MCP extension. |
| **SDG-L2 Grant** | Capability tokens: attenuation, delegation, budgets, holder binding, expiry. Owner policy in Cedar. |
| **SDG-L3 Plan** | Plan language, verifier, effect and data-flow analysis, tools on demand. |
| **SDG-L4 View** | A2UI views generated per intent, plus Trusted UI owned by the Core. |
| **SDG-L5 Core Contract** | The model proposes and the Core decides. Approvals, kill switch, log, offline mode, adaptation, accessibility. |
| **SDG-L6 Exchange** | Peer-to-peer between owners' runtimes. Signed envelopes. A2A binding, MLS for groups, legacy methods 1–5, email and messaging. |
| **SDG-L7 Egress and Provider** | Privacy Gateway, privacy reports, provider profiles P0–P3, OHTTP, residency. |
| **SDG-L8 Native System** | Kernel, then runtime, then interface. Boot, A/B updates, compositor owned by the Core, hardware as modules. |

## Decisions E1–E10

The full record for each decision follows later in this file. Consequences here match that record.

| Decision | Consequence |
|---|---|
| E1 Trusted runtime above and below MCP, A2A, and A2UI | Core objects have no transport. Those three standards are bindings. |
| E2 MCP extension as the entry | SDG-L1 is written so it can be filed as an MCP SEP after it is stable and the repository may be public. Annotations are requirements. |
| E3 Small layer specs | `0001`–`0008` as in the nomenclature table. Test vectors under `spec/test-vectors/` are the conformance suite. |
| E4 Seven primitives, no classic userland | Sidged itself is the OS (kernel -> runtime -> interface). The kernel stays. |
| E5 A language only for plans | JSON/CBOR plans, CEL expressions, an eBPF-style verifier, WASM for real computation. |
| E6 CEL, Cedar, WASI 0.3, Rust | No private expression language, policy dialect, or module ABI. |
| E7 Sign at trust boundaries | Local WASM calls are unsigned. Cross-boundary messages are signed envelopes. |
| E8 Bindings for compatibility | Option C. Legacy methods 1–5 stay, labelled legacy and unattested. |
| E9 Hosted, then native | Hosted (host service, VM, OCI container) is the stepping stone. Native is the target. `runtime/` implements the Core workspace. |

## Seven building blocks

| Primitive | Replaces | Specification |
|---|---|---|
| **Identity** | User accounts and UIDs | Roles Owner, Device, Agent, and Service. `did:key` on the owner's devices. OAuth/WIMSE at an enterprise boundary. A2A Signed Agent Cards for agents outside Sidged. |
| **Capability** | Apps, syscalls, IPC surfaces | Descriptor fields: input schema, output schema, effects, data classes, residency, cost, consequential. The thing behind it may be a device, a service, a module, or a legacy app. |
| **Grant** | File permissions and app permissions | Attenuation only. Delegation. Holder binding. Budget. Expiry. Owner policy in Cedar. No effect without a grant. No ambient authority. |
| **Plan** | Scripts and many small apps | A checkable program of capability calls and data flow. Rules for v0 are below. |
| **View** | UI toolkits and app windows | A2UI catalogue. Generated per intent as a GUI or a terminal. Trusted UI is fixed and belongs to the Core. Visual rules are in the L4 design section. |
| **Record** | The file system and app databases | A typed record with data class, provenance, residency, and retention. Files remain only as a legacy view. |
| **Module** | Packages, apps, libraries, userland drivers | A signed WASI 0.3 component with a manifest: capabilities offered and grants required. |

## Communication

- **Local.** Typed calls through the WASM Component Model. Unsigned, because the Core mediates the call.
- **Canonical encoding (SDG-L0).** Core objects have two canonical encodings: canonical JSON (JCS, RFC 8785) and deterministic CBOR (`dcbor`). `dcbor` is mandatory to implement. A signature is over one of those encodings. SDG-L6 does not define a third form.
- **Across a trust boundary** (another device, another owner, a provider, a non-Sidged system). A message: a signed envelope. The envelope signs bytes that are already in an L0 encoding. L6 specifies the envelope and the bindings.
- **Audit log.** Every effect is an audit record with a cryptographic provenance chain.

Peer-to-peer between owners' personal AIs uses the signed envelope on SDG-L6. Legacy apps, services, people (email and messaging), MCP, and A2A attach at that same boundary.

## Language model

Three levels:

| Level | Who writes it | Language |
|---|---|---|
| Core | People, audited | Rust. Minimal dependencies. `no_std`-capable where a component can be. |
| Modules | People or a model | Any language compiled to a WASM/WASI 0.3 component. Foreign code stays out of the Core. |
| Plans | The model, and people | The Sidged plan language. Expressions in CEL. Owner policy in Cedar. An eBPF-style verifier runs before execution. |

Vision section 6 names the on-device ensemble: an embedding model, a router/personal model, a builder model, and further specialists. The choice of weights is open. [0009-models.md](0009-models.md) records the roles. Every one of those models stays outside the security boundary.

## Plan language v0

Accepted with question 4 on 2026-10-14. SDG-L3 will norm this. v0 includes:

- ordered steps
- CEL expressions
- `map` over a finite list with an explicit upper bound
- explicit approval points
- data-flow labels
- budgets
- canonical JSON, with deterministic CBOR for signatures

Canonical JSON (JCS when the bytes are signed) and deterministic CBOR (`dcbor`) are both L0 encodings of that tree. SDG-L6 uses them inside envelopes. It does not own the encoding. Question 4 records the same split: JSON is the form v0 names first, and deterministic CBOR is the signature encoding.

Out of v0: general recursion, unbounded loops, a normative human text syntax, a custom expression language, compiling plans to WASM, and multi-party negotiation inside the plan language. The illustrative plan in analysis chapter 7 is an example, not the grammar.

The verifier computes, before execution, which capabilities run, which data classes are read, which destinations data can leave toward, which steps are consequential, and the maximum cost. A `health.records` value reaches an egress capability only when a Cedar policy allows it. A checked plan can be stored as a tool, signed by the owner, with its own manifest and expiry.

## Security invariants

These are MUSTs in every layer and every mode. Later specs do not weaken them.

1. The model MUST NOT be the security boundary. It proposes. The Core decides.
2. The Core MUST NOT perform an effect without a grant. There is no ambient authority.
3. The Core MUST treat anything a model, a tool, a web page, or a peer supplies as data until the verifier has checked it.
4. A consequential effect MUST have a human approval through Trusted UI. A voice approval MUST include a step a synthetic voice cannot satisfy.
5. Data MUST leave the device only through the Privacy Gateway, with a privacy report.
6. Generated code MUST run only in the WASM sandbox, with at most the rights of the task that generated it.
7. The runtime MUST work offline, in a local mode with no network.
8. Everything outside the Core MUST be a module. The Core stays small.
9. Every effect MUST be logged, with a cryptographic provenance chain.

## Native target (SDG-L8)

Hosted comes first. Native is the end state of E9, not the entry. Vision section 6 packages the same stack four ways: bare metal, a VPS host, a VM, and an OCI container. [0010-deployment.md](0010-deployment.md) names those targets. This section remains the bare-metal image.

- The image is a minimal immutable Linux. The kernel stays, because drivers are decades of work. There is no classic userland: no desktop shell, no app model, no app store, no package manager, no file-manager shell, no separate end-user account logic. Sidged itself is the OS (kernel -> runtime -> interface).
- The Sidged runtime is the system process after init. It owns policy, grants, the verifier, the Privacy Gateway, and the log.
- Updates are A/B images. A failed boot falls back to the previous slot. Rollback does not install an image that has been revoked.
- The Core owns the compositor (Wayland, for example Smithay in Rust). Only the Core can draw Trusted UI. A generated view cannot paint over an approval, the kill switch, or the residency indicator.
- Hardware is reached through kernel drivers and hardware modules with capability descriptors. A model does not receive ambient device files.
- Phones come last, on unlockable hardware (a postmarketOS or AOSP base). iOS is out of scope.
- Devices that cannot carry a full runtime use a shim. The shim speaks the trust-boundary message format and does not pretend to be a Core.

## L4 and the VAIEV Design System

SDG-L4 views and Trusted UI follow VAIEV Design System v4.

- Content is flat. Controls float.
- Semantic tokens are `--vv-*`, with `light-dark()` for light and dark values.
- A sub-brand fills `--vv-color-*`. It does not invent a parallel token set.
- Rose `#A81C55` and `#FF8CB8` are reserved for VAIEV.
- Views MUST meet WCAG 2.2 AA.
- Hit targets are at least 48 by 48 px.
- Views MUST honour `prefers-reduced-motion` and `prefers-reduced-transparency`.

Trusted UI keeps these rules and remains owned by the Core. A generated A2UI view does not restyle an approval, the kill switch, or the residency indicator.

## Runtime crates

The Cargo workspace under `runtime/` comprises 12 crates with minimal, audited dependencies (E6):

```
runtime/
├── sidged-core         shared types and Runtime::execute pipeline
├── sidged-capability   capability descriptor registry
├── sidged-grant        tokens, JCS, Ed25519, did:key, Cedar evaluator
├── sidged-verify       SDG-L3 plan verifier, dCBOR plans, and CedarFlowPolicy (IFC)
├── sidged-mcp          MCP tools/list annotation binding
├── sidged-gateway      Privacy Gateway, residency checks, P0 profiles, anonymization
├── sidged-log          append-only SHA-256 hash-chained and Ed25519-signed audit log
├── sidged-record       content-addressed dCBOR Record store and ResultSurface artifacts
├── sidged-model        stub planner and gateway-routed OpenAI-compatible planner
├── sidged-cli          CLI orchestration, SO_PEERCRED approval, Swarm (0015), Adapters, Turnkey
├── sidged-guard        main `sidged` binary and scenario/conformance runner
└── sidged-tui          `sidged-tui` terminal interface and Core gate
```

Specification text is CC BY 4.0. Code is Apache-2.0.

## E1 – Occupy the trusted runtime

**Status:** Accepted (2026-10-14)

**Decision:** Sidged does not compete with MCP, A2A, or A2UI. It occupies the trusted runtime above and below them: the Core that decides what of that traffic may run.

**Rationale:** Since 2025/26, tools, agent-to-agent exchange, and generated UI each have a foundation behind them. None of those standards decides who may do what, with which data, to where, with whose approval, and how that decision is checked. That missing layer is the Core. It is also where the predecessor drafts were already strongest: Trusted UI, the Privacy Gateway, residency, and provider profiles.

**Rejected alternatives:**

- Another tool protocol beside MCP.
- Another agent protocol beside A2A.
- Another generated-UI protocol beside A2UI, as the thing Sidged is for.

**Consequences:** Capability, Grant, Plan, and Record are defined without a transport. MCP, A2A, and A2UI are bindings. When MCP changes, the binding changes. The core objects do not.

## E2 – Enter as an MCP extension

**Status:** Accepted (2026-10-14)

**Decision:** The first public slice is an MCP extension: capability annotations for effects, data classes, residency, and whether a call is consequential.

**Rationale:** An annotation profile makes an existing MCP server a capability on day one. That is the adoption path. A new server protocol would wait for an ecosystem that MCP already has.

**Rejected alternatives:**

- Requiring every tool to be rewritten against a Sidged-only protocol before it can be described.
- Waiting for the native image before publishing the annotation profile.

**Consequences:** L1 is written so it can be submitted as an MCP SEP, in the same spirit as MCP Apps. Filing waits until L1 is stable and question 10 allows a public repository. The annotations are requirements the Core enforces, not hints the model may ignore.

## E3 – Small layer specs

**Status:** Accepted (2026-10-14)

**Decision:** Replace the three large predecessor documents with small layer specs. Each layer is useful on its own. Each normative spec is at most about 15 pages, in English, with BCP 14 terms, a rationale on each rule, and an explicit "out of scope".

**Rationale:** Standards that shipped were small enough to try in an afternoon, and they ran beside what already existed. Standards that asked everyone to replace their stack first did not. A 15-page layer with a schema, test vectors, and one real user can be adopted. A combined document cannot.

**Rejected alternatives:**

- One combined Sidged standard.
- Keeping three monolithic documents and only renaming them.

**Consequences:** L0 and L1 are the next spec. Later layers do not block that slice. Test vectors under `spec/test-vectors/` are the conformance suite for every implementation. The corpus already ported into `spec/` is input to those specs, not a substitute for them.

## E4 – Seven primitives, no classic userland

**Status:** Accepted (2026-10-14)

**Decision:** Identity, Capability, Grant, Plan, View, Record, and Module replace the classic OS userland. The Linux kernel stays.

**Rationale:** no classic userland; Sidged itself is the OS (kernel -> runtime -> interface). There is no desktop, no app model, no app store, no package manager, no file manager, and no end-user account logic. The kernel stays, because drivers are decades of work. Apps become capabilities. The UI around a capability is generated per task. A tool the planner needs is a checked plan, or, when it needs real computation, a WASM module. It is never code loaded into the Core.

**Rejected alternatives:**

- A new Linux distribution whose userland is still apps, packages, and files, with a chat window on top.
- Treating the model as the shell and giving it ambient authority.

**Consequences:** Installers disappear for anything the task does not need. Records carry class, provenance, residency, and retention. The file system is a legacy view, required for adoption, not the data model.

## E5 – A language only for plans

**Status:** Accepted (2026-10-14)

**Decision:** Sidged defines one new language, and only for plans. A plan is declarative, always terminates, is statically checkable, and carries data-flow labels. The canonical form is a JSON or CBOR tree. Expressions are CEL. There is no Sidged expression language.

**Rationale:** The Core has to prove, before execution, what a model-written tool will do. That is the property that existing tool protocols do not give. Models write JSON reliably and write unfamiliar general-purpose languages poorly. A new general-purpose language would also mean a compiler, a debugger, a standard library, and years of audit. The precedent is eBPF: foreign code runs only after a verifier has proved the properties that matter. Here the foreign program is a plan, and the properties are effects, data classes, egress, consequential steps, and cost.

**Rejected alternatives:**

- A new general-purpose language for modules and plans.
- Letting the model emit host code into the Core.
- Using the prompt as the policy.

**Consequences:** v0 of the plan language is bounded in question 4. The verifier computes, before execution, which capabilities run, which data classes are read, which destinations data can leave toward, which steps are consequential, and the maximum cost. Data-flow labels travel with values: a `health.records` value does not flow into an egress capability unless a policy explicitly allows it. That check does not depend on the model, which is what makes it a control against prompt injection. A checked plan can be stored as a tool, signed by the owner, with its own manifest and expiry. Computation that is not a plan is a WASM module in the sandbox.

## E6 – Adopt CEL, Cedar, WASI 0.3, and Rust

**Status:** Accepted (2026-10-14)

**Decision:** Invent a mechanism only where none exists. Expressions in plans are CEL. Owner policy is Cedar. Modules are WASM components on WASI 0.3. The Core is Rust, with a small dependency set, and `no_std` where a component can be.

**Rationale:** CEL is already non-Turing-complete and deployed. Cedar has a formal semantics and is built to be checked. WASI 0.3 (ratified 11 June 2026) is the portable, isolated, typed module format this system needs. Rust is memory-safe and auditable. A private expression language, a private policy language, or a private bytecode would be permanent maintenance.

**Rejected alternatives:**

- A Sidged expression language beside CEL.
- A smaller home-grown policy language for v0 that would fork away from Cedar.
- A Python or TypeScript Core.
- A module ABI other than the WASM Component Model.

**Consequences:** Every new crate in `runtime/` needs a reason. The workspace exists (phase 7). The v0 runtime may implement only the Cedar fragment it evaluates, and that fragment is Cedar, not a dialect (question 5). Foreign code does not run in the Core. Grant checks use that fragment. The plan verifier's flow hook is separate and is not that evaluator.

## E7 – Sign at trust boundaries

**Status:** Accepted (2026-10-14)

**Decision:** Sign when a message crosses a trust boundary. Do not sign local calls inside the Core.

**Rationale:** Local calls are mediated by the Core. An envelope on each of them costs latency and adds no trust, because the Core is the party that would check the signature it just produced. A message to another device, another owner, or a provider is outside that trust. That message is a signed envelope. The same boundary is where an A2A binding carries a foreign agent.

**Rejected alternatives:**

- An envelope on every in-process call.
- No signatures anywhere, including provider and peer traffic.

**Consequences:** L6 specifies the envelope and the bindings. The bytes it signs are an L0 canonical encoding (`dcbor` or JCS), not an encoding L6 invents. L2 tokens are still bound to the sender. The schema for the envelope stays in `spec/schemas/` and is scoped, in the layer spec, to trust-boundary messages. Signature checks need keys and are not done by the structural validator.

## E8 – Compatibility through bindings

**Status:** Accepted (2026-10-14)

**Decision:** Confirm option C from the analysis. Sidged defines bindings and extensions for MCP, A2A, and A2UI, and its own specs only for the Core contract, grants, the plan language, Trusted UI, the Privacy Gateway, provider profiles, and the native system. Legacy methods 1–5 stay, as modules, labelled legacy and unattested.

**Rationale:** Option C is usable on day one and still owns the decisions that the other standards do not make. Someone who already speaks MCP or A2A can participate without a rewrite. Legacy methods are how existing apps, contacts, and services show up as capabilities.

**Rejected alternatives:**

- Option A: a private tool, agent, UI, and identity stack. Full control, no ecosystem, one project against foundations.
- Option B: only a profile over MCP, A2A, and A2UI. Fast to adopt, and unable to carry the plan language, Trusted UI, or the native target.

**Consequences:** Bindings are maintained when MCP or A2A changes. Core objects stay protocol-neutral so a binding can be replaced. Enterprise identity aligns with OAuth, WIMSE, and A2A signed Agent Cards instead of a competing identity protocol. `did:key` remains the mechanism for the owner's own devices.

## E9 – Hosted, then native

**Status:** Accepted (2026-10-14)

**Decision:** The path is Hosted, then Native, with Shim for devices that cannot run a full runtime. Native means kernel, then runtime, then interface, as drawn above.

**Rationale:** Systems that required a full replacement on day one failed. Systems that ran beside what people already use shipped. Each step on this path has to be useful by itself. The vision stays the native image. The work that reaches it is a hosted runtime on ordinary Linux.

**Rejected alternatives:**

- Starting with a phone image or a new device.
- Treating native as the first milestone and hosted as a demo.

**Consequences:** `runtime/` implements the hosted Core workspace, packaged for Linux hosts (`scripts/install-sidged-host.sh`), OCI containers (`Containerfile`), and bootable VM disk images (`scripts/build-vm-disk.sh`). L8 specifies the bare-metal native target.

## Summary of foundational choices

1. **Identifiers.** The name is Sidged, the prefix is `sdg.*`, the namespace is `urn:sidged:`, and the schema root is <https://sidged.com/spec/schemas/>.
2. **Option C.** Confirm E8: Sidged defines bindings for MCP, A2A, and A2UI while owning the security Core, grants, plan verification, Trusted UI, and the Privacy Gateway.
3. **MCP extension.** L1 is written so it can be submitted as an MCP SEP.
4. **Plan language v0.** Ordered steps, CEL expressions, bounded `map` (`1..32`), explicit approval points, data-flow labels, and budgets. Canonical JSON and deterministic CBOR (`dcbor`).
5. **Policy language.** Cedar (`cedar-policy`) for capability grant checks (`sidged-grant`) and Information Flow Control (`sidged-verify::flow`).
6. **Data classes and residency.** Maintained in `spec/registries/data-classes.md` and `spec/registries/residency.md` (`CH`, `EU`, `CH-EU`, `unrestricted`, plus `x-` owner tags).
7. **Language.** Specifications, code, tests, and commit messages are in English.

## Out of scope for this decision record

- Replacing the individual layer specifications (`0001`–`0017`).
- Governance, external RFC comment windows, or patent policy beyond the Apache-2.0 and CC BY 4.0 licenses and Developer Certificate of Origin (DCO).
